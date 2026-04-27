#!/usr/bin/env python3
"""
core/acunetix.py — Integración con Acunetix API REST
Documentación: https://www.acunetix.com/support/docs/api/

Flujo:
  1. Crea target en Acunetix
  2. Lanza scan
  3. Espera resultados
  4. Recoge findings → guarda en DB de Hackeadora
  5. Borra scan Y target de Acunetix (limpieza automática)
  6. Notifica por Telegram

Uso:
  python3 core/acunetix.py --scan app.empresa.com --domain empresa.com
  python3 core/acunetix.py --scan app.empresa.com --domain empresa.com --no-wait
  python3 core/acunetix.py --collect <acunetix_scan_id> --domain empresa.com
  python3 core/acunetix.py --test
  python3 core/acunetix.py --list-scans
"""

import os
import sys
import json
import sqlite3
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] pip3 install requests urllib3")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent
DB_PATH       = os.environ.get("RECONFLOW_DB",       str(BASE_DIR / "data" / "recon.db"))
ACX_URL       = os.environ.get("ACUNETIX_URL",       "https://localhost:3443")
ACX_API_KEY   = os.environ.get("ACUNETIX_API_KEY",   "")
VERIFY_SSL    = os.environ.get("ACUNETIX_VERIFY_SSL","false").lower() == "true"
TELEGRAM_BOT  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID",   "")

# Profiles disponibles en Acunetix
PROFILES = {
    "full":         "full_scan",
    "high_risk":    "high_risk_vulnerabilities",
    "xss":          "xss_vulnerabilities",
    "sqli":         "sql_injection",
    "crawl":        "crawl_only",
    "weak_pass":    "weak_passwords",
}

# ── API Client ────────────────────────────────────────────────
class AcunetixClient:
    def __init__(self):
        self.base = ACX_URL.rstrip("/")
        self.headers = {
            "X-Auth":       ACX_API_KEY,
            "Content-Type": "application/json",
        }

    def _req(self, method: str, path: str, **kwargs) -> Optional[dict]:
        url = f"{self.base}/api/v1{path}"
        try:
            r = getattr(requests, method)(
                url, headers=self.headers,
                verify=VERIFY_SSL, timeout=30, **kwargs
            )
            if r.status_code in (200, 201):
                try:    return r.json()
                except: return {"status": r.status_code}
            if r.status_code == 204:
                return {"status": 204}
            print(f"  [!] Acunetix {r.status_code}: {path} — {r.text[:150]}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"  [!] Sin conexión con Acunetix en {self.base}")
            print(f"      Verifica que Acunetix está corriendo y ACUNETIX_URL es correcto")
            return None
        except Exception as e:
            print(f"  [!] Error Acunetix: {e}")
            return None

    # ── Test ──────────────────────────────────────────────────
    def test(self) -> bool:
        r = self._req("get", "/me")
        if r:
            print(f"  [✓] Acunetix OK: {self.base}")
            print(f"      Cuenta: {r.get('email', r.get('first_name','?'))}")
            # Ver límites de scans si están disponibles
            info = self._req("get", "/info")
            if info:
                concurrent = info.get("max_scans", "?")
                print(f"      Scans concurrentes permitidos: {concurrent}")
            return True
        return False

    # ── Targets ───────────────────────────────────────────────
    def get_target_by_address(self, address: str) -> Optional[str]:
        r = self._req("get", "/targets", params={"l": 100})
        if not r: return None
        for t in r.get("targets", []):
            if t.get("address","").rstrip("/") == address.rstrip("/"):
                return t["target_id"]
        return None

    def create_target(self, address: str, description: str = "") -> Optional[str]:
        r = self._req("post", "/targets", json={
            "address":     address,
            "description": description or f"Hackeadora — {address}",
            "type":        "default",
        })
        return r.get("target_id") if r else None

    def delete_target(self, target_id: str) -> bool:
        r = self._req("delete", f"/targets/{target_id}")
        return r is not None

    # ── Scans ─────────────────────────────────────────────────
    def launch_scan(self, target_id: str,
                    profile: str = "full_scan") -> Optional[str]:
        r = self._req("post", "/scans", json={
            "target_id":  target_id,
            "profile_id": profile,
            "schedule": {
                "disable":        False,
                "start_date":     None,
                "time_sensitive": False,
            },
        })
        return r.get("scan_id") if r else None

    def get_scan_status(self, scan_id: str) -> Optional[dict]:
        return self._req("get", f"/scans/{scan_id}")

    def abort_scan(self, scan_id: str) -> bool:
        r = self._req("post", f"/scans/{scan_id}/abort")
        return r is not None

    def delete_scan(self, scan_id: str) -> bool:
        r = self._req("delete", f"/scans/{scan_id}")
        return r is not None

    def list_scans(self) -> list:
        r = self._req("get", "/scans", params={"l": 100})
        return r.get("scans", []) if r else []

    # ── Results ───────────────────────────────────────────────
    def get_results(self, scan_id: str) -> tuple[Optional[str], list]:
        """Devuelve (result_id, lista de vulnerabilidades)."""
        r = self._req("get", f"/scans/{scan_id}/results")
        if not r: return None, []

        # Coger el result completado más reciente
        result_id = None
        for res in sorted(r.get("results", []),
                          key=lambda x: x.get("end_date",""), reverse=True):
            if res.get("status") == "completed":
                result_id = res.get("result_id")
                break

        if not result_id:
            return None, []

        # Paginación — Acunetix devuelve max 100 por página
        vulns = []
        cursor = None
        while True:
            params = {"l": 100}
            if cursor: params["c"] = cursor
            page = self._req("get",
                f"/scans/{scan_id}/results/{result_id}/vulnerabilities",
                params=params)
            if not page: break
            page_vulns = page.get("vulnerabilities", [])
            vulns.extend(page_vulns)
            cursor = page.get("next_cursor")
            if not cursor or not page_vulns:
                break

        return result_id, vulns

# ── DB helpers ────────────────────────────────────────────────
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_domain_id(domain: str) -> Optional[int]:
    with db_conn() as conn:
        r = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        return r["id"] if r else None

def save_scan_record(domain_id: int, subdomain: str,
                     acx_scan_id: str, acx_target_id: str) -> int:
    with db_conn() as conn:
        conn.execute(
            """INSERT INTO acunetix_scans
               (domain_id,subdomain,acunetix_scan_id,acunetix_target_id,
                status,started_at)
               VALUES(?,?,?,?,'running',CURRENT_TIMESTAMP)""",
            (domain_id, subdomain, acx_scan_id, acx_target_id)
        )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]

def complete_scan_record(scan_db_id: int, status: str, n_findings: int):
    with db_conn() as conn:
        conn.execute(
            """UPDATE acunetix_scans
               SET status=?, finished_at=CURRENT_TIMESTAMP, findings_count=?
               WHERE id=?""",
            (status, n_findings, scan_db_id)
        )
        conn.commit()

def save_finding_record(domain_id: int, scan_db_id: int,
                        subdomain: str, vuln: dict):
    SEV_MAP = {
        "critical":"critical","high":"high",
        "medium":"medium","low":"low",
        "informational":"info","info":"info",
    }
    sev = SEV_MAP.get(vuln.get("severity","").lower(), "info")

    with db_conn() as conn:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO acunetix_findings
                   (domain_id,scan_id,subdomain,vuln_id,name,severity,
                    confidence,url,parameter,detail,recommendation,
                    cvss_score,cwe)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    domain_id, scan_db_id, subdomain,
                    vuln.get("vuln_id",""),
                    vuln.get("vt_name", vuln.get("name","")),
                    sev,
                    vuln.get("confidence",""),
                    vuln.get("affects_url",""),
                    vuln.get("affects_detail",""),
                    str(vuln.get("description",""))[:500],
                    str(vuln.get("recommendation",""))[:300],
                    float(vuln.get("cvss3_score", vuln.get("cvss_score", 0)) or 0),
                    vuln.get("cwe",""),
                )
            )
            conn.commit()
        except Exception as e:
            print(f"  [!] Error guardando finding: {e}")

    # También insertar en la tabla findings principal de Hackeadora
    # para que aparezca en el dashboard general
    try:
        name  = vuln.get("vt_name", vuln.get("name",""))
        url   = vuln.get("affects_url","")
        with db_conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO findings
                   (domain_id,type,severity,target,template,detail)
                   VALUES(?,?,?,?,?,?)""",
                (domain_id, "acunetix", sev,
                 url or subdomain, f"acunetix:{name}",
                 f"{name} — {vuln.get('affects_detail','')}".strip("— "))
            )
            conn.commit()
    except Exception:
        pass

# ── Telegram ──────────────────────────────────────────────────
def notify(msg: str):
    if not TELEGRAM_BOT or not TELEGRAM_CHAT: return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception:
        pass

# ── Flujo principal ───────────────────────────────────────────
def run_scan(subdomain: str, domain: str,
             profile: str = "full_scan",
             wait: bool = True,
             cleanup: bool = True) -> dict:
    """
    Lanza un scan Acunetix completo sobre un subdominio.
    cleanup=True → borra el scan Y el target de Acunetix al terminar.
    """
    client     = AcunetixClient()
    domain_id  = get_domain_id(domain)

    if not domain_id:
        return {"error": f"Dominio {domain} no encontrado en DB de Hackeadora"}

    if not ACX_API_KEY:
        return {"error": "ACUNETIX_API_KEY no configurada"}

    address = f"https://{subdomain}"
    print(f"\n[→] Acunetix — {address} ({profile})")

    # ── Crear target ──────────────────────────────────────────
    # Primero intentar reusar uno existente
    target_id = client.get_target_by_address(address)
    if target_id:
        print(f"    Reusando target: {target_id}")
    else:
        target_id = client.create_target(address)
        if not target_id:
            return {"error": "No se pudo crear el target en Acunetix"}
        print(f"    Target creado: {target_id}")

    # ── Lanzar scan ───────────────────────────────────────────
    scan_id = client.launch_scan(target_id, profile)
    if not scan_id:
        if cleanup: client.delete_target(target_id)
        return {"error": "No se pudo lanzar el scan"}

    print(f"    Scan ID: {scan_id}")
    scan_db_id = save_scan_record(domain_id, subdomain, scan_id, target_id)

    notify(f"🔍 *Acunetix scan iniciado*\n"
           f"🌐 `{subdomain}`\n"
           f"📋 Profile: `{profile}`\n"
           f"🆔 `{scan_id}`\n"
           f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if not wait:
        return {
            "scan_id":    scan_id,
            "scan_db_id": scan_db_id,
            "target_id":  target_id,
            "status":     "running",
        }

    # ── Esperar resultados ────────────────────────────────────
    print(f"    Esperando", end="", flush=True)
    start    = time.time()
    MAX_WAIT = 7200  # 2 horas

    while time.time() - start < MAX_WAIT:
        time.sleep(30)
        print(".", end="", flush=True)

        status_data = client.get_scan_status(scan_id)
        if not status_data:
            continue

        session  = status_data.get("current_session", {})
        status   = session.get("status", "")
        progress = session.get("progress", 0)

        if status == "completed":
            print(f" ✓ completado ({int(time.time()-start)}s)")
            break
        elif status in ("aborted","failed"):
            print(f" {status}")
            complete_scan_record(scan_db_id, status, 0)
            if cleanup:
                print("    Limpiando Acunetix...")
                client.delete_scan(scan_id)
                client.delete_target(target_id)
            return {"scan_id": scan_id, "status": status, "findings": []}
    else:
        print(" timeout")
        client.abort_scan(scan_id)
        complete_scan_record(scan_db_id, "timeout", 0)
        if cleanup:
            client.delete_scan(scan_id)
            client.delete_target(target_id)
        return {"scan_id": scan_id, "status": "timeout", "findings": []}

    # ── Recoger findings ──────────────────────────────────────
    print(f"    Recogiendo findings...")
    result_id, vulns = client.get_results(scan_id)
    print(f"    {len(vulns)} vulnerabilidades")

    findings_summary = []
    for vuln in vulns:
        save_finding_record(domain_id, scan_db_id, subdomain, vuln)
        sev  = vuln.get("severity","info").lower()
        name = vuln.get("vt_name", vuln.get("name",""))
        url  = vuln.get("affects_url","")
        findings_summary.append({"name": name, "severity": sev, "url": url})

        # Notificar críticos y altos inmediatamente
        if sev in ("critical","high"):
            notify(f"🔴 *Acunetix — {sev.upper()}*\n"
                   f"🌐 `{subdomain}`\n"
                   f"📋 `{name}`\n"
                   f"🔗 `{url[:100]}`\n"
                   f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    complete_scan_record(scan_db_id, "completed", len(vulns))

    # ── Resumen por Telegram ──────────────────────────────────
    crits  = sum(1 for f in findings_summary if f["severity"] == "critical")
    highs  = sum(1 for f in findings_summary if f["severity"] == "high")
    notify(f"✅ *Acunetix scan completado*\n"
           f"🌐 `{subdomain}`\n"
           f"📊 Total: {len(vulns)} vulnerabilidades\n"
           f"🔴 Critical: {crits} | High: {highs}\n"
           f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Limpiar Acunetix (scan + target) ─────────────────────
    if cleanup:
        print(f"    Limpiando Acunetix (scan + target)...")
        deleted_scan   = client.delete_scan(scan_id)
        deleted_target = client.delete_target(target_id)
        if deleted_scan and deleted_target:
            print(f"    [✓] Scan y target eliminados de Acunetix")
        else:
            print(f"    [!] Error en limpieza — revisa Acunetix manualmente")

    return {
        "scan_id":    scan_id,
        "scan_db_id": scan_db_id,
        "status":     "completed",
        "total":      len(vulns),
        "critical":   crits,
        "high":       highs,
        "findings":   findings_summary,
    }

# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Acunetix integration para Hackeadora")
    parser.add_argument("--scan",       help="Subdominio a escanear (ej: app.empresa.com)")
    parser.add_argument("--domain",     help="Dominio raíz (ej: empresa.com)")
    parser.add_argument("--profile",    default="full_scan",
                        choices=list(PROFILES.values()) + list(PROFILES.keys()),
                        help="Profile de scan (default: full_scan)")
    parser.add_argument("--no-wait",    action="store_true",
                        help="No esperar — lanzar y salir")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="No borrar scan/target de Acunetix tras terminar")
    parser.add_argument("--collect",    help="Recoger resultados de un scan_id existente")
    parser.add_argument("--test",       action="store_true",
                        help="Test de conectividad con Acunetix")
    parser.add_argument("--list-scans", action="store_true",
                        help="Ver scans activos en Acunetix")
    args = parser.parse_args()

    if args.test:
        AcunetixClient().test()
        return

    if args.list_scans:
        scans = AcunetixClient().list_scans()
        print(f"{len(scans)} scans en Acunetix:")
        for s in scans:
            sess   = s.get("current_session", {})
            status = sess.get("status","?")
            prog   = sess.get("progress", 0)
            target = s.get("target",{}).get("address","?")
            print(f"  {s['scan_id'][:8]}... {target} — {status} ({prog}%)")
        return

    if args.scan:
        if not args.domain:
            print("[!] --domain requerido con --scan")
            sys.exit(1)

        # Resolver profile alias
        profile = PROFILES.get(args.profile, args.profile)

        result = run_scan(
            subdomain = args.scan,
            domain    = args.domain,
            profile   = profile,
            wait      = not args.no_wait,
            cleanup   = not args.no_cleanup,
        )

        print(f"\nResultado: {json.dumps(result, indent=2)}")
        return

    parser.print_help()

if __name__ == "__main__":
    main()
