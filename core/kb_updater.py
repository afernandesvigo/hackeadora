#!/usr/bin/env python3
"""
core/kb_updater.py — Actualizador mensual de la Knowledge Base
Fuentes:
  - HackerOne Hacktivity API (reportes públicos divulgados)
  - GitHub commits de PayloadsAllTheThings
  - GitHub commits de HowToHunt
  - GitHub commits de nuclei-templates
Uso:
  python3 core/kb_updater.py [--force]
  python3 core/kb_updater.py --dry-run
"""

import os
import sys
import json
import re
import time
import argparse
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] Instala requests: pip3 install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
KB_PATH     = BASE_DIR / "core" / "knowledge_base.json"
KB_BACKUP   = BASE_DIR / "core" / "knowledge_base.bak.json"
UPDATE_LOG  = BASE_DIR / "data" / "kb_updates.jsonl"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
TELEGRAM_BOT = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

HEADERS = {
    "User-Agent": "Hackeadora-KB-Updater/1.0",
    "Accept": "application/json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ── Fuentes ───────────────────────────────────────────────────
GITHUB_REPOS = [
    {
        "repo": "swisskyrepo/PayloadsAllTheThings",
        "relevant_paths": [
            "Server Side Request Forgery",
            "SQL Injection",
            "XSS Injection",
            "File Inclusion",
            "Open Redirect",
            "CSRF Injection",
            "XXE Injection",
            "Upload Insecure Files",
            "Server Side Template Injection",
            "GraphQL Injection",
        ],
        "vuln_map": {
            "Server Side Request Forgery": "SSRF",
            "SQL Injection": "SQLI",
            "XSS Injection": "XSS_STORED",
            "File Inclusion": "LFI",
            "Open Redirect": "OPEN_REDIRECT",
            "CSRF Injection": "CSRF",
            "XXE Injection": "XXE",
            "Upload Insecure Files": "FILE_UPLOAD",
            "Server Side Template Injection": "SSTI",
            "GraphQL Injection": "GRAPHQL",
        }
    },
    {
        "repo": "KathanP19/HowToHunt",
        "relevant_paths": ["IDOR","SSRF","XSS","SQLi","CORS","Open_Redirect"],
        "vuln_map": {
            "IDOR": "IDOR",
            "SSRF": "SSRF",
            "XSS":  "XSS_STORED",
            "SQLi": "SQLI",
            "CORS": "CORS",
            "Open_Redirect": "OPEN_REDIRECT",
        }
    },
    {
        "repo": "projectdiscovery/nuclei-templates",
        "relevant_paths": ["vulnerabilities","exposures","misconfiguration","cves"],
        "vuln_map": {}
    }
]

# ── Regex para extraer patrones de parámetros de Markdown ─────
PARAM_PATTERN = re.compile(
    r'\b(\w+)[\s]*[=:][\s]*["\']?(?:FUZZ|test|payload|evil|attacker)',
    re.IGNORECASE
)
URL_PARAM_PATTERN = re.compile(
    r'\?(\w+)=',
    re.IGNORECASE
)
PAYLOAD_PATTERN = re.compile(
    r'`([^`\n]{3,100})`|"([^"\n]{3,100})"',
)

# ── Helpers ───────────────────────────────────────────────────
def gh_get(url: str, params: dict = None) -> Optional[dict]:
    """GET a GitHub API URL con rate limiting."""
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=15)
        if r.status_code == 403:
            reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait  = max(reset - int(time.time()), 5)
            print(f"  [!] Rate limit GitHub — esperando {wait}s")
            time.sleep(wait)
            r = requests.get(url, headers=HEADERS, params=params, timeout=15)
        if r.status_code == 200:
            return r.json()
        print(f"  [!] GitHub API {r.status_code}: {url}")
        return None
    except Exception as e:
        print(f"  [!] Error: {e}")
        return None

def notify_telegram(msg: str):
    if not TELEGRAM_BOT or not TELEGRAM_CHAT:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception:
        pass

def load_kb() -> dict:
    with open(KB_PATH) as f:
        return json.load(f)

def save_kb(kb: dict):
    # Backup primero
    if KB_PATH.exists():
        import shutil
        shutil.copy(KB_PATH, KB_BACKUP)
    with open(KB_PATH, "w") as f:
        json.dump(kb, f, indent=2, ensure_ascii=False)

def log_update(entry: dict):
    UPDATE_LOG.parent.mkdir(exist_ok=True)
    with open(UPDATE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def get_vuln_by_id(kb: dict, vuln_id: str) -> Optional[dict]:
    for v in kb["vulnerabilities"]:
        if v["id"] == vuln_id:
            return v
    return None

# ── Parsers de contenido Markdown ─────────────────────────────
def extract_params_from_md(content: str) -> list:
    """Extrae nombres de parámetros mencionados en Markdown."""
    params = set()
    # Parámetros en URLs de ejemplo
    params.update(URL_PARAM_PATTERN.findall(content))
    # Parámetros con = en code blocks
    params.update(PARAM_PATTERN.findall(content))
    # Limpiar y filtrar
    cleaned = []
    for p in params:
        p = p.strip().lower()
        if p and len(p) > 1 and len(p) < 30 and p.isidentifier():
            cleaned.append(p)
    return cleaned

def extract_payloads_from_md(content: str, vuln_type: str) -> list:
    """Extrae payloads de bloques de código en Markdown."""
    payloads = []
    # Bloques de código ```
    code_blocks = re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL)
    for block in code_blocks[:5]:  # máximo 5 bloques
        lines = block.strip().split('\n')
        for line in lines[:10]:  # máximo 10 líneas por bloque
            line = line.strip()
            if len(line) > 3 and len(line) < 200:
                # Filtrar solo líneas que parecen payloads
                if any(c in line for c in ["'","\"","<",">","{{","${","../","//","%",";","--"]):
                    payloads.append(line)
    return payloads[:20]  # máximo 20 payloads nuevos por fuente

def extract_paths_from_md(content: str) -> list:
    """Extrae rutas de endpoints mencionadas en Markdown."""
    paths = re.findall(r'(?<!["\w])(\/[a-zA-Z0-9_/\-\.]+)', content)
    filtered = []
    for p in paths:
        if len(p) > 2 and len(p) < 50 and '.' not in p.split('/')[-1]:
            filtered.append(p)
    return list(set(filtered))[:15]

# ── Fuente 1: HackerOne Hacktivity ───────────────────────────
def update_from_hackerone(kb: dict, days_back: int = 30) -> dict:
    """
    Consulta HackerOne Hacktivity API pública.
    Extrae patrones de los reportes públicos divulgados.
    """
    print("\n[→] HackerOne Hacktivity...")
    stats = {"new_params": 0, "new_payloads": 0, "reports_parsed": 0}

    # H1 tiene una API GraphQL pública para hacktivity
    # Usamos el endpoint de búsqueda público
    url = "https://hackerone.com/graphql"
    since = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = """
    query {
      hacktivity_items(
        order_direction: DESC,
        order_field: popular,
        product_area: hacktivity,
        product_feature: overview,
        filter: {
          disclosed: true,
          hacktivity_type: ALL
        },
        first: 50
      ) {
        edges {
          node {
            ... on HacktivityItem {
              report {
                title
                vulnerability_information
                weakness { name external_id }
                severity { rating }
                structured_scope { asset_identifier }
              }
            }
          }
        }
      }
    }
    """

    try:
        r = requests.post(
            url,
            json={"query": query},
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=20
        )
        if r.status_code != 200:
            print(f"  [!] HackerOne API: {r.status_code}")
            return stats

        data = r.json()
        edges = data.get("data", {}).get("hacktivity_items", {}).get("edges", [])
        print(f"  Reportes obtenidos: {len(edges)}")

        # Mapeo de CWE/weakness a nuestros IDs de vuln
        weakness_map = {
            "XSS":           "XSS_STORED",
            "Cross-Site Scripting": "XSS_STORED",
            "SQL Injection": "SQLI",
            "SSRF":          "SSRF",
            "Server-Side Request Forgery": "SSRF",
            "IDOR":          "IDOR",
            "Insecure Direct Object Reference": "IDOR",
            "Open Redirect": "OPEN_REDIRECT",
            "SSTI":          "SSTI",
            "LFI":           "LFI",
            "Path Traversal": "LFI",
            "CORS":          "CORS",
            "CSRF":          "CSRF",
            "XXE":           "XXE",
            "File Upload":   "FILE_UPLOAD",
            "GraphQL":       "GRAPHQL",
            "OAuth":         "OAUTH_MISCONFIG",
            "Cache":         "CACHE_POISON",
            "Host Header":   "HOST_HEADER",
        }

        for edge in edges:
            try:
                node   = edge.get("node", {})
                report = node.get("report", {})
                if not report:
                    continue

                title   = report.get("title", "")
                vuln_info = report.get("vulnerability_information", "") or ""
                weakness = report.get("weakness", {}) or {}
                w_name   = weakness.get("name", "")

                # Detectar tipo de vuln
                vuln_id = None
                for kw, vid in weakness_map.items():
                    if kw.lower() in w_name.lower() or kw.lower() in title.lower():
                        vuln_id = vid
                        break

                if not vuln_id:
                    continue

                vuln = get_vuln_by_id(kb, vuln_id)
                if not vuln:
                    continue

                # Extraer parámetros del título y descripción
                new_params = extract_params_from_md(title + " " + vuln_info[:2000])
                added = 0
                for p in new_params:
                    if p not in vuln.get("trigger_params", []):
                        vuln.setdefault("trigger_params", []).append(p)
                        added += 1
                        stats["new_params"] += 1

                stats["reports_parsed"] += 1

            except Exception:
                continue

    except Exception as e:
        print(f"  [!] Error HackerOne: {e}")

    print(f"  → {stats['reports_parsed']} reportes, {stats['new_params']} params nuevos")
    return stats

# ── Fuente 2: GitHub repos (PayloadsAllTheThings, HowToHunt) ──
def update_from_github_repos(kb: dict, days_back: int = 30) -> dict:
    """Descarga commits recientes y extrae patrones nuevos."""
    stats = {"new_params": 0, "new_payloads": 0, "new_paths": 0, "files_parsed": 0}
    since = (datetime.now() - timedelta(days=days_back)).isoformat() + "Z"

    for repo_cfg in GITHUB_REPOS[:2]:  # Solo las 2 primeras para no agotar rate limit
        repo = repo_cfg["repo"]
        print(f"\n[→] GitHub: {repo}...")

        # Obtener commits recientes
        commits_data = gh_get(
            f"https://api.github.com/repos/{repo}/commits",
            params={"since": since, "per_page": 20}
        )
        if not commits_data:
            continue

        print(f"  Commits recientes: {len(commits_data)}")

        for commit in commits_data[:10]:  # Máximo 10 commits
            sha = commit.get("sha", "")
            if not sha:
                continue

            # Obtener archivos modificados en este commit
            commit_detail = gh_get(f"https://api.github.com/repos/{repo}/commits/{sha}")
            if not commit_detail:
                continue

            files = commit_detail.get("files", [])
            for file_info in files[:5]:  # Máximo 5 archivos por commit
                filename = file_info.get("filename", "")
                if not filename.endswith(".md") and not filename.endswith(".txt"):
                    continue

                # Determinar qué vuln corresponde
                vuln_id = None
                for path_key, vid in repo_cfg["vuln_map"].items():
                    if path_key.lower() in filename.lower():
                        vuln_id = vid
                        break

                if not vuln_id:
                    continue

                vuln = get_vuln_by_id(kb, vuln_id)
                if not vuln:
                    continue

                # Descargar contenido del archivo
                raw_url = f"https://raw.githubusercontent.com/{repo}/master/{filename}"
                try:
                    r = requests.get(raw_url, timeout=10)
                    if r.status_code != 200:
                        continue
                    content = r.text[:50000]  # Máximo 50KB
                except Exception:
                    continue

                # Extraer patrones
                new_params = extract_params_from_md(content)
                for p in new_params:
                    if p not in vuln.get("trigger_params", []):
                        vuln.setdefault("trigger_params", []).append(p)
                        stats["new_params"] += 1

                new_payloads = extract_payloads_from_md(content, vuln_id)
                for p in new_payloads:
                    if p not in vuln.get("payloads", []):
                        vuln.setdefault("payloads", []).append(p)
                        stats["new_payloads"] += 1

                new_paths = extract_paths_from_md(content)
                for p in new_paths:
                    if p not in vuln.get("trigger_paths", []):
                        vuln.setdefault("trigger_paths", []).append(p)
                        stats["new_paths"] += 1

                stats["files_parsed"] += 1
                time.sleep(0.5)  # Rate limiting

            time.sleep(1)

    print(f"\n  → {stats['files_parsed']} archivos: "
          f"+{stats['new_params']} params, "
          f"+{stats['new_payloads']} payloads, "
          f"+{stats['new_paths']} paths")
    return stats

# ── Fuente 3: Nuclei templates nuevos ─────────────────────────
def update_from_nuclei_templates(kb: dict, days_back: int = 30) -> dict:
    """Analiza nuevos templates de nuclei para extraer tags relevantes."""
    stats = {"new_tags": 0, "templates_parsed": 0}
    since = (datetime.now() - timedelta(days=days_back)).isoformat() + "Z"

    print("\n[→] Nuclei templates nuevos...")

    commits_data = gh_get(
        "https://api.github.com/repos/projectdiscovery/nuclei-templates/commits",
        params={"since": since, "per_page": 10}
    )
    if not commits_data:
        return stats

    tag_to_vuln = {
        "ssrf": "SSRF", "sqli": "SQLI", "xss": "XSS_STORED",
        "lfi": "LFI", "idor": "IDOR", "ssti": "SSTI",
        "xxe": "XXE", "cors": "CORS", "csrf": "CSRF",
        "graphql": "GRAPHQL", "oauth": "OAUTH_MISCONFIG",
        "upload": "FILE_UPLOAD", "redirect": "OPEN_REDIRECT",
        "cache": "CACHE_POISON", "host-header": "HOST_HEADER",
    }

    for commit in commits_data[:5]:
        sha = commit.get("sha", "")
        commit_detail = gh_get(f"https://api.github.com/repos/projectdiscovery/nuclei-templates/commits/{sha}")
        if not commit_detail:
            continue

        for file_info in commit_detail.get("files", [])[:5]:
            filename = file_info.get("filename", "")
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue

            raw_url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/{filename}"
            try:
                r = requests.get(raw_url, timeout=10)
                if r.status_code != 200:
                    continue
                content = r.text

                # Extraer tags del YAML
                tags_match = re.search(r'tags:\s*(.+)', content)
                if not tags_match:
                    continue

                tags = [t.strip() for t in tags_match.group(1).split(",")]

                for tag in tags:
                    vuln_id = tag_to_vuln.get(tag.lower())
                    if not vuln_id:
                        continue
                    vuln = get_vuln_by_id(kb, vuln_id)
                    if vuln and tag not in vuln.get("nuclei_tags", []):
                        vuln.setdefault("nuclei_tags", []).append(tag)
                        stats["new_tags"] += 1

                stats["templates_parsed"] += 1
            except Exception:
                continue
            time.sleep(0.3)

    print(f"  → {stats['templates_parsed']} templates, +{stats['new_tags']} tags")
    return stats

# ── Deduplicar y limpiar la KB ────────────────────────────────
def clean_kb(kb: dict) -> dict:
    """Elimina duplicados y ordena listas."""
    for vuln in kb["vulnerabilities"]:
        for list_field in ["trigger_params","trigger_paths","trigger_techs",
                           "payloads","nuclei_tags","test_extensions"]:
            if list_field in vuln:
                # Deduplicar preservando orden
                seen = set()
                cleaned = []
                for item in vuln[list_field]:
                    key = item.lower() if isinstance(item, str) else str(item)
                    if key not in seen and item:
                        seen.add(key)
                        cleaned.append(item)
                vuln[list_field] = cleaned
    return kb

# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Actualizador de KB de Hackeadora")
    parser.add_argument("--force",   action="store_true", help="Forzar actualización")
    parser.add_argument("--dry-run", action="store_true", help="Sin guardar cambios")
    parser.add_argument("--days",    type=int, default=30, help="Días hacia atrás")
    parser.add_argument("--source",  choices=["h1","github","nuclei","all"], default="all")
    args = parser.parse_args()

    print("═" * 50)
    print("  Hackeadora — KB Updater")
    print(f"  Periodo: últimos {args.days} días")
    print("═" * 50)

    # Verificar si necesita actualización (máximo 1 vez al mes)
    kb = load_kb()
    last_updated = kb.get("_meta", {}).get("last_updated", "2000-01-01")
    days_since = (datetime.now() - datetime.fromisoformat(last_updated)).days

    if days_since < 28 and not args.force:
        print(f"\n[✓] KB actualizada hace {days_since} días. Usa --force para forzar.")
        return

    # Hash de la KB antes de cambios
    kb_hash_before = hashlib.md5(json.dumps(kb, sort_keys=True).encode()).hexdigest()

    total_stats = {"new_params": 0, "new_payloads": 0, "new_paths": 0,
                   "new_tags": 0, "reports_parsed": 0, "files_parsed": 0}

    # Ejecutar fuentes
    if args.source in ("h1", "all"):
        s = update_from_hackerone(kb, args.days)
        for k, v in s.items(): total_stats[k] = total_stats.get(k, 0) + v

    if args.source in ("github", "all"):
        s = update_from_github_repos(kb, args.days)
        for k, v in s.items(): total_stats[k] = total_stats.get(k, 0) + v

    if args.source in ("nuclei", "all"):
        s = update_from_nuclei_templates(kb, args.days)
        for k, v in s.items(): total_stats[k] = total_stats.get(k, 0) + v

    # Limpiar y actualizar metadata
    kb = clean_kb(kb)
    kb["_meta"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    kb["_meta"]["version"] = str(float(kb["_meta"].get("version", "1.0")) + 0.1)[:4]

    # Verificar si hubo cambios reales
    kb_hash_after = hashlib.md5(json.dumps(kb, sort_keys=True).encode()).hexdigest()
    changed = kb_hash_before != kb_hash_after

    print("\n" + "═" * 50)
    print("  Resumen de actualización:")
    print(f"  • Reportes H1 parseados:  {total_stats.get('reports_parsed', 0)}")
    print(f"  • Archivos GitHub:         {total_stats.get('files_parsed', 0)}")
    print(f"  • Parámetros nuevos:       {total_stats.get('new_params', 0)}")
    print(f"  • Payloads nuevos:         {total_stats.get('new_payloads', 0)}")
    print(f"  • Paths nuevos:            {total_stats.get('new_paths', 0)}")
    print(f"  • Tags nuclei nuevos:      {total_stats.get('new_tags', 0)}")
    print(f"  • Cambios en KB:           {'Sí' if changed else 'No'}")
    print("═" * 50)

    if not args.dry_run and changed:
        save_kb(kb)
        log_update({
            "date": datetime.now().isoformat(),
            "stats": total_stats,
            "version": kb["_meta"]["version"]
        })
        print("\n[✓] KB guardada correctamente")
        print(f"[✓] Backup en: {KB_BACKUP}")

        # Notificar por Telegram
        msg = (f"🧠 *Knowledge Base actualizada*\n"
               f"📊 Params nuevos: `{total_stats.get('new_params', 0)}`\n"
               f"💉 Payloads nuevos: `{total_stats.get('new_payloads', 0)}`\n"
               f"🏷️ Tags nuclei: `{total_stats.get('new_tags', 0)}`\n"
               f"📅 {datetime.now().strftime('%Y-%m-%d')}")
        notify_telegram(msg)
    elif args.dry_run:
        print("\n[→] Dry-run: no se guardaron cambios")
    else:
        print("\n[✓] Sin cambios — KB ya está actualizada")

if __name__ == "__main__":
    main()
