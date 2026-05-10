#!/usr/bin/env python3
"""
core/cve_matcher.py — match technologies(tech_name, tech_version) → CVE catalog.

Lee:
  core/cve_catalog.json (curado, ~40 entries)
  data/cve_catalog_custom.json (user-extensible, append-only)

Para cada entry de technologies con version detectada:
  - busca matches por tech_match (substring match)
  - parsea versions_affected (formato: "X.Y.Z-A.B.C,...,*")
  - emite findings con severity + PoC

Uso:
  python3 core/cve_matcher.py --domain workday.com [--db data/recon.db]
  python3 core/cve_matcher.py --tech "Apache Tomcat" --version "9.0.30"  # test directo
"""

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
CATALOG_BUILTIN = SCRIPT_DIR / "core" / "cve_catalog.json"
CATALOG_CUSTOM = SCRIPT_DIR / "data" / "cve_catalog_custom.json"
DEFAULT_DB = SCRIPT_DIR / "data" / "recon.db"


def load_catalog():
    """Merge custom + built-in. Custom overrides by CVE id."""
    entries = []
    seen = set()
    for path in [CATALOG_CUSTOM, CATALOG_BUILTIN]:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            for e in data:
                cve = e.get("cve", "").strip()
                if not cve or cve in seen:
                    continue
                e.setdefault("cve_family", "")
                e.setdefault("tech_match", "")
                e.setdefault("versions_affected", "*")
                e.setdefault("severity", "medium")
                e.setdefault("title", "")
                e.setdefault("description", "")
                e.setdefault("poc", "")
                e.setdefault("ref", "")
                entries.append(e)
                seen.add(cve)
        except Exception as ex:
            print(f"[cve_matcher] WARN load {path}: {ex}", file=sys.stderr)
    return entries


def parse_version(v):
    """'9.0.30' → (9, 0, 30). Tolerante a sufijos (RC, beta)."""
    if not v:
        return None
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v.strip())
    if not m:
        return None
    parts = [int(g) if g is not None else 0 for g in m.groups()]
    return tuple(parts)


def version_in_range(detected, range_str):
    """detected: '9.0.30'. range_str: '9.0.0-9.0.98,10.0.0-10.1.34' o '<6.4.4' o '*'."""
    if not range_str or range_str == "*":
        return True

    dv = parse_version(detected)
    if not dv:
        return False

    for chunk in range_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        # '<X.Y.Z' (versión vulnerable es CUALQUIER versión menor)
        m = re.match(r"^<(.+)$", chunk)
        if m:
            target = parse_version(m.group(1))
            if target and dv < target:
                return True
            continue

        # '>=X.Y.Z'
        m = re.match(r"^>=(.+)$", chunk)
        if m:
            target = parse_version(m.group(1))
            if target and dv >= target:
                return True
            continue

        # 'A.B.C-X.Y.Z' (rango inclusivo)
        m = re.match(r"^(\d[\d\.]*)-(\d[\d\.]*)$", chunk)
        if m:
            lo = parse_version(m.group(1))
            hi = parse_version(m.group(2))
            if lo and hi and lo <= dv <= hi:
                return True
            continue

        # 'X.Y.Z' exacto
        target = parse_version(chunk)
        if target and dv == target:
            return True

    return False


def match_technologies(domain_id, db_path, catalog):
    """Query technologies for domain → list of (tech_row, cve_entry) matches.

    Reglas:
      - Si versions_affected != '*' Y version detectada → match con confidence=medium (CVE confirmado por version)
      - Si versions_affected == '*' Y version detectada → match con confidence=low (CVE aplica pero versión específica desconocida)
      - Si version NO detectada → SKIP (no podemos confirmar nada, evita FPs masivos)
      - Dedup por (cve, subdomain) — solo 1 match por host por CVE.
    """
    matches = {}
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """SELECT DISTINCT tech_name, tech_version, subdomain, url, source
               FROM technologies
               WHERE domain_id=?""",
            (domain_id,),
        ).fetchall()
    finally:
        conn.close()

    for tech in rows:
        tech_name = (tech["tech_name"] or "").strip()
        version = (tech["tech_version"] or "").strip()
        subdomain = tech["subdomain"] or ""
        if not tech_name:
            continue

        for cve in catalog:
            tm = cve.get("tech_match", "").strip()
            if not tm:
                continue
            # Match exigente: tech_match completo en tech_name (case-insensitive).
            # Substring "Apache" matchearía Apache HTTPd, Apache Tomcat, etc. — usar
            # contains bidireccional pero requerir longitud mínima razonable
            if len(tm) < 5:
                continue
            # Forward-only: tech_match del CVE debe ser substring del tech_name detectado.
            # Evita que tech_name="Apache" (genérico de whatweb) matchee tech_match="Apache Tomcat".
            # tech_name específico (e.g. "Apache HTTPd 2.4.65") sí matchea tm="Apache HTTPd".
            if tm.lower() not in tech_name.lower():
                continue

            va = cve.get("versions_affected", "*")

            # Sin versión detectada → no podemos confirmar el CVE (descartar)
            if not version:
                continue

            # Verificar version_in_range
            if not version_in_range(version, va):
                continue

            # Confidence basado en si el CVE tiene rango específico o aplica a "*"
            confidence = "medium" if va != "*" else "low"

            key = (cve["cve"], subdomain, tech_name)
            if key in matches:
                continue  # dedup por (cve, host, tech)

            matches[key] = {
                "tech_name": tech_name,
                "tech_version": version,
                "subdomain": subdomain,
                "url": tech["url"],
                "source": tech["source"],
                "cve": cve["cve"],
                "severity": cve["severity"],
                "confidence": confidence,
                "title": cve["title"],
                "description": cve["description"],
                "poc": cve.get("poc", ""),
                "ref": cve.get("ref", ""),
            }

    return list(matches.values())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", help="Dominio en DB (e.g. workday.com)")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Path a recon.db")
    parser.add_argument("--tech", help="Tech name para test directo")
    parser.add_argument("--version", default="", help="Version para test directo")
    parser.add_argument("--json", action="store_true", help="Output JSON en vez de TSV")
    args = parser.parse_args()

    catalog = load_catalog()

    if args.tech:
        # Test directo sin DB. Sin versión, no matchear (igual que en match_technologies).
        matches = []
        if not args.version:
            print("--version requerido para test directo (sin versión no matcheamos para evitar FPs)", file=sys.stderr)
            sys.exit(1)
        for cve in catalog:
            tm = cve.get("tech_match", "").strip()
            if not tm or len(tm) < 5:
                continue
            if tm.lower() not in args.tech.lower():
                continue
            va = cve.get("versions_affected", "*")
            if not version_in_range(args.version, va):
                continue
            confidence = "medium" if va != "*" else "low"
            matches.append({
                "tech_name": args.tech,
                "tech_version": args.version,
                "subdomain": "",
                "url": "",
                "source": "test",
                "cve": cve["cve"],
                "severity": cve["severity"],
                "confidence": confidence,
                "title": cve["title"],
                "description": cve["description"],
                "poc": cve.get("poc", ""),
                "ref": cve.get("ref", ""),
            })
    else:
        if not args.domain:
            print("--domain requerido (o usa --tech para test directo)", file=sys.stderr)
            sys.exit(1)

        conn = sqlite3.connect(args.db)
        try:
            row = conn.execute("SELECT id FROM domains WHERE domain=?", (args.domain,)).fetchone()
        finally:
            conn.close()
        if not row:
            print(f"Dominio {args.domain} no encontrado en DB", file=sys.stderr)
            sys.exit(1)
        domain_id = row[0]

        matches = match_technologies(domain_id, args.db, catalog)

    if args.json:
        print(json.dumps(matches, ensure_ascii=False, indent=2))
    else:
        for m in matches:
            print(
                f"{m['cve']}\t{m['severity']}\t{m.get('confidence','?')}\t{m['tech_name']}"
                f"\t{m['tech_version']}\t{m['subdomain']}\t{m['title']}"
            )


if __name__ == "__main__":
    main()
