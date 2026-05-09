#!/usr/bin/env python3
"""
core/backfill_url_params.py

Backfill de la tabla url_params a partir de las URLs ya guardadas en `urls`.
Necesario una vez tras adoptar la auto-extracción de params en db_add_url —
los datos previos a ese cambio no tienen sus params en url_params.

Uso:
  python3 core/backfill_url_params.py            # backfill global
  python3 core/backfill_url_params.py example.com  # solo un dominio
  python3 core/backfill_url_params.py --dry-run    # solo reportar, no insertar

Filtros aplicados (alineados con db_add_url):
  - Param names alfanuméricos + . _ - [ ]
  - Longitud <= 100
  - Excluye literal 'FUZZ'
"""

import os
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

BASE_DIR = Path(__file__).parent.parent
DB_PATH = os.environ.get("RECONFLOW_DB", str(BASE_DIR / "data" / "recon.db"))

VALID_NAME = re.compile(r"^[][A-Za-z0-9._-]+$")


def iter_param_rows(domain_id, url, source):
    """Yield (domain_id, base_url, param_name, source) tuples for a URL."""
    if "?" not in url:
        return
    try:
        parts = urlsplit(url)
    except Exception:
        return
    if not parts.query:
        return
    base = url.split("?", 1)[0]
    seen = set()
    for name, _ in parse_qsl(parts.query, keep_blank_values=True):
        name = name.strip()
        if not name or name == "FUZZ":
            continue
        if len(name) > 100:
            continue
        if not VALID_NAME.match(name):
            continue
        if name in seen:
            continue
        seen.add(name)
        yield (domain_id, base, name, source)


def backfill(domain_filter=None, dry_run=False):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    cur = conn.cursor()

    if domain_filter:
        cur.execute("SELECT id, domain FROM domains WHERE domain=?", (domain_filter,))
        row = cur.fetchone()
        if not row:
            print(f"[!] Dominio no encontrado: {domain_filter}")
            return 1
        domain_ids = [row[0]]
        print(f"[+] Backfill solo para {domain_filter} (id={row[0]})")
    else:
        cur.execute("SELECT id, domain FROM domains ORDER BY id")
        rows = cur.fetchall()
        domain_ids = [r[0] for r in rows]
        print(f"[+] Backfill global: {len(domain_ids)} dominios")

    total_url = 0
    total_inserted = 0

    for did in domain_ids:
        cur.execute(
            """SELECT url, COALESCE(source, 'unknown')
                 FROM urls
                WHERE domain_id=? AND url LIKE '%?%'""",
            (did,),
        )
        urls = cur.fetchall()
        if not urls:
            continue

        rows_to_insert = []
        for url, src in urls:
            total_url += 1
            for tup in iter_param_rows(did, url, src):
                rows_to_insert.append(tup)

        if not rows_to_insert:
            continue

        if dry_run:
            cur.execute(
                "SELECT domain FROM domains WHERE id=?", (did,)
            )
            dname = cur.fetchone()[0]
            print(
                f"  [dry] {dname}: {len(rows_to_insert)} param-rows derivados de {len(urls)} URLs con `?`"
            )
            continue

        # INSERT OR IGNORE en batch
        cur.executemany(
            """INSERT OR IGNORE INTO url_params(domain_id, url, param_name, source)
                 VALUES(?, ?, ?, ?)""",
            rows_to_insert,
        )
        # rowcount con OR IGNORE devuelve total intentado, no insertado.
        # Usamos changes() para insertados reales.
        before = cur.rowcount
        conn.commit()
        cur.execute("SELECT changes()")
        inserted = cur.fetchone()[0]
        total_inserted += inserted

        cur.execute("SELECT domain FROM domains WHERE id=?", (did,))
        dname = cur.fetchone()[0]
        print(
            f"  ✓ {dname}: {len(rows_to_insert)} candidatos, +{inserted} nuevos en url_params"
        )

    print()
    print(f"[+] URLs procesadas: {total_url}")
    if not dry_run:
        print(f"[+] Filas nuevas en url_params: {total_inserted}")
    conn.close()
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    domain = args[0] if args else None
    sys.exit(backfill(domain, dry_run))
