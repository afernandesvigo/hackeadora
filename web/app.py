#!/usr/bin/env python3
"""
ReconFlow — API backend (FastAPI)
Sirve datos desde SQLite y archivos estáticos del dashboard.
Uso: python3 web/app.py  (o uvicorn web.app:app --reload)
"""

import os
import sqlite3
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ── Config ────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
DB_PATH    = os.environ.get("RECONFLOW_DB", str(BASE_DIR / "data" / "recon.db"))
OUTPUT_DIR = os.environ.get("RECONFLOW_OUTPUT", str(BASE_DIR / "output"))
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="ReconFlow Dashboard", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── DB helper ─────────────────────────────────────────────────
def db_conn():
    if not Path(DB_PATH).exists():
        raise HTTPException(503, f"Base de datos no encontrada: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def rows_to_list(rows):
    return [dict(r) for r in rows]

# ══════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════

# ── Dashboard general ─────────────────────────────────────────
@app.get("/api/summary")
def summary():
    """Stats globales de todos los dominios."""
    with db_conn() as conn:
        domains   = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        subs      = conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
        alive     = conn.execute("SELECT COUNT(*) FROM subdomains WHERE status='alive'").fetchone()[0]
        urls      = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        findings  = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        critical  = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
        high      = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0]
        last_scan = conn.execute(
            "SELECT MAX(last_scan) FROM domains"
        ).fetchone()[0]

    return {
        "domains": domains, "subdomains": subs, "alive": alive,
        "urls": urls, "findings": findings,
        "critical": critical, "high": high,
        "last_scan": last_scan,
    }

# ── Dominios ──────────────────────────────────────────────────
@app.get("/api/domains")
def list_domains():
    with db_conn() as conn:
        rows = conn.execute("""
            SELECT d.*,
              (SELECT COUNT(*) FROM subdomains s WHERE s.domain_id=d.id) AS sub_count,
              (SELECT COUNT(*) FROM subdomains s WHERE s.domain_id=d.id AND s.status='alive') AS alive_count,
              (SELECT COUNT(*) FROM urls u WHERE u.domain_id=d.id) AS url_count,
              (SELECT COUNT(*) FROM findings f WHERE f.domain_id=d.id) AS finding_count,
              (SELECT COUNT(*) FROM findings f WHERE f.domain_id=d.id AND f.severity IN ('high','critical')) AS high_count
            FROM domains d
            ORDER BY d.last_scan DESC
        """).fetchall()
    return rows_to_list(rows)

@app.get("/api/domains/{domain}")
def get_domain(domain: str):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            raise HTTPException(404, "Dominio no encontrado")
    return dict(row)

# ── Subdominios ───────────────────────────────────────────────
@app.get("/api/domains/{domain}/subdomains")
def get_subdomains(
    domain: str,
    status: Optional[str] = None,
    q: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
):
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404)
        domain_id = d["id"]

        where = ["domain_id=?"]
        params = [domain_id]
        if status:
            where.append("status=?"); params.append(status)
        if q:
            where.append("subdomain LIKE ?"); params.append(f"%{q}%")

        total = conn.execute(
            f"SELECT COUNT(*) FROM subdomains WHERE {' AND '.join(where)}", params
        ).fetchone()[0]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT * FROM subdomains WHERE {' AND '.join(where)}
                ORDER BY status, first_seen DESC LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}

# ── URLs ──────────────────────────────────────────────────────
@app.get("/api/domains/{domain}/urls")
def get_urls(
    domain: str,
    q: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
):
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404)
        domain_id = d["id"]

        where = ["domain_id=?"]
        params = [domain_id]
        if q:
            where.append("url LIKE ?"); params.append(f"%{q}%")

        total = conn.execute(
            f"SELECT COUNT(*) FROM urls WHERE {' AND '.join(where)}", params
        ).fetchone()[0]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT * FROM urls WHERE {' AND '.join(where)}
                ORDER BY first_seen DESC LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}

# ── Findings ──────────────────────────────────────────────────
@app.get("/api/domains/{domain}/findings")
def get_findings(domain: str, severity: Optional[str] = None, type_: Optional[str] = Query(None, alias="type")):
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404)
        domain_id = d["id"]

        where = ["domain_id=?"]
        params = [domain_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if type_:
            where.append("type=?"); params.append(type_)

        rows = conn.execute(
            f"SELECT * FROM findings WHERE {' AND '.join(where)} ORDER BY found_at DESC",
            params
        ).fetchall()
    return rows_to_list(rows)

@app.get("/api/findings")
def all_findings(severity: Optional[str] = None, limit: int = 100):
    """Todos los findings de todos los dominios (vista global)."""
    with db_conn() as conn:
        where = []
        params = []
        if severity:
            where.append("f.severity=?"); params.append(severity)
        w = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(
            f"""SELECT f.*, d.domain FROM findings f
                JOIN domains d ON d.id=f.domain_id
                {w} ORDER BY f.found_at DESC LIMIT ?""",
            params + [limit]
        ).fetchall()
    return rows_to_list(rows)

# ── Timeline / Scan history ───────────────────────────────────
@app.get("/api/domains/{domain}/timeline")
def get_timeline(domain: str):
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404)
        domain_id = d["id"]

        scans = conn.execute("""
            SELECT * FROM scan_history
            WHERE domain_id=? ORDER BY started_at DESC LIMIT 50
        """, (domain_id,)).fetchall()

        # Stats por fecha para el gráfico
        daily = conn.execute("""
            SELECT date(first_seen) as day,
                   COUNT(*) as new_subs
            FROM subdomains WHERE domain_id=?
            GROUP BY day ORDER BY day
        """, (domain_id,)).fetchall()

        daily_urls = conn.execute("""
            SELECT date(first_seen) as day,
                   COUNT(*) as new_urls
            FROM urls WHERE domain_id=?
            GROUP BY day ORDER BY day
        """, (domain_id,)).fetchall()

        daily_findings = conn.execute("""
            SELECT date(found_at) as day,
                   COUNT(*) as findings
            FROM findings WHERE domain_id=?
            GROUP BY day ORDER BY day
        """, (domain_id,)).fetchall()

    return {
        "scans": rows_to_list(scans),
        "daily_subs": rows_to_list(daily),
        "daily_urls": rows_to_list(daily_urls),
        "daily_findings": rows_to_list(daily_findings),
    }

# ── Screenshots ───────────────────────────────────────────────
@app.get("/api/domains/{domain}/screenshots")
def get_screenshots(domain: str):
    """Lista las imágenes de screenshots disponibles."""
    shots = []
    output_path = Path(OUTPUT_DIR) / domain
    if output_path.exists():
        for scan_dir in sorted(output_path.iterdir(), reverse=True):
            shot_dir = scan_dir / "screenshots"
            if shot_dir.exists():
                for img in sorted(shot_dir.glob("*.png")):
                    shots.append({
                        "file": img.name,
                        "scan": scan_dir.name,
                        "url": f"/screenshots/{domain}/{scan_dir.name}/{img.name}",
                    })
    return shots

@app.get("/screenshots/{domain}/{scan}/{filename}")
def serve_screenshot(domain: str, scan: str, filename: str):
    path = Path(OUTPUT_DIR) / domain / scan / "screenshots" / filename
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path)

# ── Servir frontend ───────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"status": "ReconFlow API running", "docs": "/docs"}

# ── Entrypoint ────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 8080)),
        reload=False,
    )

# ── Technologies ──────────────────────────────────────────────

@app.get("/api/technologies")
def all_technologies(
    tech: Optional[str] = None,
    version: Optional[str] = None,
    category: Optional[str] = None,
    domain: Optional[str] = None,
    page: int = 1,
    per_page: int = 100,
):
    """
    Vista global de tecnologías — ideal para triaje de CVEs.
    Filtra por nombre, versión, categoría o dominio.
    Ej: /api/technologies?tech=WordPress&version=6.4
    """
    with db_conn() as conn:
        where = []
        params = []

        if tech:
            where.append("t.tech_name LIKE ?")
            params.append(f"%{tech}%")
        if version:
            where.append("t.tech_version LIKE ?")
            params.append(f"%{version}%")
        if category:
            where.append("t.category LIKE ?")
            params.append(f"%{category}%")
        if domain:
            where.append("d.domain LIKE ?")
            params.append(f"%{domain}%")

        w = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM technologies t JOIN domains d ON d.id=t.domain_id {w}",
            params
        ).fetchone()[0]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT t.*, d.domain
                FROM technologies t
                JOIN domains d ON d.id=t.domain_id
                {w}
                ORDER BY t.tech_name, t.tech_version, d.domain
                LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}


@app.get("/api/technologies/summary")
def tech_summary():
    """
    Resumen global: top tecnologías + versiones detectadas.
    Útil para ver de un vistazo qué hay en toda la infraestructura.
    """
    with db_conn() as conn:
        # Top tecnologías por nº de URLs
        top = conn.execute("""
            SELECT tech_name, tech_version, category,
                   COUNT(DISTINCT url) as url_count,
                   COUNT(DISTINCT domain_id) as domain_count
            FROM technologies
            GROUP BY tech_name, tech_version
            ORDER BY url_count DESC
            LIMIT 100
        """).fetchall()

        # Categorías
        categories = conn.execute("""
            SELECT category, COUNT(DISTINCT tech_name) as tech_count
            FROM technologies
            WHERE category != ''
            GROUP BY category ORDER BY tech_count DESC
        """).fetchall()

        # Total distinct techs
        total_techs = conn.execute(
            "SELECT COUNT(DISTINCT tech_name) FROM technologies"
        ).fetchone()[0]
        total_urls = conn.execute(
            "SELECT COUNT(DISTINCT url) FROM technologies"
        ).fetchone()[0]

    return {
        "total_techs": total_techs,
        "total_urls_analyzed": total_urls,
        "top": rows_to_list(top),
        "categories": rows_to_list(categories),
    }


@app.get("/api/technologies/cve-search")
def cve_search(tech: str, version: Optional[str] = None):
    """
    Dado un nombre de tech (y versión opcional), devuelve todas las
    URLs donde se detectó esa tecnología — para cruzar con CVEs.
    Ej: /api/technologies/cve-search?tech=Apache&version=2.4.49
    """
    with db_conn() as conn:
        params = [f"%{tech}%"]
        ver_clause = ""
        if version:
            ver_clause = "AND t.tech_version LIKE ?"
            params.append(f"%{version}%")

        rows = conn.execute(
            f"""SELECT t.url, t.subdomain, t.tech_name, t.tech_version,
                       t.category, t.confidence, t.source, t.last_seen,
                       d.domain
                FROM technologies t
                JOIN domains d ON d.id=t.domain_id
                WHERE t.tech_name LIKE ? {ver_clause}
                ORDER BY d.domain, t.subdomain""",
            params
        ).fetchall()

    return {
        "query": {"tech": tech, "version": version},
        "count": len(rows),
        "affected_urls": rows_to_list(rows),
    }


@app.get("/api/domains/{domain}/technologies")
def domain_technologies(
    domain: str,
    category: Optional[str] = None,
    q: Optional[str] = None,
):
    """Tecnologías detectadas en un dominio concreto."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404)
        domain_id = d["id"]

        where = ["domain_id=?"]
        params = [domain_id]
        if category:
            where.append("category LIKE ?"); params.append(f"%{category}%")
        if q:
            where.append("(tech_name LIKE ? OR tech_version LIKE ? OR url LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]

        rows = conn.execute(
            f"""SELECT tech_name, tech_version, category, url, subdomain,
                       confidence, source, last_seen
                FROM technologies
                WHERE {' AND '.join(where)}
                ORDER BY tech_name, tech_version""",
            params
        ).fetchall()

        # Agrupar por tech_name para la vista de árbol
        by_tech = {}
        for r in rows_to_list(rows):
            key = f"{r['tech_name']}||{r['tech_version'] or ''}"
            if key not in by_tech:
                by_tech[key] = {
                    "tech_name": r["tech_name"],
                    "tech_version": r["tech_version"],
                    "category": r["category"],
                    "urls": [],
                }
            by_tech[key]["urls"].append({
                "url": r["url"],
                "subdomain": r["subdomain"],
                "confidence": r["confidence"],
                "source": r["source"],
                "last_seen": r["last_seen"],
            })

    return {
        "domain": domain,
        "total_techs": len(by_tech),
        "total_detections": len(rows),
        "technologies": list(by_tech.values()),
    }

# ── JS Analysis ───────────────────────────────────────────────

@app.get("/api/js/secrets")
def all_js_secrets(
    secret_type: Optional[str] = None,
    domain: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
):
    """Todos los secrets encontrados en JS — búsqueda global."""
    with db_conn() as conn:
        where, params = [], []
        if secret_type:
            where.append("s.secret_type LIKE ?"); params.append(f"%{secret_type}%")
        if domain:
            where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM js_secrets s JOIN domains d ON d.id=s.domain_id {w}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT s.*, d.domain FROM js_secrets s
                JOIN domains d ON d.id=s.domain_id
                {w} ORDER BY s.found_at DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page-1)*per_page]
        ).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}


@app.get("/api/js/secrets/summary")
def js_secrets_summary():
    """Resumen de secrets: totales por tipo y por dominio."""
    with db_conn() as conn:
        by_type = conn.execute("""
            SELECT secret_type, COUNT(*) as count
            FROM js_secrets GROUP BY secret_type ORDER BY count DESC
        """).fetchall()
        by_domain = conn.execute("""
            SELECT d.domain, COUNT(*) as count
            FROM js_secrets s JOIN domains d ON d.id=s.domain_id
            GROUP BY d.domain ORDER BY count DESC
        """).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM js_secrets").fetchone()[0]
        total_files = conn.execute("SELECT COUNT(*) FROM js_files").fetchone()[0]
    return {
        "total_secrets": total,
        "total_js_files": total_files,
        "by_type": rows_to_list(by_type),
        "by_domain": rows_to_list(by_domain),
    }


@app.get("/api/js/endpoints")
def all_js_endpoints(
    domain: Optional[str] = None,
    q: Optional[str] = None,
    page: int = 1,
    per_page: int = 100,
):
    """Endpoints extraídos de JS — con filtros."""
    with db_conn() as conn:
        where, params = [], []
        if domain:
            where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        if q:
            where.append("(e.endpoint LIKE ? OR e.full_url LIKE ?)"); params += [f"%{q}%", f"%{q}%"]
        w = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM js_endpoints e JOIN domains d ON d.id=e.domain_id {w}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT e.*, d.domain FROM js_endpoints e
                JOIN domains d ON d.id=e.domain_id
                {w} ORDER BY e.first_seen DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page-1)*per_page]
        ).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}


@app.get("/api/domains/{domain}/js")
def domain_js(domain: str):
    """Vista completa de JS para un dominio: archivos, secrets y endpoints."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        did = d["id"]

        files = conn.execute(
            "SELECT * FROM js_files WHERE domain_id=? ORDER BY secrets_found DESC, endpoints_found DESC",
            (did,)
        ).fetchall()
        secrets = conn.execute(
            "SELECT * FROM js_secrets WHERE domain_id=? ORDER BY found_at DESC",
            (did,)
        ).fetchall()
        endpoints = conn.execute(
            "SELECT * FROM js_endpoints WHERE domain_id=? ORDER BY first_seen DESC LIMIT 500",
            (did,)
        ).fetchall()

    return {
        "domain": domain,
        "js_files": rows_to_list(files),
        "secrets": rows_to_list(secrets),
        "endpoints": rows_to_list(endpoints),
    }

# ── Login Forms ───────────────────────────────────────────────

@app.get("/api/login-forms")
def all_login_forms(
    login_type: Optional[str] = None,
    domain: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
):
    """Todos los login forms detectados — vista global."""
    with db_conn() as conn:
        # La tabla puede no existir si el módulo no ha corrido
        try:
            conn.execute("SELECT 1 FROM login_forms LIMIT 1")
        except Exception:
            return {"total": 0, "page": page, "per_page": per_page, "items": []}

        where, params = [], []
        if login_type:
            where.append("l.login_type = ?"); params.append(login_type)
        if domain:
            where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM login_forms l JOIN domains d ON d.id=l.domain_id {w}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT l.*, d.domain FROM login_forms l
                JOIN domains d ON d.id=l.domain_id
                {w} ORDER BY l.found_at DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page-1)*per_page]
        ).fetchall()

    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}


@app.get("/api/login-forms/summary")
def login_forms_summary():
    """Resumen de login forms por tipo y dominio."""
    with db_conn() as conn:
        try:
            conn.execute("SELECT 1 FROM login_forms LIMIT 1")
        except Exception:
            return {"total": 0, "by_type": [], "by_domain": [], "by_tech": []}

        total = conn.execute("SELECT COUNT(*) FROM login_forms").fetchone()[0]
        by_type = conn.execute("""
            SELECT login_type, COUNT(*) as count
            FROM login_forms GROUP BY login_type ORDER BY count DESC
        """).fetchall()
        by_domain = conn.execute("""
            SELECT d.domain, COUNT(*) as count
            FROM login_forms l JOIN domains d ON d.id=l.domain_id
            GROUP BY d.domain ORDER BY count DESC
        """).fetchall()
        by_tech = conn.execute("""
            SELECT tech_hints, COUNT(*) as count
            FROM login_forms WHERE tech_hints != ''
            GROUP BY tech_hints ORDER BY count DESC LIMIT 10
        """).fetchall()

    return {
        "total": total,
        "by_type": rows_to_list(by_type),
        "by_domain": rows_to_list(by_domain),
        "by_tech": rows_to_list(by_tech),
    }


@app.get("/api/domains/{domain}/login-forms")
def domain_login_forms(domain: str):
    """Login forms de un dominio concreto."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            rows = conn.execute(
                "SELECT * FROM login_forms WHERE domain_id=? ORDER BY found_at DESC",
                (d["id"],)
            ).fetchall()
        except Exception:
            rows = []
    return rows_to_list(rows)

# ── Port Findings ─────────────────────────────────────────────

@app.get("/api/ports")
def all_port_findings(domain: Optional[str] = None, port: Optional[int] = None):
    """Servicios web encontrados en puertos no estándar."""
    with db_conn() as conn:
        try:
            conn.execute("SELECT 1 FROM port_findings LIMIT 1")
        except Exception:
            return {"total": 0, "items": []}
        where, params = [], []
        if domain:
            where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        if port:
            where.append("p.port = ?"); params.append(port)
        w = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(
            f"""SELECT p.*, d.domain FROM port_findings p
                JOIN domains d ON d.id=p.domain_id
                {w} ORDER BY p.first_seen DESC LIMIT 500""", params
        ).fetchall()
    return {"total": len(rows), "items": rows_to_list(rows)}

@app.get("/api/domains/{domain}/ports")
def domain_ports(domain: str):
    """Puertos no estándar de un dominio."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            rows = conn.execute(
                "SELECT * FROM port_findings WHERE domain_id=? ORDER BY port",
                (d["id"],)
            ).fetchall()
        except Exception:
            rows = []
    return rows_to_list(rows)

# ── Breach Findings ───────────────────────────────────────────

@app.get("/api/breaches")
def all_breaches(domain: Optional[str] = None, page: int = 1, per_page: int = 50):
    """Filtraciones de datos detectadas — vista global."""
    with db_conn() as conn:
        try:
            conn.execute("SELECT 1 FROM breach_findings LIMIT 1")
        except Exception:
            return {"total": 0, "page": page, "per_page": per_page, "items": []}

        where, params = [], []
        if domain:
            where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM breach_findings b JOIN domains d ON d.id=b.domain_id {w}",
            params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT b.id, b.email, b.username, b.breach_source,
                       b.has_password, b.ip_address, b.found_at, d.domain
                FROM breach_findings b
                JOIN domains d ON d.id=b.domain_id
                {w} ORDER BY b.found_at DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page-1)*per_page]
        ).fetchall()

    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}


@app.get("/api/breaches/summary")
def breach_summary():
    """Resumen global de filtraciones por dominio y fuente."""
    with db_conn() as conn:
        try:
            conn.execute("SELECT 1 FROM breach_findings LIMIT 1")
        except Exception:
            return {"total": 0, "with_hashes": 0, "by_domain": [], "by_source": []}

        total       = conn.execute("SELECT COUNT(*) FROM breach_findings").fetchone()[0]
        with_hashes = conn.execute("SELECT COUNT(*) FROM breach_findings WHERE has_password=1").fetchone()[0]
        by_domain   = conn.execute("""
            SELECT d.domain, COUNT(*) as count,
                   SUM(b.has_password) as with_hashes
            FROM breach_findings b JOIN domains d ON d.id=b.domain_id
            GROUP BY d.domain ORDER BY count DESC
        """).fetchall()
        by_source = conn.execute("""
            SELECT breach_source, COUNT(*) as count,
                   SUM(has_password) as with_hashes
            FROM breach_findings
            GROUP BY breach_source ORDER BY count DESC LIMIT 20
        """).fetchall()

    return {
        "total": total, "with_hashes": with_hashes,
        "by_domain": rows_to_list(by_domain),
        "by_source": rows_to_list(by_source),
    }


@app.get("/api/domains/{domain}/breaches")
def domain_breaches(domain: str):
    """Filtraciones de un dominio concreto."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            rows = conn.execute(
                """SELECT id, email, username, breach_source,
                          has_password, ip_address, found_at
                   FROM breach_findings WHERE domain_id=?
                   ORDER BY has_password DESC, found_at DESC""",
                (d["id"],)
            ).fetchall()
        except Exception:
            rows = []
    return rows_to_list(rows)

# ── Breach — trigger manual refresh ──────────────────────────
import subprocess, threading

def _run_breach_lookup(domain: str):
    """Lanza el módulo 14 en background con FORCE=true."""
    try:
        script = Path(__file__).parent.parent / "recon.sh"
        env = {
            **__import__("os").environ,
            "RECONFLOW_DB": DB_PATH,
            "RECONFLOW_OUTPUT": OUTPUT_DIR,
        }
        subprocess.run(
            [str(script), domain, "--modules=14", "--force-breach"],
            env=env, timeout=120, capture_output=True
        )
    except Exception as e:
        print(f"[breach] Error: {e}")

@app.post("/api/domains/{domain}/breaches/refresh")
def refresh_breaches(domain: str):
    """
    Fuerza una nueva consulta a Dehashed para este dominio.
    Se ejecuta en background — no bloquea la respuesta.
    """
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            raise HTTPException(404, "Dominio no encontrado")

    t = threading.Thread(target=_run_breach_lookup, args=(domain,), daemon=True)
    t.start()

    return {"status": "running", "message": f"Actualizando breaches para {domain} en background"}

# ── Bloque A — Surface Discovery ─────────────────────────────

@app.get("/api/params")
def all_params(domain: Optional[str] = None, q: Optional[str] = None, page: int = 1, per_page: int = 100):
    with db_conn() as conn:
        try: conn.execute("SELECT 1 FROM url_params LIMIT 1")
        except: return {"total": 0, "page": page, "per_page": per_page, "items": []}
        where, params = [], []
        if domain: where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        if q:
            where.append("(p.param_name LIKE ? OR p.url LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        w = f"WHERE {' AND '.join(where)}" if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM url_params p JOIN domains d ON d.id=p.domain_id {w}", params).fetchone()[0]
        rows  = conn.execute(f"SELECT p.*, d.domain FROM url_params p JOIN domains d ON d.id=p.domain_id {w} ORDER BY p.first_seen DESC LIMIT ? OFFSET ?", params + [per_page, (page-1)*per_page]).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}

@app.get("/api/params/summary")
def params_summary():
    with db_conn() as conn:
        try: conn.execute("SELECT 1 FROM url_params LIMIT 1")
        except: return {"total": 0, "juicy": [], "by_domain": []}
        total = conn.execute("SELECT COUNT(*) FROM url_params").fetchone()[0]
        juicy_names = ['url','redirect','next','dest','file','path','cmd','id','token','key','api','secret','pass','auth','admin','debug','src','href','query','search']
        placeholders = ','.join(['?' for _ in juicy_names])
        juicy = conn.execute(f"SELECT param_name, COUNT(*) as cnt FROM url_params WHERE param_name IN ({placeholders}) GROUP BY param_name ORDER BY cnt DESC", juicy_names).fetchall()
        by_domain = conn.execute("SELECT d.domain, COUNT(*) as cnt FROM url_params p JOIN domains d ON d.id=p.domain_id GROUP BY d.domain ORDER BY cnt DESC LIMIT 10").fetchall()
    return {"total": total, "juicy": rows_to_list(juicy), "by_domain": rows_to_list(by_domain)}

@app.get("/api/github-findings")
def all_github_findings(domain: Optional[str] = None, page: int = 1, per_page: int = 50):
    with db_conn() as conn:
        try: conn.execute("SELECT 1 FROM github_findings LIMIT 1")
        except: return {"total": 0, "page": page, "per_page": per_page, "items": []}
        where, params = [], []
        if domain: where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM github_findings g JOIN domains d ON d.id=g.domain_id {w}", params).fetchone()[0]
        rows  = conn.execute(f"SELECT g.*, d.domain FROM github_findings g JOIN domains d ON d.id=g.domain_id {w} ORDER BY g.found_at DESC LIMIT ? OFFSET ?", params + [per_page, (page-1)*per_page]).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}

@app.get("/api/cloud-assets")
def all_cloud_assets(domain: Optional[str] = None, provider: Optional[str] = None, status: Optional[str] = None):
    with db_conn() as conn:
        try: conn.execute("SELECT 1 FROM cloud_assets LIMIT 1")
        except: return {"total": 0, "items": []}
        where, params = [], []
        if domain:   where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        if provider: where.append("c.provider=?"); params.append(provider)
        if status:   where.append("c.status=?"); params.append(status)
        w = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(f"SELECT c.*, d.domain FROM cloud_assets c JOIN domains d ON d.id=c.domain_id {w} ORDER BY c.status, c.found_at DESC", params).fetchall()
    return {"total": len(rows), "items": rows_to_list(rows)}

@app.get("/api/asn-ranges")
def all_asn_ranges(domain: Optional[str] = None):
    with db_conn() as conn:
        try: conn.execute("SELECT 1 FROM asn_ranges LIMIT 1")
        except: return {"total": 0, "items": []}
        where, params = [], []
        if domain: where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""
        rows = conn.execute(f"SELECT a.*, d.domain FROM asn_ranges a JOIN domains d ON d.id=a.domain_id {w} ORDER BY a.asn", params).fetchall()
    return {"total": len(rows), "items": rows_to_list(rows)}

@app.get("/api/surface/summary")
def surface_summary():
    """Resumen global del Bloque A para el dashboard."""
    with db_conn() as conn:
        def safe_count(q):
            try: return conn.execute(q).fetchone()[0]
            except: return 0
        return {
            "params":        safe_count("SELECT COUNT(*) FROM url_params"),
            "github":        safe_count("SELECT COUNT(*) FROM github_findings"),
            "cloud_open":    safe_count("SELECT COUNT(*) FROM cloud_assets WHERE status='open'"),
            "cloud_total":   safe_count("SELECT COUNT(*) FROM cloud_assets"),
            "asn_ranges":    safe_count("SELECT COUNT(*) FROM asn_ranges"),
        }

# ── Auth Vault ────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))

def _vault_encrypt(plaintext: str) -> str:
    try:
        from vault import encrypt
        return encrypt(plaintext)
    except Exception as e:
        raise HTTPException(500, f"Error cifrando vault: {e}")

def _vault_decrypt(ciphertext: str) -> str:
    try:
        from vault import decrypt
        return decrypt(ciphertext)
    except Exception as e:
        raise HTTPException(500, f"Error descifrando vault: {e}")

def _vault_mask(value: str) -> str:
    try:
        from vault import mask
        return mask(value)
    except:
        return "****"

class VaultAddRequest(BaseModel):
    domain: str
    subdomain: str
    app_url: str
    username: str
    password: str
    auth_type: str = "form"
    notes: str = ""

class BaseModel:
    pass

try:
    from pydantic import BaseModel
    class VaultAddRequest(BaseModel):
        domain: str
        subdomain: str
        app_url: str
        username: str
        password: str
        auth_type: str = "form"
        notes: str = ""
except ImportError:
    pass


@app.get("/api/vault")
def list_vault(domain: Optional[str] = None):
    """Lista todas las credenciales del vault (sin mostrar passwords)."""
    with db_conn() as conn:
        try:
            conn.execute("SELECT 1 FROM auth_credentials LIMIT 1")
        except Exception:
            return {"total": 0, "items": []}

        where, params = [], []
        if domain:
            where.append("domain LIKE ?"); params.append(f"%{domain}%")
        w = f"WHERE {' AND '.join(where)}" if where else ""

        rows = conn.execute(
            f"""SELECT id, domain, subdomain, app_url, username,
                       auth_type, valid, last_used, last_verified, notes, added_at
                FROM auth_credentials {w}
                ORDER BY domain, subdomain""",
            params
        ).fetchall()

    items = rows_to_list(rows)
    # Nunca devolver passwords — solo metadatos
    return {"total": len(items), "items": items}


@app.get("/api/domains/{domain}/vault")
def domain_vault(domain: str):
    """Credenciales del vault para un dominio — agrupadas por subdominio."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            rows = conn.execute(
                """SELECT id, subdomain, app_url, username, auth_type,
                          valid, last_used, notes, added_at
                   FROM auth_credentials WHERE domain_id=?
                   ORDER BY subdomain""",
                (d["id"],)
            ).fetchall()
        except Exception:
            rows = []
    return rows_to_list(rows)


@app.post("/api/vault/add")
async def vault_add(request: Request):
    """Añade credenciales al vault (cifradas con VAULT_KEY)."""
    body = await request.json()
    domain    = body.get("domain", "")
    subdomain = body.get("subdomain", "")
    app_url   = body.get("app_url", "")
    username  = body.get("username", "")
    password  = body.get("password", "")
    auth_type = body.get("auth_type", "form")
    notes     = body.get("notes", "")

    if not all([domain, subdomain, app_url, username, password]):
        raise HTTPException(400, "Faltan campos obligatorios")

    password_enc = _vault_encrypt(password)

    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d:
            # Auto-registrar el dominio si no existe
            conn.execute("INSERT OR IGNORE INTO domains(domain) VALUES(?)", (domain,))
            conn.commit()
            d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()

        conn.execute(
            """INSERT OR REPLACE INTO auth_credentials
               (domain_id, domain, subdomain, app_url, username,
                password_enc, auth_type, notes)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
            (d["id"], domain, subdomain, app_url, username,
             password_enc, auth_type, notes)
        )
        conn.commit()

    return {
        "status": "ok",
        "message": f"Credenciales para {subdomain} guardadas en el vault",
        "username": username,
        "subdomain": subdomain,
    }


@app.delete("/api/vault/{cred_id}")
def vault_delete(cred_id: int):
    """Elimina una credencial del vault."""
    with db_conn() as conn:
        conn.execute("DELETE FROM auth_credentials WHERE id=?", (cred_id,))
        conn.commit()
    return {"status": "ok", "deleted": cred_id}


@app.post("/api/vault/{cred_id}/invalidate")
def vault_invalidate(cred_id: int):
    """Marca credenciales como inválidas."""
    with db_conn() as conn:
        conn.execute("UPDATE auth_credentials SET valid=0 WHERE id=?", (cred_id,))
        conn.commit()
    return {"status": "ok"}

# ── Knowledge Base ────────────────────────────────────────────
import subprocess as _subprocess

@app.get("/api/kb/status")
def kb_status():
    """Estado actual de la Knowledge Base."""
    kb_path = Path(__file__).parent.parent / "core" / "knowledge_base.json"
    update_log = Path(__file__).parent.parent / "data" / "kb_updates.jsonl"

    if not kb_path.exists():
        return {"status": "missing", "vulns": 0}

    try:
        with open(kb_path) as f:
            kb = json.load(f)
        meta = kb.get("_meta", {})
        vulns = kb.get("vulnerabilities", [])

        # Leer últimas actualizaciones
        updates = []
        if update_log.exists():
            with open(update_log) as f:
                lines = f.readlines()[-10:]
            for line in lines:
                try: updates.append(json.loads(line))
                except: pass

        return {
            "status": "ok",
            "version": meta.get("version", "1.0"),
            "last_updated": meta.get("last_updated", "never"),
            "sources": meta.get("sources", []),
            "total_vulns": len(vulns),
            "total_params": sum(len(v.get("trigger_params", [])) for v in vulns),
            "total_payloads": sum(len(v.get("payloads", [])) for v in vulns),
            "vulns": [
                {
                    "id": v["id"],
                    "name": v["name"],
                    "h1_frequency": v.get("h1_frequency"),
                    "h1_avg_bounty_usd": v.get("h1_avg_bounty_usd", 0),
                    "params_count": len(v.get("trigger_params", [])),
                    "payloads_count": len(v.get("payloads", [])),
                    "severity": v.get("severity", "medium"),
                }
                for v in vulns
            ],
            "recent_updates": updates[-5:],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/kb/update")
def kb_update_trigger(force: bool = False):
    """Lanza una actualización manual de la KB en background."""
    script = Path(__file__).parent.parent / "core" / "kb_updater.py"
    if not script.exists():
        raise HTTPException(404, "kb_updater.py no encontrado")

    cmd = [sys.executable, str(script)]
    if force:
        cmd.append("--force")

    def _run():
        try:
            _subprocess.run(cmd, timeout=300, capture_output=True)
        except Exception as e:
            print(f"[kb_update] Error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "running", "message": "Actualización de KB iniciada en background"}

# ── AI Advisor + Business Logic ───────────────────────────────

@app.get("/api/domains/{domain}/business")
def domain_business(domain: str):
    """Entidades de negocio inferidas para un dominio."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            entities = conn.execute(
                "SELECT * FROM business_entities WHERE domain_id=? ORDER BY risk_score DESC",
                (d["id"],)
            ).fetchall()
            tests = conn.execute(
                "SELECT * FROM business_tests WHERE domain_id=? ORDER BY executed_at DESC LIMIT 50",
                (d["id"],)
            ).fetchall()
        except Exception:
            entities, tests = [], []
    return {
        "entities": rows_to_list(entities),
        "tests": rows_to_list(tests),
    }

@app.get("/api/domains/{domain}/ai-suggestions")
def domain_ai_suggestions(domain: str):
    """Sugerencias del AI Advisor para un dominio."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        try:
            rows = conn.execute(
                "SELECT * FROM ai_suggestions WHERE domain_id=? ORDER BY priority, scan_date DESC",
                (d["id"],)
            ).fetchall()
        except Exception:
            rows = []
    return rows_to_list(rows)

@app.get("/api/ai-suggestions/summary")
def ai_suggestions_global():
    """Vista global de sugerencias IA de todos los dominios."""
    with db_conn() as conn:
        try:
            total    = conn.execute("SELECT COUNT(*) FROM ai_suggestions").fetchone()[0]
            pending  = conn.execute("SELECT COUNT(*) FROM ai_suggestions WHERE status='pending'").fetchone()[0]
            by_type  = conn.execute("""
                SELECT suggestion_type, COUNT(*) as count, MIN(priority) as top_prio
                FROM ai_suggestions GROUP BY suggestion_type
            """).fetchall()
            top      = conn.execute("""
                SELECT s.*, d.domain FROM ai_suggestions s
                JOIN domains d ON d.id=s.domain_id
                WHERE s.status='pending' ORDER BY s.priority LIMIT 20
            """).fetchall()
            total_cost = conn.execute(
                "SELECT SUM(estimated_cost_usd) FROM ai_suggestions WHERE status='done'"
            ).fetchone()[0] or 0.0
        except Exception:
            return {"total": 0, "pending": 0, "by_type": [], "top": [], "total_cost": 0}
    return {
        "total": total, "pending": pending,
        "total_cost_spent": round(total_cost, 4),
        "by_type": rows_to_list(by_type),
        "top_suggestions": rows_to_list(top),
    }

@app.post("/api/domains/{domain}/ai-advisor/run")
async def run_ai_advisor(domain: str, request: Request):
    """Lanza el AI Advisor en background."""
    body = await request.json()
    run_chains = body.get("run_chains", False)
    report_id  = body.get("report_id", None)

    script = Path(__file__).parent.parent / "core" / "ai_advisor.py"
    if not script.exists():
        raise HTTPException(404, "ai_advisor.py no encontrado")

    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)

    cmd = [sys.executable, str(script), "--domain", domain]
    if run_chains: cmd.append("--run-chains")
    if report_id:  cmd += ["--report", str(report_id)]

    def _run():
        try:
            __import__("subprocess").run(cmd, timeout=300, capture_output=True)
        except Exception as e:
            print(f"[ai_advisor] Error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "running", "message": f"AI Advisor iniciado para {domain}"}

# ── Cloud Rotator ─────────────────────────────────────────────

@app.get("/api/rotator/status")
def rotator_status():
    """Estado actual del rotador de IPs."""
    state_file = Path(__file__).parent.parent / "data" / "rotator_state.json"
    aws_key = bool(os.environ.get("AWS_ACCESS_KEY_ID"))
    aws_secret = bool(os.environ.get("AWS_SECRET_ACCESS_KEY"))

    state = {"instances": [], "request_count": 0, "total_cost": 0.0}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except Exception:
            pass

    return {
        "enabled": aws_key and aws_secret,
        "configured": aws_key and aws_secret,
        "region": os.environ.get("AWS_REGION", "eu-west-1"),
        "interval": int(os.environ.get("ROTATION_INTERVAL", 500)),
        "instance_type": os.environ.get("AWS_INSTANCE_TYPE", "t3.small"),
        "ami_prebuilt": bool(os.environ.get("AWS_AMI_ID")),
        "active_instances": len(state.get("instances", [])),
        "total_requests": state.get("request_count", 0),
        "instances": state.get("instances", []),
    }

@app.post("/api/rotator/test")
def rotator_test():
    """Testea la conectividad con AWS."""
    script = Path(__file__).parent.parent / "core" / "cloud_rotator.py"

    def _run():
        try:
            _subprocess.run(
                [sys.executable, str(script), "--test"],
                timeout=30, capture_output=True
            )
        except Exception as e:
            print(f"[rotator test] {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "running", "message": "Test AWS iniciado — revisa los logs"}

@app.post("/api/rotator/cleanup")
def rotator_cleanup():
    """Destruye todas las instancias activas."""
    script = Path(__file__).parent.parent / "core" / "cloud_rotator.py"

    def _run():
        try:
            _subprocess.run(
                [sys.executable, str(script), "--cleanup"],
                timeout=120, capture_output=True
            )
        except Exception as e:
            print(f"[rotator cleanup] {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "running", "message": "Limpieza de instancias iniciada"}

# ── Block C findings ──────────────────────────────────────────

@app.get("/api/domains/{domain}/blockc")
def domain_blockc(domain: str):
    """Findings del Bloque C: CORS, 403 bypass, Smuggling."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE domain_id=? AND type IN ('cors','403_bypass','http_smuggling')
               ORDER BY found_at DESC""",
            (d["id"],)
        ).fetchall()
    return rows_to_list(rows)

@app.get("/api/blockc/summary")
def blockc_summary():
    """Resumen global del Bloque C."""
    with db_conn() as conn:
        def safe(q, p=()):
            try: return conn.execute(q, p).fetchone()[0]
            except: return 0
        return {
            "cors":      safe("SELECT COUNT(*) FROM findings WHERE type='cors'"),
            "bypass_403":safe("SELECT COUNT(*) FROM findings WHERE type='403_bypass'"),
            "smuggling": safe("SELECT COUNT(*) FROM findings WHERE type='http_smuggling'"),
        }

# ── Single target scan ────────────────────────────────────────

class ScanRequest(BaseModel):
    pass

try:
    from pydantic import BaseModel as _BM
    class ScanRequest(_BM):
        modules: Optional[str] = None
        force_breach: bool = False
except Exception:
    pass

@app.post("/api/domains/{domain}/scan")
async def domain_scan(domain: str, request: Request):
    """Lanza un scan completo del dominio en background."""
    body = await request.json()
    modules     = body.get("modules", "")
    force_breach = body.get("force_breach", False)

    script = Path(__file__).parent.parent / "recon.sh"
    cmd = ["bash", str(script), domain]
    if modules:     cmd.append(f"--modules={modules}")
    if force_breach: cmd.append("--force-breach")

    def _run():
        try:
            _subprocess.run(cmd, timeout=86400, capture_output=False)
        except Exception as e:
            print(f"[scan] Error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "running", "message": f"Scan completo de {domain} iniciado"}


@app.post("/api/domains/{domain}/subdomains/{subdomain}/scan")
async def subdomain_scan(domain: str, subdomain: str, request: Request):
    """
    Lanza un scan single-target sobre un subdominio específico.
    Ideal para profundizar en un subdominio concreto.
    """
    body = await request.json()
    modules = body.get("modules", "")

    # Verificar que el subdominio pertenece al dominio
    if not subdomain.endswith(f".{domain}") and subdomain != domain:
        raise HTTPException(400, f"{subdomain} no pertenece al dominio {domain}")

    script = Path(__file__).parent.parent / "recon.sh"
    cmd = ["bash", str(script), domain, f"--target={subdomain}"]
    if modules: cmd.append(f"--modules={modules}")

    def _run():
        try:
            _subprocess.run(cmd, timeout=86400, capture_output=False)
        except Exception as e:
            print(f"[subdomain_scan] Error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return {
        "status": "running",
        "message": f"Single-target scan de {subdomain} iniciado",
        "target": subdomain,
        "domain": domain,
    }

# ── Acunetix Integration ──────────────────────────────────────

@app.get("/api/acunetix/status")
def acunetix_status():
    """Estado de la integración con Acunetix."""
    configured = bool(os.environ.get("ACUNETIX_API_KEY"))
    url        = os.environ.get("ACUNETIX_URL", "https://localhost:3443")

    with db_conn() as conn:
        def safe(q):
            try: return conn.execute(q).fetchone()[0]
            except: return 0
        return {
            "configured":     configured,
            "url":            url,
            "total_scans":    safe("SELECT COUNT(*) FROM acunetix_scans"),
            "running_scans":  safe("SELECT COUNT(*) FROM acunetix_scans WHERE status='running'"),
            "total_findings": safe("SELECT COUNT(*) FROM acunetix_findings"),
            "critical":       safe("SELECT COUNT(*) FROM acunetix_findings WHERE severity='critical'"),
            "high":           safe("SELECT COUNT(*) FROM acunetix_findings WHERE severity='high'"),
        }

@app.post("/api/acunetix/test")
def acunetix_test():
    """Testea la conexión con Acunetix."""
    script = Path(__file__).parent.parent / "core" / "acunetix.py"
    def _run():
        try: _subprocess.run([sys.executable, str(script), "--test"],
                              timeout=30, capture_output=True)
        except Exception as e: print(f"[acunetix test] {e}")
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "running", "message": "Test Acunetix iniciado — revisa logs"}

@app.post("/api/domains/{domain}/subdomains/{subdomain}/acunetix-scan")
async def launch_acunetix_scan(domain: str, subdomain: str, request: Request):
    """Lanza un scan Acunetix bajo demanda sobre un subdominio específico."""
    body    = await request.json()
    profile = body.get("profile", "full_scan")
    no_wait = body.get("no_wait", False)

    # Verificar que el subdominio pertenece al dominio
    if not subdomain.endswith(f".{domain}") and subdomain != domain:
        raise HTTPException(400, f"{subdomain} no pertenece a {domain}")

    if not os.environ.get("ACUNETIX_API_KEY"):
        raise HTTPException(503, "ACUNETIX_API_KEY no configurada")

    script = Path(__file__).parent.parent / "core" / "acunetix.py"
    cmd = [sys.executable, str(script),
           "--scan", subdomain,
           "--domain", domain,
           "--profile", profile]
    if no_wait: cmd.append("--no-wait")

    def _run():
        try: _subprocess.run(cmd, timeout=10800, capture_output=False)
        except Exception as e: print(f"[acunetix] {e}")

    threading.Thread(target=_run, daemon=True).start()
    return {
        "status":  "running",
        "message": f"Acunetix scan lanzado sobre {subdomain}",
        "profile": profile,
    }

@app.get("/api/domains/{domain}/acunetix")
def domain_acunetix(domain: str):
    """Scans y findings de Acunetix para un dominio."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        did = d["id"]
        try:
            scans = conn.execute(
                "SELECT * FROM acunetix_scans WHERE domain_id=? ORDER BY requested_at DESC",
                (did,)
            ).fetchall()
            findings = conn.execute(
                """SELECT * FROM acunetix_findings
                   WHERE domain_id=? ORDER BY
                   CASE severity
                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                     WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
                     ELSE 5 END, found_at DESC""",
                (did,)
            ).fetchall()
        except Exception:
            scans, findings = [], []
    return {
        "scans":    rows_to_list(scans),
        "findings": rows_to_list(findings),
    }

@app.get("/api/acunetix/findings")
def all_acunetix_findings(
    severity: Optional[str] = None,
    domain:   Optional[str] = None,
    page: int = 1, per_page: int = 50,
):
    """Todos los findings de Acunetix — vista global."""
    with db_conn() as conn:
        try:
            where, params = [], []
            if severity: where.append("f.severity=?");       params.append(severity)
            if domain:   where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
            w = f"WHERE {' AND '.join(where)}" if where else ""
            total = conn.execute(
                f"SELECT COUNT(*) FROM acunetix_findings f JOIN domains d ON d.id=f.domain_id {w}",
                params
            ).fetchone()[0]
            rows = conn.execute(
                f"""SELECT f.*, d.domain FROM acunetix_findings f
                    JOIN domains d ON d.id=f.domain_id
                    {w} ORDER BY
                    CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 ELSE 4 END
                    LIMIT ? OFFSET ?""",
                params + [per_page, (page-1)*per_page]
            ).fetchall()
        except Exception:
            return {"total": 0, "items": []}
    return {"total": total, "page": page, "per_page": per_page, "items": rows_to_list(rows)}

# ── Watchdog status ───────────────────────────────────────────

@app.get("/api/watchdog/log")
def watchdog_log(lines: int = 100):
    """Últimas líneas del log del watchdog."""
    log_files = list(Path(OUTPUT_DIR).rglob("recon.log"))
    if not log_files:
        return {"lines": [], "total": 0}
    # El más reciente
    latest = sorted(log_files, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    try:
        all_lines = latest.read_text(errors="replace").splitlines()
        # Filtrar solo líneas del watchdog
        wd_lines = [l for l in all_lines if "[WATCHDOG]" in l]
        return {"file": str(latest), "total": len(wd_lines),
                "lines": wd_lines[-lines:]}
    except Exception as e:
        return {"error": str(e), "lines": []}

# ── HTTP Error Analysis ───────────────────────────────────────

@app.get("/api/domains/{domain}/http-errors")
def domain_http_errors(domain: str):
    """Findings del analizador de respuestas HTTP (404, 429, 500 con info)."""
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE domain_id=? AND type='http_error_analysis'
               ORDER BY
                 CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 found_at DESC""",
            (d["id"],)
        ).fetchall()
    return rows_to_list(rows)

# ── Blind XSS ─────────────────────────────────────────────────

@app.get("/api/blindxss/summary")
def blindxss_summary():
    with db_conn() as conn:
        def safe(q):
            try: return conn.execute(q).fetchone()[0]
            except: return 0
        return {
            "total_payloads": safe("SELECT COUNT(*) FROM blindxss_payloads"),
            "pending":        safe("SELECT COUNT(*) FROM blindxss_payloads WHERE fired=0"),
            "fired":          safe("SELECT COUNT(*) FROM blindxss_payloads WHERE fired=1"),
            "configured":     bool(os.environ.get("EZXSS_URL")),
            "ezxss_url":      os.environ.get("EZXSS_URL",""),
        }

@app.get("/api/blindxss/payloads")
def blindxss_payloads(domain: Optional[str] = None, fired: Optional[bool] = None):
    with db_conn() as conn:
        try:
            where, params = [], []
            if domain: where.append("d.domain LIKE ?"); params.append(f"%{domain}%")
            if fired is not None: where.append("p.fired=?"); params.append(int(fired))
            w = f"WHERE {' AND '.join(where)}" if where else ""
            rows = conn.execute(
                f"""SELECT p.*, d.domain FROM blindxss_payloads p
                    JOIN domains d ON d.id=p.domain_id
                    {w} ORDER BY p.injected_at DESC LIMIT 100""",
                params
            ).fetchall()
            return rows_to_list(rows)
        except Exception:
            return []

# ── Cache attacks ─────────────────────────────────────────────

@app.get("/api/domains/{domain}/cache")
def domain_cache_findings(domain: str):
    with db_conn() as conn:
        d = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if not d: raise HTTPException(404)
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE domain_id=? AND type IN ('cache_poisoning','cache_deception')
               ORDER BY CASE severity
                 WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                 WHEN 'medium' THEN 3 ELSE 4 END, found_at DESC""",
            (d["id"],)
        ).fetchall()
    return rows_to_list(rows)

# ── PoC Generator ─────────────────────────────────────────────
import subprocess as _subprocess2

@app.post("/api/findings/{finding_id}/poc")
async def generate_finding_poc(finding_id: int):
    """Genera PoC con datos reales para un finding concreto."""
    script = Path(__file__).parent.parent / "core" / "poc_generator.py"
    out_dir = Path(__file__).parent.parent / "output" / "poc"
    out_dir.mkdir(parents=True, exist_ok=True)

    result = {"status": "running", "finding_id": finding_id}

    def _run():
        try:
            _subprocess2.run(
                [sys.executable, str(script), "--finding-id", str(finding_id),
                 "--output", str(out_dir)],
                timeout=120, capture_output=False
            )
        except Exception as e:
            print(f"[poc] {e}")

    threading.Thread(target=_run, daemon=True).start()
    return result

@app.post("/api/domains/{domain}/poc")
async def generate_domain_poc(domain: str, request: Request):
    """Genera PoC para todos los findings críticos/altos de un dominio."""
    body    = await request.json()
    sev     = body.get("severity", None)
    all_    = body.get("all", False)
    script  = Path(__file__).parent.parent / "core" / "poc_generator.py"
    out_dir = Path(__file__).parent.parent / "output" / "poc"
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(script), "--domain", domain,
           "--output", str(out_dir)]
    if sev:   cmd += ["--severity", sev]
    if all_:  cmd += ["--all"]

    def _run():
        try:
            _subprocess2.run(cmd, timeout=600, capture_output=False)
        except Exception as e:
            print(f"[poc] {e}")

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "running", "domain": domain, "output": str(out_dir)}

@app.get("/api/domains/{domain}/poc/files")
def list_poc_files(domain: str):
    """Lista las PoCs generadas para un dominio."""
    out_dir = Path(__file__).parent.parent / "output" / "poc"
    domain_safe = domain.replace(".", "_")
    files = []
    if out_dir.exists():
        for f in sorted(out_dir.glob(f"poc_{domain_safe}*.html"),
                       key=lambda x: x.stat().st_mtime, reverse=True):
            files.append({
                "filename": f.name,
                "size_kb":  round(f.stat().st_size / 1024, 1),
                "created":  datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
        # Índice
        idx = out_dir / f"index_{domain_safe}.html"
        if idx.exists():
            files.insert(0, {
                "filename": idx.name,
                "size_kb":  round(idx.stat().st_size / 1024, 1),
                "created":  datetime.fromtimestamp(idx.stat().st_mtime).isoformat(),
                "is_index": True,
            })
    return {"domain": domain, "files": files, "output_dir": str(out_dir)}

@app.get("/poc/{filename}")
def serve_poc(filename: str):
    """Sirve un archivo PoC HTML generado."""
    from fastapi.responses import FileResponse
    out_dir = Path(__file__).parent.parent / "output" / "poc"
    fpath   = out_dir / filename
    if not fpath.exists() or not filename.endswith(".html"):
        raise HTTPException(404)
    return FileResponse(str(fpath), media_type="text/html")

# ── PoC Generator ─────────────────────────────────────────────

@app.post("/api/findings/{finding_id}/poc")
def generate_poc(finding_id: int, background_tasks: BackgroundTasks):
    """Genera la PoC HTML para un finding concreto."""
    script = Path(__file__).parent.parent / "core" / "poc_generator.py"
    def _run():
        try:
            result = _subprocess.run(
                [sys.executable, str(script),
                 "--finding-id", str(finding_id)],
                capture_output=True, text=True, timeout=120
            )
            print(result.stdout)
            if result.returncode != 0:
                print("[poc error]", result.stderr[:300])
        except Exception as e:
            print(f"[poc] {e}")
    background_tasks.add_task(_run)
    return {"status": "generating",
            "message": f"PoC para finding #{finding_id} en proceso"}

@app.get("/api/findings/{finding_id}/poc/download")
def download_poc(finding_id: int):
    """Descarga la última PoC generada para un finding."""
    from fastapi.responses import FileResponse
    poc_dir = Path(OUTPUT_DIR)
    # Buscar el HTML más reciente para este finding_id
    files = list(poc_dir.rglob(f"poc_{finding_id}_*.html"))
    if not files:
        raise HTTPException(404, "PoC no generada aún. Genera primero con POST /api/findings/{id}/poc")
    latest = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    return FileResponse(str(latest), media_type="text/html",
                        filename=latest.name)

@app.get("/api/domains/{domain}/poc/list")
def list_pocs(domain: str):
    """Lista las PoCs generadas para un dominio."""
    poc_dir = Path(OUTPUT_DIR) / domain.replace(".", "_")
    if not poc_dir.exists():
        return []
    files = sorted(poc_dir.glob("poc_*.html"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return [{"name": f.name, "size_kb": round(f.stat().st_size/1024,1),
             "generated_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat()[:16]}
            for f in files]
