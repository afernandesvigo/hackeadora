#!/usr/bin/env python3
"""
core/poc_generator.py — Generador de PoC con datos reales capturados

La PoC NO es "debería ser vulnerable" — son los datos REALES:
  - Request exacto capturado durante el scan
  - Response real con la evidencia de la vulnerabilidad
  - Comando curl reproducible copiable
  - Pasos de reproducción numerados y específicos
  - Screenshot si está disponible
  - AI Advisor genera el texto de impacto con los datos reales

Uso:
  python3 core/poc_generator.py --finding-id 42
  python3 core/poc_generator.py --domain empresa.com --severity high
  python3 core/poc_generator.py --domain empresa.com --all
  python3 core/poc_generator.py --domain empresa.com --list
"""

import os
import sys
import json
import sqlite3
import subprocess
import argparse
import re
import base64
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] pip3 install requests"); sys.exit(1)

# ── Config ─────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent
DB_PATH       = os.environ.get("RECONFLOW_DB",      str(BASE_DIR / "data" / "recon.db"))
OUTPUT_DIR    = BASE_DIR / "output" / "poc"
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
TELEGRAM_BOT  = os.environ.get("TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID",  "")

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#65a30d",
    "info":     "#6366f1",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}

# ── DB helpers ──────────────────────────────────────────────────
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_finding(finding_id: int) -> Optional[dict]:
    with db_conn() as conn:
        r = conn.execute(
            """SELECT f.*, d.domain FROM findings f
               JOIN domains d ON d.id = f.domain_id
               WHERE f.id = ?""", (finding_id,)
        ).fetchone()
        return dict(r) if r else None

def get_findings_by_domain(domain: str, severity: Optional[str] = None,
                            ftype: Optional[str] = None) -> list:
    with db_conn() as conn:
        where = ["d.domain = ?"]
        params = [domain]
        if severity:
            where.append("f.severity = ?"); params.append(severity)
        if ftype:
            where.append("f.type LIKE ?"); params.append(f"%{ftype}%")
        w = " AND ".join(where)
        rows = conn.execute(
            f"""SELECT f.*, d.domain FROM findings f
                JOIN domains d ON d.id = f.domain_id
                WHERE {w}
                ORDER BY CASE f.severity
                  WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3 ELSE 4 END""",
            params
        ).fetchall()
        return [dict(r) for r in rows]

def get_acunetix_finding(domain: str, target: str) -> Optional[dict]:
    """Busca el finding de Acunetix correspondiente al mismo target."""
    with db_conn() as conn:
        try:
            r = conn.execute(
                """SELECT af.* FROM acunetix_findings af
                   JOIN domains d ON d.id = af.domain_id
                   WHERE d.domain = ? AND af.url LIKE ?
                   LIMIT 1""",
                (domain, f"%{target.split('?')[0]}%")
            ).fetchone()
            return dict(r) if r else None
        except Exception:
            return None

def get_screenshot(domain: str, subdomain: str, out_dir: Path) -> Optional[Path]:
    """Busca la screenshot de gowitness para este subdominio."""
    shots_dir = BASE_DIR / "output" / domain
    for scan_dir in sorted(shots_dir.glob("*"), reverse=True):
        shots = scan_dir / "screenshots"
        if not shots.exists():
            continue
        for f in shots.glob("*.png"):
            if subdomain.replace(".", "_") in f.name or subdomain in f.name:
                # Copiar a output/poc
                dest = out_dir / f.name
                shutil.copy(f, dest)
                return dest
    return None

# ── Captura real del request/response ──────────────────────────
def capture_live_evidence(url: str, method: str = "GET",
                           headers: dict = None,
                           body: str = None,
                           timeout: int = 15) -> dict:
    """
    Hace la petición REAL al target y captura request + response.
    Solo para vulnerabilidades pasivas/detectables sin riesgo.
    """
    extra_headers = headers or {}
    try:
        resp = requests.request(
            method, url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                **extra_headers,
            },
            data=body,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        # Construir representación del request
        req_lines = [f"{method} {resp.request.path_url} HTTP/1.1"]
        for k, v in resp.request.headers.items():
            req_lines.append(f"{k}: {v}")
        if resp.request.body:
            req_lines.append("")
            body_str = resp.request.body if isinstance(resp.request.body, str) \
                       else resp.request.body.decode("utf-8", errors="replace")
            req_lines.append(body_str[:500])
        raw_request = "\n".join(req_lines)

        # Construir representación del response
        resp_lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
        for k, v in resp.headers.items():
            resp_lines.append(f"{k}: {v}")
        resp_lines.append("")
        body_content = resp.text[:3000]
        if len(resp.text) > 3000:
            body_content += "\n[... truncado ...]"
        resp_lines.append(body_content)
        raw_response = "\n".join(resp_lines)

        return {
            "status_code":  resp.status_code,
            "raw_request":  raw_request,
            "raw_response": raw_response,
            "response_size": len(resp.content),
            "headers":      dict(resp.headers),
            "captured_at":  datetime.now().isoformat(),
            "live":         True,
        }
    except Exception as e:
        return {
            "status_code":  0,
            "raw_request":  f"{method} {url} HTTP/1.1",
            "raw_response": f"Error capturando evidencia en vivo: {e}",
            "live":         False,
            "error":        str(e),
        }

# ── Generar curl reproducible ───────────────────────────────────
def build_curl_command(url: str, method: str = "GET",
                       headers: dict = None, body: str = None,
                       extra_flags: list = None) -> str:
    parts = ["curl -v"]
    if method != "GET":
        parts.append(f"-X {method}")
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"--data '{body}'")
    for flag in (extra_flags or []):
        parts.append(flag)
    parts.append(f"'{url}'")
    return " \\\n  ".join(parts)

# ── Estrategia de PoC por tipo de vulnerabilidad ───────────────
def build_poc_strategy(finding: dict, evidence: dict) -> dict:
    """
    Según el tipo de vulnerabilidad, genera los pasos de reproducción
    usando los datos REALES del finding enriquecidos con la Knowledge Base.
    """
    # Enriquecer con KB
    kb_entry    = kb_for_finding(finding)
    kb_payloads = kb_entry.get("payloads", [])
    kb_refs     = kb_entry.get("references", [])
    kb_name     = kb_entry.get("name", "")
    kb_conf     = kb_entry.get("conference", "")

    ftype    = finding.get("type", "")
    template = finding.get("template", "")
    target   = finding.get("target", "")
    detail   = finding.get("detail", "")

    # ── CORS ──────────────────────────────────────────────────
    if "cors" in ftype or "cors" in template:
        origin = "https://evil-attacker.com"
        return {
            "title": "CORS Misconfiguration — Credentialed Cross-Origin Request",
            "steps": [
                f"Enviar la siguiente petición HTTP al endpoint vulnerable:",
                f"curl -v -H 'Origin: {origin}' '{target}'",
                f"Verificar que la respuesta incluye:",
                f"  Access-Control-Allow-Origin: {origin}",
                f"  Access-Control-Allow-Credentials: true",
                "Si ambos headers están presentes, el origen arbitrario está permitido con credenciales.",
                "Un atacante desde {origin} puede leer la respuesta autenticada del usuario víctima.",
            ],
            "curl": build_curl_command(target, headers={"Origin": origin}),
            "impact_note": "Permite a cualquier web maliciosa leer respuestas de API autenticadas del usuario víctima.",
            "fix": "Validar el Origin contra una whitelist explícita. Nunca usar Access-Control-Allow-Origin: * con credentials: true.",
        }

    # ── 403 Bypass ────────────────────────────────────────────
    if "403" in ftype or "bypass" in template:
        return {
            "title": "Acceso no autorizado — Bypass de restricción 403",
            "steps": [
                f"Verificar que el endpoint devuelve 403 normalmente:",
                f"  curl -o /dev/null -w '%{{http_code}}' '{target}'",
                f"Intentar el bypass con la técnica detectada:",
                f"  {detail[:200] if detail else 'ver curl reproducible'}",
                "Si la respuesta cambia a 200, el acceso restringido es accesible.",
            ],
            "curl": build_curl_command(target),
            "impact_note": "Acceso a recursos que deberían estar restringidos.",
            "fix": "Implementar control de acceso en el backend, no solo en el enrutamiento de frontend.",
        }

    # ── Cache Poisoning ───────────────────────────────────────
    if "cache_poison" in ftype:
        header_match = re.search(r'Header (\S+) reflejado', detail)
        vuln_header  = header_match.group(1) if header_match else "X-Forwarded-Host"
        canary_match = re.search(r'canary: (\S+)', detail)
        canary       = canary_match.group(1) if canary_match else "evil.com"
        return {
            "title": "Web Cache Poisoning via Unkeyed Header",
            "steps": [
                f"1. Enviar petición con header no-keyed que se refleja en la respuesta:",
                f"   curl -H '{vuln_header}: {canary}' '{target}?cb=test1'",
                f"2. El valor '{canary}' aparece en la respuesta (evidencia abajo).",
                f"3. Enviar la misma petición SIN el header:",
                f"   curl '{target}?cb=test1'",
                f"4. Si '{canary}' sigue apareciendo → la respuesta envenenada está cacheada.",
                f"5. Cualquier usuario que visite {target} recibirá la respuesta envenenada.",
            ],
            "curl": build_curl_command(target, headers={vuln_header: canary},
                                        extra_flags=["--get", "--data-urlencode 'cb=test1'"]),
            "impact_note": f"El header {vuln_header} no forma parte del cache key pero afecta la respuesta. Un atacante puede cachear contenido malicioso que se sirve a todos los usuarios.",
            "fix": f"Incluir {vuln_header} en el cache key o eliminar su reflejo en la respuesta.",
        }

    # ── Web Cache Deception ───────────────────────────────────
    if "cache_dec" in ftype or "wcd" in template:
        delim_match = re.search(r"delimiter '(.+?)'", detail)
        delim       = delim_match.group(1) if delim_match else ";"
        ext_match   = re.search(r'as \.(css|js|png)', detail)
        ext         = ext_match.group(1) if ext_match else "css"
        poc_url     = f"{target}{delim}poc.{ext}"
        return {
            "title": "Web Cache Deception — Datos privados cacheados públicamente",
            "steps": [
                "PASO 1 — Como usuario autenticado (víctima):",
                f"  Visitar la siguiente URL estando logueado:",
                f"  {poc_url}",
                f"  La respuesta contiene datos privados del usuario (email, token, etc.)",
                f"  y el CDN la cachea como recurso estático (.{ext}).",
                "",
                "PASO 2 — Como atacante (sin autenticación):",
                f"  curl '{poc_url}'",
                f"  La caché devuelve los datos privados de la víctima sin requerir autenticación.",
            ],
            "curl": build_curl_command(poc_url),
            "impact_note": f"Datos privados del usuario autenticado (email, tokens, información personal) quedan expuestos sin autenticación a través de la caché del CDN.",
            "fix": "Usar Cache-Control: no-store en respuestas dinámicas autenticadas. Normalizar paths de forma consistente entre CDN y origin server.",
        }

    # ── Blind XSS ─────────────────────────────────────────────
    if "blind_xss" in ftype:
        field_match = re.search(r'Campo: (\S+)', detail)
        field       = field_match.group(1) if field_match else "campo desconocido"
        fired_from  = finding.get("fired_from", "panel de administración")
        return {
            "title": f"Blind XSS — Ejecución en panel interno via campo '{field}'",
            "steps": [
                f"1. El payload fue inyectado en el campo '{field}' de {target}",
                f"2. Cuando el administrador revisó el dato en {fired_from or 'panel interno'},",
                f"   el JavaScript se ejecutó en su contexto autenticado.",
                f"3. El callback fue recibido con:",
                f"   - URL del panel: {fired_from or 'capturada'}",
                f"   - IP del admin: {finding.get('fired_ip', 'capturada')}",
                f"   - User-Agent: {(finding.get('fired_ua','') or '')[:80]}",
                f"4. Un atacante puede usar esto para robar la sesión del administrador.",
            ],
            "curl": f"# El payload fue: {detail[:200]}",
            "impact_note": f"XSS ejecutado en el panel de administración. Permite robo de sesión de administrador, defacement del panel o exfiltración de datos de todos los usuarios.",
            "fix": "Sanitizar input en todos los campos que sean renderizados en paneles de administración. Usar CSP estricto en el panel de administración.",
        }

    # ── SQLi / Template error ─────────────────────────────────
    if "sql" in template.lower() or "sql" in detail.lower():
        return {
            "title": "SQL Error en Respuesta HTTP — Posible SQL Injection",
            "steps": [
                f"1. La siguiente petición provocó un error SQL en la respuesta:",
                f"   curl '{target}'",
                f"2. El servidor devolvió un error de base de datos:",
                f"   {detail[:300]}",
                "3. Esto indica que el input del usuario llega a la query SQL sin sanitizar.",
                "4. Enviar un payload de test para confirmar inyección:",
                f"   curl '{target}' --data \"param=1'\"",
            ],
            "curl": build_curl_command(target),
            "impact_note": "El error SQL expone la tecnología de base de datos y potencialmente permite extracción de datos, bypass de autenticación o ejecución de comandos.",
            "fix": "Usar prepared statements / consultas parametrizadas. Deshabilitar mensajes de error detallados en producción.",
        }

    # ── Path Traversal / Confusion ────────────────────────────
    if "traversal" in ftype or "confusion" in template or "path" in ftype:
        return {
            "title": "Path Traversal / Path Confusion",
            "steps": [
                f"1. Enviar la petición de traversal al endpoint vulnerable:",
                f"   curl --path-as-is '{target}'",
                f"2. El servidor devuelve contenido fuera del directorio raíz.",
                f"3. Evidencia: {detail[:200]}",
            ],
            "curl": build_curl_command(target, extra_flags=["--path-as-is"]),
            "impact_note": "Acceso a archivos fuera del directorio web raíz, incluyendo potencialmente configuraciones, código fuente o archivos del sistema.",
            "fix": "Normalizar paths de forma consistente. Validar que el path resuelto está dentro del directorio permitido.",
        }

    # ── Genérico — enriquecido con KB si existe ──────────────
    # Construir pasos con payloads de la KB si los hay
    steps = [
        f"1. Acceder a la URL vulnerable:",
        f"   curl '{target}'",
        f"2. Evidencia capturada:",
        f"   {detail[:300]}",
    ]
    if kb_payloads:
        steps.append("3. Payloads conocidos para este tipo de vulnerabilidad (KB):")
        for pl in kb_payloads[:3]:
            steps.append(f"   {pl}")
    if kb_conf:
        steps.append(f"4. Técnica documentada en: {kb_conf}")

    refs_text = ""
    if kb_refs:
        refs_text = "\nReferencias: " + " | ".join(kb_refs[:2])

    return {
        "title": kb_name or f"Vulnerabilidad detectada — {template or ftype}",
        "steps": steps,
        "curl": build_curl_command(target),
        "impact_note": (detail[:300] if detail else "Ver evidencia capturada.") + refs_text,
        "fix": "Revisar la configuración del componente afectado según las mejores prácticas de seguridad.",
        "kb_refs": kb_refs,
        "kb_conf": kb_conf,
    }

# ── AI Advisor: texto profesional ─────────────────────────────
def generate_ai_narrative(finding: dict, strategy: dict,
                           evidence: dict) -> dict:
    """
    Usa Claude Haiku para generar el texto profesional del reporte
    usando los datos REALES del finding.
    """
    if not ANTHROPIC_KEY:
        return {
            "description":      strategy.get("impact_note",""),
            "business_impact":  "Ver detalles técnicos",
            "fix":              strategy.get("fix",""),
            "h1_title":         strategy.get("title",""),
        }

    prompt = f"""Eres un investigador de seguridad escribiendo un reporte de bug bounty profesional.
Genera el texto para un reporte de HackerOne basado en datos REALES capturados.

DATOS REALES DEL FINDING:
- Tipo: {finding.get('type','')}
- Severidad: {finding.get('severity','')}
- Target real: {finding.get('target','')}
- Template/herramienta: {finding.get('template','')}
- Evidencia real: {finding.get('detail','')[:400]}
- Dominio del programa: {finding.get('domain','')}
- Evidencia HTTP capturada: Status {evidence.get('status_code',0)}, Live: {evidence.get('live',False)}

ESTRATEGIA DE POC:
- Título: {strategy.get('title','')}
- Impacto técnico: {strategy.get('impact_note','')}

Genera un JSON con exactamente estas claves (sin texto antes ni después, sin backticks):
{{
  "h1_title": "Título conciso para HackerOne (máx 80 chars, en inglés)",
  "description": "Descripción técnica clara de la vulnerabilidad (2-3 párrafos en inglés). Incluye los datos reales: URL {finding.get('target','')}, tipo {finding.get('type','')}, evidencia observada.",
  "business_impact": "Impacto para el negocio del cliente (1 párrafo en inglés). Qué puede hacer un atacante real con esta vulnerabilidad.",
  "fix": "Recomendación de remediación específica y técnica (en inglés).",
  "cvss_vector": "CVSS:3.1/AV:N/..." 
}}"""

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      "claude-haiku-4-5-20251001",
                "max_tokens": 800,
                "messages":   [{"role":"user","content":prompt}],
            },
            timeout=30,
        )
        text = resp.json()["content"][0]["text"].strip()
        text = re.sub(r"^```json\s*|\s*```$", "", text).strip()
        return json.loads(text)
    except Exception as e:
        return {
            "h1_title":        strategy.get("title",""),
            "description":     strategy.get("impact_note",""),
            "business_impact": "Datos reales capturados durante el análisis autorizado.",
            "fix":             strategy.get("fix",""),
            "cvss_vector":     "",
        }

# ── Generar HTML de la PoC ─────────────────────────────────────
def render_poc_html(finding: dict, strategy: dict,
                    evidence: dict, narrative: dict,
                    screenshot: Optional[Path]) -> str:

    sev        = finding.get("severity","info")
    sev_color  = SEVERITY_COLOR.get(sev,"#6366f1")
    sev_emoji  = SEVERITY_EMOJI.get(sev,"⚪")
    target     = finding.get("target","")
    domain     = finding.get("domain","")
    now        = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    steps_html = "".join(
        f'<li>{s}</li>' for s in strategy.get("steps",[])
    )

    curl_cmd   = strategy.get("curl","").replace("&","&amp;").replace("<","&lt;")
    raw_req    = (evidence.get("raw_request","") or "").replace("&","&amp;").replace("<","&lt;")
    raw_resp   = (evidence.get("raw_response","") or "").replace("&","&amp;").replace("<","&lt;")

    shot_html  = ""
    if screenshot and screenshot.exists():
        with open(screenshot,"rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        shot_html = f"""
        <div class="section">
          <div class="section-title">📸 Screenshot</div>
          <img src="data:image/png;base64,{b64}"
               style="max-width:100%;border:1px solid #e5e7eb;border-radius:8px"/>
        </div>"""

    cvss_html = ""
    if narrative.get("cvss_vector"):
        cvss_html = f'<div class="meta-item"><span class="label">CVSS Vector</span><code>{narrative["cvss_vector"]}</code></div>'

    # KB enrichment
    kb_refs  = strategy.get("kb_refs", [])
    kb_conf  = strategy.get("kb_conf", "")
    kb_refs_html = ""
    if kb_refs or kb_conf:
        items = ""
        if kb_conf:
            items += f'<li style="margin-bottom:6px"><strong>Origen de la investigación:</strong> {kb_conf}</li>'
        for ref in kb_refs[:3]:
            items += f'<li style="margin-bottom:4px"><a href="{ref}" style="color:#3b82f6" target="_blank">{ref}</a></li>'
        kb_refs_html = f"""
  <div class="section">
    <div class="section-title">📚 Knowledge Base — Referencias</div>
    <ul style="padding-left:20px;font-size:13px;color:#374151">{items}</ul>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PoC — {finding.get('id','')} — {domain}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
          background:#f9fafb; color:#111827; line-height:1.6 }}
  .wrapper {{ max-width:900px; margin:0 auto; padding:32px 24px }}

  /* Header */
  .header {{ background:#fff; border:1px solid #e5e7eb; border-radius:12px;
             padding:28px 32px; margin-bottom:24px }}
  .severity-badge {{ display:inline-flex; align-items:center; gap:6px;
    background:{sev_color}15; color:{sev_color}; border:1px solid {sev_color}40;
    padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700;
    text-transform:uppercase; letter-spacing:.5px; margin-bottom:14px }}
  .title {{ font-size:22px; font-weight:700; color:#111827; margin-bottom:8px }}
  .meta {{ display:flex; flex-wrap:wrap; gap:16px; margin-top:16px }}
  .meta-item {{ font-size:13px; color:#6b7280 }}
  .meta-item .label {{ font-weight:600; color:#374151 }}
  .meta-item code {{ background:#f3f4f6; padding:2px 6px; border-radius:4px;
                      font-size:12px; color:#1f2937 }}

  /* Sections */
  .section {{ background:#fff; border:1px solid #e5e7eb; border-radius:10px;
              padding:22px 26px; margin-bottom:20px }}
  .section-title {{ font-size:14px; font-weight:700; color:#374151;
                    text-transform:uppercase; letter-spacing:.8px;
                    margin-bottom:14px; padding-bottom:10px;
                    border-bottom:1px solid #f3f4f6 }}

  /* Steps */
  .steps ol {{ padding-left:20px }}
  .steps li {{ margin-bottom:10px; font-size:14px; color:#374151 }}

  /* Code blocks */
  .code-block {{ background:#0f172a; color:#e2e8f0; border-radius:8px;
                 padding:16px 20px; font-family:"JetBrains Mono","Fira Code",monospace;
                 font-size:12px; line-height:1.7; overflow-x:auto;
                 white-space:pre-wrap; word-break:break-all }}
  .code-label {{ font-size:11px; font-weight:600; color:#9ca3af;
                 text-transform:uppercase; letter-spacing:.5px;
                 margin-bottom:6px }}

  /* HTTP blocks */
  .http-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px }}
  @media(max-width:640px) {{ .http-grid {{ grid-template-columns:1fr }} }}
  .http-block {{ border-radius:8px; overflow:hidden }}
  .http-header {{ padding:8px 14px; font-size:11px; font-weight:700;
                  text-transform:uppercase; letter-spacing:.5px }}
  .http-req .http-header {{ background:#1e3a5f; color:#93c5fd }}
  .http-resp .http-header {{ background:#14432a; color:#86efac }}
  .http-body {{ background:#0f172a; color:#e2e8f0;
                font-family:"JetBrains Mono","Fira Code",monospace;
                font-size:11px; line-height:1.7; padding:12px 14px;
                overflow-x:auto; white-space:pre-wrap; max-height:320px;
                overflow-y:auto }}

  /* Impact */
  .impact-box {{ background:#fef2f2; border:1px solid #fecaca;
                 border-left:4px solid {sev_color};
                 border-radius:8px; padding:16px 20px }}
  .impact-box p {{ font-size:14px; color:#374151 }}

  /* Fix */
  .fix-box {{ background:#f0fdf4; border:1px solid #bbf7d0;
              border-left:4px solid #16a34a;
              border-radius:8px; padding:16px 20px }}
  .fix-box p {{ font-size:14px; color:#374151 }}

  /* Footer */
  .footer {{ text-align:center; color:#9ca3af; font-size:12px;
             padding:24px 0 8px }}
  .badge-live {{ display:inline-flex; align-items:center; gap:4px;
                 background:#dcfce7; color:#15803d; border:1px solid #86efac;
                 padding:2px 10px; border-radius:10px; font-size:11px;
                 font-weight:600 }}
  .badge-captured {{ background:#fef9c3; color:#854d0e; border-color:#fde047 }}
</style>
</head>
<body>
<div class="wrapper">

  <!-- Header -->
  <div class="header">
    <div class="severity-badge">{sev_emoji} {sev.upper()}</div>
    <div class="title">{narrative.get("h1_title", strategy.get("title",""))}</div>
    <div class="meta">
      <div class="meta-item"><span class="label">Target</span><br>
        <code>{target}</code></div>
      <div class="meta-item"><span class="label">Program</span><br>
        <code>{domain}</code></div>
      <div class="meta-item"><span class="label">Finding type</span><br>
        <code>{finding.get("type","")}</code></div>
      <div class="meta-item"><span class="label">Tool</span><br>
        <code>{finding.get("template","")}</code></div>
      <div class="meta-item"><span class="label">Evidence</span><br>
        <span class="badge-live {'badge-live' if evidence.get('live') else 'badge-captured'}">
          {'✓ Live captured' if evidence.get('live') else '📋 From scan DB'}
        </span></div>
      <div class="meta-item"><span class="label">Generated</span><br>
        <code>{now}</code></div>
      {cvss_html}
    </div>
  </div>

  <!-- Description -->
  <div class="section">
    <div class="section-title">📋 Vulnerability Description</div>
    <p style="font-size:14px;color:#374151;white-space:pre-line">{
      narrative.get("description", strategy.get("impact_note",""))
    }</p>
  </div>

  <!-- Steps to reproduce -->
  <div class="section steps">
    <div class="section-title">🔁 Steps to Reproduce</div>
    <ol>{steps_html}</ol>
  </div>

  <!-- curl command -->
  <div class="section">
    <div class="section-title">💻 Reproducible cURL Command</div>
    <div class="code-label">Copy and run:</div>
    <div class="code-block">{curl_cmd}</div>
  </div>

  <!-- HTTP evidence -->
  {f'''
  <div class="section">
    <div class="section-title">📡 HTTP Evidence (Real Captured Traffic)</div>
    <div style="margin-bottom:8px;font-size:12px;color:#6b7280">
      Status: <strong>{evidence.get("status_code","")}</strong> &nbsp;|&nbsp;
      Response size: <strong>{evidence.get("response_size",0):,} bytes</strong> &nbsp;|&nbsp;
      Captured: <strong>{evidence.get("captured_at","")[:16]}</strong>
    </div>
    <div class="http-grid">
      <div class="http-block http-req">
        <div class="http-header">→ Request</div>
        <div class="http-body">{raw_req[:2000]}</div>
      </div>
      <div class="http-block http-resp">
        <div class="http-header">← Response</div>
        <div class="http-body">{raw_resp[:2000]}</div>
      </div>
    </div>
  </div>''' if raw_req else ''}

  {shot_html}

  <!-- Impact -->
  <div class="section">
    <div class="section-title">💥 Business Impact</div>
    <div class="impact-box">
      <p>{narrative.get("business_impact", strategy.get("impact_note",""))}</p>
    </div>
  </div>

  <!-- Fix -->
  <div class="section">
    <div class="section-title">🔧 Recommended Fix</div>
    <div class="fix-box">
      <p>{narrative.get("fix", strategy.get("fix",""))}</p>
    </div>
  </div>

  <!-- KB References -->
  {kb_refs_html}

  <div class="footer">
    Generated by <strong>Hackeadora</strong> — Bug Bounty Automation Pipeline<br>
    Claude (Anthropic) &amp; Antonio Fernandes
  </div>

</div>
</body>
</html>"""

# ── Generar PoC completa ───────────────────────────────────────
def generate_poc(finding_id: int,
                 recapture: bool = True,
                 open_browser: bool = False) -> Optional[Path]:
    """
    Genera la PoC completa para un finding específico.
    Si recapture=True, hace la petición en vivo al target.
    """
    finding = get_finding(finding_id)
    if not finding:
        print(f"[!] Finding {finding_id} no encontrado en DB")
        return None

    sev    = finding.get("severity","info")
    target = finding.get("target","")
    domain = finding.get("domain","")
    ftype  = finding.get("type","")

    print(f"\n[→] Generando PoC para finding #{finding_id}")
    print(f"    Tipo: {ftype} | Severidad: {sev}")
    print(f"    Target: {target}")

    # 1. Capturar evidencia en vivo (si es posible y seguro)
    evidence = {}
    if recapture and target.startswith("http"):
        print(f"    Capturando evidencia en vivo...")
        # Solo hacemos GET seguro — no re-explotar activamente
        evidence = capture_live_evidence(target)
        if evidence.get("live"):
            print(f"    ✓ Evidencia capturada: HTTP {evidence['status_code']}")
        else:
            print(f"    ! No se pudo capturar en vivo: {evidence.get('error','')}")
    else:
        evidence = {
            "raw_request":  f"GET {target} HTTP/1.1",
            "raw_response": finding.get("detail",""),
            "status_code":  "—",
            "live":         False,
        }

    # 2. Estrategia de PoC según el tipo
    strategy = build_poc_strategy(finding, evidence)

    # 3. Buscar screenshot si hay
    subdomain = target.replace("https://","").replace("http://","").split("/")[0]
    shot_dir  = OUTPUT_DIR / domain.replace(".","_")
    shot_dir.mkdir(parents=True, exist_ok=True)
    screenshot = get_screenshot(domain, subdomain, shot_dir)
    if screenshot:
        print(f"    ✓ Screenshot encontrada: {screenshot.name}")

    # 4. AI Advisor genera el texto profesional
    print(f"    Generando texto con AI Advisor...")
    narrative = generate_ai_narrative(finding, strategy, evidence)

    # 5. Renderizar HTML
    html = render_poc_html(finding, strategy, evidence, narrative, screenshot)

    # 6. Guardar
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"poc_{finding_id}_{ftype}_{sev}_{ts}.html"
    out_path = shot_dir / filename
    out_path.write_text(html, encoding="utf-8")

    print(f"    ✓ PoC generada: {out_path}")

    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{out_path}")

    return out_path

def generate_all(domain: str, severity: Optional[str] = None,
                 ftype: Optional[str] = None) -> list:
    """Genera PoC para todos los findings de un dominio."""
    findings = get_findings_by_domain(domain, severity, ftype)
    if not findings:
        print(f"[!] Sin findings para {domain}")
        return []

    print(f"[→] Generando PoC para {len(findings)} findings de {domain}")
    generated = []
    for f in findings:
        try:
            path = generate_poc(f["id"])
            if path: generated.append(path)
        except Exception as e:
            print(f"    [!] Error en finding {f['id']}: {e}")
    return generated

# ── Main ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Generador de PoC — Hackeadora")
    parser.add_argument("--finding-id", type=int, help="ID del finding")
    parser.add_argument("--domain",     help="Dominio para generar todas las PoC")
    parser.add_argument("--severity",   help="Filtrar por severidad (critical/high/medium/low)")
    parser.add_argument("--type",       help="Filtrar por tipo de finding")
    parser.add_argument("--all",        action="store_true", help="Generar todas las PoC del dominio")
    parser.add_argument("--list",       action="store_true", help="Listar findings disponibles")
    parser.add_argument("--no-capture", action="store_true", help="No recapturar evidencia en vivo")
    parser.add_argument("--open",       action="store_true", help="Abrir PoC en navegador al generar")
    args = parser.parse_args()

    if args.list and args.domain:
        findings = get_findings_by_domain(args.domain, args.severity, args.type)
        print(f"\nFindings disponibles para {args.domain} ({len(findings)}):")
        for f in findings:
            print(f"  [{f['id']:4d}] [{f['severity']:8s}] {f['type']:20s} {f['target'][:60]}")
        return

    if args.finding_id:
        path = generate_poc(args.finding_id,
                             recapture=not args.no_capture,
                             open_browser=args.open)
        if path:
            print(f"\n[✓] PoC lista: {path}")
        return

    if args.domain and args.all:
        paths = generate_all(args.domain, args.severity, args.type)
        print(f"\n[✓] {len(paths)} PoCs generadas en {OUTPUT_DIR}")
        return

    parser.print_help()

if __name__ == "__main__":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    main()
