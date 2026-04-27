#!/usr/bin/env python3
"""
core/ai_advisor.py — AI Advisor para Hackeadora
Usa la API de Claude para:
  1. Analizar findings y proponer chains de vulnerabilidades
  2. Identificar dónde la IA aportaría más profundidad
  3. Generar borradores de reportes H1

Modelos:
  - Haiku  → análisis masivo, sugerencias de depth (barato)
  - Sonnet → chaining, análisis de lógica (medio)

Uso:
  python3 core/ai_advisor.py --domain empresa.com
  python3 core/ai_advisor.py --domain empresa.com --run-chains
  python3 core/ai_advisor.py --domain empresa.com --report <finding_id>
"""

import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] pip3 install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent.parent
DB_PATH   = os.environ.get("RECONFLOW_DB", str(BASE_DIR / "data" / "recon.db"))
API_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
TELEGRAM_BOT  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

# Precios por millón de tokens (input/output)
PRICING = {
    "claude-haiku-4-5-20251001":  {"in": 0.80,  "out": 4.00},
    "claude-sonnet-4-6": {"in": 3.00,  "out": 15.00},
}
DEFAULT_MODEL_CHEAP  = "claude-haiku-4-5-20251001"
DEFAULT_MODEL_SMART  = "claude-sonnet-4-6"

# ── DB helpers ────────────────────────────────────────────────
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_domain_id(domain: str) -> Optional[int]:
    with db_conn() as conn:
        row = conn.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        return row["id"] if row else None

def get_findings(domain_id: int) -> list:
    with db_conn() as conn:
        try:
            rows = conn.execute(
                """SELECT f.*, d.domain FROM findings f
                   JOIN domains d ON d.id=f.domain_id
                   WHERE f.domain_id=? ORDER BY f.found_at DESC LIMIT 50""",
                (domain_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

def get_business_entities(domain_id: int) -> list:
    with db_conn() as conn:
        try:
            rows = conn.execute(
                "SELECT * FROM business_entities WHERE domain_id=? ORDER BY risk_score DESC",
                (domain_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

def get_acunetix_findings(domain_id: int) -> list:
    """Findings de Acunetix para este dominio."""
    with db_conn() as conn:
        try:
            rows = conn.execute(
                """SELECT name, severity, url, parameter, detail
                   FROM acunetix_findings WHERE domain_id=?
                   ORDER BY CASE severity
                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                     WHEN 'medium' THEN 3 ELSE 4 END
                   LIMIT 30""",
                (domain_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

def get_ai_suggestions(domain_id: int, status: str = "pending") -> list:
    with db_conn() as conn:
        try:
            rows = conn.execute(
                "SELECT * FROM ai_suggestions WHERE domain_id=? AND status=? ORDER BY priority",
                (domain_id, status)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

def save_ai_response(suggestion_id: int, response: str):
    with db_conn() as conn:
        conn.execute(
            "UPDATE ai_suggestions SET status='done', ai_response=? WHERE id=?",
            (response, suggestion_id)
        )
        conn.commit()

def save_suggestion(domain_id: int, s_type: str, priority: int,
                    title: str, desc: str, urls: list,
                    model: str, cost: float = 0.0):
    with db_conn() as conn:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO ai_suggestions
                   (domain_id,suggestion_type,priority,title,description,
                    affected_urls,ai_model,estimated_cost_usd)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (domain_id, s_type, priority, title, desc,
                 json.dumps(urls), model, cost)
            )
            conn.commit()
        except Exception as e:
            print(f"[!] Error guardando suggestion: {e}")

# ── Claude API ────────────────────────────────────────────────
def call_claude(prompt: str, model: str = DEFAULT_MODEL_CHEAP,
                max_tokens: int = 1000, system: str = "") -> tuple[str, float]:
    """Llama a la API de Claude. Devuelve (respuesta, coste_usd)."""
    if not API_KEY:
        return "⚠️ ANTHROPIC_API_KEY no configurada", 0.0

    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=body,
            timeout=60
        )
        if r.status_code != 200:
            return f"Error API: {r.status_code} — {r.text[:200]}", 0.0

        data = r.json()
        text = data["content"][0]["text"]

        # Calcular coste
        usage = data.get("usage", {})
        pricing = PRICING.get(model, {"in": 3.0, "out": 15.0})
        cost = (
            usage.get("input_tokens", 0)  / 1_000_000 * pricing["in"] +
            usage.get("output_tokens", 0) / 1_000_000 * pricing["out"]
        )

        return text, cost

    except Exception as e:
        return f"Error: {e}", 0.0

# ── Funciones del advisor ─────────────────────────────────────

def analyze_depth_opportunities(domain: str, domain_id: int) -> list:
    """
    Analiza con Haiku qué puntos del scan necesitan más profundidad con IA.
    Barato: ~$0.001-0.005 por dominio.
    """
    findings       = get_findings(domain_id)
    entities       = get_business_entities(domain_id)
    suggestions    = get_ai_suggestions(domain_id)
    acx_findings   = get_acunetix_findings(domain_id)

    if not findings and not entities and not suggestions:
        print(f"  Sin datos suficientes para analizar {domain}")
        return []

    # Preparar contexto compacto
    findings_summary = json.dumps([
        {"type": f["type"], "severity": f["severity"],
         "target": f["target"][:80], "template": f.get("template", "")}
        for f in findings[:20]
    ], ensure_ascii=False)

    entities_summary = json.dumps([
        {"type": e["entity_type"], "risk": e["risk_score"],
         "rules": json.loads(e.get("rules_inferred", "[]"))[:3]}
        for e in entities[:10]
    ], ensure_ascii=False)

    suggestions_summary = json.dumps([
        {"title": s["title"], "priority": s["priority"]}
        for s in suggestions[:10]
    ], ensure_ascii=False)

    system = """Eres un experto en bug bounty y seguridad ofensiva.
Analiza los datos de recon de una aplicación web y propón de forma concisa
dónde el análisis con IA aportaría más valor que las herramientas automáticas.
Responde SOLO en JSON válido, sin texto adicional ni markdown."""

    acx_summary = json.dumps([
        {"name": f["name"], "severity": f["severity"], "url": f.get("url","")}
        for f in acx_findings[:15]
    ], ensure_ascii=False) if acx_findings else "[]"

    prompt = f"""Dominio: {domain}

Findings de Hackeadora (recon + nuclei + smart scan):
{findings_summary}

Findings de Acunetix (DAST):
{acx_summary}

Entidades de negocio detectadas:
{entities_summary}

Sugerencias pendientes:
{suggestions_summary}

Devuelve un JSON con esta estructura exacta:
{{
  "depth_opportunities": [
    {{
      "priority": 1,
      "title": "título corto",
      "why_ai": "por qué la IA aporta aquí (1 frase)",
      "what_to_do": "acción concreta (1-2 frases)",
      "estimated_impact": "high|medium|low",
      "model": "haiku|sonnet",
      "estimated_cost_usd": 0.01
    }}
  ],
  "quick_wins": ["acción rápida 1", "acción rápida 2"],
  "summary": "resumen ejecutivo en 2 frases"
}}"""

    print("  Analizando oportunidades con Haiku...")
    response, cost = call_claude(prompt, DEFAULT_MODEL_CHEAP, 800, system)
    print(f"  Coste: ${cost:.4f}")

    try:
        # Limpiar posibles backticks
        clean = response.strip().strip("```json").strip("```").strip()
        data  = json.loads(clean)

        # Guardar en DB
        for opp in data.get("depth_opportunities", []):
            save_suggestion(
                domain_id, "ai_depth", opp.get("priority", 5),
                opp.get("title", ""),
                f"{opp.get('why_ai','')} | {opp.get('what_to_do','')}",
                [], opp.get("model", "haiku"),
                opp.get("estimated_cost_usd", 0.0)
            )

        return data

    except json.JSONDecodeError:
        # Si no devuelve JSON válido, guardar como texto
        save_suggestion(domain_id, "ai_depth", 5,
                        "Análisis de oportunidades IA",
                        response[:500], [], DEFAULT_MODEL_CHEAP, cost)
        return []


def analyze_chains(domain: str, domain_id: int) -> str:
    """
    Usa Sonnet para proponer chains de vulnerabilidades.
    Más caro pero más inteligente: ~$0.02-0.10 por dominio.
    """
    findings      = get_findings(domain_id)
    entities      = get_business_entities(domain_id)
    acx_findings  = get_acunetix_findings(domain_id)

    if len(findings) < 2:
        return "Insuficientes findings para proponer chains (mínimo 2)"

    system = """Eres un investigador senior de seguridad especializado en bug bounty.
Tu tarea es analizar findings combinados de Hackeadora y Acunetix y proponer cadenas de vulnerabilidades
(vulnerability chaining) que escalen el impacto. Sé específico y práctico.
Responde en español."""

    findings_detail = json.dumps([
        {"type": f["type"], "severity": f["severity"],
         "target": f["target"], "template": f.get("template",""),
         "detail": f.get("detail","")[:100]}
        for f in findings[:30]
    ], ensure_ascii=False, indent=2)

    entities_detail = json.dumps([
        {"type": e["entity_type"], "name": e["entity_name"],
         "risk_score": e["risk_score"],
         "rules": json.loads(e.get("rules_inferred","[]"))}
        for e in entities
    ], ensure_ascii=False, indent=2)

    acx_detail = json.dumps([
        {"name": f["name"], "severity": f["severity"],
         "url": f.get("url",""), "detail": f.get("detail","")[:80]}
        for f in acx_findings
    ], ensure_ascii=False, indent=2) if acx_findings else "[]"

    prompt = f"""Analiza estos hallazgos de seguridad del dominio {domain}:

## Findings de Hackeadora (recon + nuclei + smart scan):
{findings_detail}

## Findings de Acunetix (DAST — verificados por motor comercial):
{acx_detail}

## Entidades de negocio detectadas:
{entities_detail}

Por favor:
1. Identifica las 2-3 cadenas de vulnerabilidades más prometedoras
2. Para cada chain: describe los pasos, el impacto resultante y la severidad final
3. Indica qué findings/entidades hay que combinar
4. Estima el bounty potencial en HackerOne basándote en chains similares

Sé concreto y accionable. Si hay un chain crítico (account takeover, RCE, etc.), destácalo primero."""

    print("  Analizando chains con Sonnet...")
    response, cost = call_claude(prompt, DEFAULT_MODEL_SMART, 1500, system)
    print(f"  Coste: ${cost:.4f}")

    # Guardar en DB
    save_suggestion(
        domain_id, "chain", 1,
        f"Análisis de chains — {domain}",
        response, [], DEFAULT_MODEL_SMART, cost
    )

    return response


def generate_h1_report(domain: str, domain_id: int, finding_id: int) -> str:
    """
    Genera un borrador de reporte H1 para un finding concreto.
    Usa Sonnet: ~$0.05-0.15 por reporte.
    """
    with db_conn() as conn:
        finding = conn.execute(
            "SELECT * FROM findings WHERE id=? AND domain_id=?",
            (finding_id, domain_id)
        ).fetchone()

    if not finding:
        return f"Finding {finding_id} no encontrado para {domain}"

    finding = dict(finding)

    system = """Eres un experto en bug bounty que escribe reportes de alta calidad para HackerOne.
Los buenos reportes son claros, tienen steps to reproduce detallados, impacto bien definido
y sugerencia de fix. Escribe en inglés (estándar de H1). Sé profesional pero directo."""

    prompt = f"""Escribe un reporte de HackerOne para este hallazgo:

Dominio: {domain}
Tipo: {finding['type']}
Severidad: {finding['severity']}
Target: {finding['target']}
Template/Tool: {finding.get('template', 'N/A')}
Detalle técnico: {finding.get('detail', 'N/A')}

El reporte debe incluir:
1. **Title** — conciso y descriptivo (máximo 80 chars)
2. **Severity** — con justificación CVSS básica
3. **Summary** — 2-3 frases del issue
4. **Steps to Reproduce** — paso a paso, reproducible
5. **Impact** — qué puede hacer un atacante
6. **Proof of Concept** — comando curl o payload de ejemplo
7. **Suggested Fix** — recomendación técnica concreta

Si no tienes suficiente información para alguna sección, indica qué datos
necesitarías del researcher para completarla."""

    print("  Generando reporte H1 con Sonnet...")
    response, cost = call_claude(prompt, DEFAULT_MODEL_SMART, 1200, system)
    print(f"  Coste: ${cost:.4f}")

    # Guardar en DB
    save_suggestion(
        domain_id, "report_draft", 1,
        f"Reporte H1 — {finding['type']} en {finding['target'][:50]}",
        response, [finding['target']], DEFAULT_MODEL_SMART, cost
    )

    return response


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


def print_summary(domain: str, data: dict):
    """Imprime resumen en consola de forma legible."""
    print("\n" + "═"*60)
    print(f"  🤖 AI Advisor — {domain}")
    print("═"*60)

    if isinstance(data, dict):
        summary = data.get("summary", "")
        if summary:
            print(f"\n📋 {summary}\n")

        opps = data.get("depth_opportunities", [])
        if opps:
            print("🎯 Oportunidades de profundidad con IA:")
            for o in opps:
                icon = "🔴" if o.get("estimated_impact") == "high" else \
                       "🟠" if o.get("estimated_impact") == "medium" else "🟡"
                print(f"  {icon} [{o.get('priority',5)}] {o.get('title','')}")
                print(f"      {o.get('why_ai','')}")
                print(f"      → {o.get('what_to_do','')}")
                print(f"      Modelo: {o.get('model','haiku')} | Est. coste: ${o.get('estimated_cost_usd',0):.3f}")
                print()

        wins = data.get("quick_wins", [])
        if wins:
            print("⚡ Quick wins:")
            for w in wins:
                print(f"  • {w}")
    else:
        print(data)

    print("\n" + "═"*60)


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AI Advisor para Hackeadora")
    parser.add_argument("--domain",     required=True, help="Dominio a analizar")
    parser.add_argument("--run-chains", action="store_true", help="Analizar chains (usa Sonnet)")
    parser.add_argument("--report",     type=int, help="Generar reporte H1 para finding ID")
    parser.add_argument("--dry-run",    action="store_true", help="Sin llamar a la API")
    args = parser.parse_args()

    domain    = args.domain
    domain_id = get_domain_id(domain)

    if not domain_id:
        print(f"[!] Dominio '{domain}' no encontrado en la DB")
        sys.exit(1)

    if not API_KEY and not args.dry_run:
        print("[!] ANTHROPIC_API_KEY no configurada")
        print("    Añade ANTHROPIC_API_KEY=... a tu .env")
        print("    O usa --dry-run para ver qué se analizaría sin gastar")
        sys.exit(1)

    total_cost = 0.0

    # ── Análisis de oportunidades (siempre, barato) ───────────
    if not args.dry_run:
        data = analyze_depth_opportunities(domain, domain_id)
        print_summary(domain, data)

        # Notificar por Telegram
        if data and isinstance(data, dict):
            opps = data.get("depth_opportunities", [])
            if opps:
                msg = f"🤖 *AI Advisor — {domain}*\n"
                msg += f"📋 {data.get('summary','')}\n\n"
                for o in opps[:3]:
                    icon = "🔴" if o.get("estimated_impact") == "high" else "🟠"
                    msg += f"{icon} *{o.get('title','')}*\n"
                    msg += f"   {o.get('why_ai','')}\n\n"
                notify_telegram(msg)
    else:
        # Dry run — mostrar qué se analizaría
        findings  = get_findings(domain_id)
        entities  = get_business_entities(domain_id)
        print(f"\n[DRY RUN] Analizaría {len(findings)} findings y {len(entities)} entidades")
        print(f"  Coste estimado análisis básico: ~${len(findings) * 0.001:.3f}")
        if args.run_chains:
            print(f"  Coste estimado chains: ~$0.05-0.10")

    # ── Chains (opcional, más caro) ────────────────────────────
    if args.run_chains and not args.dry_run:
        print("\n" + "─"*40)
        chain_result = analyze_chains(domain, domain_id)
        print("\n🔗 VULNERABILITY CHAINS PROPUESTOS:")
        print("─"*40)
        print(chain_result)
        notify_telegram(
            f"🔗 *Chains analizados — {domain}*\n\n" +
            chain_result[:800] + ("..." if len(chain_result) > 800 else "")
        )

    # ── Reporte H1 (por finding específico) ───────────────────
    if args.report and not args.dry_run:
        print("\n" + "─"*40)
        report = generate_h1_report(domain, domain_id, args.report)
        print("\n📄 BORRADOR REPORTE H1:")
        print("─"*40)
        print(report)

    print(f"\n[✓] AI Advisor completado para {domain}")


if __name__ == "__main__":
    main()
