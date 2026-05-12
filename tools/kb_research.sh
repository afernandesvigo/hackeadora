#!/usr/bin/env bash
# ============================================================
#  tools/kb_research.sh — KB research mensual via Claude + WebSearch
#
#  Spawn `claude -p` con WebSearch/WebFetch para investigar las últimas
#  técnicas/CVEs de BBP, pentest y security research del último mes
#  (cualquier fuente: Twitter, blogs, papers, advisories, etc.).
#
#  Output: 2 archivos staging (NO se mergean automáticamente):
#    data/kb_research_staging.json     — nuevas KB entries propuestas
#    data/cve_research_staging.json    — nuevos CVEs propuestos
#
#  Tras review humano:
#    ./tools/kb_research.sh --merge       (mergea ambos staging a KB+catalog)
#    ./tools/kb_research.sh --merge-kb    (solo KB)
#    ./tools/kb_research.sh --merge-cves  (solo CVEs)
#
#  Coste: 1 llamada a Claude con tools (WebSearch + WebFetch + multiple steps).
#  Estimado: 50-200k tokens via subscription. Hacer mensual.
#
#  Vars opt:
#    KB_RESEARCH_DAYS  cuántos días atrás (default 30)
#    KB_RESEARCH_FOCUS extra topics (default: BBP+pentest+CVE)
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DAYS="${KB_RESEARCH_DAYS:-30}"
EXTRA_FOCUS="${KB_RESEARCH_FOCUS:-}"
KB_PATH="$SCRIPT_DIR/core/knowledge_base.json"
CVE_PATH="$SCRIPT_DIR/core/cve_catalog.json"
KB_STAGING="$SCRIPT_DIR/data/kb_research_staging.json"
CVE_STAGING="$SCRIPT_DIR/data/cve_research_staging.json"

mkdir -p "$SCRIPT_DIR/data"

# ── Modos: research / merge ─────────────────────────────────
if [[ "$1" == "--merge" || "$1" == "--merge-kb" || "$1" == "--merge-cves" ]]; then
  MODE="$1"

  # Merge KB
  if [[ "$MODE" == "--merge" || "$MODE" == "--merge-kb" ]]; then
    if [[ ! -s "$KB_STAGING" ]]; then
      echo "[!] No hay $KB_STAGING — corre research primero"
    else
      python3 - <<PYEOF
import json
kb = json.load(open("$KB_PATH"))
new_entries = json.load(open("$KB_STAGING"))
existing_ids = {v["id"] for v in kb["vulnerabilities"]}
added, updated = [], []
for entry in new_entries:
    if entry.get("id") in existing_ids:
        # Update: merge new payloads/refs/triggers (no overwrite)
        for v in kb["vulnerabilities"]:
            if v["id"] == entry["id"]:
                for key in ["trigger_params", "trigger_paths", "trigger_techs", "payloads", "references", "h1_top_reports"]:
                    if key in entry:
                        existing = set(v.get(key, []))
                        new = [x for x in entry[key] if x not in existing]
                        v.setdefault(key, []).extend(new)
                updated.append(entry["id"])
    else:
        kb["vulnerabilities"].append(entry)
        added.append(entry["id"])
import datetime
kb["_meta"]["last_updated"] = datetime.date.today().isoformat()
kb["_meta"]["total_patterns"] = len(kb["vulnerabilities"])
ver = kb["_meta"].get("version", "1.0")
parts = ver.split(".")
kb["_meta"]["version"] = f"{parts[0]}.{int(parts[1])+1}"
import shutil
shutil.copy("$KB_PATH", "$KB_PATH.bak.json")
with open("$KB_PATH", "w") as f:
    json.dump(kb, f, indent=2, ensure_ascii=False)
print(f"KB: +{len(added)} nuevas ({', '.join(added) or 'none'}), ~{len(updated)} actualizadas ({', '.join(updated) or 'none'})")
PYEOF
    fi
  fi

  # Merge CVEs
  if [[ "$MODE" == "--merge" || "$MODE" == "--merge-cves" ]]; then
    if [[ ! -s "$CVE_STAGING" ]]; then
      echo "[!] No hay $CVE_STAGING — corre research primero"
    else
      python3 - <<PYEOF
import json
cve = json.load(open("$CVE_PATH"))
new_cves = json.load(open("$CVE_STAGING"))
existing = {c["cve"] for c in cve}
added = []
for c in new_cves:
    if c.get("cve") not in existing:
        cve.append(c)
        added.append(c["cve"])
with open("$CVE_PATH", "w") as f:
    json.dump(cve, f, indent=2, ensure_ascii=False)
print(f"CVE catalog: +{len(added)} nuevos ({', '.join(added[:10])})")
PYEOF
    fi
  fi
  exit 0
fi

# ── Modo research: invocar Claude con WebSearch ─────────────
PROMPT_FILE=$(mktemp /tmp/kb_research_prompt.XXXXXX)
cat > "$PROMPT_FILE" <<EOF
# Investigación KB Hackeadora — últimos ${DAYS} días

Eres un security researcher experto en bug bounty y pentest. Tu tarea es investigar
las novedades de los últimos ${DAYS} días en cualquier fuente relevante y devolver
JSON formateable para enriquecer la knowledge base de Hackeadora.

## Fuentes a explorar (NO te limites a estas)
- PortSwigger Research blog (https://portswigger.net/research)
- HackerOne disclosed reports recientes
- BlackHat / DEF CON / BSidesLV nuevos talks/papers
- Twitter/X security research accounts (@SamWCyo, @intigriti, @Rhynorater, etc.)
- GitHub Advisory Database (cualquier CVE 2024-2025 importante reciente)
- Reddit r/netsec / r/bugbounty top posts del mes
- Security blogs de empresas (Trail of Bits, Doyensec, Assetnote, NCC Group)
- SecurityWeek, The Hacker News, BleepingComputer (filtrar a research técnico)
- arXiv eprints (cs.CR security research)
- Cualquier writeup de bounty notable (\$5k+) publicado el último mes
- Nuevos exploits 1-day en Hacktivity / Twitter
${EXTRA_FOCUS:+
## Foco adicional solicitado
$EXTRA_FOCUS
}

## Lo que necesito

### 1. Nuevas vulnerabilidades / técnicas (KB entries)
Para cada técnica nueva o actualización significativa, generar entry JSON:

\`\`\`json
{
  "id": "ID_UNICO_UPPER",
  "name": "Nombre descriptivo de la técnica",
  "h1_frequency": "very_high|high|medium|low",
  "h1_avg_bounty_usd": 3500,
  "h1_top_reports": [
    "Sample report description ($bounty)",
    "..."
  ],
  "trigger_paths": ["/path1", "/path2"],
  "trigger_params": ["param1", "param2"],
  "trigger_techs": ["Tech1", "Tech2"],
  "trigger_response_hints": ["regex marker", "..."],
  "payloads": ["payload string 1", "..."],
  "nuclei_tags": ["tag1", "tag2"],
  "references": ["https://...", "..."],
  "severity": "critical|high|medium|low",
  "discovered_date": "2026-XX-XX",
  "source": "URL principal del research"
}
\`\`\`

### 2. CVEs nuevos críticos (catalog entries)
Para cada CVE 2024-2025 high/critical de tech común, generar entry:

\`\`\`json
{
  "cve": "CVE-2025-XXXXX",
  "cve_family": "tech-slug",
  "tech_match": "Tech Name (matches tech_registry)",
  "versions_affected": "X.Y.Z-A.B.C,..." or "<X.Y.Z" or "*",
  "severity": "critical|high|medium",
  "title": "Short title",
  "description": "Description corta",
  "poc": "PoC payload",
  "ref": "https://nvd.nist.gov/vuln/detail/CVE-XXXX"
}
\`\`\`

## Criterios de calidad

- **NO incluir** ataques mobile-only, OS-level (Linux kernel, Windows), o hardware
- **SÍ incluir** todo lo web/API/cloud/infra que se pueda automatizar en pipeline
- **Confirma fechas**: solo cosas REALES de los últimos ${DAYS} días
- **Verifica versions_affected** consultando NVD si no está claro
- **Skipea duplicados** con lo que ya está en core/knowledge_base.json y core/cve_catalog.json (puedes leerlos para verificar)

## Output

Escribe los resultados a 2 archivos:
- \`data/kb_research_staging.json\` — array JSON de nuevas KB entries
- \`data/cve_research_staging.json\` — array JSON de nuevos CVEs

NO mergees nada al KB ni al CVE catalog. El usuario revisará el staging primero.

Si no encuentras nada digno tras búsqueda exhaustiva, escribe arrays vacíos \`[]\`.

## Tarea

Empieza investigando ahora. Usa WebSearch + WebFetch para acceder a las fuentes.
Sé honesto: si una técnica no es claramente nueva o no aplica a pipeline web/API
automatizado, NO la incluyas. Calidad > cantidad. Apunta a 5-15 entries útiles.
EOF

echo "═══════════════════════════════════════════════════════"
echo "  kb_research.sh — investigando últimos ${DAYS} días"
echo "  Usando: claude -p con WebSearch + WebFetch"
echo "  Output staging: data/kb_research_staging.json"
echo "                  data/cve_research_staging.json"
echo "  ⏱  Esto puede tardar 5-15 minutos (research profundo)"
echo "═══════════════════════════════════════════════════════"

# Limpiar staging anterior
> "$KB_STAGING"
> "$CVE_STAGING"

# Spawn claude con tools necesarios. Permitir Read/Write porque debe leer KB
# existente para deduplicar y escribir staging files.
CLAUDE_CMD="${CLAUDE_CMD:-claude}"
$CLAUDE_CMD -p "$(cat "$PROMPT_FILE")" \
  --allowed-tools "WebSearch,WebFetch,Read,Write,Bash" \
  2>&1 | tee /tmp/kb_research_session.log

rm -f "$PROMPT_FILE"

echo
echo "═══════════════════════════════════════════════════════"
KB_COUNT=$(jq 'length' "$KB_STAGING" 2>/dev/null || echo 0)
CVE_COUNT=$(jq 'length' "$CVE_STAGING" 2>/dev/null || echo 0)
echo "  Resultado:"
echo "    KB entries propuestas:   $KB_COUNT  (data/kb_research_staging.json)"
echo "    CVE entries propuestos:  $CVE_COUNT (data/cve_research_staging.json)"
echo
echo "  Review:"
echo "    cat data/kb_research_staging.json | jq '.[].name'"
echo "    cat data/cve_research_staging.json | jq '.[].cve'"
echo
echo "  Merge tras review:"
echo "    ./tools/kb_research.sh --merge       # KB + CVEs"
echo "    ./tools/kb_research.sh --merge-kb    # solo KB"
echo "    ./tools/kb_research.sh --merge-cves  # solo CVEs"
echo "═══════════════════════════════════════════════════════"
