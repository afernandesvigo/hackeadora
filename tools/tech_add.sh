#!/usr/bin/env bash
# tools/tech_add.sh — añadir nueva tech al registry custom tras un análisis.
#
# Uso:
#   ./tools/tech_add.sh "Tech Name" CATEGORY HEADER_RE BODY_RE [URL_PROBE,URL_PROBE2] [STATUS_OK]
#
# Ej:
#   ./tools/tech_add.sh "Acme CMS" cms '^X-Acme-Version:' 'powered by Acme' '/acme/admin' '200,302'
#   ./tools/tech_add.sh "Sprinklr Modern Care" support '' 'sprinklr-modern-care' '' ''
#
# El registry custom se carga con prioridad sobre el built-in. Para overridear
# una entry existente, reusa el mismo "name".
#
# Categorías comunes: cms, ecommerce, webserver, appserver, framework, sso,
# devops, cloud, cdn, api, admin, analytics, payment, marketing, support, waf, auth

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CUSTOM="$SCRIPT_DIR/data/tech_registry_custom.json"

if [[ $# -lt 4 ]]; then
  cat <<USAGE
Uso: $0 "Tech Name" CATEGORY HEADER_RE BODY_RE [URL_PROBES_CSV] [STATUS_OK]

Ejemplos:
  $0 "Acme CMS" cms '^X-Acme-Version:' 'powered by Acme' '/acme/admin' '200,302'
  $0 "Sprinklr Modern Care" support '' 'sprinklr-modern-care' '' ''

Categorías: cms ecommerce webserver appserver framework sso devops cloud cdn api admin analytics payment marketing support waf auth

Lista actual del registry custom:
USAGE
  jq -r '.[] | "  - \(.name) (\(.category))"' "$CUSTOM" 2>/dev/null
  exit 0
fi

NAME="$1"
CATEGORY="$2"
HEADER_RE="$3"
BODY_RE="$4"
URL_PROBES_CSV="${5:-}"
STATUS_OK="${6:-}"

# Convertir URL_PROBES_CSV a JSON array
URL_PROBES_JSON="[]"
if [[ -n "$URL_PROBES_CSV" ]]; then
  URL_PROBES_JSON=$(echo "$URL_PROBES_CSV" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
fi

# Construir entry
NEW_ENTRY=$(jq -n \
  --arg name "$NAME" \
  --arg category "$CATEGORY" \
  --arg header_re "$HEADER_RE" \
  --arg body_re "$BODY_RE" \
  --argjson url_probes "$URL_PROBES_JSON" \
  --arg url_status_ok "$STATUS_OK" \
  --arg cve_family "$(echo "$NAME" | tr '[:upper:] ' '[:lower:]-' | sed 's/[^a-z0-9-]//g')" \
  '{
    name: $name,
    category: $category,
    header_re: $header_re,
    body_re: $body_re,
    url_probes: $url_probes,
    url_status_ok: $url_status_ok,
    cve_family: $cve_family
  }')

# Si ya existe entry con mismo name, reemplazar; si no, append
if jq -e --arg name "$NAME" '.[] | select(.name == $name)' "$CUSTOM" >/dev/null 2>&1; then
  jq --argjson new "$NEW_ENTRY" --arg name "$NAME" \
    'map(if .name == $name then $new else . end)' "$CUSTOM" > "$CUSTOM.tmp"
  mv "$CUSTOM.tmp" "$CUSTOM"
  echo "✓ Actualizada entry '$NAME' en $CUSTOM"
else
  jq --argjson new "$NEW_ENTRY" '. + [$new]' "$CUSTOM" > "$CUSTOM.tmp"
  mv "$CUSTOM.tmp" "$CUSTOM"
  echo "✓ Añadida entry '$NAME' a $CUSTOM"
fi

echo ""
echo "Test:"
echo "  python3 core/tech_detector.py --probe-host https://target.com"
