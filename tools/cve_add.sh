#!/usr/bin/env bash
# tools/cve_add.sh — añadir nueva CVE al catálogo custom.
#
# Uso:
#   ./tools/cve_add.sh CVE-XXXX-NNNNN tech_match severity "title" \
#                      "versions_affected" "description" "poc" "ref"
#
# Ej:
#   ./tools/cve_add.sh CVE-2024-99999 "Apache Tomcat" critical \
#     "Tomcat new RCE" "9.0.0-9.0.99" \
#     "Description here" "PoC payload here" "https://nvd.nist.gov/vuln/detail/CVE-2024-99999"
#
# El catálogo custom (data/cve_catalog_custom.json) tiene prioridad sobre el built-in.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CUSTOM="$SCRIPT_DIR/data/cve_catalog_custom.json"

if [[ $# -lt 4 ]]; then
  cat <<USAGE
Uso: $0 CVE-XXXX-NNNNN tech_match severity "title" \\
        "versions_affected" "description" "poc" "ref"

Ejemplos:
  $0 CVE-2024-99999 "Apache Tomcat" critical "Title" "9.0.0-9.0.99" "Desc" "PoC" "URL"
  $0 CVE-2024-12345 "Wordpress" high "XSS in comments" "*" "Desc" "PoC" ""

Severities: critical | high | medium | low | info
Versions formato: "9.0.0-9.0.98,10.0.0-10.1.34" o "<6.4.4" o ">=2.0.0" o "*"

Catálogo custom actual:
USAGE
  jq -r '.[] | "  - \(.cve) (\(.tech_match) — \(.severity))"' "$CUSTOM" 2>/dev/null
  exit 0
fi

CVE="$1"
TECH_MATCH="$2"
SEVERITY="$3"
TITLE="$4"
VERSIONS="${5:-*}"
DESCRIPTION="${6:-}"
POC="${7:-}"
REF="${8:-}"

# Validar CVE format
[[ "$CVE" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || {
  echo "Error: CVE id formato inválido. Usa CVE-YYYY-NNNNN"
  exit 1
}

# Validar severity
case "$SEVERITY" in
  critical|high|medium|low|info) ;;
  *) echo "Error: severity debe ser critical|high|medium|low|info"; exit 1 ;;
esac

# Auto-detect cve_family desde tech_match (lowercase, primer word útil)
CVE_FAMILY=$(echo "$TECH_MATCH" | tr '[:upper:] ' '[:lower:]-' | sed 's/[^a-z0-9-]//g' | head -c 40)

NEW_ENTRY=$(jq -n \
  --arg cve "$CVE" \
  --arg fam "$CVE_FAMILY" \
  --arg tm "$TECH_MATCH" \
  --arg va "$VERSIONS" \
  --arg sev "$SEVERITY" \
  --arg t "$TITLE" \
  --arg d "$DESCRIPTION" \
  --arg p "$POC" \
  --arg r "$REF" \
  '{
    cve: $cve,
    cve_family: $fam,
    tech_match: $tm,
    versions_affected: $va,
    severity: $sev,
    title: $t,
    description: $d,
    poc: $p,
    ref: $r
  }')

# Si ya existe CVE con mismo id, reemplazar; si no, append
if jq -e --arg cve "$CVE" '.[] | select(.cve == $cve)' "$CUSTOM" >/dev/null 2>&1; then
  jq --argjson new "$NEW_ENTRY" --arg cve "$CVE" \
    'map(if .cve == $cve then $new else . end)' "$CUSTOM" > "$CUSTOM.tmp"
  mv "$CUSTOM.tmp" "$CUSTOM"
  echo "✓ Actualizada entry $CVE en $CUSTOM"
else
  jq --argjson new "$NEW_ENTRY" '. + [$new]' "$CUSTOM" > "$CUSTOM.tmp"
  mv "$CUSTOM.tmp" "$CUSTOM"
  echo "✓ Añadida entry $CVE a $CUSTOM"
fi

echo
echo "Test inmediato:"
echo "  python3 core/cve_matcher.py --tech \"$TECH_MATCH\" --version \"<test_version>\""
