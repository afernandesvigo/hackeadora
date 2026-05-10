#!/usr/bin/env bash
# tools/tech_review.sh — agrupa tech_suggestions.txt y propone tech_add.sh.
#
# Uso:
#   ./tools/tech_review.sh output/<dominio>/<ts>/tech_suggestions.txt
#
# Lee el archivo de sugerencias generado por mod 10 (Capa C registry) y emite,
# por cada marker desconocido:
#   - el marker
#   - sample de hosts donde apareció
#   - comando tech_add.sh listo para copiar+pegar (con placeholders donde haga falta)
#
# El usuario revisa, decide si añadir, edita el placeholder si toca y lo ejecuta.
# El próximo scan ya detecta esa tech.

set -e
SUGG_FILE="${1:-}"

if [[ -z "$SUGG_FILE" || ! -f "$SUGG_FILE" ]]; then
  echo "Uso: $0 <ruta_a_tech_suggestions.txt>"
  echo
  echo "Sugerencias disponibles en scans recientes:"
  find output -maxdepth 3 -name "tech_suggestions.txt" -size +0 2>/dev/null | sort | tail -10
  exit 1
fi

if [[ ! -s "$SUGG_FILE" ]]; then
  echo "Sin sugerencias en $SUGG_FILE"
  exit 0
fi

TOTAL_RAW=$(wc -l < "$SUGG_FILE" | tr -d ' ')
TOTAL_UNIQUE=$(sort -u "$SUGG_FILE" | wc -l | tr -d ' ')
echo "═══════════════════════════════════════════════════════════════"
echo "  Tech Registry Review — $SUGG_FILE"
echo "  Total raw: $TOTAL_RAW | únicos: $TOTAL_UNIQUE"
echo "═══════════════════════════════════════════════════════════════"

# Format del archivo: HOST|MARKER (uno por línea)
# Agrupar por MARKER, contar hits, listar hosts sample, proponer tech_add.sh

awk -F'|' 'NF>=2 {print $2}' "$SUGG_FILE" | sort | uniq -c | sort -rn | while IFS= read -r LINE; do
  COUNT=$(echo "$LINE" | awk '{print $1}')
  MARKER=$(echo "$LINE" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')
  [[ -z "$MARKER" ]] && continue

  HOSTS=$(awk -F'|' -v m="$MARKER" 'NF>=2 && $2==m {print $1}' "$SUGG_FILE" | sort -u | head -3 | paste -sd ', ')

  echo
  echo "── ${MARKER}  (hits: ${COUNT})"
  echo "   hosts: ${HOSTS}"

  case "$MARKER" in
    "unknown_server: "*)
      VAL="${MARKER#unknown_server: }"
      NAME="${VAL%% *}"
      echo "   → ./tools/tech_add.sh \"${NAME}\" webserver '^Server:\\s*${NAME}' '' '' ''"
      ;;
    "unknown_x_powered_by: "*)
      VAL="${MARKER#unknown_x_powered_by: }"
      NAME="${VAL%% *}"
      echo "   → ./tools/tech_add.sh \"${NAME}\" framework '^X-Powered-By:.*${NAME}' '' '' ''"
      ;;
    "unknown_custom_header: "*)
      VAL="${MARKER#unknown_custom_header: }"
      echo "   → ./tools/tech_add.sh \"<TBD>\" <category> '^${VAL}:' '' '' ''"
      ;;
    "unknown_generator: "*)
      VAL="${MARKER#unknown_generator: }"
      NAME="${VAL%% *}"
      echo "   → ./tools/tech_add.sh \"${NAME}\" cms '' '<meta name=\"generator\" content=\"${NAME}' '' ''"
      ;;
    *)
      echo "   → marker no reconocido — añadir manualmente con tech_add.sh"
      ;;
  esac
done

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  Categorías comunes: cms ecommerce webserver appserver framework"
echo "                       sso devops cloud cdn api admin analytics"
echo "                       payment marketing support waf auth"
echo "═══════════════════════════════════════════════════════════════"
