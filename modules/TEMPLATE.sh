#!/usr/bin/env bash
# ============================================================
#  modules/TEMPLATE.sh
#  Plantilla para nuevos módulos de ReconFlow
# ============================================================
#
#  CÓMO CREAR UN NUEVO MÓDULO:
#
#  1. Copia este archivo: cp TEMPLATE.sh 08_mi_modulo.sh
#  2. Rellena MODULE_NAME y MODULE_DESC
#  3. Implementa la función module_run()
#  4. Regístralo en recon.sh en la sección PIPELINE
#
#  CONTRATO DE LA FUNCIÓN module_run():
#    Argumentos:
#      $1 → DOMAIN     (dominio raíz, ej: ejemplo.com)
#      $2 → DOMAIN_ID  (id en SQLite)
#      $3 → OUT_DIR    (directorio de output para este dominio/fecha)
#
#    Convenciones:
#      - Usa log_phase / log_info / log_warn / log_ok para logging
#      - Usa notify_* para enviar alertas a Telegram
#      - Usa db_* para interactuar con la base de datos
#      - Usa las variables de config.env (THREADS, TIMEOUT, etc.)
#      - Archivos temporales: prefija con punto (.) o usa mktemp
#      - Limpia temporales al salir (trap o rm explícito)
#      - No hagas exit; usa return para salir del módulo
#
#    Archivos comunes disponibles en OUT_DIR:
#      subs_raw.txt     → todos los subdominios encontrados
#      subs_alive.txt   → subdominios que resuelven HTTP
#      subs_dead.txt    → subdominios sin respuesta HTTP
#      subs_httpx.json  → metadata completa de httpx
#      urls_raw.txt     → todas las URLs descubiertas
#      urls_new.txt     → URLs nuevas (no estaban en DB)
# ============================================================

MODULE_NAME="mi_modulo"
MODULE_DESC="Descripción de lo que hace este módulo"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo XX — $MODULE_DESC: $DOMAIN"

  # ── Verificar herramientas necesarias ──────────────────────
  if ! command -v mi_herramienta &>/dev/null; then
    log_warn "mi_herramienta no encontrada, saltando módulo"
    return
  fi

  # ── Lógica principal ───────────────────────────────────────
  local OUT="$OUT_DIR/mi_modulo_results.txt"
  > "$OUT"

  log_info "Ejecutando tarea principal..."

  # Ejemplo: leer subdominios alive y procesar
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue

      # ... hacer algo con $SUB ...

      # Si encuentras algo importante, notifica y guarda en DB
      # notify_nuclei_finding "$DOMAIN" "template-id" "high" "$SUB" "Detalle"
      # db_add_finding "$DOMAIN_ID" "tipo" "high" "$SUB" "template" "detalle"

    done < "$OUT_DIR/subs_alive.txt"
  fi

  # ── Resumen ────────────────────────────────────────────────
  local COUNT
  COUNT=$(wc -l < "$OUT" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $COUNT resultados"
}
