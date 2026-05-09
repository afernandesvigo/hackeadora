#!/usr/bin/env bash
# ============================================================
#  modules/04_nuclei_scan.sh — STUB NEUTRALIZED 2026-05-09
#  Manual override: nuclei is deadweight (Bug #14, see project_module_fp_catalog.md).
#  Original backed up at .04_nuclei_scan.sh.bak_pre_neutralize
# ============================================================
MODULE_NAME="nuclei_scan_stub"
MODULE_DESC="Nuclei scan (NEUTRALIZED — manual skip)"

module_run() {
  log_warn "Módulo 04 nuclei_scan NEUTRALIZADO manualmente — saltando (ver project_module_fp_catalog.md Bug #14)"
  return 0
}
