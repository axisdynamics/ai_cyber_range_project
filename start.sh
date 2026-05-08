#!/usr/bin/env bash
# =============================================================================
# start.sh — AI Cyber Range: Ofensiva Controlada con IA
# =============================================================================
# Launches the full controlled offensive program.
#
# Usage:
#   ./start.sh                          # full cycle (default)
#   ./start.sh --mode offensive_only    # offensive pipeline only
#   ./start.sh --mode defensive_only    # defensive/detection only
#   ./start.sh --config configs/custom.yaml
#   ./start.sh --watch                  # continuous mode (run on change)
#   ./start.sh --help
# =============================================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Defaults ─────────────────────────────────────────────────────────────────
CONFIG="configs/default.yaml"
MODE="full"
WATCH=false
WATCH_INTERVAL=60
WEB=false
WEB_PORT=8080
WEB_ONLY=false

print_banner() {
  echo ""
  echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${RED}${BOLD}║   AI CYBER RANGE — OFENSIVA CONTROLADA CON IA            ║${RESET}"
  echo -e "${RED}${BOLD}║   MITRE ATT&CK · Agentive Red Team · Evidence Engine     ║${RESET}"
  echo -e "${RED}${BOLD}║   Kill Chains · Evasion Tests · PoC Builder · CI/CD Loop ║${RESET}"
  echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════════════╣${RESET}"
  echo -e "${RED}${BOLD}║   Powered by AxisDynamics · https://axisdynamics.cl      ║${RESET}"
  echo -e "${RED}${BOLD}║   MIT License · Copyright © 2026 AxisDynamics            ║${RESET}"
  echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
  echo ""
}

print_help() {
  print_banner
  echo -e "${BOLD}Uso:${RESET}"
  echo "  ./start.sh [opciones]"
  echo ""
  echo -e "${BOLD}Opciones:${RESET}"
  echo "  --config <path>           Archivo de configuración YAML (default: configs/default.yaml)"
  echo "  --mode <mode>             Modo de ejecución: full | offensive_only | defensive_only"
  echo "  --watch                   Modo continuo: re-ejecutar cada ${WATCH_INTERVAL}s si hay cambios"
  echo "  --watch-interval <secs>   Intervalo en modo watch (default: 60)"
  echo "  --help                    Mostrar este mensaje"
  echo ""
  echo -e "${BOLD}Modos:${RESET}"
  echo "  full             Ciclo completo: ofensiva + blue team + remediación + dashboard"
  echo "  offensive_only   Solo ofensiva: hipótesis, cadenas, evasión, PoCs"
  echo "  defensive_only   Solo defensiva: validación de detección y métricas"
  echo ""
  echo -e "${BOLD}Ejemplos:${RESET}"
  echo "  ./start.sh                                  # modo full estándar"
  echo "  ./start.sh --mode offensive_only            # red team agentivo"
  echo "  ./start.sh --watch --watch-interval 120     # CI/CD loop cada 2 min"
  echo "  ./start.sh --config configs/custom.yaml     # configuración personalizada"
  echo ""
}

# ─── Arg parsing ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --config)          CONFIG="$2";         shift 2 ;;
    --mode)            MODE="$2";           shift 2 ;;
    --watch)           WATCH=true;          shift   ;;
    --watch-interval)  WATCH_INTERVAL="$2"; shift 2 ;;
    --web)             WEB=true;              shift   ;;
    --web-only)        WEB=true; WEB_ONLY=true; shift  ;;
    --port)            WEB_PORT="$2";         shift 2 ;;
    --help|-h)         print_help; exit 0           ;;
    *)                 echo -e "${RED}Opción desconocida: $1${RESET}"; print_help; exit 1 ;;
  esac
done

# ─── Pre-flight checks ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
  echo -e "${RED}[✗] Entorno virtual no encontrado. Ejecuta primero: ./install.sh${RESET}"
  exit 1
fi

if [ ! -f "$CONFIG" ]; then
  echo -e "${RED}[✗] Archivo de configuración no encontrado: $CONFIG${RESET}"
  exit 1
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# Ensure required directories exist
mkdir -p artifacts/evidence python_orchestrator/reports

# ─── Single run ───────────────────────────────────────────────────────────────
run_once() {
  local start_ts
  start_ts=$(date +%s)

  print_banner
  echo -e "${CYAN}${BOLD}Configuración:${RESET} $CONFIG"
  echo -e "${CYAN}${BOLD}Modo:${RESET}          $MODE"
  echo -e "${CYAN}${BOLD}Timestamp:${RESET}     $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""

  PYTHONPATH="$SCRIPT_DIR" python3 -m python_orchestrator.main \
    --config "$CONFIG" \
    --mode   "$MODE"

  local end_ts
  end_ts=$(date +%s)
  local elapsed=$(( end_ts - start_ts ))

  echo ""
  echo -e "${GREEN}${BOLD}[✓] Run completado en ${elapsed}s${RESET}"
  echo -e "${DIM}    Reporte: python_orchestrator/reports/latest_report.md${RESET}"
  echo -e "${DIM}    JSON:    python_orchestrator/reports/latest_report.json${RESET}"
  echo -e "${DIM}    Evidencia: artifacts/evidence/${RESET}"
}

# ─── Continuous / watch mode ──────────────────────────────────────────────────
# ─── Web dashboard launcher ──────────────────────────────────────────────────
start_web() {
  echo -e "${CYAN}${BOLD}[►] Iniciando dashboard web en http://localhost:${WEB_PORT}${RESET}"
  # Check if uvicorn is available
  if ! python3 -c "import uvicorn" &>/dev/null; then
    echo -e "${YELLOW}[!] uvicorn no instalado. Instalando...${RESET}"
    pip install fastapi uvicorn[standard] --quiet
  fi
  echo -e "${GREEN}[✓] Dashboard disponible en: ${CYAN}http://localhost:${WEB_PORT}${RESET}"
  echo -e "${DIM}    Fallback HTML: web/frontend/dashboard_standalone.html${RESET}"
  echo -e "${DIM}    Ctrl+C para detener${RESET}"
  echo ""
  PYTHONPATH="$SCRIPT_DIR" uvicorn web.api.main:app \
    --host 0.0.0.0 \
    --port "$WEB_PORT" \
    --reload \
    --log-level info
}

if [ "$WEB" = true ] && [ "$WEB_ONLY" = true ]; then
  print_banner
  start_web
elif [ "$WEB" = true ]; then
  # Run pipeline first, then launch web server
  if [ "$WATCH" = true ]; then
    echo -e "${YELLOW}${BOLD}[►] Modo continuo + web activado${RESET}"
    # Run once first, then start web in background, then continue watching
    run_once || true
    start_web &
    WEB_PID=$!
    trap "kill $WEB_PID 2>/dev/null; exit 0" INT TERM
    RUN_COUNT=1
    while true; do
      RUN_COUNT=$(( RUN_COUNT + 1 ))
      echo -e "${YELLOW}── Run #${RUN_COUNT} ────────────────────────────────────────────────${RESET}"
      run_once || echo -e "${RED}[!] Run #${RUN_COUNT} falló — reintentando en ${WATCH_INTERVAL}s${RESET}"
      sleep "$WATCH_INTERVAL"
    done
  else
    run_once
    echo ""
    start_web
  fi
elif [ "$WATCH" = true ]; then
  echo -e "${YELLOW}${BOLD}[►] Modo continuo activado (intervalo: ${WATCH_INTERVAL}s)${RESET}"
  echo -e "${DIM}    Ctrl+C para detener${RESET}"
  echo ""
  RUN_COUNT=0
  while true; do
    RUN_COUNT=$(( RUN_COUNT + 1 ))
    echo -e "${YELLOW}── Run #${RUN_COUNT} ────────────────────────────────────────────────${RESET}"
    run_once || echo -e "${RED}[!] Run #${RUN_COUNT} falló — reintentando en ${WATCH_INTERVAL}s${RESET}"
    echo ""
    echo -e "${DIM}Próximo run en ${WATCH_INTERVAL}s... (Ctrl+C para salir)${RESET}"
    sleep "$WATCH_INTERVAL"
  done
else
  run_once
fi
