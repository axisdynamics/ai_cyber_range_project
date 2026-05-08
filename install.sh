#!/usr/bin/env bash
# =============================================================================
# install.sh — AI Cyber Range: Ofensiva Controlada con IA
# =============================================================================
# Sets up the Python virtual environment, installs dependencies, and
# optionally builds the C lab service and Rust evidence validator.
#
# Usage:
#   chmod +x install.sh && ./install.sh
#   ./install.sh --skip-c       # skip C service build
#   ./install.sh --skip-rust    # skip Rust validator build
#   ./install.sh --full         # build everything (default)
# =============================================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

SKIP_C=false
SKIP_RUST=false
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

for arg in "$@"; do
  case $arg in
    --skip-c)    SKIP_C=true ;;
    --skip-rust) SKIP_RUST=true ;;
    --full)      SKIP_C=false; SKIP_RUST=false ;;
  esac
done

print_step() { echo -e "${CYAN}${BOLD}[►] $1${RESET}"; }
print_ok()   { echo -e "${GREEN}[✓] $1${RESET}"; }
print_warn() { echo -e "${YELLOW}[!] $1${RESET}"; }
print_err()  { echo -e "${RED}[✗] $1${RESET}"; }

echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║   AI CYBER RANGE — OFENSIVA CONTROLADA CON IA            ║${RESET}"
echo -e "${RED}${BOLD}║   MITRE ATT&CK · Agentive Red Team · Evidence Engine     ║${RESET}"
echo -e "${RED}${BOLD}╠══════════════════════════════════════════════════════════╣${RESET}"
echo -e "${RED}${BOLD}║   Powered by AxisDynamics · https://axisdynamics.cl      ║${RESET}"
echo -e "${RED}${BOLD}║   MIT License · Copyright © 2026 AxisDynamics            ║${RESET}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Python version check ──────────────────────────────────────────────────────
print_step "Verificando Python >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}"

PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" &>/dev/null; then
    VERSION=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    MAJOR=$(echo "$VERSION" | cut -d. -f1)
    MINOR=$(echo "$VERSION" | cut -d. -f2)
    if [ "$MAJOR" -ge "$PYTHON_MIN_MAJOR" ] && [ "$MINOR" -ge "$PYTHON_MIN_MINOR" ]; then
      PYTHON_BIN="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  print_err "Python >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} no encontrado."
  echo "  Instala Python desde https://python.org/downloads"
  exit 1
fi
print_ok "Python encontrado: $($PYTHON_BIN --version)"

# ─── Virtual environment ───────────────────────────────────────────────────────
VENV_DIR=".venv"
print_step "Creando entorno virtual en '.venv/'"

if [ -d "$VENV_DIR" ]; then
  print_warn "Entorno virtual existente encontrado — reutilizando."
else
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  print_ok "Entorno virtual creado."
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
print_ok "Entorno virtual activado: $VIRTUAL_ENV"

# ─── Python dependencies ───────────────────────────────────────────────────────
print_step "Instalando dependencias Python"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
print_ok "Dependencias instaladas."

# ─── Create required directories ──────────────────────────────────────────────
print_step "Creando directorios de trabajo"
mkdir -p artifacts/evidence
mkdir -p python_orchestrator/reports
print_ok "Directorios listos."

# ─── C lab service (DEPRECATED — migrado a Rust) ─────────────────────────────
if [ "$SKIP_C" = false ]; then
  print_warn "C lab service deprecado — usando Rust lab_service en su lugar."
  print_warn "Si necesitas el binario C por compatibilidad: make -C c_service"
fi

# ─── Rust binaries (lab_service + evidence_validator) ─────────────────────────
if [ "$SKIP_RUST" = false ]; then
  print_step "Compilando binarios Rust (lab_service + evidence_validator)"
  if command -v cargo &>/dev/null; then
    # Build both binaries from the same crate
    if cargo build --release --manifest-path rust_validator/Cargo.toml 2>/tmp/rust_build_err; then
      print_ok "lab_service compilado: rust_validator/target/release/lab_service"
      print_ok "evidence_validator compilado: rust_validator/target/release/evidence_validator"

      # Selftest the lab service
      if rust_validator/target/release/lab_service selftest >/dev/null 2>&1; then
        print_ok "lab_service selftest OK (15/15 pruebas)."
      else
        print_warn "lab_service selftest falló — verificar compilación."
      fi
    else
      print_warn "Rust compilation failed. Ver /tmp/rust_build_err"
      cat /tmp/rust_build_err >&2 || true
      print_warn "Escenarios usarán modo sintético Python automáticamente."
    fi
  else
    print_warn "cargo no encontrado."
    print_warn "  macOS: brew install rust"
    print_warn "  Linux: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    print_warn "  Escenarios usarán modo sintético Python automáticamente."
  fi
else
  print_warn "Rust saltado (--skip-rust)."
fi


# ─── Harness verification ──────────────────────────────────────────────────────
print_step "Verificando arnés (harness integrity)"

# C1: Required files
HARNESS_OK=true
for f in AGENTS.md CLAUDE.md CHECKPOINTS.md engagement_backlog.json progress/current.md; do
  if [ ! -f "$f" ]; then
    print_warn "Harness: archivo faltante: $f"
    HARNESS_OK=false
  fi
done

for d in .claude/agents; do
  if [ ! -d "$d" ]; then
    print_warn "Harness: directorio faltante: $d"
    HARNESS_OK=false
  fi
done

# C2: Single in_progress rule
IN_PROGRESS_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('engagement_backlog.json'))
    count = sum(1 for s in d.get('scenarios',[]) if s.get('status')=='in_progress')
    print(count)
except Exception as e:
    print(0)
" 2>/dev/null || echo 0)

if [ "$IN_PROGRESS_COUNT" -gt "1" ]; then
  print_err "Harness C2 FAIL: $IN_PROGRESS_COUNT escenarios en in_progress (máximo: 1)"
  print_err "  Revisa engagement_backlog.json y corrige antes de continuar"
  HARNESS_OK=false
fi

# C3: Sovereign config
if grep -q "allow_external_targets: true" configs/default.yaml 2>/dev/null; then
  print_err "Harness C3 FAIL: allow_external_targets: true en configs/default.yaml"
  HARNESS_OK=false
fi

# Python harness smoke test
if python3 -c "
import sys; sys.path.insert(0,'.')
from python_orchestrator.harness.session_manager import SessionManager
sm = SessionManager()
errors = sm.verify_harness()
if errors:
    for e in errors: print(f'  Harness: {e}')
    sys.exit(1)
" 2>/dev/null; then
  print_ok "Harness Python (SessionManager) OK."
else
  print_warn "Harness Python check con advertencias — revisa engagement_backlog.json"
fi

if [ "$HARNESS_OK" = true ]; then
  print_ok "Arnés completo y coherente."
else
  print_warn "Arnés tiene warnings — el range puede ejecutarse pero revisa los errores."
fi

# ─── Web API dependencies ─────────────────────────────────────────────────────
print_step "Instalando dependencias web (FastAPI + uvicorn)"
if pip install -r web/api/requirements.txt --quiet 2>/dev/null; then
  print_ok "FastAPI + uvicorn instalados."
else
  print_warn "No se pudieron instalar dependencias web. Ejecuta manualmente: pip install fastapi uvicorn[standard]"
fi

# ─── Frontend build (optional, requires npm) ──────────────────────────────────
print_step "Verificando frontend React (Vite)"
if command -v npm &>/dev/null; then
  print_ok "npm encontrado: $(npm --version)"
  cd web/frontend

  # Siempre limpiar dist/ y reconstruir con los fuentes correctos del ZIP
  rm -rf dist/
  print_step "Instalando dependencias npm..."
  npm install --quiet 2>/dev/null || npm install
  print_ok "Dependencias instaladas."

  print_step "Compilando frontend React (Vite)..."
  if npm run build; then
    # Verificar que las páginas compilaron correctamente (no stubs)
    CHAINS_SIZE=$(wc -c < dist/assets/Chains-*.js 2>/dev/null | tr -d ' ' || echo 0)
    if [ "${CHAINS_SIZE:-0}" -gt 2000 ]; then
      print_ok "Frontend compilado correctamente (páginas completas: ${CHAINS_SIZE} bytes)."
    else
      print_err "Build produjo páginas incompletas (${CHAINS_SIZE} bytes). Algo falló."
      print_err "Verifica que los archivos src/pages/*.jsx no estén corruptos."
      ls -la dist/assets/*.js 2>/dev/null | head -10
    fi
  else
    print_err "npm run build falló."
  fi
  cd "$SCRIPT_DIR"
else
  print_warn "npm no encontrado — instala Node.js desde https://nodejs.org"
  print_warn "Luego: cd web/frontend && npm install && npm run build"
fi

# ─── Installation summary ──────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   INSTALACIÓN COMPLETA                                   ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Próximo paso:${RESET}"
echo -e "    ${CYAN}./start.sh${RESET}           — ejecutar con modo full (ofensiva + defensiva)"
echo -e "    ${CYAN}./start.sh --mode offensive_only${RESET}  — solo ofensiva"
echo -e "    ${CYAN}./start.sh --help${RESET}    — ver todas las opciones"
echo ""
echo -e "  ${CYAN}./start.sh --web${RESET}                  — pipeline + dashboard (http://localhost:8080)"
echo -e "  ${BOLD}Dashboard directo (sin build):${RESET} abrir ${CYAN}web/frontend/dashboard_standalone.html${RESET}"
echo ""
