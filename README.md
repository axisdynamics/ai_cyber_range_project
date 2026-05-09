# AI Cyber Range

> **Powered by [AxisDynamics](https://axisdynamics.cl)** · Licencia MIT

Validación defensiva segura y simulación purple-team.  
Simula kill chains autorizados sobre fixtures locales, valida cobertura de detección
con motores determinísticos + razonamiento IA, genera evidencia verificable con SHA-256
y mantiene un backlog de remediación priorizado por riesgo real.

**Lo que no hace:** no explota targets reales, no ejecuta malware, no tiene
movimiento lateral real, no se conecta a infraestructura externa.
Operable sin conexión a internet.

---

## Inicio rápido

```bash
# 1. Instalar
bash install.sh

# 2. Activar entorno Python
source .venv/bin/activate

# 3. Instalar paquete cyber-range
pip install -e .

# 4. Validar configuración
cyber-range validate-config --config examples/local.yaml

# 5. Ejecutar
cyber-range run
```

Dashboard web:

```bash
./start.sh --web        # pipeline + http://localhost:8080
cyber-range serve-api   # solo API + dashboard
```

---

## CLI — Referencia completa

### `run` — Simulación

```bash
cyber-range run                              # pipeline estándar
cyber-range run --config examples/local.yaml
cyber-range run --mode agent                 # Hermes: 9 agentes paralelos
cyber-range run --mode agent --config examples/local.yaml
cyber-range run --dry-run                    # planifica sin ejecutar
```

### `validate-config` — Configuración

```bash
cyber-range validate-config                  # valida configs/default.yaml
cyber-range validate-config --config f.yaml  # exit 0 OK · exit 1 inválido · exit 2 no existe
cyber-range validate-config --config f.yaml --verbose
```

### `verify-evidence` — Evidencia

```bash
cyber-range verify-evidence                  # verifica artifacts/evidence/
cyber-range verify-evidence --run-id RUN-X   # run específico
# exit 1 si hay evidencia alterada o faltante
```

### `generate-report` — Reportes

```bash
cyber-range generate-report                  # último run → report.md + report.json
cyber-range generate-report --run-id RUN-X
cyber-range generate-report --output-dir ./out/
```

### `serve-api` — API + Dashboard

```bash
cyber-range serve-api                        # http://127.0.0.1:8080
cyber-range serve-api --port 9090
cyber-range serve-api --api-key mysecretkey  # habilita auth X-API-Key
# o variable de entorno: CYBER_RANGE_API_KEY=... cyber-range serve-api
```

### `status` — Estado del sistema

```bash
cyber-range status   # último run · memoria Hermes · gaps persistentes
```

### `memory` — Memoria cross-run (Hermes)

```bash
cyber-range memory show                      # historial + aprendizaje por técnica
cyber-range memory gaps                      # todos los gaps de detección
cyber-range memory gaps --min-occurrences 2  # solo persistentes (≥2 runs)
cyber-range memory clear                     # resetea memoria (con confirmación)
```

---

## Arquitectura en 6 capas

```
┌──────────────────────────────────────────────────────────────────────┐
│  C1 · HARNESS                                                        │
│  CLAUDE.md · AGENTS.md · CHECKPOINTS.md                             │
│  engagement_backlog.json · .claude/agents/                           │
├──────────────────────────────────────────────────────────────────────┤
│  C2 · src/cyber_range/ (paquete Python productivo v0.2.0-beta)       │
│  cli/ · config/ · policy/ · pipeline/ · scoring/                    │
│  evidence/ · reporting/ · logging/ · api/                           │
├──────────────────────────────────────────────────────────────────────┤
│  C3 · HERMES MULTI-AGENTE                                            │
│  HermesOrchestrator → 9 agentes paralelos → AgentMemory (SQLite)    │
│  GapAnalysisAgent → prioriza técnicas por historial de evasión       │
├──────────────────────────────────────────────────────────────────────┤
│  C4 · PIPELINE OFENSIVO (python_orchestrator/)                       │
│  Governance → OffensiveHarness → Chains → Evasion → PoC → Evidence  │
├──────────────────────────────────────────────────────────────────────┤
│  C5 · DETECCIÓN HÍBRIDA + RDT                                        │
│  RuleEngine · SigmaCorrelator · IoCMatcher · AnomalyDetector         │
│  HybridDetector → RecurrentDepthReasoner (OpenMythos)                │
├──────────────────────────────────────────────────────────────────────┤
│  C6 · NATIVO + WEB                                                   │
│  Rust: lab_service + evidence_validator · React + FastAPI            │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Modo estándar vs. modo agent (Hermes)

| | `cyber-range run` | `cyber-range run --mode agent` |
|---|---|---|
| Ejecución | Secuencial | 9 agentes paralelos (ThreadPoolExecutor) |
| Memoria | No | SQLite cross-run persistente |
| Priorización | Siempre igual | Gap analysis: foca en técnicas que más evaden |
| Aprendizaje | No | `gap_rate × avg_score` acumulado entre runs |
| Scope / soberanía | PolicyEnforcer | PolicyEnforcer (primera capa siempre) |

---

## Soberanía (no negociable)

```yaml
allow_external_targets: false   # hardcoded — no acepta true en ninguna config
blocked_techniques:             # hardcoded en PolicyEnforcer
  - T1485  # Data Destruction
  - T1561  # Disk Wipe
  - T1529  # System Shutdown/Reboot
```

---

## Desarrollo

```bash
# Instalar con dependencias dev
pip install -e ".[dev,api]"

# Tests (115 tests, 85% cobertura core)
pytest tests/unit/ -v
pytest tests/unit/ --cov=cyber_range.scoring --cov=cyber_range.policy \
  --cov=cyber_range.config --cov=cyber_range.evidence \
  --cov=cyber_range.reporting --cov=cyber_range.logging

# Lint
ruff check src/ tests/
```

---

## Estructura del proyecto

```
ai_cyber_range_project/
├── pyproject.toml               ← packaging, entrypoints, herramientas
├── examples/local.yaml          ← config de ejemplo (lab local seguro)
├── src/cyber_range/             ← paquete Python productivo
│   ├── cli/main.py              ← cyber-range (Click + Rich)
│   ├── config/schema.py         ← Pydantic v2
│   ├── policy/enforcer.py       ← fail-closed, soberanía
│   ├── pipeline/runner.py       ← fases con estado
│   ├── scoring/engine.py        ← determinístico, [0,100]
│   ├── evidence/verifier.py     ← SHA-256, tamper detection
│   ├── reporting/generator.py   ← report.md + report.json v1
│   ├── logging/structured.py    ← JSONL, sin secretos
│   ├── api/app.py               ← FastAPI, auth, CORS allowlist
│   └── agents/
│       ├── memory.py            ← SQLite cross-run
│       └── hermes.py            ← HermesOrchestrator + 9 agentes
├── python_orchestrator/         ← pipeline ofensivo existente
├── rust_validator/              ← lab_service + evidence_validator (Rust)
├── web/frontend/                ← React + Vite (dist/ pre-compilado)
├── tests/unit/                  ← 115 tests, 85% cobertura core
├── artifacts/
│   ├── runs/<RUN_ID>/           ← summary.json · findings.json · report.md · logs.jsonl
│   ├── evidence/EVD-*.json      ← evidencia con SHA-256
│   └── agent_memory.db          ← memoria Hermes (SQLite)
├── CLAUDE.md                    ← Claude Code: actúa como cyber_leader
├── AGENTS.md                    ← mapa de navegación
└── CHECKPOINTS.md               ← criterios C1-C7 de sistema sano
```

---

## Licencia

MIT License — Copyright © 2026 [AxisDynamics](https://axisdynamics.cl)

---

<p align="center">
  <strong>Powered by <a href="https://axisdynamics.cl">AxisDynamics</a></strong><br>
  <em>Ofensiva Controlada con IA · MITRE ATT&CK · Harness Engineering · OpenMythos RDT</em>
</p>
