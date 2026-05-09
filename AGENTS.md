# AGENTS.md — Mapa de navegación del AI Cyber Range

> Punto de entrada para cualquier agente en este repositorio.
> Es un mapa, no una biblia. Lee solo lo que necesites.

---

## Rol obligatorio al abrir este repo

Si estás en Claude Code → actúas como `cyber_leader` (ver `CLAUDE.md`).

---

## Estructura del proyecto (v2.0-beta)

```
ai_cyber_range_project/
│
├── src/cyber_range/               ← PAQUETE PYTHON PRODUCTIVO
│   ├── cli/main.py                ← cyber-range (Click + Rich)
│   ├── config/schema.py           ← Pydantic: valida antes de ejecutar
│   ├── policy/enforcer.py         ← PolicyEnforcer: check_scenario() siempre primero
│   ├── pipeline/runner.py         ← Fases con estado
│   ├── scoring/engine.py          ← Determinístico, [0,100]
│   ├── evidence/verifier.py       ← SHA-256, tamper detection
│   ├── reporting/generator.py     ← report.md + report.json schema v1
│   ├── logging/structured.py      ← JSONL, sin secretos
│   ├── api/app.py                 ← FastAPI: auth, CORS allowlist, errores JSON
│   └── agents/
│       ├── memory.py              ← AgentMemory SQLite cross-run
│       └── hermes.py              ← HermesOrchestrator + 9 agentes especializados
│
├── python_orchestrator/           ← Pipeline ofensivo existente
│   ├── main.py                    ← Entry point original
│   ├── agents/                    ← GovernanceAgent, RedTeamAgent, etc.
│   ├── detectors/                 ← RuleEngine, Sigma, IoC, Anomaly, HybridDetector
│   ├── harness/                   ← HarnessOrchestrator, SessionManager
│   └── data/                      ← assets.json, attack_subset.json
│
├── rust_validator/                ← Binarios Rust (lab_service + evidence_validator)
├── web/                           ← FastAPI API + React dashboard
├── tests/unit/                    ← 115 tests (scoring, policy, config, evidence, logging, memory)
├── examples/local.yaml            ← Config ejemplo (safe defaults)
├── configs/default.yaml           ← Config producción
├── artifacts/                     ← Artefactos generados
│   ├── runs/<RUN_ID>/             ← summary · findings · report · logs · evidence
│   └── agent_memory.db            ← Memoria Hermes (SQLite)
│
├── CLAUDE.md                      ← Instrucciones para Claude Code
├── AGENTS.md                      ← Este archivo
├── CHECKPOINTS.md                 ← Criterios C1-C7 de sistema sano
├── engagement_backlog.json        ← Backlog de escenarios
└── progress/                      ← current.md · history.md
```

---

## Comandos esenciales

```bash
# Estado del sistema
cyber-range status

# Validar configuración
cyber-range validate-config --config examples/local.yaml

# Ejecutar (modo estándar)
cyber-range run

# Ejecutar (modo Hermes — agentes paralelos con memoria)
cyber-range run --mode agent

# Verificar evidencia
cyber-range verify-evidence

# Memoria cross-run
cyber-range memory show
cyber-range memory gaps --min-occurrences 2

# Tests
pytest tests/unit/ -v

# API + Dashboard
cyber-range serve-api        # http://127.0.0.1:8080
```

---

## Guía de navegación rápida

| Tarea | Dónde ir |
|-------|----------|
| Cambiar configuración | `examples/local.yaml` o `configs/default.yaml` |
| Añadir técnica bloqueada | `src/cyber_range/config/schema.py` (EngagementConfig) |
| Modificar scoring | `src/cyber_range/scoring/engine.py` + test |
| Cambiar política de scope | `src/cyber_range/policy/enforcer.py` + test |
| Añadir agente Hermes | `src/cyber_range/agents/hermes.py` (AGENT_CLUSTERS) |
| Modificar evidencia | `src/cyber_range/evidence/verifier.py` |
| Cambiar API endpoints | `src/cyber_range/api/app.py` |
| Ver último reporte | `python_orchestrator/reports/latest_report.json` |
| Ver runs históricos | `artifacts/runs/` |
| Ver gaps persistentes | `cyber-range memory gaps` |
| Verificar harness | `CHECKPOINTS.md` · `cyber-range status` |

---

## Restricciones absolutas (no negociables)

1. `allow_external_targets` nunca es `true`
2. `PolicyEnforcer.check_scenario()` es la primera llamada antes de cualquier simulación
3. T1485, T1561, T1529 bloqueadas hardcoded — nunca en `allowed`
4. Métricas porcentuales siempre en [0, 100]
5. Un finding sin `hash_sha256` de 64 chars no existe
6. El `blue_team_agent` no aprueba su propio trabajo

---

## Archivos de referencia por área

| Área | Spec | Implementación | Tests |
|------|------|----------------|-------|
| Config | `examples/local.yaml` | `config/schema.py` | `test_config.py` |
| Policy | `CHECKPOINTS.md C3` | `policy/enforcer.py` | `test_policy.py` |
| Scoring | `docs/conventions.md` | `scoring/engine.py` | `test_scoring.py` |
| Evidence | `CHECKPOINTS.md C4` | `evidence/verifier.py` | `test_evidence.py` |
| Reports | `docs/ARCHITECTURE.md` | `reporting/generator.py` | `test_reporting.py` |
| Hermes | `docs/ARCHITECTURE.md C3` | `agents/hermes.py` + `memory.py` | `test_memory.py` |
| CLI | `README.md` | `cli/main.py` | — |
| API | `docs/ARCHITECTURE.md` | `api/app.py` | — |

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
