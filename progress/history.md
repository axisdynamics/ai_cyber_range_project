# progress/history.md — Bitácora de sesiones

> Archivo append-only. Nunca se borra. Cada sesión completada agrega una entrada al final.

---

## Sesión 001 · 2026-05-08T16:40:52Z

**Run ID:** RUN-A54858EC
**Engagement:** ENG-001
**Modo:** full (ofensiva + defensiva)
**Duración:** ~3.4s (pipeline sintético)

### Escenarios completados

| ID | Asset | Técnica | Severity | Score | Detection | Revisado por |
|----|-------|---------|----------|-------|-----------|-------------|
| 1 | iam_role_demo | T1078 | critical | 100.0 | gap | ReviewerAgent |
| 2 | iam_role_demo | T1548 | critical | 100.0 | gap | ReviewerAgent |
| 3 | iam_role_demo | T1003 | critical | 100.0 | gap | ReviewerAgent |
| — | api_gateway_demo | T1078 | critical | 95.0 | gap | ReviewerAgent |
| — | api_gateway_demo | T1003 | critical | 95.0 | gap | ReviewerAgent |
| — | api_gateway_demo | T1041 | critical | 95.0 | gap | ReviewerAgent |
| — | pipeline_demo | T1548 | critical | 95.0 | gap | ReviewerAgent |
| — | secrets_store_demo | T1003 | critical | 100.0 | gap | ReviewerAgent |
| ... | (27 más) | ... | high/medium/low | ... | gap/detected | ReviewerAgent |

### Métricas de la sesión

- Findings totales: 35
- Críticos: 8 · Altos: 12 · Medios: 11 · Bajos: 4
- Cobertura ATT&CK: 97.2%
- Detection gap: 62.9% (53/84 controles evadidos)
- Kill chains: 36 simuladas
- PoCs: 32 reproducibles

### Estado del arnés al cierre

- [x] C1 completo (arnés OK)
- [x] C2 coherente (0 in_progress al cierre)
- [x] C3 soberanía intacta (sin targets externos)
- [x] C4 cadena custodia OK (78 evidencias con SHA-256)
- [x] C5 detectores activos (62.9% gap != 100%)
- [x] C6 sesión cerrada limpia

### Notas

Primera sesión completa. Harness Engineering integrado. Web dashboard añadido.
Motores determinísticos (RuleEngine, Sigma, IoC, Anomaly) + HybridDetector operativos.

---

## Sesión 002 · 2026-05-08T17:30:00Z — Integración capas v3-v5

**Alcance:** Tres integraciones mayores completadas en esta sesión.

### v3 — Web layer + Detectores híbridos

- FastAPI (`web/api/main.py`) con 10 endpoints REST
- React dashboard (`dashboard_standalone.html`) — 6 páginas, ops-center aesthetic
- 4 motores determinísticos: RuleEngine (12 reglas), SigmaCorrelator (7), IoCMatcher (12), AnomalyDetector (Z-score)
- HybridDetector orquestador con integración LLM opcional

### v4 — Harness Engineering (github.com/betta-tech/ejemplo-harness-subagentes)

- `CLAUDE.md`, `AGENTS.md`, `CHECKPOINTS.md` (C1-C6)
- `engagement_backlog.json` (8 escenarios: 3 done, 5 pending)
- `.claude/agents/`: cyber_leader, red_team_agent, blue_team_agent
- `python_orchestrator/harness/`: HarnessOrchestrator, SessionManager, run_scenario CLI
- Patrón anti-hallucination: findings sin SHA-256 en disco = no existen

### v5 — OpenMythos RDT + C/Rust ampliados (github.com/kyegomez/OpenMythos)

- `RecurrentDepthReasoner`: h_{t+1} = A·h_t + B·e + Transformer(h_t, e)
  - MAX_LOOPS=6, ACT halt (ρ̂ < 0.28), LTI stability (RETENTION_DECAY=0.65)
- `MoERouter`: 8 expertos ATT&CK + 1 compartido, loop-index embedding
- HybridDetector actualizado para usar MythosReasoner en lugar de llamada LLM simple
- C service: 70 → 455 líneas, 14 comandos, 11 técnicas, 3 build targets
- Rust validator: 78 → 793 líneas, 9 comandos de auditoría

### Estado del arnés al cierre

- [x] C1 completo
- [x] C2 coherente (0 in_progress)
- [x] C3 soberanía intacta
- [x] C4 evidencias con SHA-256
- [x] C5 detectores activos
- [x] C6 sesión cerrada, directorios limpios

### Limpieza aplicada

- Eliminados: `{configs,docs,artifacts,scripts,tests}/` y `python_orchestrator/{core,agents,...}/` (brace expansion fallida)
- Eliminados: `__pycache__/`, `*.pyc`, `*.bak`
- Creados: `docs/ARCHITECTURE.md`, `docs/OPERATING_MODEL.md`, `docs/conventions.md`, `docs/verification.md`
- Actualizado: `README.md`, `docs/OFFENSIVE_PLAYBOOK.md`

---

## Sesión 003 · 2026-05-08T23:00:00Z — v2.0-beta: CLI + Hermes + Productización

### Alcance

**Productización beta** según SPEC de producto. Tres bloques de trabajo.

### Bloque A — src/cyber_range/ (paquete productivo)

- `pyproject.toml` con entrypoints CLI (`cyber-range`)
- `config/schema.py` — Pydantic v2: `CyberRangeConfig`, `EngagementConfig`, `LLMConfig`
- `policy/enforcer.py` — `PolicyEnforcer.check_scenario()`, `assert_allowed()`, fail-closed
- `pipeline/runner.py` — 11 fases con estado, run directories `artifacts/runs/<id>/`
- `scoring/engine.py` — `risk_score`, `coverage_pct`, `detection_gap_pct` — todos [0,100]
- `evidence/verifier.py` — SHA-256 recalculado, MODIFIED/MISSING/UNREFERENCED
- `reporting/generator.py` — report.md + report.json schema v1
- `logging/structured.py` — JSONL + redacción automática de secretos
- `api/app.py` — FastAPI: auth X-API-Key, CORS allowlist, errores JSON, `/health /version /runs`

### Bloque B — Hermes multi-agente

- `agents/memory.py` — SQLite cross-run: runs, findings, gaps, learning
- `agents/hermes.py` — `HermesOrchestrator`, 9 agentes especializados, `ThreadPoolExecutor(4)`
- GapAnalysisAgent: prioriza técnicas por `gap_rate × avg_score`
- Memoria persistente: `get_persistent_gaps()`, `get_priority_techniques()`, `get_technique_learning()`

### Bloque C — CLI completo

- `cyber-range run [--mode standard|agent] [--dry-run]`
- `cyber-range validate-config` — exit 1 si inválido, exit 2 si no existe
- `cyber-range verify-evidence [--run-id ID]` — exit 1 si modificada
- `cyber-range generate-report [--run-id ID]`
- `cyber-range serve-api [--port N] [--api-key KEY]`
- `cyber-range status` — último run + memoria Hermes
- `cyber-range memory show|clear|gaps`

### Tests

- 115 tests, 0 failures
- Cobertura core: 85% (scoring 100%, policy 94%, config 95%, logging 95%)

### Bugs corregidos

- `coverage_pct` nunca supera 100% (fix + regression test)
- `python_orchestrator/main.py` `KeyError: 'program'` con nuevos configs
- `examples/local.yaml` compatible con legacy orchestrator

### Estado al cierre

- [x] C1 config válida
- [x] C2 pipeline sin errores
- [x] C3 soberanía intacta
- [x] C4 evidencias con SHA-256
- [x] C5 tests 115/115
- [x] C6 Hermes con memoria
- [x] C7 API operativa
- [x] Todos los .md actualizados

---

## Sesión 003 · 2026-05-09T00:06:00Z — Beta productivo + Hermes multi-agente

**Alcance:** Productización completa siguiendo spec Spec Driven Development.

### src/cyber_range/ (nuevo paquete Python)

- `config/schema.py` — Pydantic v2, fail-closed, `allow_external_targets` rechazado siempre
- `policy/enforcer.py` — PolicyEnforcer stateless, T1485/T1561/T1529 hardcoded, IPs externas bloqueadas
- `scoring/engine.py` — Determinístico, coverage_pct NUNCA > 100% (fix bug 105.6%), risk_score/confidence/gap/remediation_priority
- `evidence/verifier.py` — SHA-256 recalculado, estados: valid/missing/modified/unreferenced/no_hash
- `reporting/generator.py` — report.md + report.json schema v1 estable
- `logging/structured.py` — JSONL, redacción automática de secretos
- `pipeline/runner.py` — Fases con estado (pending/running/success/failed/skipped/blocked)
- `api/app.py` — FastAPI: auth X-API-Key, CORS allowlist (sin *), errores JSON estructurados, /health /version /runs
- `cli/main.py` — CLI completo (run/validate-config/verify-evidence/generate-report/serve-api/status/memory)

### Hermes multi-agente

- `agents/memory.py` — AgentMemory SQLite cross-run: runs, findings, gaps, learning tables
- `agents/hermes.py` — HermesOrchestrator: GapAnalysisAgent + 9 agentes especializados paralelos
- Memoria: `get_persistent_gaps()`, `get_priority_techniques()`, `get_technique_learning()`
- CLI: `cyber-range run --mode agent`, `cyber-range memory show/clear/gaps`

### pyproject.toml + packaging

- `pip install -e .` → `cyber-range` en PATH
- Entrypoints: run/validate-config/verify-evidence/generate-report/serve-api/status/memory
- Dev deps: pytest/pytest-cov/ruff/mypy
- CI: `.github/workflows/ci.yml`

### Tests

- 115 tests, 0 failures
- Cobertura 85% en módulos core (scoring:100%, policy:94%, config:95%, logging:95%, reporting:76%)
- Nuevos: test_memory.py (10 tests), test_logging.py (15), test_evidence.py (7)

### Estado del sistema al cierre

- [x] C1 Config válida
- [x] C2 Pipeline ejecuta sin errores
- [x] C3 Soberanía intacta
- [x] C4 Evidencias verificables
- [x] C5 Tests pasan (115/0)
- [x] C6 Hermes con memoria (3 runs en memory.db)
- [x] C7 API operativa
