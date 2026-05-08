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
