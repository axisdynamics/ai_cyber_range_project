# CHECKPOINTS — Estado sano del AI Cyber Range

> En sistemas multi-agente de seguridad no se evalúa el camino, se evalúa
> el destino. Estos checkpoints objetivos los puede verificar un humano o
> el `blue_team_agent` al cerrar cualquier sesión.

---

## C1 — El arnés está completo

- [ ] Existen los archivos base: `AGENTS.md`, `CLAUDE.md`, `init.sh`,
      `engagement_backlog.json`, `progress/current.md`
- [ ] Existen los 3 docs: `docs/ARCHITECTURE.md`, `docs/OPERATING_MODEL.md`,
      `docs/OFFENSIVE_PLAYBOOK.md`
- [ ] `./init.sh` termina con **exit code 0**
- [ ] `.claude/agents/` contiene `cyber_leader.md`, `red_team_agent.md`,
      `blue_team_agent.md`

## C2 — El estado del engagement es coherente

- [ ] **Como máximo un escenario** con `status: "in_progress"` en
      `engagement_backlog.json`
- [ ] Todo escenario `done` tiene al menos un `artifacts/evidence/EVD-*.json`
      con campo `hash_sha256` no vacío
- [ ] `progress/current.md` describe la sesión activa o está en plantilla vacía
      (no contiene basura de sesiones anteriores)
- [ ] No hay escenarios `in_progress` sin entrada correspondiente en
      `progress/current.md`

## C3 — La soberanía está intacta

- [ ] `configs/default.yaml` tiene `allow_external_targets: false`
- [ ] Ningún finding tiene un asset fuera del `engagement_perimeter`
      definido en `configs/engagement_perimeter.yaml`
- [ ] No hay evidencias con rutas absolutas externas al directorio del proyecto
- [ ] Las técnicas bloqueadas (T1485, T1561, T1529) no aparecen en ningún
      finding con `detection_status: confirmed`

## C4 — La cadena de custodia es verificable

- [ ] Cada `artifacts/evidence/EVD-*.json` tiene campo `hash_sha256` (64 hex chars)
- [ ] Cada finding en `latest_report.json` referencia un `evidence_path` que
      existe en disco
- [ ] Ningún finding tiene `reproducible: true` sin `poc_id` asociado
- [ ] El campo `chain_of_custody` de cada evidencia tiene al menos 1 entrada

## C5 — Los detectores están activos

- [ ] `python_orchestrator/detectors/rule_engine.py` carga sin errores
- [ ] `python_orchestrator/detectors/hybrid_detector.py` carga sin errores
- [ ] `./init.sh` ejecuta el smoke test de detectores y pasa
- [ ] El último reporte tiene campo `detection_gap_pct` < 100%
      (alguna detección funcionó)

## C6 — La sesión se cerró bien

- [ ] No hay archivos `.tmp`, `*.pyc` sueltos fuera de `__pycache__`
- [ ] `progress/history.md` tiene una entrada por la última sesión completada
- [ ] La última feature trabajada está en su estado correcto en
      `engagement_backlog.json`
- [ ] No hay `print()` de debug en ningún archivo de `python_orchestrator/`

---

## Cómo usar este archivo

El `blue_team_agent` recorre cada checkbox al cerrar una sesión. Si quedan
boxes sin marcar en C1–C5, **rechaza el cierre** y reporta los fallos al
`cyber_leader` con referencia al archivo de revisión
(`progress/review_<scenario_id>.md`).

Un C4 fallido (evidencia sin SHA-256) es **motivo de rechazo automático** del
finding — nunca puede entrar al backlog de remediación.
---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
