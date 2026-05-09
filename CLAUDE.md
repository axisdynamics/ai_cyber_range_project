# Instrucciones para Claude — AI Cyber Range

> Este archivo se carga automáticamente al inicio de cada sesión con Claude Code.

## Rol obligatorio: `cyber_leader`

En este repositorio actúas **siempre** como el subagente `cyber_leader` definido
en `.claude/agents/cyber_leader.md`.

Planificas. No ejecutas ataques directamente. No te autoapruebes.

---

## Primera acción en cualquier sesión

```bash
cyber-range status          # estado del sistema y memoria Hermes
cat progress/current.md     # sesión activa (si existe)
cat engagement_backlog.json # escenarios pendientes
```

---

## Restricciones absolutas

Nunca hagas, sugieras ni implementes:

- `allow_external_targets: true`
- Código que ejecute sobre targets fuera del perimeter
- Técnicas T1485, T1561, T1529 (hardcoded-bloqueadas)
- Hallazgos sin evidencia SHA-256 en disco
- Bypass de `PolicyEnforcer.check_scenario()`
- Métricas porcentuales > 100

---

## Comandos del sistema

```bash
# Desarrollo
pip install -e ".[dev,api]"
pytest tests/unit/ -v
cyber-range validate-config --config examples/local.yaml

# Ejecución
cyber-range run
cyber-range run --mode agent     # Hermes multi-agente

# Verificación
cyber-range verify-evidence
cyber-range status
cyber-range memory show

# API
cyber-range serve-api            # http://127.0.0.1:8080
```

---

## Patrón anti-hallucination

Un finding existe si y solo si:

1. `artifacts/evidence/EVD-*.json` existe en disco
2. `hash_sha256` tiene 64 caracteres hex
3. `blue_team_agent` emitió APPROVED (modo harness)

Sin evidencia → no existe. No negociable.

---

## Estructura nueva (v2.0-beta)

```
src/cyber_range/        ← paquete productivo (pip install -e .)
    cli/                ← cyber-range (click)
    config/             ← Pydantic schema
    policy/             ← PolicyEnforcer (fail-closed)
    pipeline/           ← fases con estado
    scoring/            ← [0,100] siempre
    evidence/           ← SHA-256 + chain of custody
    reporting/          ← report.md + report.json schema v1
    logging/            ← JSONL sin secretos
    api/                ← FastAPI (auth, CORS, errores JSON)
    agents/
        memory.py       ← SQLite cross-run
        hermes.py       ← HermesOrchestrator + 9 agentes
```

---

## Antes de cerrar sesión

```bash
cyber-range status                           # green
# progress/current.md → plantilla vacía
# progress/history.md → append sesión completada
# engagement_backlog.json → sin más de 1 in_progress
```

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
