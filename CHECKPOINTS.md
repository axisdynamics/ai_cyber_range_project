# CHECKPOINTS — Estado sano del AI Cyber Range

> Criterios objetivos verificables por humano o por `blue_team_agent`.
> El sistema está sano cuando **todos** están en verde.

---

## C1 — Configuración válida

```bash
cyber-range validate-config --config examples/local.yaml
# Esperado: exit 0, "Config válida"

cyber-range validate-config --config bad.yaml
# Esperado: exit 1, mensaje descriptivo
```

✅ `allow_external_targets = false` (hardcoded)  
✅ T1485, T1561, T1529 en `blocked_techniques`  
✅ Ningún perfil desconocido (`local_lab` | `purple_team` | `blue_team_validation`)

---

## C2 — Pipeline ejecuta sin errores

```bash
cyber-range run --dry-run
# Esperado: exit 0, plan visible

cyber-range run
# Esperado: exit 0, tabla de findings, reportes generados
```

✅ `python_orchestrator/reports/latest_report.json` actualizado  
✅ `artifacts/runs/<RUN_ID>/` creado con todos los artefactos  
✅ Cobertura ATT&CK ≤ 100% (nunca 105.6%)

---

## C3 — Soberanía intacta

```bash
# El PolicyEnforcer bloquea targets externos
python3 -c "
from cyber_range.config.schema import CyberRangeConfig
from cyber_range.policy.enforcer import PolicyEnforcer
e = PolicyEnforcer(CyberRangeConfig())
assert not e.check_technique('T1485').allowed
assert not e.check_asset('8.8.8.8').allowed
print('OK — soberanía verificada')
"
```

✅ T1485 / T1561 / T1529 bloqueadas en cualquier contexto  
✅ IPs externas bloqueadas  
✅ Dominios externos (`.amazonaws`, `.com`, etc.) bloqueados

---

## C4 — Evidencias verificables

```bash
cyber-range verify-evidence
# Esperado: exit 0, "Toda la evidencia es válida"

# Tamper test
echo "corrupted" >> artifacts/evidence/$(ls artifacts/evidence/ | head -1)
cyber-range verify-evidence
# Esperado: exit 1, "EVIDENCIA ALTERADA"
```

✅ Todos los EVD-*.json tienen `hash_sha256` de 64 chars  
✅ Recalcular hash = hash almacenado  
✅ `verify-evidence` falla non-zero ante cualquier modificación

---

## C5 — Tests pasan

```bash
pytest tests/unit/ -v
# Esperado: 115 passed, 0 failed

pytest tests/unit/ \
  --cov=cyber_range.config --cov=cyber_range.policy \
  --cov=cyber_range.scoring --cov=cyber_range.evidence \
  --cov=cyber_range.reporting --cov=cyber_range.logging
# Esperado: ≥ 70% cobertura core (actualmente: 85%)
```

✅ `coverage_pct` nunca > 100 (test `test_never_exceeds_100`)  
✅ T1485 bloqueada (test `test_hardcoded_blocked`)  
✅ `allow_external_targets=True` rechazado (test `test_cannot_set_external_true`)

---

## C6 — Hermes con memoria

```bash
cyber-range run --mode agent
# Esperado: 9 agentes, findings por agente, reportes

cyber-range memory show
# Esperado: historial de runs, gaps acumulados, aprendizaje por técnica

cyber-range status
# Esperado: último run, memoria Hermes, gaps persistentes
```

✅ `artifacts/agent_memory.db` se crea y persiste entre runs  
✅ Segunda ejecución muestra gaps de la primera  
✅ `memory gaps --min-occurrences 2` lista gaps persistentes tras 2+ runs

---

## C7 — API operativa

```bash
cyber-range serve-api &
sleep 2
curl -s http://localhost:8080/health | python3 -m json.tool
# Esperado: {"status": "ok", ...}

curl -s http://localhost:8080/version
# Esperado: {"version": "0.2.0-beta", ...}
```

✅ `/health` responde 200  
✅ Sin CORS wildcard (`*`) por defecto  
✅ Errores en formato `{"error": {"code": ..., "message": ..., "details": ...}}`  
✅ Con `--api-key`: requests sin header retornan 401

---

## Cierre de sesión limpio

```bash
# Antes de cerrar cualquier sesión:
cyber-range status         # green en todos los checkpoints
# engagement_backlog.json  # sin más de 1 in_progress
# progress/current.md      # en plantilla vacía
# progress/history.md      # con entrada de la sesión
```

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
