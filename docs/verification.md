# Verificación — Cómo demostrar que un cambio funciona

---

## Pre-vuelo (antes de cualquier cambio)

```bash
cyber-range status            # debe mostrar último run + memoria
cyber-range validate-config   # exit 0
pytest tests/unit/ -q         # 115 passed
```

---

## Smoke tests por capa

### C2 — src/cyber_range/ (paquete)

```bash
cyber-range --help
cyber-range validate-config --config examples/local.yaml
python3 -c "from cyber_range.policy.enforcer import PolicyEnforcer; print('OK')"
```

### C3 — Hermes

```bash
cyber-range run --mode agent --dry-run
cyber-range memory show
```

### C4 — Pipeline ofensivo

```bash
cyber-range run --config examples/local.yaml
# Esperado: exit 0, findings > 0, artifacts/runs/<RUN_ID>/ creado
```

### C5 — Detectores

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
import json
from python_orchestrator.detectors.hybrid_detector import HybridDetector
findings = json.load(open('python_orchestrator/reports/latest_report.json'))['findings'][:5]
r = HybridDetector().analyze(findings, [])
assert len(r.all_alerts) > 0
print(f'OK: {len(r.all_alerts)} alertas')
"
```

### C6 — Rust

```bash
rust_validator/target/release/lab_service selftest
# Esperado: SELFTEST_RESULT: passed=15 failed=0
```

### Evidencia

```bash
cyber-range verify-evidence
# Esperado: "Toda la evidencia es válida", exit 0

# Test tamper:
f=$(ls artifacts/evidence/EVD-*.json | head -1)
echo "corrupted" >> "$f"
cyber-range verify-evidence
# Esperado: "EVIDENCIA ALTERADA", exit 1
git checkout "$f"  # restaurar
```

### API

```bash
cyber-range serve-api &
sleep 2
curl -s http://localhost:8080/health | python3 -m json.tool
# Esperado: {"status": "ok", ...}
kill %1
```

---

## Definición de "done"

- [ ] `cyber-range status` muestra sistema sano
- [ ] `pytest tests/unit/ -q` — 0 failures
- [ ] `cyber-range verify-evidence` — exit 0
- [ ] `engagement_backlog.json` — sin >1 in_progress
- [ ] `progress/current.md` — en plantilla vacía (si se cerró sesión)
- [ ] `progress/history.md` — con entrada de la sesión

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
