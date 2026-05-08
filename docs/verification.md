# Verificacion — Como demostrar que un cambio funciona

Antes de cualquier cambio:
  ./init.sh   (debe terminar verde)

Smoke tests por capa:

Harness:
  python3 -m python_orchestrator.harness.run_scenario --verify

Pipeline:
  PYTHONPATH=. python3 -m python_orchestrator.main --config configs/default.yaml

Detectores:
  PYTHONPATH=. python3 -c "
  import sys, json; sys.path.insert(0,'.')
  from python_orchestrator.detectors.hybrid_detector import HybridDetector
  f = json.load(open('python_orchestrator/reports/latest_report.json'))['findings'][:5]
  r = HybridDetector().analyze(f, [])
  print(f'OK: {len(r.all_alerts)} alertas')
  "

C service:
  gcc -O2 -o c_service/build/lab_service c_service/src/lab_service.c
  ./c_service/build/lab_service selftest
  # SELFTEST_RESULT: passed=15 failed=0

Rust:
  cargo build --manifest-path rust_validator/Cargo.toml
  ./rust_validator/target/release/evidence_validator audit-evidence artifacts/evidence/
  # EVIDENCE_AUDIT: invalid=0

FastAPI:
  PYTHONPATH=. python3 -c "from web.api.main import _read_report; r=_read_report(); print('OK' if r else 'FAIL')"

Definicion de done:
  - ./init.sh exit 0
  - Smoke test de capa modificada pasa
  - engagement_backlog.json sin mas de 1 in_progress
  - progress/current.md en plantilla vacia (si se cerro la sesion)
  - progress/history.md con entrada de la sesion completada

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
