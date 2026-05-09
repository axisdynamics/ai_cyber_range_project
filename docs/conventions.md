# Convenciones — AI Cyber Range

---

## Naming

| Objeto | Formato | Ejemplo |
|--------|---------|---------|
| Finding | `FND-SCN-<asset>-<technique>` | `FND-SCN-iam_role_demo-T1078` |
| Evidencia | `EVD-<hash8>` | `EVD-A3F2C1B0` |
| Remediación | `REM-<hash8>` | `REM-727A8A15` |
| Run | `RUN-<uuid8_upper>` | `RUN-A54858EC` |
| Impl report | `impl_<scenario>.md` | `impl_t1078_iam.md` |
| Review report | `review_<scenario>.md` | `review_t1078_iam.md` |

---

## Severidades

| Nivel | Score | SLA |
|-------|-------|-----|
| `critical` | 90–100 | 1d |
| `high` | 70–89 | 7d |
| `medium` | 50–69 | 30d |
| `low` | 0–49 | 90d |
| `informational` | 0–30 | 90d |

---

## Estructura EVD (obligatoria)

```json
{
  "id": "EVD-XXXXXXXX",
  "asset_id": "iam_role_demo",
  "technique_id": "T1078",
  "evidence_type": "stdout | log | poc | chain_step | evasion",
  "hash_sha256": "<64-char hex>",
  "chain_of_custody": ["collected by RedTeamAgent at 2026-05-08T..."],
  "collector": "RedTeamAgent",
  "collected_at": "2026-05-08T16:40:52Z",
  "content": "<evidence content>"
}
```

`hash_sha256` es obligatorio. Un EVD sin hash no puede ser aprobado.

---

## Métricas — definiciones

`coverage_pct`: `len(set(finding_techs) ∩ set(scope_techs)) / len(scope_techs) × 100`. Acotado [0, 100]. Nunca > 100%.

`detection_gap_pct`: `count(detection_status=="gap") / total_findings × 100`. Acotado [0, 100].

`risk_score`: `0.40×severity + 0.25×criticality + 0.20×gap + 0.15×reproducibility × 100`. Acotado [0, 100].

`confidence_score`: `0.40 base + 0.30 evidence + 0.20 verified + 0.10 reproducible`. Acotado [0.0, 1.0].

---

## Código Python

- Type hints en todas las funciones públicas
- Dataclasses con `to_dict()` para serialización
- No silenciar excepciones con `except: pass` en código productivo
- No `print()` sueltos en módulos `src/` — usar `StructuredLogger`

---

## Código Rust

- `serde::Serialize` en structs de output
- `process::exit(0)` solo en success, `exit(5)` en validation failures
- `/proc/...` siempre bajo `#[cfg(target_os = "linux")]`
- Mensajes prefijados: `VALIDATION_ERROR:`, `AUDIT_REPORT:`

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
