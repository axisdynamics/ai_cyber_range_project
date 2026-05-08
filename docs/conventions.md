# Convenciones — AI Cyber Range

---

## Naming

| Objeto | Formato | Ejemplo |
|--------|---------|---------|
| Finding | `FND-SCN-<asset>-<technique>` | `FND-SCN-iam_role_demo-T1078` |
| Evidencia | `EVD-<hash8>` | `EVD-A3F2C1B0` |
| Remediación | `REM-<hash8>` | `REM-727A8A15` |
| PoC | `POC-<finding_id>-<hash8>` | `POC-FND-SCN-...-0AB37252` |
| Run | `RUN-<hash8>` | `RUN-A54858EC` |
| Engagement | `ENG-<NNN>` | `ENG-001` |
| Impl report | `impl_<scenario_name>.md` | `impl_credential_exposure_iam_t1078.md` |
| Review report | `review_<scenario_name>.md` | `review_credential_exposure_iam_t1078.md` |

---

## Severidad

| Nivel | Score | Criterio | SLA |
|-------|-------|----------|-----|
| `critical` | 90-100 | detection_gap=true AND reproducible=true AND criticality>=4 | 1d |
| `high` | 70-89 | detection_gap=true OR (reproducible=true AND criticality>=3) | 7d |
| `medium` | 50-69 | detected but exploitable | 30d |
| `low` | 0-49 | detected, low exploitability | 90d |

---

## Estructura de evidencia (obligatoria)

```json
{
  "id": "EVD-XXXXXXXX",
  "asset_id": "iam_role_demo",
  "technique_id": "T1078",
  "evidence_type": "stdout | log | poc | chain_step | evasion",
  "hash_sha256": "<64-char hex>",
  "chain_of_custody": ["collected by RedTeamAgent at 2026-05-08T..."],
  "collector": "RedTeamAgent",
  "collected_at": "2026-05-08T16:40:52.000000",
  "content": "<evidence content>"
}
```

`hash_sha256` es **obligatorio**. Un EVD sin hash no puede ser aprobado.

---

## Código Python

- Type hints en todas las funciones públicas
- Dataclasses con `to_dict()` para serialización
- No `print()` sueltos — usar `fprintf(stderr, ...)` para warnings y `printf()` solo para output útil (C service)
- Imports relativos dentro del paquete

---

## Código C

- `safe_copy()` para TODA copia de strings de usuario
- Constantes en `#define`, no magic numbers
- Return codes estándar: `RC_OK=0`, `RC_WARN=3`, `RC_AUTH_FAIL=10`, `RC_ERROR=1`
- Los markers sintéticos (SYNTHETIC_VALID_TOKEN_1234, etc.) SIEMPRE en mayúsculas
- Comentarios inline en inglés para superficies de vulnerabilidad

---

## Código Rust

- `serde::Serialize` en todos los structs de output
- `process::exit(0)` solo en success, `exit(5)` para validation failures
- `/proc/...` acceso siempre con `#[cfg(target_os = "linux")]`
- Mensajes de error prefijados: `VALIDATION_ERROR:`, `AUDIT_REPORT:`, etc.

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
