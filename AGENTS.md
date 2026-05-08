# AGENTS.md — Mapa de navegación para el AI Cyber Range

> **Punto de entrada** para cualquier agente que trabaje en este repositorio.
> No es una biblia de reglas: es un **mapa**. Lee solo lo que necesites cuando
> lo necesites (divulgación progresiva).

---

## 1. Antes de empezar (obligatorio)

1. Ejecuta `./init.sh` y verifica que termina sin errores.
   Si falla → **para**. Nunca ejecutes ofensiva con el arnés roto.
2. Lee `progress/current.md` para saber el estado de la última sesión.
3. Lee `engagement_backlog.json` y elige **un** escenario con `status: "pending"`.
   No trabajas en más de uno a la vez.

---

## 2. Mapa del repositorio

| Archivo / carpeta | Qué contiene | Cuándo leerlo |
|---|---|---|
| `engagement_backlog.json` | Lista de escenarios pendientes/activos/completados | Siempre, al empezar |
| `progress/current.md` | Estado de la sesión activa | Siempre, al empezar |
| `progress/history.md` | Bitácora append-only de sesiones anteriores | Si necesitas contexto histórico |
| `CHECKPOINTS.md` | Criterios objetivos de "estado sano" del range | Para auto-evaluarte |
| `.claude/agents/cyber_leader.md` | Rol del líder: planifica, no implementa | Si eres el líder |
| `.claude/agents/red_team_agent.md` | Rol del implementer: ejecuta UN escenario | Si ejecutas ataques |
| `.claude/agents/blue_team_agent.md` | Rol del reviewer: valida sin auto-aprobarse | Si revisas findings |
| `configs/default.yaml` | Parámetros del engagement (perimeter, mode) | Antes de cualquier run |
| `configs/engagement_perimeter.yaml` | Activos autorizados y técnicas habilitadas | Antes de ejecutar |
| `docs/ARCHITECTURE.md` | Arquitectura completa del sistema | Antes de modificar código |
| `docs/OPERATING_MODEL.md` | Modelo operativo y SLAs | Para entender el contexto |
| `docs/OFFENSIVE_PLAYBOOK.md` | Tácticas autorizadas y reglas de engagement | Antes de ejecutar ofensiva |
| `python_orchestrator/agents/` | Agentes Python ofensivos y defensivos | Para modificar comportamiento |
| `python_orchestrator/detectors/` | Motores de detección determinísticos + híbrido | Para detección |
| `artifacts/evidence/` | Evidencias con SHA-256 verificables | Nunca editar manualmente |
| `python_orchestrator/reports/latest_report.json` | Último reporte completo | Para leer resultados |

---

## 3. Reglas duras del engagement

- **Un solo escenario a la vez.** `engagement_backlog.json` no puede tener más de un
  ítem en `in_progress`. `./init.sh` rechaza el estado si viola esta regla.
- **Sin evidencia verificable = sin finding.** Todo hallazgo debe tener un registro
  `artifacts/evidence/EVD-*.json` con SHA-256. Si no existe en disco, no existe.
- **Soberanía absoluta.** `allow_external_targets: false` en todos los configs.
  Las técnicas destructivas (T1485, T1561, T1529) están bloqueadas por governance.
- **No declares `confirmed` sin que el `blue_team_agent` haya revisado.**
  El implementer nunca se auto-aprueba.
- **Documenta mientras trabajas**, no al final. `progress/current.md` es el estado vivo.

---

## 4. Cómo elegir un escenario

```
1. Abre engagement_backlog.json
2. Filtra por status == "pending"
3. Elige el de menor "id" (o mayor prioridad si hay campo priority)
4. Cambia status a "in_progress" y guarda
5. Anota en progress/current.md: scenario_id, asset, technique, hora, plan
```

---

## 5. Flujo de un escenario completo

```
cyber_leader
    │
    ├── 1. Selecciona escenario de engagement_backlog.json
    ├── 2. Actualiza progress/current.md con el plan
    ├── 3. Lanza → red_team_agent (implementer)
    │         └── Ejecuta escenario
    │         └── Escribe progress/impl_<scenario_id>.md
    │         └── Genera artifacts/evidence/EVD-*.json
    │         └── Devuelve: "ver progress/impl_<scenario_id>.md"
    │
    ├── 4. Lanza → blue_team_agent (reviewer)
    │         └── Lee progress/impl_<scenario_id>.md
    │         └── Verifica SHA-256 de cada evidencia
    │         └── Escribe progress/review_<scenario_id>.md
    │         └── Devuelve: APPROVED o REJECTED + razón
    │
    └── 5. Si APPROVED:
              └── Actualiza engagement_backlog.json → status: "done"
              └── Mueve resumen de current.md a history.md
              └── Vacía current.md (deja solo plantilla)
```

---

## 6. Cierre de sesión

Antes de terminar:

1. Ejecuta `./init.sh` — todo verde.
2. Si el escenario está completo: `status: "done"` en `engagement_backlog.json`.
3. Mueve el resumen de `progress/current.md` al final de `progress/history.md`.
4. Vacía `progress/current.md` dejando solo la plantilla.
5. No dejes archivos temporales ni evidencias sin SHA-256.

---

## 7. Si te bloqueas

- Relee `docs/OFFENSIVE_PLAYBOOK.md` para tácticas autorizadas.
- Si un escenario falla, documenta el bloqueo en `progress/current.md` y
  marca el escenario como `blocked` en `engagement_backlog.json`.
- Nunca inventes evidencia. Un bloqueo documentado es mejor que un hallucinated finding.
---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
