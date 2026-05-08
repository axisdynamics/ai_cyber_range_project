# Modelo Operativo — AI Cyber Range

> Quién hace qué, cuándo, y cómo se cierra bien una sesión.

---

## Roles y responsabilidades

| Rol | Agente | Lo que hace | Lo que NO hace |
|-----|--------|-------------|----------------|
| **Líder** | `cyber_leader` | Planifica, asigna, supervisa | No ejecuta ataques, no valida findings |
| **Implementer** | `red_team_agent` | Ejecuta UN escenario autorizado | No se autoaprueba, no toca dos escenarios |
| **Reviewer** | `blue_team_agent` | Verifica SHA-256, chain of custody | No edita evidencias, no aprueba sin verificar |
| **Humano** | operador | Abre Claude Code, supervisa, escala bloqueos | No bypasea el arnés |

---

## Cadencia operativa recomendada

### Sesión estándar (1 escenario)

```
1. ./init.sh                          → verifica arnés (C1-C6)
2. python3 -m ...harness.run_scenario --list  → elige siguiente pending
3. python3 -m ...harness.run_scenario --scenario-id N
   └── Líder → RedTeam → BlueTeam → APPROVED/REJECTED
4. ./init.sh                          → confirma estado sano al cierre
```

Duración típica: 2-5 minutos por escenario en modo sintético.

### Sesión web (dashboard en tiempo real)

```
./start.sh --web
→ abre http://localhost:8080
→ botón "RUN SCAN" dispara pipeline completo
→ /api/detections corre HybridDetector + MythosReasoner
```

### CI/CD loop (modo continuo)

```
./start.sh --watch --watch-interval 300
→ re-ejecuta el pipeline cada 5 minutos
→ útil en pipelines de desarrollo: cualquier merge puede abrir un gap nuevo
```

---

## SLAs de remediación

| Prioridad | Score | SLA | Owner típico |
|-----------|-------|-----|--------------|
| Critical | 90-100 | 1 día | security |
| High | 70-89 | 7 días | security / platform |
| Medium | 50-69 | 30 días | platform / engineering |
| Low | 0-49 | 90 días | platform |

Un finding con `detection_status: gap` y `reproducible: true` sube automáticamente
un nivel de prioridad respecto a uno detectado.

---

## Estados del engagement_backlog.json

```
pending     → escenario disponible para asignar
in_progress → red_team_agent trabajando (máximo 1 simultáneo)
done        → APPROVED por blue_team_agent, evidencia verificada
blocked     → fallo técnico o rechazo repetido → escala a humano
skipped     → fuera de scope para esta sesión (no bloqueado, no done)
```

Regla dura: `init.sh` falla si hay >1 `in_progress` al mismo tiempo.

---

## Protocolo de cierre de sesión

```
Antes de cerrar:
1. ./init.sh               → green en C1-C6
2. engagement_backlog.json → escenario activo en status correcto
3. progress/current.md     → vaciado a plantilla (no arrastrar estado)
4. progress/history.md     → entrada añadida al final
5. Sin archivos temporales, sin evidencias sin SHA-256
```

Si el blue_team_agent rechaza un finding (REJECTED), el cyber_leader decide:
- **Reintentar** → status: pending, anotar causa en notes
- **Bloquear** → status: blocked, documentar en progress/current.md, escalar

---

## Métricas que importan

| Métrica | Señal verde | Señal roja |
|---------|-------------|------------|
| `detection_gap_pct` | < 40% | > 60% (como ahora: 62.9%) |
| `coverage_pct` | > 90% | < 80% |
| Escenarios `done` / total | > 80% | < 50% |
| Evidencias con SHA-256 | 100% | Cualquier finding sin evidencia |
| SLA breach (criticos en >1d) | 0 | > 2 |

---

## Soberanía operativa

**Estas restricciones son permanentes y no se negocian:**

```yaml
# configs/default.yaml
allow_external_targets: false
blocked_techniques:
  - T1485  # Data Destruction
  - T1561  # Disk Wipe
  - T1529  # System Shutdown/Reboot
max_risk_level: controlled_lab
mode: local_lab_only
```

Cualquier escenario que intente un target externo recibe `SOVEREIGNTY_VIOLATION`
del `red_team_agent` y es bloqueado antes de ejecutarse.

---

## Integración con herramientas externas

| Herramienta | Cómo integrar |
|-------------|---------------|
| SIEM (Splunk, Elastic) | Ingestar `artifacts/evidence/EVD-*.json` vía API |
| JIRA / Linear | `/api/remediation` → POST tickets automático |
| Slack / Teams | Webhook en FastAPI tras cada `POST /api/run` |
| GitHub Actions | `./start.sh --watch` como step en CI |
| Claude Code | Abrir repo en raíz — `CLAUDE.md` fuerza rol cyber_leader |

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
