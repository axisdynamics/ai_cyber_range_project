# Modelo Operativo — AI Cyber Range

> v2.0-beta · Quién hace qué, cuándo, y cómo se cierra bien una sesión.

---

## Roles

| Rol | Agente | Lo que hace | Lo que NO hace |
|-----|--------|-------------|----------------|
| **Líder** | `cyber_leader` | Planifica, asigna, supervisa | No ejecuta, no se autoaprueba |
| **Implementer** | `red_team_agent` | Ejecuta UN escenario | No toca dos a la vez |
| **Reviewer** | `blue_team_agent` | Verifica SHA-256 | No edita evidencias |
| **Humano** | operador | Abre Claude Code, escala bloqueos | No bypasea PolicyEnforcer |

---

## Dos modos de operación

### Modo estándar (`cyber-range run`)

Pipeline agentivo completo en secuencia:

```
Governance → OffensiveHarness → AttackChain → Evasion → PoC
→ Evidence → Review → Scoring → Remediation → Report
```

Duración típica: 1–3 segundos sobre fixtures locales.

### Modo Hermes (`cyber-range run --mode agent`)

9 agentes especializados en paralelo con memoria cross-run:

```
GapAnalysisAgent (lee memoria, prioriza técnicas)
    └── ThreadPoolExecutor:
        InitialAccess · Execution · Privilege · Evasion
        Credential · Discovery · Lateral · Collection · Impact
    └── SynthesisAgent (consolida, detector, memoria)
```

El modo Hermes **mejora** entre runs: acumula qué técnicas persisten
sin cobertura de detección y las prioriza en la siguiente ejecución.

---

## Cadencia recomendada

### Sesión estándar

```bash
source .venv/bin/activate
cyber-range status                    # estado del sistema
cyber-range validate-config           # config OK antes de ejecutar
cyber-range run
cyber-range verify-evidence           # confirmar integridad
cyber-range generate-report           # report.md + report.json
```

### Sesión Hermes (primera vez)

```bash
cyber-range run --mode agent          # crea artifacts/agent_memory.db
cyber-range memory show               # ver qué aprendió
```

### Sesión Hermes (runs subsiguientes)

```bash
cyber-range status                    # ver gaps persistentes acumulados
cyber-range run --mode agent          # prioriza automáticamente los gaps
cyber-range memory gaps --min-occurrences 2
```

### Dashboard en tiempo real

```bash
./start.sh --web                      # pipeline + http://localhost:8080
# o solo el servidor:
cyber-range serve-api --port 8080
```

---

## SLAs de remediación

| Prioridad | Score | SLA | Owner típico |
|-----------|-------|-----|--------------|
| Critical | 90–100 | 1 día | security |
| High | 70–89 | 7 días | security / platform |
| Medium | 50–69 | 30 días | platform / engineering |
| Low | 0–49 | 90 días | platform |

Un finding con `detection_status: gap` + `reproducible: true` sube un nivel automáticamente.

---

## Protocolo de cierre de sesión

```bash
# Antes de cerrar:
cyber-range status               # green en C1-C7
# progress/current.md → plantilla vacía
# progress/history.md → entrada de la sesión
# engagement_backlog.json → sin >1 in_progress
```

Si el blue_team_agent rechaza un finding:
- **Reintentar** → status: pending, anotar causa
- **Bloquear** → status: blocked, documentar, escalar

---

## Métricas que importan

| Métrica | Verde | Rojo |
|---------|-------|------|
| `detection_gap_pct` | < 40% | > 60% |
| `coverage_pct` | > 90% | < 80% |
| Tests | 115 passing | Cualquier failure |
| Evidencias con SHA-256 | 100% | Cualquier sin hash |
| SLA breach (críticos >1d) | 0 | > 2 |

---

## Integración con herramientas externas

| Herramienta | Cómo integrar |
|-------------|---------------|
| SIEM (Splunk, Elastic) | Ingestar `artifacts/runs/<id>/findings.json` |
| JIRA / Linear | `GET /api/remediation` → POST tickets |
| Slack / Teams | Webhook en FastAPI tras `POST /api/run` |
| GitHub Actions | `cyber-range run --dry-run` como gate en CI |
| Claude Code | Abrir repo en raíz — `CLAUDE.md` fuerza rol cyber_leader |

---

## Soberanía (no negociable)

```yaml
allow_external_targets: false   # hardcoded en config Y policy
blocked_techniques:             # hardcoded en PolicyEnforcer
  - T1485  # Data Destruction
  - T1561  # Disk Wipe
  - T1529  # System Shutdown/Reboot
```

PolicyEnforcer bloquea: IPs externas, dominios .com/.net/.amazonaws/etc,
técnicas fuera de formato T####, técnicas en lista config.

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
