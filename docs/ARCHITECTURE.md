# Arquitectura — AI Cyber Range

> Versión 5.0 · Última actualización: 2026-05-08

---

## Visión general

El Cyber Range implementa cinco capas cohesivas. Cada capa depende de la
anterior y expone una interfaz limpia hacia arriba.

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  HARNESS (orquestación multi-agente)                            │
 │  Líder → Implementer (red_team) → Reviewer (blue_team)         │
 ├─────────────────────────────────────────────────────────────────┤
 │  PIPELINE OFENSIVO (Python agentivo)                            │
 │  Governance → OffensiveHarness → Chains → Evasion → PoC        │
 ├─────────────────────────────────────────────────────────────────┤
 │  DETECCIÓN HÍBRIDA (determinístico + RDT)                       │
 │  Rule + Sigma + IoC + Anomaly → HybridDetector → MythosReasoner │
 ├─────────────────────────────────────────────────────────────────┤
 │  CAPA NATIVA (C + Rust)                                         │
 │  lab_service (ataque) · evidence_validator (auditoría)          │
 ├─────────────────────────────────────────────────────────────────┤
 │  WEB (React SPA + FastAPI)                                      │
 │  6 páginas · 10 endpoints REST · polling en tiempo real        │
 └─────────────────────────────────────────────────────────────────┘
```

---

## Capa 1 — Harness

Inspirado en Harness Engineering (github.com/betta-tech/ejemplo-harness-subagentes).

### Principios
- **El repositorio ES el sistema.** Todo el estado vive en disco, no en chat.
- **Una feature (escenario) a la vez.** `init.sh` rechaza >1 `in_progress`.
- **Anti-hallucination.** Un finding sin evidencia en disco con SHA-256 no existe.
- **Nadie se autoaprueba.** El red_team_agent no valida su propio trabajo.
- **Divulgación progresiva.** `AGENTS.md` es un mapa, no una biblia.

### Archivos del arnés

| Archivo | Rol |
|---------|-----|
| `CLAUDE.md` | Fuerza a Claude Code a actuar como `cyber_leader` |
| `AGENTS.md` | Mapa de navegación para cualquier agente |
| `CHECKPOINTS.md` | Criterios C1-C6 de "range sano" |
| `engagement_backlog.json` | Backlog de escenarios (pending/in_progress/done) |
| `progress/current.md` | Estado de la sesión activa (vivo) |
| `progress/history.md` | Bitácora append-only entre sesiones |
| `.claude/agents/cyber_leader.md` | Planifica, no ejecuta |
| `.claude/agents/red_team_agent.md` | Ejecuta UN escenario, escribe a disco |
| `.claude/agents/blue_team_agent.md` | Valida SHA-256, no se autoaprueba |

### Flujo de un escenario

```
cyber_leader
    │
    ├── 1. Lee engagement_backlog.json → elige scenario pending (id mínimo)
    ├── 2. Actualiza progress/current.md
    ├── 3. → red_team_agent
    │         ejecuta via HarnessOrchestrator
    │         escribe progress/impl_<id>.md
    │         genera artifacts/evidence/EVD-*.json
    │         devuelve: "ver progress/impl_<id>.md"
    │
    ├── 4. → blue_team_agent
    │         lee impl_<id>.md
    │         verifica SHA-256 de cada evidencia
    │         escribe progress/review_<id>.md
    │         devuelve: "APPROVED / REJECTED"
    │
    └── 5. Si APPROVED:
              engagement_backlog → status: done
              progress/current.md → plantilla vacía
              progress/history.md → append sesión
```

### HarnessOrchestrator (Python)

```python
# python_orchestrator/harness/harness_orchestrator.py
orch = HarnessOrchestrator()
result = orch.run_single_scenario(scenario_id=4)
# result.verdict: APPROVED | REJECTED | BLOCKED
# result.impl_ref: "progress/impl_scenario_4.md"
# result.review_ref: "progress/review_scenario_4.md"
```

---

## Capa 2 — Pipeline ofensivo

### Agentes Python

| Agente | Función |
|--------|---------|
| `GovernanceAgent` | Autorización + soberanía + reglas de engagement |
| `OffensiveHarness` | Coordinador central del ciclo ofensivo |
| `AttackChainSimulator` | Kill chains multi-paso (orden táctico MITRE, depth=6) |
| `EvasionTester` | Tests de evasión por control |
| `PoCBuilder` | PoCs reproducibles con IoCs + SHA-256 |
| `RedTeamAgent` | Ejecución sobre fixtures locales |
| `DetectionAgent` | Validación de telemetría blue team |
| `ReviewerAgent` | Quality gate + deduplicación |
| `RiskScoringEngine` | Severidad × criticidad × gap × reproducibilidad |

### Ciclo ofensivo

```
GovernanceAgent.authorize()
    │
    └── OffensiveHarness.run()
            ├── para cada (asset × técnica) en perimeter:
            │       AttackChainSimulator.simulate()   → kill chain
            │       EvasionTester.test()              → evasion results
            │       PoCBuilder.build()                → PoC + IoCs
            │       EvidenceEngine.collect()          → EVD-*.json (SHA-256)
            │
            ├── ReviewerAgent.review()               → dedup + quality gate
            ├── RiskScoringEngine.score()             → priorización
            └── RemediationEngine.generate_backlog() → tickets con SLA
```

### Modelos de datos clave

```python
# python_orchestrator/core/models.py
@dataclass
class Finding:
    id: str
    asset: str
    technique_id: str
    severity: str          # critical | high | medium | low
    detection_status: str  # gap | detected | partial
    score: float           # 0-100
    reproducible: bool
    evidence_path: str
    poc_id: Optional[str]

@dataclass
class Evidence:
    id: str
    asset_id: str
    technique_id: str
    evidence_type: str
    hash_sha256: str       # 64-char hex, OBLIGATORIO
    chain_of_custody: List[str]
    content: Any
```

---

## Capa 3 — Detección híbrida

### Motores determinísticos

```
RuleEngine         12 reglas YARA-like
                   Cada regla: patterns (AND) + any_of (OR) + fields
                   Completamente determinístico — mismo input = mismo output

SigmaCorrelator    7 reglas correlación multi-evento
                   Modos: count | sequence | threshold
                   Ventanas temporales configurables

IoCMatcher         12 IoCs con tipos: string | domain | hash | filepath | process
                   Wildcard support para dominios (*.attacker.invalid)

AnomalyDetector    Z-score sobre métricas rolling
                   Algoritmo de Welford (online, O(1) por evento)
                   Mínimo 5 muestras antes de activar alertas
```

### RecurrentDepthReasoner (OpenMythos RDT)

Implementa la ecuación de actualización del Recurrent-Depth Transformer:

```
h_{t+1} = A·h_t + B·e + Transformer(h_t, e)

Donde:
  h_t  = hipótesis de amenaza actual (JSON)
  e    = evidencia original (inyectada en CADA loop — previene drift)
  A    = matriz de retención → implementada como RETENTION_DECAY=0.65
  B    = inyección → constante 1.0 (evidencia siempre presente)
  Transformer(h_t, e) = llamada a Anthropic API con experto + profundidad

Halting (ACT):
  ρ̂ = 1 - Jaccard(h_t, h_{t+1})
  Si ρ̂ < 0.28 → convergido, detener

MoE routing:
  8 expertos enrutados (uno por clúster de táctica ATT&CK)
  1 experto compartido (siempre activo: General Security Analyst)
  Loop 0 → experto compartido (reconocimiento amplio)
  Loop 1+ → especialista según technique_id (análisis profundo)

Loop-index embedding:
  Fase 0: reconocimiento general
  Fase 1: análisis técnico profundo
  Fase 2: refinamiento de hipótesis
  Fase 3+: convergencia y eliminación de falsos positivos
```

### Pipeline de detección completo

```python
from python_orchestrator.detectors.hybrid_detector import HybridDetector

detector = HybridDetector()
result = detector.analyze(findings, evidence_records)

# result.all_alerts       → List[DetectionAlert] (ordenadas por severidad × confianza)
# result.engine_stats     → {rule_engine_rules, sigma_rules, ioc_count,
#                            mythos_available, mythos_last_loops,
#                            mythos_spectral_profile, ...}
# result.new_rules_suggested → reglas generadas por LLM → registradas en RuleEngine
```

---

## Capa 4 — C y Rust

### Rust lab_service (`rust_validator/src/lab_service.rs`)

**Sustitución completa del C service en Rust.**
Misma interfaz CLI y exit codes. Seguro en memoria por diseño. macOS + Linux + Windows.

| Comando | Técnica | Superficie |
|---------|---------|------------|
| `add <text>` | T1190 | Bounds check — Rust enforces sin overflow real |
| `echo <input>` | T1190 | Format string detection (`%` chars) |
| `auth <u> <p>` | T1078, T1190 | Constant-time compare + timing simulation |
| `exec <cmd>` | T1059 | Shell metacharacter injection detection |
| `env` | T1082 | /etc/os-release, PID, env vars, Linux caps |
| `privesc` | T1548 | SUID scan (`PermissionsExt`), capabilities |
| `persist` | T1053 | Crontab paths + macOS LaunchAgents |
| `lateral <target>` | T1021 | Sovereignty check + pivot marker |
| `collect [path]` | T1005, T1003 | `std::fs::metadata` — sin stat() |
| `exfil <data>` | T1041 | DNS + C2 POST marker sintético |
| `dos <count>` | T1499 | CPU burn acotado + `std::hint::spin_loop` |
| `alloc <size>` | T1190 | Integer overflow bounds check con Vec |
| `selftest` | todos | 15 casos, `passed=15 failed=0` |
| `audit` | T1082+ | Surface scan completo |

**Por qué Rust en lugar de C:**
- `std::fs::metadata` reemplaza `stat()` — funciona en macOS Y Linux sin `#ifdef`
- Memory safety por diseño — imposible buffer overflow real (solo simulado)
- `cargo build --release` funciona igual en macOS y Linux sin flags de plataforma
- `ct_eq()` implementado en safe Rust sin `volatile` ni `ct_memcmp`

**Compilar:**
```bash
cargo build --release --manifest-path rust_validator/Cargo.toml
# Produce dos binarios:
# rust_validator/target/release/lab_service         ← superficie de ataque
# rust_validator/target/release/evidence_validator  ← auditoría
```

### Rust validator (`rust_validator/src/main.rs`)

Audit binary de 793 líneas con 9 comandos. Es la fuente de verdad del `blue_team_agent`.

| Comando | Función |
|---------|---------|
| `validate <finding.json>` | 8 checks: id, técnica, severidad, evidencia, SHA-256, chain |
| `validate-batch <dir>` | Valida todos los findings de un directorio |
| `audit-evidence <dir>` | SHA-256 chain audit sobre todos los EVD-*.json |
| `attack-surface` | PIDs, UIDs, FDs, memory maps, sockets, process tree |
| `entropy <file>` | Shannon entropy con ventanas de 512 bytes |
| `capabilities` | CapPrm, CapEff, CapBnd desde /proc/self/status |
| `sockets` | /proc/net/tcp,tcp6,udp,udp6 con decode de estado |
| `process-tree` | Cadena PPID hasta init |
| `audit-report [out.json]` | Reporte JSON completo: health=HEALTHY/DEGRADED/CRITICAL |

---

## Capa 5 — Web

### FastAPI (`web/api/main.py`)

10 endpoints REST:

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/status` | Estado del sistema + último scan |
| GET | `/api/summary` | Métricas ejecutivas |
| GET | `/api/findings` | Findings con filtros (severity, asset, detection_status) |
| GET | `/api/remediation` | Backlog agrupado por prioridad + owner |
| GET | `/api/chains` | Kill chains simuladas |
| GET | `/api/evidence` | Registros de evidencia |
| GET | `/api/detections` | Ejecuta HybridDetector, devuelve todas las alertas |
| GET | `/api/metrics` | Cobertura, gap, distribución de scores |
| POST | `/api/run` | Lanza un nuevo scan en background |
| GET | `/` | Sirve el dashboard React |

### Dashboard React

6 páginas en el dashboard (Rajdhani + Share Tech Mono, tema oscuro ops-center):

- **Overview** — 8 metric cards + PieChart severidades + BarChart scores + BarChart tácticas
- **Findings** — tabla sortable/filtrable con severity badges y score bars
- **Detectores** — stats de motores + feed de alertas (RULE/SIGMA/IOC/ANOMALY/LLM)
             + browser de reglas + browser de IoCs + análisis LLM (MythosReasoner)
- **Kill Chains** — cobertura de tácticas ATT&CK + tarjetas de cadenas con timeline
- **Remediación** — backlog agrupado por SLA con controles y reglas necesarias
- **Evidencia** — browser con chain-of-custody expandible + SHA-256

---

## Convenciones de código

Ver `docs/conventions.md` para naming, error handling y formato de artefactos.

## Verificación

Ver `docs/verification.md` para cómo demostrar que un cambio funciona.

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
