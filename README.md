# AI Cyber Range — Ofensiva Controlada con IA

> **Powered by [AxisDynamics](https://axisdynamics.cl)** · Licencia MIT

> **Institucionalizar el ataque autorizado antes del ataque real.**

Programa permanente de red team agentivo sobre activos críticos propios.
Un agente de IA simula kill chains autorizados, valida cobertura de detección,
genera evidencia verificable y mantiene un backlog de remediación priorizado —
todo bajo soberanía absoluta y con reglas propias.

---

## Inicio rápido

```bash
git clone <repo>
chmod +x install.sh start.sh
./install.sh                  # venv + deps Python + FastAPI + C + Rust (+ npm si disponible)

./start.sh                    # pipeline completo (ofensiva + detección + remediación)
./start.sh --web              # pipeline + dashboard en http://localhost:8080
./start.sh --web-only         # solo el servidor web (carga el último reporte)
./start.sh --watch            # CI/CD loop continuo (re-ejecuta cada 60s)
```

Si no tienes npm, el dashboard funciona igual:

```bash
open web/frontend/dashboard_standalone.html   # sin build, sin deps
```

---

## Arquitectura en cinco capas

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. HARNESS (Líder → Red Team → Blue Team)                          │
│     CLAUDE.md  AGENTS.md  engagement_backlog.json  progress/        │
│     .claude/agents/{cyber_leader,red_team_agent,blue_team_agent}.md │
├─────────────────────────────────────────────────────────────────────┤
│  2. PIPELINE OFENSIVO (Python)                                       │
│     GovernanceAgent → OffensiveHarness → AttackChainSimulator       │
│     EvasionTester → PoCBuilder → EvidenceEngine → RemediationEngine │
├─────────────────────────────────────────────────────────────────────┤
│  3. DETECCIÓN HÍBRIDA (determinístico + IA recurrente)              │
│     RuleEngine (12 reglas) + SigmaCorrelator (7 reglas)             │
│     IoCMatcher (12 IoCs) + AnomalyDetector (Z-score)               │
│     └── HybridDetector → RecurrentDepthReasoner (OpenMythos RDT)   │
│              MoERouter (8 expertos + 1 compartido)                  │
├─────────────────────────────────────────────────────────────────────┤
│  4. CAPA NATIVA (C + Rust)                                          │
│     c_service/   — 14 superficies de ataque, 11 técnicas ATT&CK    │
│     rust_validator/ — audit binary: SHA-256, entropía, superficies │
├─────────────────────────────────────────────────────────────────────┤
│  5. WEB DASHBOARD (React + FastAPI)                                  │
│     6 páginas: Overview · Findings · Detectores · Kill Chains       │
│                Remediación · Evidencia                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Comandos del harness

```bash
# Ver backlog de escenarios
python3 -m python_orchestrator.harness.run_scenario --list

# Verificar estado del arnés (CHECKPOINTS C1-C6)
python3 -m python_orchestrator.harness.run_scenario --verify

# Ejecutar el siguiente escenario pendiente (Líder→RedTeam→BlueTeam)
python3 -m python_orchestrator.harness.run_scenario

# Ejecutar escenario específico
python3 -m python_orchestrator.harness.run_scenario --scenario-id 4
```

El patrón anti-hallucination: cada subagente escribe en `progress/impl_<id>.md`
y devuelve solo la referencia. Un finding sin `artifacts/evidence/EVD-*.json`
con SHA-256 verificable **no existe**.

---

## Capa nativa

```bash
# C service — 14 comandos, 11 técnicas ATT&CK
make -C c_service              # hardened (todas las mitigaciones)
make -C c_service vulnerable   # mitigaciones desactivadas (T1190 surface)
make -C c_service debug        # AddressSanitizer
./c_service/build/lab_service selftest   # 15 casos, todos green

# Rust validator — 9 comandos de auditoría
cargo build --release --manifest-path rust_validator/Cargo.toml
./rust_validator/target/release/evidence_validator validate <finding.json>
./rust_validator/target/release/evidence_validator audit-report
./rust_validator/target/release/evidence_validator attack-surface
./rust_validator/target/release/evidence_validator entropy <binary>
```

---

## Estructura del proyecto

```
ai_cyber_range_project/
├── CLAUDE.md                    ← Claude Code: actúa siempre como cyber_leader
├── AGENTS.md                    ← Mapa de navegación (divulgación progresiva)
├── CHECKPOINTS.md               ← Criterios C1-C6 de "range sano"
├── engagement_backlog.json      ← 8 escenarios: 3 done, 5 pending
├── progress/
│   ├── current.md               ← Estado de la sesión activa
│   └── history.md               ← Bitácora append-only
├── .claude/agents/
│   ├── cyber_leader.md
│   ├── red_team_agent.md
│   └── blue_team_agent.md
├── configs/
│   ├── default.yaml
│   └── engagement_perimeter.yaml
├── docs/
│   ├── ARCHITECTURE.md          ← Arquitectura detallada
│   ├── OPERATING_MODEL.md       ← Modelo operativo y SLAs
│   └── OFFENSIVE_PLAYBOOK.md    ← Tácticas autorizadas
├── python_orchestrator/
│   ├── main.py
│   ├── agents/                  ← GovernanceAgent, OffensiveHarness, RedTeam, etc.
│   │   ├── mythos_reasoner.py   ← RecurrentDepthReasoner (OpenMythos RDT)
│   │   └── moe_router.py        ← MoE routing (9 expertos ATT&CK)
│   ├── detectors/               ← RuleEngine, Sigma, IoC, Anomaly, HybridDetector
│   ├── harness/                 ← HarnessOrchestrator, SessionManager, run_scenario
│   ├── engine/                  ← EvidenceEngine, RemediationEngine
│   ├── core/                    ← models.py, io.py
│   └── data/                    ← assets.json, attack_subset.json, synthetic_logs.jsonl
├── c_service/
│   ├── src/lab_service.c        ← 455 líneas, 14 comandos, 11 técnicas
│   └── Makefile                 ← hardened / vulnerable / debug
├── rust_validator/
│   └── src/main.rs              ← 793 líneas, 9 comandos de auditoría
├── web/
│   ├── api/main.py              ← FastAPI (10 endpoints REST)
│   └── frontend/
│       ├── dashboard_standalone.html  ← sin npm, funciona directamente
│       └── src/                       ← React + Vite (npm run build)
├── artifacts/
│   ├── FND-SCN-*.json           ← Findings por activo × técnica
│   ├── SCN-*_evidence.json      ← Evidencias con SHA-256
│   └── evidence/EVD-*.json      ← Registros de evidencia con chain of custody
├── install.sh
├── start.sh
└── tests/
```

---

## Motor de detección híbrida

El `HybridDetector` combina cuatro motores determinísticos con razonamiento
iterativo en profundidad inspirado en la arquitectura OpenMythos (RDT):

```
Eventos/Findings
    │
    ├── RuleEngine         12 reglas YARA-like (AND/OR, regex compilado)
    ├── SigmaCorrelator    7 reglas: count / sequence / threshold, ventanas temporales
    ├── IoCMatcher         12 IoCs: strings, dominios wildcard, hashes, procesos
    └── AnomalyDetector    Z-score, algoritmo de Welford, rolling baseline
         │
         ▼ Consolidación por confianza
    HybridDetector
         │
         ├── Alta confianza  → DetectionAlert inmediata (determinístico puro)
         └── Novel / baja    → RecurrentDepthReasoner
                                 h_{t+1} = A·h_t + B·e + Transformer(h_t, e)
                                 ├── MoERouter: 8 expertos + 1 compartido
                                 ├── Loop-index embedding (Fase 0→1→2→3)
                                 ├── ACT halt: ρ̂ < 0.28 → convergido
                                 └── Nuevas reglas → RuleEngine (learning loop)
```

Si `ANTHROPIC_API_KEY` está disponible, el razonador itera hasta 4 loops.
Sin API key, opera en modo determinístico puro sin degradación.

---

## Soberanía (no negociable)

| Parámetro | Valor |
|-----------|-------|
| `allow_external_targets` | `false` — hardcoded en governance |
| Técnicas bloqueadas | T1485, T1561, T1529 (destructivas) |
| Ejecución | Solo sobre fixtures locales, sin impacto real |
| Evidencia | SHA-256 + chain of custody obligatorio |
| `init.sh` | Rechaza el arnés si viola C1-C6 |

---

## Métricas del último run (RUN-A54858EC)

| Métrica | Valor |
|---------|-------|
| Findings | 35 (8 críticos · 12 altos · 11 medios · 4 bajos) |
| Cobertura ATT&CK | 97.2% |
| Detection gap | 62.9% (53/84 controles evadidos) |
| Kill chains | 36 simuladas (profundidad 6) |
| PoCs reproducibles | 32 |
| Evidencias (SHA-256) | 78 registros |
| Tickets remediación | 35 abiertos (8 con SLA=1d) |
---

## Licencia

MIT License — Copyright © 2026 [AxisDynamics](https://axisdynamics.cl)

Ver [LICENSE](./LICENSE) para el texto completo.

---

<p align="center">
  <strong>Powered by <a href="https://axisdynamics.cl">AxisDynamics</a></strong><br/>
  <em>Ofensiva Controlada con IA · MITRE ATT&CK · Harness Engineering</em>
</p>
