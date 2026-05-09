# Arquitectura — AI Cyber Range

> v2.0-beta · Última actualización: 2026-05-08

---

## Las 6 capas

```
┌──────────────────────────────────────────────────────────────────────┐
│  C1 · HARNESS                                                        │
│  CLAUDE.md · AGENTS.md · CHECKPOINTS.md                             │
│  engagement_backlog.json · progress/ · .claude/agents/              │
├──────────────────────────────────────────────────────────────────────┤
│  C2 · src/cyber_range/ (paquete Python productivo)                   │
│  cli/ · config/ · policy/ · pipeline/ · scoring/                    │
│  evidence/ · reporting/ · logging/ · api/                           │
├──────────────────────────────────────────────────────────────────────┤
│  C3 · HERMES MULTI-AGENTE                                            │
│  HermesOrchestrator → 9 agentes paralelos → AgentMemory (SQLite)    │
│  GapAnalysisAgent → prioriza por historial de evasión               │
├──────────────────────────────────────────────────────────────────────┤
│  C4 · PIPELINE OFENSIVO (python_orchestrator/)                       │
│  Governance → OffensiveHarness → Chains → Evasion → PoC → Evidence  │
├──────────────────────────────────────────────────────────────────────┤
│  C5 · DETECCIÓN HÍBRIDA + RDT (OpenMythos)                          │
│  RuleEngine · Sigma · IoC · Anomaly → HybridDetector → Mythos        │
├──────────────────────────────────────────────────────────────────────┤
│  C6 · NATIVO + WEB                                                   │
│  Rust: lab_service + evidence_validator · React + FastAPI            │
└──────────────────────────────────────────────────────────────────────┘
```

---

## C2 — src/cyber_range/ (paquete productivo)

`pip install -e .` → entrypoint `cyber-range`.

### config/schema.py — Pydantic v2

Valida toda config antes de ejecutar. Fail-closed.  
`allow_external_targets=true` → rechazado siempre.  
`T1485, T1561, T1529` → siempre en `blocked_techniques`.

### policy/enforcer.py — Fail-closed

```python
enforcer.check_technique("T1485")           # BLOCKED (hardcoded)
enforcer.check_asset("8.8.8.8")             # BLOCKED (external IP)
enforcer.check_scenario("iam_role", "T1078") # asset + technique juntos
```

### scoring/engine.py — Determinístico, siempre [0,100]

```python
coverage_pct(finding_techs, scope)     # nunca > 100%
detection_gap_pct(findings)            # fracción con status=gap
risk_score(severity, criticality, ...) # 0-100
confidence_score(repro, evidence, ver) # 0.0-1.0
```

### evidence/verifier.py — SHA-256 + tamper detection

Estados: `valid | missing | modified | unreferenced | no_hash`.  
`report.passed` → True solo si missing=0 AND modified=0 AND no_hash=0.

### reporting/generator.py — Schema v1 estable

```json
{
  "schema_version": "1.0",
  "executive_summary": {
    "coverage_pct": 97.2,
    "detection_gap_pct": 65.8
  },
  "findings": [...],
  "limitations": [...]
}
```

### api/app.py — FastAPI

- Auth: `X-API-Key` header (configurable)
- CORS: allowlist explícita, nunca `*`
- Errores: `{"error": {"code": "...", "message": "...", "details": {}}}`

---

## C3 — Hermes Multi-Agente

```
HermesOrchestrator
├── AgentMemory (SQLite: artifacts/agent_memory.db)
│   ├── get_persistent_gaps(min_occurrences=2)
│   ├── get_priority_techniques(scope)  ← gap_rate × avg_score
│   └── get_technique_learning(tech_id)
│
├── GapAnalysisAgent — prioriza técnicas por historial de evasión
│
└── ThreadPoolExecutor (max_workers=4):
    ├── InitialAccessAgent  (T1190, T1078, T1133)
    ├── ExecutionAgent      (T1059, T1053, T1203)
    ├── PrivilegeAgent      (T1548, T1055, T1134)
    ├── EvasionAgent        (T1562, T1078, T1027)
    ├── CredentialAgent     (T1003, T1552, T1558)
    ├── DiscoveryAgent      (T1082, T1046, T1049)
    ├── LateralAgent        (T1021, T1091, T1550)
    ├── CollectionAgent     (T1005, T1041, T1074)
    └── ImpactAgent         (T1499, T1486, T1490)
```

**Flujo por agente:**
```
PolicyEnforcer.check_scenario()  ← SIEMPRE PRIMERO
    BLOCKED → skip + log
    ALLOWED → RedTeamAgent.run_scenario() → AgentResult
```

**Memoria cross-run:**
```python
memory.remember_run(summary)           # métricas del run
memory.remember_findings(run_id, fs)   # actualiza gaps y learning
priority = memory.get_priority_techniques(scope)
# → técnicas con mayor gap_rate y avg_score primero
```

---

## C4 — Pipeline ofensivo

```
GovernanceAgent.authorize()
    └── OffensiveHarness.run()
            ├── [asset × technique]: RedTeamAgent.run_scenario()
            │   ├── AttackChainSimulator  → kill chains (depth=6)
            │   ├── EvasionTester        → control bypass tests
            │   ├── PoCBuilder           → PoCs + SHA-256
            │   └── EvidenceEngine       → EVD-*.json
            ├── ReviewerAgent            → dedup + quality gate
            ├── RiskScoringEngine        → priorización
            └── RemediationEngine        → tickets con SLA
```

---

## C5 — Detección híbrida + RDT

```
Findings
    ├── RuleEngine         12 reglas determinísticas
    ├── SigmaCorrelator    7 reglas correlación multi-evento
    ├── IoCMatcher         12 IoCs
    └── AnomalyDetector    Z-score Welford
         └── HybridDetector
                  ├── Alta confianza → alert inmediata
                  └── Novel/baja → RecurrentDepthReasoner
                            h_{t+1} = A·h_t + B·e + Transformer(h_t,e)
                            MoERouter: 8 expertos + 1 compartido
                            ACT halt: ρ̂ < 0.28
```

---

## C6 — Capa nativa + Web

### Rust (`rust_validator/`)

| Binario | Comandos | Técnicas |
|---------|---------|---------|
| `lab_service` | add, echo, auth, exec, env, privesc, persist, lateral, collect, exfil, dos, alloc, selftest, audit | T1190, T1059, T1078, T1548, T1082, T1003, T1021, T1005, T1041, T1499, T1053 |
| `evidence_validator` | validate, audit-evidence, attack-surface, entropy, sockets... | — |

Compilación: `cargo build --release --manifest-path rust_validator/Cargo.toml`.

### Web

React (6 páginas) + FastAPI. `dist/` pre-compilado incluido en el repositorio.

---

## Artefactos por run

```
artifacts/runs/<RUN_ID>/
    summary.json          ← métricas del run
    findings.json         ← findings con scores [0,100]
    evidence/             ← copias EVD-*.json
    report.md + report.json
    chain_of_custody.json
    logs.jsonl            ← JSONL sin secretos
    agent_results.json    ← (modo agent) métricas por agente
```

---

## Tests — 115 passing, 85% cobertura core

| Archivo | Tests | Cobertura |
|---------|-------|-----------|
| `test_scoring.py` | 28 | 100% |
| `test_config.py` | 13 | 95% |
| `test_logging.py` | 15 | 95% |
| `test_policy.py` | 17 | 94% |
| `test_reporting.py` | 13 | 76% |
| `test_evidence.py` | 7 | 69% |
| `test_memory.py` | 10 | — |

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
