"""
moe_router.py
=============
Mixture-of-Experts router for threat analysis — inspired by OpenMythos's
fine-grained MoE design: each FFN is replaced by N small experts, a router
selects the top-k per token, and shared experts are always activated.

Here the "experts" are specialized analyst system prompts:
  - 8 routed experts (one per ATT&CK tactic cluster)
  - 1 shared expert (always active: general security analyst)

The router scores each event against the technique taxonomy and returns
the top-1 expert for single calls, or top-k for parallel analysis.

No ML — pure deterministic routing based on technique_id and tactic keywords.
The LLM (Transformer in the OpenMythos equation) receives the expert's
specialized system prompt, making each loop iteration structurally distinct
even though the same model weights are used.

This implements the "loop-index embedding" hypothesis: by varying the
system prompt with {expert_role, loop_depth}, each pass operates in a
different representational regime.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class Expert:
    id: str
    name: str
    techniques: List[str]        # T-codes handled by this expert
    tactic_keywords: List[str]   # tactic name fragments
    system_prompt: str
    shared: bool = False         # shared experts are always activated


# ─── Expert definitions (1 shared + 8 routed) ────────────────────────────────

SHARED_EXPERT = Expert(
    id="EXP-SHARED",
    name="General Security Analyst",
    techniques=[],
    tactic_keywords=[],
    system_prompt="""Eres un analista de ciberseguridad senior con experiencia en MITRE ATT&CK.
Tu rol: evaluar cualquier hallazgo de seguridad con rigor técnico y sin sesgo.
Principios: evidencia > conjetura. Sin hallazgos sin evidencia verificable.
Formato de respuesta: JSON puro, sin markdown.""",
    shared=True,
)

ROUTED_EXPERTS: List[Expert] = [
    Expert(
        id="EXP-001",
        name="Initial Access & Exploitation Specialist",
        techniques=["T1190", "T1133", "T1078", "T1091"],
        tactic_keywords=["initial access", "exploit", "boundary", "edge", "external"],
        system_prompt="""Especialista en Initial Access y explotación de perímetro.
Enfoque: vulnerabilidades en superficies expuestas, bypass de autenticación, explotación remota.
Evalúa: CVSS, exploitability, patch status, WAF coverage.
Hipótesis típicas: CVE sin parchear, credenciales expuestas, servicios sin MFA.""",
    ),
    Expert(
        id="EXP-002",
        name="Execution & Command Injection Specialist",
        techniques=["T1059", "T1203", "T1106", "T1053"],
        tactic_keywords=["execution", "command", "script", "interpreter", "shell", "payload"],
        system_prompt="""Especialista en Execution: inyección de comandos, scripting, scheduled tasks.
Enfoque: análisis de command chains, shell metacharacters, script block logging gaps.
Evalúa: argument arrays vs shell=True, process ancestry, AppLocker gaps.
Hipótesis típicas: shell injection, unsanitized subprocess calls, cron misconfigurations.""",
    ),
    Expert(
        id="EXP-003",
        name="Persistence & Evasion Specialist",
        techniques=["T1053", "T1547", "T1098", "T1562"],
        tactic_keywords=["persistence", "defense evasion", "scheduled", "startup", "boot"],
        system_prompt="""Especialista en Persistence y Defense Evasion.
Enfoque: mecanismos de supervivencia a reinicios, bypass de controles de seguridad.
Evalúa: FIM coverage, agent health monitoring, telemetry gaps, log integrity.
Hipótesis típicas: cron sin monitoring, disabled EDR, log tampering, living-off-the-land.""",
    ),
    Expert(
        id="EXP-004",
        name="Privilege Escalation Specialist",
        techniques=["T1548", "T1055", "T1134", "T1611"],
        tactic_keywords=["privilege", "escalation", "elevation", "root", "admin", "sudo"],
        system_prompt="""Especialista en Privilege Escalation: escalación local y cloud.
Enfoque: sudo misconfigs, SUID binaries, capability abuse, container escapes.
Evalúa: PAM controls, JIT access, least-privilege enforcement, kernel exploits.
Hipótesis típicas: NOPASSWD sudo, SUID bit on writeable binary, cap_setuid abuse.""",
    ),
    Expert(
        id="EXP-005",
        name="Credential Access Specialist",
        techniques=["T1003", "T1078", "T1552", "T1558", "T1110"],
        tactic_keywords=["credential", "password", "hash", "token", "lsass", "secrets", "vault"],
        system_prompt="""Especialista en Credential Access: dumping, stealing, brute forcing.
Enfoque: LSASS protection, secrets management, MFA gaps, Kerberos attacks.
Evalúa: LSA protection, Credential Guard, secrets rotation policy, anomaly detection.
Hipótesis típicas: LSASS dump, /etc/shadow access, secrets exposed in env vars.""",
    ),
    Expert(
        id="EXP-006",
        name="Discovery & Lateral Movement Specialist",
        techniques=["T1082", "T1021", "T1046", "T1135", "T1049"],
        tactic_keywords=["discovery", "lateral", "movement", "scan", "enumerate", "pivot", "remote"],
        system_prompt="""Especialista en Discovery y Lateral Movement.
Enfoque: network enumeration, SSH/RDP/WinRM abuse, east-west traffic, micro-segmentation.
Evalúa: network monitoring coverage, segment boundaries, east-west inspection.
Hipótesis típicas: unrestricted SSH between segments, no east-west detection, SMB relay.""",
    ),
    Expert(
        id="EXP-007",
        name="Collection & Exfiltration Specialist",
        techniques=["T1005", "T1074", "T1041", "T1048", "T1567"],
        tactic_keywords=["collection", "exfil", "staging", "data", "transfer", "egress", "dns"],
        system_prompt="""Especialista en Collection y Exfiltration.
Enfoque: DLP gaps, egress filtering, DNS tunneling, staging points, large file transfers.
Evalúa: DLP rules, egress allowlists, DNS monitoring, outbound anomaly detection.
Hipótesis típicas: no egress filtering, DNS exfil via subdomain, unmonitored cloud upload.""",
    ),
    Expert(
        id="EXP-008",
        name="Impact & DoS Specialist",
        techniques=["T1499", "T1486", "T1490", "T1531"],
        tactic_keywords=["impact", "dos", "denial", "ransom", "destroy", "disrupt", "availability"],
        system_prompt="""Especialista en Impact: DoS, ransomware, data destruction.
Enfoque: availability controls, rate limiting, backup integrity, BCDR testing.
Evalúa: rate limits, connection quotas, auto-remediation, backup recoverability.
Hipótesis típicas: no rate limiting, unprotected backups, missing BCDR procedures.""",
    ),
]

# Build lookup maps
_TECHNIQUE_TO_EXPERT: Dict[str, Expert] = {}
for exp in ROUTED_EXPERTS:
    for t in exp.techniques:
        _TECHNIQUE_TO_EXPERT[t] = exp


class MoERouter:
    """
    Routes threat events to the appropriate specialist expert.

    Implements the OpenMythos MoE design:
      - Routed experts: selected based on technique_id / tactic keywords
      - Shared expert: always activated (injected into every prompt)
    """

    def route_single(self, event: Dict[str, Any]) -> Expert:
        """Select the single best expert for an event."""
        technique_id = event.get("technique_id", "")
        if technique_id in _TECHNIQUE_TO_EXPERT:
            return _TECHNIQUE_TO_EXPERT[technique_id]

        # Fallback: keyword scoring against tactic field
        tactic = (event.get("tactic", "") + " " + event.get("title", "")).lower()
        best_score = -1
        best_expert = ROUTED_EXPERTS[0]
        for exp in ROUTED_EXPERTS:
            score = sum(1 for kw in exp.tactic_keywords if kw in tactic)
            if score > best_score:
                best_score = score
                best_expert = exp
        return best_expert

    def route_topk(self, event: Dict[str, Any], k: int = 2) -> List[Expert]:
        """Return top-k experts for parallel analysis."""
        technique_id = event.get("technique_id", "")
        tactic = (event.get("tactic", "") + " " + event.get("title", "")).lower()

        scored: List[Tuple[int, Expert]] = []
        for exp in ROUTED_EXPERTS:
            score = sum(1 for kw in exp.tactic_keywords if kw in tactic)
            if technique_id in exp.techniques:
                score += 10
            scored.append((score, exp))

        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:k]]

    def get_shared_expert(self) -> Expert:
        return SHARED_EXPERT

    def build_system_prompt(self, expert: Expert, loop_depth: int = 0) -> str:
        """
        Build the final system prompt combining shared + routed expert.
        Includes loop-index embedding: different depths → different reasoning phases.

        Phase 0: broad pattern recognition
        Phase 1: deep technical analysis
        Phase 2+: focused hypothesis refinement
        """
        phases = [
            "Fase 0 — Reconocimiento: identifica patrones generales, clasifica la amenaza.",
            "Fase 1 — Análisis técnico: profundiza en el vector de ataque, evalúa controles faltantes.",
            "Fase 2 — Refinamiento: formula hipótesis específicas, prioriza por riesgo real.",
            "Fase 3+ — Convergencia: consolida el análisis, descarta falsos positivos, genera reglas.",
        ]
        phase = phases[min(loop_depth, 3)]

        return f"""{SHARED_EXPERT.system_prompt}

ROL ESPECIALIZADO: {expert.name}
{expert.system_prompt}

PROFUNDIDAD DE RAZONAMIENTO: loop={loop_depth}
{phase}

Responde SOLO con JSON válido. Sin markdown. Sin texto fuera del JSON."""

    @property
    def expert_count(self) -> int:
        return len(ROUTED_EXPERTS) + 1  # +1 shared
