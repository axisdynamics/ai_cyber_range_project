"""
mythos_reasoner.py
==================
RecurrentDepthReasoner — implements the OpenMythos Recurrent-Depth Transformer
loop pattern using the Anthropic API as the "Transformer" function.

Architecture (from OpenMythos README):
    h_{t+1} = A·h_t + B·e + Transformer(h_t, e)

Where:
    h_t  = current threat hypothesis (text/JSON state)
    e    = encoded evidence (original context, injected at EVERY loop)
    A    = retention matrix → implemented as exponential decay on old hypothesis weight
    B    = injection matrix → constant 1.0 (full evidence injection, no context drift)
    Transformer(h_t, e) = Anthropic API call with expert system prompt + loop index

Stability (LTI constraint from Parcae paper):
    We track ρ̂ (spectral radius proxy) as the normalized Jaccard distance
    between consecutive hypothesis bags-of-words. Convergence when ρ̂ < threshold.
    This ensures ρ(A) < 1 by design — the loop ALWAYS terminates.

ACT (Adaptive Computation Time):
    Simple examples converge in 1-2 loops.
    Complex multi-hop kill chains require 4-6 loops.
    The reasoner halts dynamically per-evidence, not at a fixed depth.

MoE (Mixture of Experts):
    At each loop step, the MoERouter selects the specialist expert.
    Expert identity changes across loops (loop-index embedding effect):
        Loop 0: broad recognition (shared expert)
        Loop 1+: specialist expert (based on technique routing)
    This allows the same model to operate in functionally distinct phases.

Depth-wise LoRA (from Relaxed Recursive Transformers):
    Each loop step uses a slightly different system prompt (the "LoRA adapter").
    Same base model, different per-depth specialization.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from python_orchestrator.agents.moe_router import MoERouter, Expert


# ─── Configuration ──────────────────────────────────────────────────────────

MAX_LOOPS          = 6      # Maximum loop iterations (Prelude+Coda = 2, Recurrent = max 4)
CONVERGENCE_THRESH = 0.72   # Jaccard similarity for ACT halt
RETENTION_DECAY    = 0.65   # α coefficient (how much old state to keep per loop)
LLM_TIMEOUT        = 20     # seconds


# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass
class LoopState:
    """Represents h_t at loop step t."""
    loop_index: int
    hypothesis: str           # free-text threat hypothesis
    confidence: float         # 0.0-1.0 
    technique_ids: List[str]
    severity: str
    novel_patterns: List[str]
    recommended_rules: List[str]
    spectral_radius_proxy: float  # ρ̂ estimate (smaller = more converged)
    expert_id: str
    tokens_used: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MythosResult:
    """Result of one RecurrentDepthReasoner run."""
    final_hypothesis: str
    consolidated_severity: str
    consolidated_confidence: float
    n_loops: int
    converged: bool
    technique_ids: List[str]
    novel_patterns: List[str]
    recommended_rules: List[str]
    recommended_iocs: List[str]
    loop_trace: List[LoopState]      # one entry per loop (anti-teléfono-descompuesto: in memory only)
    spectral_radius_profile: List[float]
    expert_routing: List[str]
    total_tokens: int
    analysis_summary: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["loop_trace"] = [s.to_dict() for s in self.loop_trace]
        return d


# ─── Jaccard similarity for convergence detection ────────────────────────────

def _tokenize(text: str) -> set:
    """Simple bag-of-words tokenizer for convergence detection."""
    return set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b', text.lower()))


def _jaccard(a: str, b: str) -> float:
    """Jaccard similarity ∈ [0,1] — 1 = identical, 0 = no overlap."""
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta and not tb:
        return 1.0
    intersection = len(ta & tb)
    union = len(ta | tb)
    return intersection / union if union > 0 else 0.0


def _spectral_proxy(h_old: str, h_new: str) -> float:
    """
    Proxy for spectral radius ρ̂ = 1 - Jaccard(h_old, h_new).
    ρ̂ → 0 means convergence (new state ≈ old state).
    ρ̂ → 1 means divergence (completely new content each loop).
    Halt when ρ̂ < (1 - CONVERGENCE_THRESH).
    """
    return 1.0 - _jaccard(h_old, h_new)


# ─── RecurrentDepthReasoner ───────────────────────────────────────────────────

class RecurrentDepthReasoner:
    """
    OpenMythos-inspired recurrent threat reasoning engine.

    Runs the loop:
        h_{t+1} = α·h_t + LLM(h_t, e, depth=t, expert=route(h_t,e))

    where:
        α = RETENTION_DECAY (how much old hypothesis to preserve)
        e = evidence (injected at every loop — never dropped)
        LLM = Anthropic API (the "Transformer" in the OpenMythos equation)

    Terminates when:
        ρ̂(h_t, h_{t+1}) < convergence_threshold (ACT halt)
        OR t == MAX_LOOPS (hard cap)
        OR API unavailable (falls back to single-loop)
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._available = bool(self._api_key)
        self._moe = MoERouter()

    def reason(
        self,
        events: List[Dict[str, Any]],
        existing_alerts_summary: str = "",
        max_loops: int = MAX_LOOPS,
    ) -> MythosResult:
        """
        Main entry point. Runs the recurrent reasoning loop.

        Args:
            events: list of finding/evidence dicts (the encoded input e)
            existing_alerts_summary: summary of deterministic alerts (context)
            max_loops: maximum loop iterations

        Returns:
            MythosResult with final analysis and full loop trace
        """
        if not events:
            return self._empty_result()

        # ── Prelude phase (h_0 initialization) ──────────────────────────────
        e = self._encode_evidence(events, existing_alerts_summary)
        h = self._initial_hypothesis(events)

        loop_trace: List[LoopState] = []
        spectral_profile: List[float] = []
        expert_routing: List[str] = []
        total_tokens = 0
        converged = False

        # ── Recurrent block (the looped Transformer) ─────────────────────────
        for t in range(max_loops):
            # MoE routing: shared expert at loop 0, specialized at loop 1+
            if t == 0:
                expert = self._moe.get_shared_expert()
            else:
                primary_event = events[0] if events else {}
                expert = self._moe.route_single({**primary_event, "hypothesis": h})

            system_prompt = self._moe.build_system_prompt(expert, loop_depth=t)

            # LLM call: Transformer(h_t, e, depth=t)
            if self._available:
                h_new, tokens = self._llm_step(h, e, system_prompt, t)
            else:
                # Degraded mode: simple deterministic step
                h_new = self._deterministic_step(h, e, t)
                tokens = 0

            # Retention: α·h_t blend (keep some old state to prevent full reset)
            if t > 0:
                h_new = self._blend_states(h, h_new, alpha=RETENTION_DECAY)

            # Spectral radius proxy (convergence check)
            rho_hat = _spectral_proxy(h, h_new)
            spectral_profile.append(round(rho_hat, 4))

            state = LoopState(
                loop_index=t,
                hypothesis=h_new[:500],
                confidence=max(0.0, 1.0 - rho_hat),
                technique_ids=self._extract_techniques(h_new),
                severity=self._extract_severity(h_new),
                novel_patterns=self._extract_patterns(h_new),
                recommended_rules=self._extract_rules(h_new),
                spectral_radius_proxy=rho_hat,
                expert_id=expert.id,
                tokens_used=tokens,
            )
            loop_trace.append(state)
            expert_routing.append(expert.id)
            total_tokens += tokens

            # ACT halt condition: ρ̂ < threshold
            if rho_hat < (1.0 - CONVERGENCE_THRESH):
                converged = True
                h = h_new
                break

            h = h_new

        # ── Coda phase (final consolidation) ─────────────────────────────────
        final = self._consolidate(h, loop_trace, e)

        return MythosResult(
            final_hypothesis=final.get("summary", h[:400]),
            consolidated_severity=final.get("severity", "medium"),
            consolidated_confidence=final.get("confidence", 0.6),
            n_loops=len(loop_trace),
            converged=converged,
            technique_ids=final.get("technique_ids", []),
            novel_patterns=final.get("novel_patterns", []),
            recommended_rules=final.get("recommended_rules", []),
            recommended_iocs=final.get("recommended_iocs", []),
            loop_trace=loop_trace,
            spectral_radius_profile=spectral_profile,
            expert_routing=expert_routing,
            total_tokens=total_tokens,
            analysis_summary=final.get("summary", "Sin análisis disponible"),
        )

    # ─── Prelude helpers ────────────────────────────────────────────────────

    def _encode_evidence(
        self, events: List[Dict], alerts_summary: str
    ) -> str:
        """Encode input `e` — injected at every loop step."""
        snippets = []
        for ev in events[:5]:
            snippet = {
                k: str(v)[:100]
                for k, v in ev.items()
                if k in ("asset", "technique_id", "severity", "detection_status",
                         "summary", "score", "tactic")
            }
            snippets.append(snippet)
        return json.dumps({
            "events": snippets,
            "alerts_context": alerts_summary[:300],
            "event_count": len(events),
        }, ensure_ascii=False)

    @staticmethod
    def _initial_hypothesis(events: List[Dict]) -> str:
        """h_0: generate initial hypothesis from event metadata (no LLM)."""
        techniques = list({e.get("technique_id", "") for e in events if e.get("technique_id")})
        assets     = list({e.get("asset", "") for e in events if e.get("asset")})
        gaps       = sum(1 for e in events if e.get("detection_status") == "gap")
        return json.dumps({
            "techniques": techniques[:5],
            "assets": assets[:4],
            "detection_gaps": gaps,
            "hypothesis": f"Análisis inicial: {len(events)} eventos, {gaps} gaps de detección.",
            "severity": "medium",
            "confidence": 0.3,
        }, ensure_ascii=False)

    # ─── Recurrent block helpers ────────────────────────────────────────────

    def _llm_step(
        self,
        h: str,
        e: str,
        system_prompt: str,
        loop_index: int,
    ) -> Tuple[str, int]:
        """One Transformer(h_t, e) step via Anthropic API."""
        try:
            import urllib.request

            # The input injection B·e is always present (prevents context drift)
            user_message = f"""HIPÓTESIS ACTUAL (h_{loop_index}):
{h[:600]}

EVIDENCIA ORIGINAL (e — inyectada en cada loop):
{e[:500]}

Profundidad de loop actual: {loop_index}

Tarea: Refina la hipótesis. Identifica patrones nuevos no capturados por detectores determinísticos.
Responde con JSON: {{
  "summary": "...",
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0,
  "technique_ids": [...],
  "novel_patterns": [...],
  "recommended_rules": [...],
  "recommended_iocs": [...],
  "reasoning_depth_note": "qué aportó este loop que el anterior no tenía"
}}"""

            payload = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 700,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}],
            }).encode()

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
                data = json.loads(resp.read())

            text = "".join(
                b.get("text", "") for b in data.get("content", [])
                if b.get("type") == "text"
            ).strip()

            # Strip markdown fences
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:]).rstrip("`").strip()

            tokens = data.get("usage", {}).get("output_tokens", 0)
            return text, tokens

        except Exception as exc:
            # Graceful degradation: return h_t unchanged on error
            return h, 0

    @staticmethod
    def _deterministic_step(h: str, e: str, loop_index: int) -> str:
        """Fallback when LLM is unavailable — rule-based refinement."""
        try:
            state = json.loads(h)
        except Exception:
            state = {"hypothesis": h, "severity": "medium", "confidence": 0.5}

        # Slightly increase confidence with each deterministic loop
        state["confidence"] = min(0.7, float(state.get("confidence", 0.5)) + 0.05)
        state["summary"] = (
            f"[Modo determinístico, loop={loop_index}] "
            f"{state.get('hypothesis', state.get('summary', 'Análisis sin LLM'))}"
        )
        return json.dumps(state, ensure_ascii=False)

    @staticmethod
    def _blend_states(h_old: str, h_new: str, alpha: float) -> str:
        """
        Retention blend: α·h_old + (1-α)·h_new
        Implemented as merging JSON fields (numeric blend + set union for lists).
        """
        try:
            old = json.loads(h_old)
            new = json.loads(h_new)
        except Exception:
            return h_new  # can't blend, use new state

        blended = {}
        for key in set(list(old.keys()) + list(new.keys())):
            old_val = old.get(key)
            new_val = new.get(key)
            if isinstance(old_val, float) and isinstance(new_val, float):
                blended[key] = round(alpha * old_val + (1 - alpha) * new_val, 3)
            elif isinstance(old_val, list) and isinstance(new_val, list):
                # Union of lists (set-like merge)
                blended[key] = list(dict.fromkeys(old_val + new_val))[:10]
            else:
                blended[key] = new_val if new_val is not None else old_val

        return json.dumps(blended, ensure_ascii=False)

    # ─── Coda phase ─────────────────────────────────────────────────────────

    def _consolidate(
        self,
        final_h: str,
        loop_trace: List[LoopState],
        evidence: str,
    ) -> Dict[str, Any]:
        """Coda phase: consolidate loop outputs into final structured result."""
        try:
            state = json.loads(final_h)
        except Exception:
            state = {"summary": final_h, "severity": "medium", "confidence": 0.5}

        # Aggregate recommended rules from all loop steps
        all_rules: List[str] = []
        all_patterns: List[str] = []
        all_techniques: List[str] = []
        for step in loop_trace:
            all_rules.extend(step.recommended_rules)
            all_patterns.extend(step.novel_patterns)
            all_techniques.extend(step.technique_ids)

        # Deduplicate while preserving order
        def dedup(lst: List[str]) -> List[str]:
            return list(dict.fromkeys(lst))[:8]

        return {
            "summary": state.get("summary", state.get("hypothesis", ""))[:400],
            "severity": state.get("severity", "medium"),
            "confidence": float(state.get("confidence", 0.6)),
            "technique_ids": dedup(all_techniques + state.get("technique_ids", [])),
            "novel_patterns": dedup(all_patterns + state.get("novel_patterns", [])),
            "recommended_rules": dedup(all_rules + state.get("recommended_rules", [])),
            "recommended_iocs": dedup(state.get("recommended_iocs", [])),
        }

    # ─── Extraction helpers ──────────────────────────────────────────────────

    @staticmethod
    def _extract_techniques(h: str) -> List[str]:
        return list(dict.fromkeys(re.findall(r'T\d{4}(?:\.\d{3})?', h)))

    @staticmethod
    def _extract_severity(h: str) -> str:
        for sev in ("critical", "high", "medium", "low"):
            if sev in h.lower():
                return sev
        return "medium"

    @staticmethod
    def _extract_patterns(h: str) -> List[str]:
        try:
            d = json.loads(h)
            return d.get("novel_patterns", [])[:4]
        except Exception:
            return []

    @staticmethod
    def _extract_rules(h: str) -> List[str]:
        try:
            d = json.loads(h)
            return d.get("recommended_rules", [])[:4]
        except Exception:
            return []

    @staticmethod
    def _empty_result() -> "MythosResult":
        return MythosResult(
            final_hypothesis="Sin eventos para analizar.",
            consolidated_severity="low",
            consolidated_confidence=0.0,
            n_loops=0, converged=True,
            technique_ids=[], novel_patterns=[],
            recommended_rules=[], recommended_iocs=[],
            loop_trace=[], spectral_radius_profile=[],
            expert_routing=[], total_tokens=0,
            analysis_summary="Sin eventos.",
        )

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def expert_count(self) -> int:
        return self._moe.expert_count
