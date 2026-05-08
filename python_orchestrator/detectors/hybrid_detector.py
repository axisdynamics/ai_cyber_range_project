"""
hybrid_detector.py
==================
Hybrid detection orchestrator — combines all deterministic engines with
optional LLM enrichment for novel/unmatched patterns.

Pipeline:
  Raw events/findings
       │
       ├──► RuleEngine         (fast, deterministic, pattern-matching)
       ├──► SigmaCorrelator    (fast, deterministic, multi-event correlation)
       ├──► IoCMatcher         (fast, deterministic, indicator lookup)
       └──► AnomalyDetector    (fast, deterministic, statistical)
       │
       ▼
  [Confidence Consolidator]
       │
       ├── High-confidence det results → DetectionAlert (immediate)
       ├── Low-confidence / novel      → [LLM Enrichment] (async, optional)
       │                                      └── hypotheses + new rule suggestions
       └──► HybridDetectionResult (unified output)

Integration contract with LLM agent:
  The LLM receives:
    - novel_events: events that fired NO deterministic rules
    - low_confidence_events: events with max_confidence < LOW_CONF_THRESHOLD
    - existing_det_context: summary of what deterministic engines found
    - findings_context: offensive run findings for correlation
  The LLM returns:
    - novel_hypotheses: free-text threat hypotheses
    - suggested_rules: new rule definitions for the RuleEngine
    - enriched_severity: revised severity assessments

This module does NOT depend on any LLM being present.
If no LLM is configured, it falls back to deterministic-only mode.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional

from python_orchestrator.detectors.rule_engine import RuleEngine, RuleMatch, DetectionRule
from python_orchestrator.agents.mythos_reasoner import RecurrentDepthReasoner, MythosResult
from python_orchestrator.agents.moe_router import MoERouter
from python_orchestrator.detectors.sigma_correlator import SigmaCorrelator, CorrelationAlert
from python_orchestrator.detectors.ioc_matcher import IoCMatcher, IoCMatch
from python_orchestrator.detectors.anomaly_detector import AnomalyDetector, AnomalyAlert


LOW_CONF_THRESHOLD = 0.60  # Below this, route to LLM for enrichment


@dataclass
class DetectionAlert:
    """Unified alert from any detector engine."""
    id: str
    source: str                  # rule_engine | sigma | ioc | anomaly | llm
    severity: str
    confidence: float
    technique_ids: List[str]
    tactic: str
    title: str
    description: str
    asset_id: str
    rule_or_ioc_id: str
    requires_llm_review: bool    # True if routed to LLM for enrichment
    llm_hypothesis: str = ""     # Filled by LLM enrichment
    llm_suggested_rules: List[str] = field(default_factory=list)
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LLMEnrichment:
    """Result of LLM enrichment for novel/low-confidence events."""
    novel_hypotheses: List[str]
    suggested_rule_names: List[str]
    suggested_rule_patterns: List[str]
    severity_assessments: Dict[str, str]   # event_id → revised severity
    analysis_summary: str
    model_used: str
    tokens_used: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HybridDetectionResult:
    """Complete result of one hybrid detection run."""
    run_at: str
    total_events_processed: int
    rule_matches: int
    correlation_alerts: int
    ioc_matches: int
    anomaly_alerts: int
    llm_enrichments: int
    all_alerts: List[DetectionAlert]
    novel_events_count: int
    llm_analysis_summary: str
    engine_stats: Dict[str, Any]
    new_rules_suggested: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HybridDetector:
    """
    Orchestrates deterministic detectors + optional LLM enrichment.

    Usage:
        detector = HybridDetector()
        result = detector.analyze(findings, evidence_records)
    """

    def __init__(self):
        self.rule_engine    = RuleEngine()
        self.correlator     = SigmaCorrelator()
        self.ioc_matcher    = IoCMatcher()
        self.anomaly_det    = AnomalyDetector()
        self._alert_counter = 0
        self._llm_available = self._check_llm_available()
        # OpenMythos-style recurrent depth reasoner
        self.mythos_reasoner = RecurrentDepthReasoner()
        self.moe_router      = MoERouter()
        self._last_mythos_result = None

    def _check_llm_available(self) -> bool:
        """Check if Anthropic API key is available for LLM enrichment."""
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def analyze(
        self,
        findings: List[Dict[str, Any]],
        evidence_records: List[Dict[str, Any]],
        run_llm_enrichment: bool = True,
    ) -> HybridDetectionResult:
        """
        Run all detectors against findings + evidence, then optionally
        enrich novel patterns with the LLM agent.
        """
        run_at = datetime.utcnow().isoformat()
        all_events = findings + evidence_records

        # ── Phase 1: Rule Engine ────────────────────────────────────────────
        rule_matches: List[RuleMatch] = self.rule_engine.match_all(all_events)

        # ── Phase 2: Sigma Correlation ──────────────────────────────────────
        correlation_alerts: List[CorrelationAlert] = self.correlator.process_events(findings)

        # ── Phase 3: IoC Matching ────────────────────────────────────────────
        ioc_matches: List[IoCMatch] = self.ioc_matcher.match_all(all_events)

        # ── Phase 4: Anomaly Detection ───────────────────────────────────────
        self.anomaly_det.train(findings[:max(0, len(findings)//2)])  # train on first half
        anomaly_alerts: List[AnomalyAlert] = self.anomaly_det.detect_from_findings(findings)

        # ── Consolidate into DetectionAlerts ────────────────────────────────
        alerts: List[DetectionAlert] = []
        matched_event_ids: set = set()

        for rm in rule_matches:
            alert = self._from_rule_match(rm)
            alerts.append(alert)
            matched_event_ids.add(rm.rule_id)

        for ca in correlation_alerts:
            alert = self._from_correlation(ca)
            alerts.append(alert)

        for im in ioc_matches:
            alert = self._from_ioc_match(im)
            alerts.append(alert)
            matched_event_ids.add(im.ioc_id)

        for aa in anomaly_alerts:
            alert = self._from_anomaly(aa)
            alerts.append(alert)

        # ── Phase 5: Identify novel/low-confidence events ────────────────────
        novel_events = self._find_novel_events(all_events, rule_matches, ioc_matches)
        low_conf_alerts = [a for a in alerts if a.confidence < LOW_CONF_THRESHOLD]

        # ── Phase 6: LLM Enrichment (if available) ───────────────────────────
        llm_enrichment: Optional[LLMEnrichment] = None
        new_rules: List[Dict[str, Any]] = []

        if run_llm_enrichment and (novel_events or low_conf_alerts):
            try:
                # ── OpenMythos Recurrent-Depth Reasoning ──────────────────
                # h_{t+1} = A·h_t + B·e + Transformer(h_t, e)
                # Loops until convergence (ACT halt) or max_loops
                events_to_analyze = (novel_events + [a.__dict__ for a in low_conf_alerts])[:8]
                alerts_ctx = f"{len(alerts)} alertas det., {len(novel_events)} eventos novedosos"

                mythos_result = self.mythos_reasoner.reason(
                    events=events_to_analyze,
                    existing_alerts_summary=alerts_ctx,
                    max_loops=4,
                )

                # Convert MythosResult to LLMEnrichment for backward compat
                llm_enrichment = LLMEnrichment(
                    novel_hypotheses=mythos_result.novel_patterns,
                    suggested_rule_names=mythos_result.recommended_rules,
                    suggested_rule_patterns=[],
                    severity_assessments={},
                    analysis_summary=mythos_result.analysis_summary,
                    model_used=(
                        f"claude-sonnet-4-20250514 [RDT loops={mythos_result.n_loops}, "
                        f"converged={mythos_result.converged}, "
                        f"experts={','.join(set(mythos_result.expert_routing))}]"
                    ),
                    tokens_used=mythos_result.total_tokens,
                )

                # Attach loop trace metadata to low-confidence alerts
                for alert in low_conf_alerts:
                    alert.llm_hypothesis = mythos_result.final_hypothesis[:200]
                    alert.llm_suggested_rules = mythos_result.recommended_rules[:3]

                # Register suggested rules back into RuleEngine (learning loop)
                new_rules = self._apply_llm_rules(llm_enrichment)

                # Store MythosResult for engine_stats
                self._last_mythos_result = mythos_result

            except Exception as e:
                llm_enrichment = None
                self._last_mythos_result = None

        # Deduplicate alerts (same source + technique + asset)
        alerts = self._deduplicate(alerts)

        # Sort by severity + confidence
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: (sev_order.get(a.severity, 4), -a.confidence))

        return HybridDetectionResult(
            run_at=run_at,
            total_events_processed=len(all_events),
            rule_matches=len(rule_matches),
            correlation_alerts=len(correlation_alerts),
            ioc_matches=len(ioc_matches),
            anomaly_alerts=len(anomaly_alerts),
            llm_enrichments=len(low_conf_alerts) if llm_enrichment else 0,
            all_alerts=alerts,
            novel_events_count=len(novel_events),
            llm_analysis_summary=(
                llm_enrichment.analysis_summary if llm_enrichment
                else ("LLM no disponible — modo determinístico puro" if not self._llm_available
                      else "Sin eventos novedosos para enriquecer")
            ),
            engine_stats={
                "rule_engine_rules": self.rule_engine.rule_count,
                "sigma_rules": self.correlator.rule_count,
                "ioc_count": self.ioc_matcher.ioc_count,
                "tracked_metrics": len(self.anomaly_det.tracked_metrics),
                "llm_available": self._llm_available,
                "new_rules_from_llm": len(new_rules),
                "mythos_available": self.mythos_reasoner.is_available,
                "mythos_experts": self.mythos_reasoner.expert_count,
                "mythos_last_loops": getattr(self._last_mythos_result, 'n_loops', 0),
                "mythos_last_converged": getattr(self._last_mythos_result, 'converged', False),
                "mythos_spectral_profile": getattr(self._last_mythos_result, 'spectral_radius_profile', []),
            },
            new_rules_suggested=new_rules,
        )

    # ─── Conversion helpers ───────────────────────────────────────────────────

    def _next_id(self, prefix: str) -> str:
        self._alert_counter += 1
        return f"{prefix}-{self._alert_counter:04d}"

    def _from_rule_match(self, rm: RuleMatch) -> DetectionAlert:
        return DetectionAlert(
            id=self._next_id("ALT-RULE"),
            source="rule_engine",
            severity=rm.severity,
            confidence=rm.confidence,
            technique_ids=rm.technique_ids,
            tactic=rm.tactic,
            title=f"[Rule] {rm.rule_name}",
            description=f"Rule {rm.rule_id} fired. Matched: {', '.join(rm.matched_patterns[:2])}",
            asset_id=rm.event_snapshot.get("asset", rm.event_snapshot.get("asset_id", "unknown")),
            rule_or_ioc_id=rm.rule_id,
            requires_llm_review=rm.confidence < LOW_CONF_THRESHOLD,
        )

    def _from_correlation(self, ca: CorrelationAlert) -> DetectionAlert:
        return DetectionAlert(
            id=self._next_id("ALT-COR"),
            source="sigma_correlator",
            severity=ca.severity,
            confidence=ca.confidence,
            technique_ids=ca.technique_ids,
            tactic=ca.tactic,
            title=f"[Correlation] {ca.rule_name}",
            description=ca.trigger_description,
            asset_id="multi-asset",
            rule_or_ioc_id=ca.rule_id,
            requires_llm_review=ca.confidence < LOW_CONF_THRESHOLD,
        )

    def _from_ioc_match(self, im: IoCMatch) -> DetectionAlert:
        return DetectionAlert(
            id=self._next_id("ALT-IOC"),
            source="ioc_matcher",
            severity=im.severity,
            confidence=im.confidence,
            technique_ids=im.technique_ids,
            tactic="Indicator Match",
            title=f"[IoC] {im.threat_label}",
            description=f"IoC {im.ioc_id} ({im.ioc_type}='{im.ioc_value}') matched field '{im.matched_field}'",
            asset_id=im.event_snapshot.get("asset", im.event_snapshot.get("asset_id", "unknown")),
            rule_or_ioc_id=im.ioc_id,
            requires_llm_review=im.confidence < LOW_CONF_THRESHOLD,
        )

    def _from_anomaly(self, aa: AnomalyAlert) -> DetectionAlert:
        return DetectionAlert(
            id=self._next_id("ALT-ANOM"),
            source="anomaly_detector",
            severity=aa.severity,
            confidence=aa.confidence,
            technique_ids=aa.technique_ids,
            tactic="Statistical Anomaly",
            title=f"[Anomaly] {aa.metric_name} (Z={aa.z_score:.1f}σ)",
            description=aa.description,
            asset_id=aa.asset_id,
            rule_or_ioc_id=f"METRIC-{aa.metric_name}",
            requires_llm_review=aa.confidence < LOW_CONF_THRESHOLD,
        )

    # ─── Novel event identification ───────────────────────────────────────────

    @staticmethod
    def _find_novel_events(
        events: List[Dict[str, Any]],
        rule_matches: List[RuleMatch],
        ioc_matches: List[IoCMatch],
    ) -> List[Dict[str, Any]]:
        """Return events that fired no deterministic rules or IoC matches."""
        matched_summaries = set()
        for rm in rule_matches:
            s = str(rm.event_snapshot.get("summary", ""))
            if s:
                matched_summaries.add(s[:50])
        for im in ioc_matches:
            s = str(im.event_snapshot.get("summary", ""))
            if s:
                matched_summaries.add(s[:50])

        novel = []
        for ev in events:
            s = str(ev.get("summary", ""))[:50]
            if s and s not in matched_summaries:
                novel.append(ev)
        return novel

    # ─── LLM enrichment ───────────────────────────────────────────────────────

    def _call_llm(
        self,
        novel_events: List[Dict[str, Any]],
        low_conf_alerts: List[DetectionAlert],
        findings_context: List[Dict[str, Any]],
        existing_alerts: List[DetectionAlert],
    ) -> Optional[LLMEnrichment]:
        """
        Call the Anthropic API to enrich novel/low-confidence detections.
        Returns LLMEnrichment or None if the call fails.
        """
        try:
            import urllib.request

            prompt = self._build_enrichment_prompt(
                novel_events, low_conf_alerts, findings_context, existing_alerts
            )

            payload = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}],
                "system": (
                    "Eres un analista de ciberseguridad experto. "
                    "Recibes eventos de seguridad y alertas de detección determinísticas. "
                    "Responde SOLO con un objeto JSON válido (sin markdown). "
                    "Estructura: {\"novel_hypotheses\":[...], \"suggested_rule_names\":[...], "
                    "\"suggested_rule_patterns\":[...], \"severity_assessments\":{}, "
                    "\"analysis_summary\":\"...\"}."
                ),
            }).encode()

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            text = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    text += block.get("text", "")

            # Strip markdown fences if present
            text = text.strip()
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = "\n".join(text.split("\n")[:-1])

            parsed = json.loads(text.strip())
            return LLMEnrichment(
                novel_hypotheses=parsed.get("novel_hypotheses", []),
                suggested_rule_names=parsed.get("suggested_rule_names", []),
                suggested_rule_patterns=parsed.get("suggested_rule_patterns", []),
                severity_assessments=parsed.get("severity_assessments", {}),
                analysis_summary=parsed.get("analysis_summary", ""),
                model_used="claude-sonnet-4-20250514",
                tokens_used=data.get("usage", {}).get("output_tokens", 0),
            )
        except Exception as exc:
            return LLMEnrichment(
                novel_hypotheses=[],
                suggested_rule_names=[],
                suggested_rule_patterns=[],
                severity_assessments={},
                analysis_summary=f"LLM enrichment failed: {exc}",
                model_used="unavailable",
                tokens_used=0,
            )

    @staticmethod
    def _build_enrichment_prompt(
        novel_events: List[Dict[str, Any]],
        low_conf_alerts: List[DetectionAlert],
        findings_context: List[Dict[str, Any]],
        existing_alerts: List[DetectionAlert],
    ) -> str:
        return f"""Analiza estos hallazgos de seguridad que los motores determinísticos no pudieron clasificar con alta confianza.

EVENTOS SIN REGLA COINCIDENTE (novedosos):
{json.dumps([{k: str(v)[:100] for k, v in e.items()} for e in novel_events[:3]], indent=2, ensure_ascii=False)}

ALERTAS CON BAJA CONFIANZA:
{json.dumps([{"title": a.title, "severity": a.severity, "confidence": a.confidence} for a in low_conf_alerts[:3]], indent=2)}

CONTEXTO DE HALLAZGOS OFENSIVOS:
{json.dumps([{"technique_id": f.get("technique_id"), "severity": f.get("severity"), "asset": f.get("asset")} for f in findings_context[:5]], indent=2)}

ALERTAS DETERMINÍSTICAS EXISTENTES: {len(existing_alerts)} alertas ya generadas.

Tarea: 
1. Genera hipótesis de amenazas para los eventos novedosos.
2. Sugiere nombres de nuevas reglas de detección.
3. Sugiere patrones regex para esas reglas.
4. Revisa la severidad de las alertas de baja confianza.
5. Escribe un resumen ejecutivo del análisis.
"""

    def _apply_llm_rules(self, enrichment: LLMEnrichment) -> List[Dict[str, Any]]:
        """Convert LLM rule suggestions into RuleEngine rules."""
        new_rules = []
        names = enrichment.suggested_rule_names
        patterns = enrichment.suggested_rule_patterns

        for i, name in enumerate(names[:3]):   # cap at 3 new rules per run
            pat = patterns[i] if i < len(patterns) else r"SYNTHETIC_NOVEL_PATTERN"
            import uuid
            rule = DetectionRule(
                id=f"RULE-LLM-{uuid.uuid4().hex[:6].upper()}",
                name=f"[LLM] {name}",
                description=f"Auto-generated by LLM enrichment: {name}",
                severity="medium",
                technique_ids=[],
                tactic="LLM-Detected",
                confidence=0.65,
                patterns=[],
                any_of=[pat],
                fields=["stdout", "content", "summary"],
            )
            self.rule_engine.add_rule(rule)
            new_rules.append(rule.to_dict())
        return new_rules

    @staticmethod
    def _deduplicate(alerts: List[DetectionAlert]) -> List[DetectionAlert]:
        """Remove duplicate alerts with same source+title+asset."""
        seen = set()
        unique: List[DetectionAlert] = []
        for a in alerts:
            key = f"{a.source}:{a.title}:{a.asset_id}"
            if key not in seen:
                seen.add(key)
                unique.append(a)
        return unique
