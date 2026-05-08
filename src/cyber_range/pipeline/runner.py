"""
cyber_range.pipeline.runner
============================
Phase-tracked pipeline executor.

Phases:
    load_config → validate_policy → load_scenario → execute_simulation
    → collect_telemetry → generate_findings → score_findings
    → generate_evidence → verify_evidence → generate_report
    → persist_run_summary

Each phase has state: pending | running | success | failed | skipped | blocked

Per-run artifact directory:
    artifacts/runs/<run_id>/
        summary.json
        findings.json
        evidence/
        report.md
        report.json
        chain_of_custody.json
        logs.jsonl
"""
from __future__ import annotations

import json
import subprocess
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_range.config.schema import CyberRangeConfig
from cyber_range.policy.enforcer import PolicyEnforcer, PolicyViolationError
from cyber_range.scoring.engine import (
    coverage_pct, detection_gap_pct, risk_score,
    confidence_score, severity_counts, clamp, remediation_priority,
)
from cyber_range.evidence.verifier import verify_legacy_artifacts
from cyber_range.logging.structured import StructuredLogger


class PhaseStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    SUCCESS  = "success"
    FAILED   = "failed"
    SKIPPED  = "skipped"
    BLOCKED  = "blocked"


@dataclass
class PhaseResult:
    name:       str
    status:     PhaseStatus
    started_at: Optional[str] = None
    ended_at:   Optional[str] = None
    error:      Optional[str] = None
    metrics:    Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunSummary:
    run_id:          str
    config_path:     str
    profile:         str
    started_at:      str
    finished_at:     Optional[str]
    phases:          List[PhaseResult]
    findings_count:  int
    critical_count:  int
    high_count:      int
    coverage_pct:    float
    detection_gap_pct: float
    artifacts_dir:   str
    status:          str  # success | failed | blocked

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["phases"] = [asdict(p) for p in self.phases]
        return d


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_run_id() -> str:
    return "RUN-" + uuid.uuid4().hex[:8].upper()


class PipelineRunner:
    """
    Orchestrates the full execution pipeline.

    Usage:
        runner = PipelineRunner(config, project_root=Path("."))
        summary = runner.run()
    """

    PHASE_ORDER = [
        "load_config", "validate_policy", "load_scenario",
        "execute_simulation", "collect_telemetry", "generate_findings",
        "score_findings", "generate_evidence", "verify_evidence",
        "generate_report", "persist_run_summary",
    ]

    def __init__(
        self,
        config:       CyberRangeConfig,
        config_path:  Path,
        project_root: Path,
        dry_run:      bool = False,
    ):
        self.cfg          = config
        self.config_path  = config_path
        self.root         = project_root
        self.dry_run      = dry_run or config.dry_run

        self.run_id       = _make_run_id()
        self.run_dir      = config.runs_path(project_root) / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

        log_path = self.run_dir / "logs.jsonl"
        self.logger = StructuredLogger(
            run_id=self.run_id,
            log_path=log_path,
            min_level=config.log_level,
        )

        self.enforcer = PolicyEnforcer(config)
        self.phases: List[PhaseResult] = [
            PhaseResult(name=p, status=PhaseStatus.PENDING)
            for p in self.PHASE_ORDER
        ]

    # ── Public entry point ─────────────────────────────────────────────────────

    def run(self) -> RunSummary:
        """Execute all phases. Returns RunSummary regardless of failures."""
        self.logger.info("pipeline_start", f"Run {self.run_id} starting",
                         phase="pipeline", run_id=self.run_id,
                         profile=self.cfg.profile, dry_run=self.dry_run)

        started = _now_iso()
        findings: List[Dict] = []
        overall_status = "success"

        try:
            # Phase 1: config already loaded (validated before this point)
            self._phase_success("load_config", {"config_path": str(self.config_path)})

            # Phase 2: policy validation
            self._run_phase("validate_policy", lambda: self._validate_policy())

            # Phase 3-11: delegate to existing orchestrator
            result = self._run_phase("execute_simulation",
                                      lambda: self._invoke_orchestrator())

            if result and result.status == PhaseStatus.SUCCESS:
                findings = self._load_findings()
                self._phase_success("collect_telemetry", {"findings": len(findings)})
                self._score_and_finalize(findings)
            else:
                overall_status = "failed"

        except PolicyViolationError as e:
            overall_status = "blocked"
            self.logger.error("policy_violation", str(e), phase="validate_policy")
            self._mark_remaining_blocked()

        except Exception as e:
            overall_status = "failed"
            self.logger.error("pipeline_error", str(e), phase="pipeline", exc=str(e))

        finished = _now_iso()
        sc = severity_counts(findings)

        # Compute metrics
        all_techniques = [f.get("technique_id", "") for f in findings]
        scope_techs = self._load_scope_techniques()
        cov_pct = coverage_pct(all_techniques, scope_techs)
        gap_pct = detection_gap_pct(findings)

        summary = RunSummary(
            run_id=self.run_id,
            config_path=str(self.config_path),
            profile=self.cfg.profile,
            started_at=started,
            finished_at=finished,
            phases=self.phases,
            findings_count=len(findings),
            critical_count=sc.get("critical", 0),
            high_count=sc.get("high", 0),
            coverage_pct=cov_pct,
            detection_gap_pct=gap_pct,
            artifacts_dir=str(self.run_dir),
            status=overall_status,
        )

        self._persist_summary(summary, findings)
        self.logger.info("pipeline_complete", f"Run {self.run_id} {overall_status}",
                         phase="pipeline", status=overall_status,
                         findings=len(findings), coverage_pct=cov_pct)
        self.logger.close()
        return summary

    # ── Phase helpers ──────────────────────────────────────────────────────────

    def _get_phase(self, name: str) -> PhaseResult:
        for p in self.phases:
            if p.name == name:
                return p
        raise KeyError(f"Phase not found: {name}")

    def _phase_success(self, name: str, metrics: Dict = {}) -> PhaseResult:
        p = self._get_phase(name)
        p.status = PhaseStatus.SUCCESS
        p.started_at = p.ended_at = _now_iso()
        p.metrics = metrics
        return p

    def _run_phase(self, name: str, fn) -> PhaseResult:
        p = self._get_phase(name)
        p.status = PhaseStatus.RUNNING
        p.started_at = _now_iso()
        self.logger.info(f"phase_{name}", f"Phase {name} started", phase=name)
        try:
            result = fn()
            p.status = PhaseStatus.SUCCESS
            if isinstance(result, dict):
                p.metrics = result
        except PolicyViolationError as e:
            p.status = PhaseStatus.BLOCKED
            p.error = str(e)
            self.logger.error(f"phase_{name}_blocked", str(e), phase=name)
            raise
        except Exception as e:
            p.status = PhaseStatus.FAILED
            p.error = str(e)
            self.logger.error(f"phase_{name}_failed", str(e), phase=name, exc=str(e))
        finally:
            p.ended_at = _now_iso()
        return p

    def _mark_remaining_blocked(self) -> None:
        for p in self.phases:
            if p.status == PhaseStatus.PENDING:
                p.status = PhaseStatus.BLOCKED

    # ── Policy validation ──────────────────────────────────────────────────────

    def _validate_policy(self) -> Dict:
        decisions = []
        # Check all authorized assets
        for asset in self.cfg.engagement.authorized_assets[:20]:
            d = self.enforcer.check_asset(asset)
            decisions.append(str(d))
        return {"decisions": len(decisions), "blocked": self.enforcer.blocked_count}

    # ── Orchestrator invocation ────────────────────────────────────────────────

    def _invoke_orchestrator(self) -> Dict:
        """Invoke the existing python_orchestrator pipeline."""
        if self.dry_run:
            self.logger.info("dry_run", "Dry run — skipping simulation", phase="execute_simulation")
            return {"dry_run": True}

        cmd = [
            sys.executable, "-m", "python_orchestrator.main",
            "--config", str(self.config_path),
        ]
        result = subprocess.run(
            cmd, cwd=str(self.root),
            capture_output=False, text=True, timeout=self.cfg.engagement.timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Orchestrator exited with code {result.returncode}")
        return {"exit_code": 0}

    # ── Data loading ───────────────────────────────────────────────────────────

    def _load_findings(self) -> List[Dict]:
        report_path = self.root / self.cfg.reports_dir / "latest_report.json"
        if not report_path.exists():
            return []
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return data.get("findings", [])

    def _load_scope_techniques(self) -> List[str]:
        tech_path = self.root / self.cfg.data_dir / "attack_subset.json"
        if not tech_path.exists():
            return []
        techs = json.loads(tech_path.read_text(encoding="utf-8"))
        return [t.get("id", "") for t in techs if t.get("id")]

    # ── Scoring and finalization ───────────────────────────────────────────────

    def _score_and_finalize(self, findings: List[Dict]) -> None:
        self._run_phase("generate_findings", lambda: {"count": len(findings)})

        # Normalize scores — clamp to [0, 100]
        for f in findings:
            raw_score = f.get("score", 0)
            f["score"] = clamp(float(raw_score))

        self._run_phase("score_findings", lambda: {
            "min": min((f["score"] for f in findings), default=0),
            "max": max((f["score"] for f in findings), default=0),
        })

        # Copy evidence to run dir
        src_evd = self.root / self.cfg.artifacts_dir / "evidence"
        dst_evd = self.run_dir / "evidence"
        if src_evd.exists():
            import shutil
            dst_evd.mkdir(exist_ok=True)
            for p in src_evd.glob("EVD-*.json"):
                shutil.copy2(p, dst_evd / p.name)

        self._run_phase("generate_evidence", lambda: {"copied": len(list(dst_evd.glob("EVD-*.json"))) if dst_evd.exists() else 0})

        # Verify evidence
        vreport = verify_legacy_artifacts(self.root / self.cfg.artifacts_dir)
        self._run_phase("verify_evidence", lambda: {
            "valid": vreport.valid, "total": vreport.total,
            "modified": vreport.modified, "passed": vreport.passed,
        })
        if not vreport.passed:
            self.logger.warning("evidence_verification_failed",
                                f"{vreport.modified} modified, {vreport.missing} missing",
                                phase="verify_evidence")

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist_summary(self, summary: RunSummary, findings: List[Dict]) -> None:
        # summary.json
        (self.run_dir / "summary.json").write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # findings.json
        (self.run_dir / "findings.json").write_text(
            json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # chain_of_custody.json
        custody = {
            "run_id": self.run_id,
            "generated_at": summary.finished_at,
            "entries": [
                {"step": p.name, "status": p.status, "timestamp": p.ended_at}
                for p in self.phases
            ],
        }
        (self.run_dir / "chain_of_custody.json").write_text(
            json.dumps(custody, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        self._run_phase("persist_run_summary", lambda: {"dir": str(self.run_dir)})
