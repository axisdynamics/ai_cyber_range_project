"""
engine/evidence_engine.py
=========================
Collects, structures, hashes, and stores all evidence produced during
an offensive run. Maintains a chain of custody for each evidence record.

Evidence types:
  - log       : raw log entries from detection agent
  - stdout    : captured output from red team execution
  - poc       : proof-of-concept artifact reference
  - chain_step: individual step from a simulated kill chain
  - evasion   : result from an evasion test
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from python_orchestrator.core.models import (
    EvidenceRecord, Finding, AttackChain, EvasionResult, PoCArtifact,
)
from python_orchestrator.core.io import write_json


class EvidenceEngine:
    """
    Central evidence collection and management component.

    All evidence is:
      1. Structured into EvidenceRecord objects
      2. SHA-256 hashed for integrity
      3. Written to the artifacts directory with chain-of-custody tracking
      4. Cross-referenced with findings
    """

    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._records: List[EvidenceRecord] = []

    # ─── Ingestion methods ────────────────────────────────────────────────

    def ingest_execution_output(
        self,
        scenario_id: str,
        asset_id: str,
        technique_id: str,
        stdout: str,
        stderr: str,
        returncode: int,
        collector: str = "red_team_agent",
    ) -> EvidenceRecord:
        """Record raw execution output from a red team scenario."""
        content = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        })
        rec = self._make_record(
            scenario_id=scenario_id,
            asset_id=asset_id,
            technique_id=technique_id,
            evidence_type="stdout",
            content=content,
            collector=collector,
        )
        self._save(rec)
        return rec

    def ingest_detection_signals(
        self,
        scenario_id: str,
        asset_id: str,
        technique_id: str,
        signals: List[Dict[str, Any]],
        collector: str = "detection_agent",
    ) -> EvidenceRecord:
        """Record detection signals from the blue team stack."""
        content = json.dumps(signals)
        rec = self._make_record(
            scenario_id=scenario_id,
            asset_id=asset_id,
            technique_id=technique_id,
            evidence_type="log",
            content=content,
            collector=collector,
        )
        self._save(rec)
        return rec

    def ingest_evasion_results(
        self,
        scenario_id: str,
        asset_id: str,
        technique_id: str,
        results: List[EvasionResult],
        collector: str = "evasion_tester",
    ) -> EvidenceRecord:
        """Record evasion test results."""
        content = json.dumps([r.to_dict() for r in results])
        rec = self._make_record(
            scenario_id=scenario_id,
            asset_id=asset_id,
            technique_id=technique_id,
            evidence_type="evasion",
            content=content,
            collector=collector,
        )
        self._save(rec)
        return rec

    def ingest_chain(
        self,
        chain: AttackChain,
        collector: str = "attack_chain_simulator",
    ) -> EvidenceRecord:
        """Record a simulated kill chain."""
        content = json.dumps(chain.to_dict())
        rec = self._make_record(
            scenario_id=f"SCN-{chain.asset_id}",
            asset_id=chain.asset_id,
            technique_id=chain.steps[0].technique_id if chain.steps else "N/A",
            evidence_type="chain_step",
            content=content,
            collector=collector,
        )
        self._save(rec)
        return rec

    def ingest_poc(
        self,
        poc: PoCArtifact,
        collector: str = "poc_builder",
    ) -> EvidenceRecord:
        """Record a PoC artifact as evidence."""
        content = json.dumps(poc.to_dict())
        rec = self._make_record(
            scenario_id=f"SCN-{poc.asset_id}",
            asset_id=poc.asset_id,
            technique_id=poc.technique_id,
            evidence_type="poc",
            content=content,
            collector=collector,
        )
        self._save(rec)
        return rec

    # ─── Query ─────────────────────────────────────────────────────────────

    def get_by_scenario(self, scenario_id: str) -> List[EvidenceRecord]:
        return [r for r in self._records if r.scenario_id == scenario_id]

    def get_by_asset(self, asset_id: str) -> List[EvidenceRecord]:
        return [r for r in self._records if r.asset_id == asset_id]

    def all_records(self) -> List[EvidenceRecord]:
        return list(self._records)

    def build_evidence_summary(self) -> Dict[str, Any]:
        """Return a summary of collected evidence for reporting."""
        type_counts: Dict[str, int] = {}
        for r in self._records:
            type_counts[r.evidence_type] = type_counts.get(r.evidence_type, 0) + 1
        return {
            "total_records": len(self._records),
            "by_type": type_counts,
            "assets_covered": len({r.asset_id for r in self._records}),
            "techniques_covered": len({r.technique_id for r in self._records}),
            "collected_at": datetime.utcnow().isoformat(),
        }

    # ─── Internal ──────────────────────────────────────────────────────────

    def _make_record(
        self,
        scenario_id: str,
        asset_id: str,
        technique_id: str,
        evidence_type: str,
        content: str,
        collector: str,
    ) -> EvidenceRecord:
        sha = hashlib.sha256(content.encode()).hexdigest()
        rec_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        custody = [
            f"{datetime.utcnow().isoformat()} — collected by {collector}",
            f"{datetime.utcnow().isoformat()} — SHA256 computed: {sha[:16]}...",
        ]
        rec = EvidenceRecord(
            id=rec_id,
            scenario_id=scenario_id,
            asset_id=asset_id,
            technique_id=technique_id,
            evidence_type=evidence_type,
            content=content,
            hash_sha256=sha,
            collected_at=datetime.utcnow().isoformat(),
            collector=collector,
            chain_of_custody=custody,
        )
        self._records.append(rec)
        return rec

    def _save(self, rec: EvidenceRecord) -> None:
        """Persist evidence record to disk."""
        path = self.artifacts_dir / f"{rec.id}.json"
        write_json(path, rec.to_dict())
