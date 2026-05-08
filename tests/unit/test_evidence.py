"""Unit tests for evidence verification."""
import hashlib
import json
from pathlib import Path
import pytest

from cyber_range.evidence.verifier import (
    verify_run, EvidenceStatus, _sha256_of_content
)


def _make_evd(tmp_path: Path, evd_id: str, content: str, tamper: bool = False) -> Path:
    """Helper: create an EVD file with correct (or tampered) hash."""
    real_hash = _sha256_of_content(content)
    stored_hash = "a" * 64 if tamper else real_hash
    evd = {
        "id": evd_id,
        "asset_id": "test_asset",
        "technique_id": "T1078",
        "evidence_type": "stdout",
        "hash_sha256": stored_hash,
        "chain_of_custody": ["collected by test"],
        "content": content,
    }
    path = tmp_path / "evidence" / f"{evd_id}.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(evd))
    return path


def _make_run(tmp_path: Path, findings_evd_ids: list) -> Path:
    """Helper: create a minimal run directory."""
    run_dir = tmp_path / "RUN-TEST"
    run_dir.mkdir()
    findings = [
        {"id": "FND-001", "evidence_ids": findings_evd_ids, "severity": "high"}
    ]
    (run_dir / "findings.json").write_text(json.dumps(findings))
    return run_dir


class TestEvidenceVerifier:
    def test_valid_evidence_passes(self, tmp_path):
        run_dir = _make_run(tmp_path, ["EVD-001"])
        _make_evd(run_dir, "EVD-001", "test content")
        report = verify_run(run_dir)
        assert report.valid == 1
        assert report.modified == 0
        assert report.passed

    def test_tampered_evidence_detected(self, tmp_path):
        run_dir = _make_run(tmp_path, ["EVD-001"])
        _make_evd(run_dir, "EVD-001", "original content", tamper=True)
        report = verify_run(run_dir)
        assert report.modified == 1
        assert not report.passed

    def test_missing_evidence_detected(self, tmp_path):
        run_dir = _make_run(tmp_path, ["EVD-MISSING"])
        # Don't create the EVD file
        report = verify_run(run_dir)
        assert report.missing == 1
        assert not report.passed

    def test_evidence_without_hash_flagged(self, tmp_path):
        run_dir = _make_run(tmp_path, ["EVD-NOHASH"])
        evd = {"id": "EVD-NOHASH", "content": "test", "chain_of_custody": ["test"]}
        (run_dir / "evidence" / "EVD-NOHASH.json").parent.mkdir(exist_ok=True)
        (run_dir / "evidence" / "EVD-NOHASH.json").write_text(json.dumps(evd))
        report = verify_run(run_dir)
        assert report.no_hash == 1
        assert not report.passed

    def test_passed_only_when_all_valid(self, tmp_path):
        run_dir = _make_run(tmp_path, ["EVD-001", "EVD-002"])
        _make_evd(run_dir, "EVD-001", "content 1")
        _make_evd(run_dir, "EVD-002", "content 2", tamper=True)
        report = verify_run(run_dir)
        assert not report.passed

    def test_empty_run_passes(self, tmp_path):
        run_dir = tmp_path / "RUN-EMPTY"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        report = verify_run(run_dir)
        assert report.passed
        assert report.total == 0

    def test_unreferenced_evidence_flagged(self, tmp_path):
        run_dir = _make_run(tmp_path, [])  # No findings reference this
        _make_evd(run_dir, "EVD-ORPHAN", "orphan content")
        report = verify_run(run_dir)
        assert report.unreferenced == 1
