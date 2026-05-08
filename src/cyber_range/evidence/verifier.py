"""
cyber_range.evidence.verifier
==============================
Evidence verification module.

Recalculates SHA-256 hashes and compares against stored values.
Reports: valid, missing, modified, unreferenced.
Exits non-zero on any tampered or missing evidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class EvidenceStatus(str, Enum):
    VALID       = "valid"
    MISSING     = "missing"      # referenced but file not found
    MODIFIED    = "modified"     # hash mismatch
    UNREFERENCED= "unreferenced" # file exists but no finding references it
    NO_HASH     = "no_hash"      # record has no stored hash


@dataclass
class EvidenceRecord:
    id:         str
    path:       str
    stored_hash: Optional[str]
    status:     EvidenceStatus
    computed_hash: Optional[str] = None
    finding_id:    Optional[str] = None
    error:         Optional[str] = None


@dataclass
class VerificationReport:
    run_id:          str
    total:           int
    valid:           int
    missing:         int
    modified:        int
    unreferenced:    int
    no_hash:         int
    records:         List[EvidenceRecord] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True only if every referenced piece of evidence is valid."""
        return self.missing == 0 and self.modified == 0 and self.no_hash == 0

    def summary(self) -> str:
        lines = [
            f"Run: {self.run_id}",
            f"  Valid:         {self.valid}/{self.total}",
            f"  Missing:       {self.missing}",
            f"  Modified:      {self.modified}",
            f"  Unreferenced:  {self.unreferenced}",
            f"  No hash:       {self.no_hash}",
            f"  Result:        {'PASS ✓' if self.passed else 'FAIL ✗'}",
        ]
        return "\n".join(lines)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_of_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def verify_run(run_dir: Path) -> VerificationReport:
    """
    Verify all evidence for a given run directory.

    Expects structure:
        <run_dir>/
            findings.json
            evidence/
                EVD-*.json
            chain_of_custody.json (optional)
    """
    run_id = run_dir.name
    findings_file = run_dir / "findings.json"
    evidence_dir  = run_dir / "evidence"

    records: List[EvidenceRecord] = []
    referenced_ids: set = set()

    # Collect evidence IDs referenced by findings
    if findings_file.exists():
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
        for f in findings:
            for evid in f.get("evidence_ids", []):
                referenced_ids.add(evid)

    # Verify each EVD file
    evd_files = sorted(evidence_dir.glob("EVD-*.json")) if evidence_dir.exists() else []
    seen_ids: set = set()

    for evd_path in evd_files:
        try:
            evd = json.loads(evd_path.read_text(encoding="utf-8"))
        except Exception as e:
            records.append(EvidenceRecord(
                id=evd_path.stem, path=str(evd_path),
                stored_hash=None, status=EvidenceStatus.MISSING,
                error=f"Cannot read: {e}",
            ))
            continue

        evd_id      = evd.get("id", evd_path.stem)
        stored_hash = evd.get("hash_sha256", "")
        seen_ids.add(evd_id)

        if not stored_hash:
            records.append(EvidenceRecord(
                id=evd_id, path=str(evd_path),
                stored_hash=None, status=EvidenceStatus.NO_HASH,
            ))
            continue

        # Recompute hash from the content field (same method as evidence_engine.py)
        content = evd.get("content", "")
        if isinstance(content, (dict, list)):
            content_str = json.dumps(content, sort_keys=True, ensure_ascii=False)
        else:
            content_str = str(content)
        computed = _sha256_of_content(content_str)

        if computed == stored_hash:
            status = EvidenceStatus.VALID
        else:
            status = EvidenceStatus.MODIFIED

        records.append(EvidenceRecord(
            id=evd_id, path=str(evd_path),
            stored_hash=stored_hash[:16] + "…",
            computed_hash=computed[:16] + "…",
            status=status,
        ))

    # Check for missing referenced evidence
    for ref_id in referenced_ids:
        if ref_id not in seen_ids:
            records.append(EvidenceRecord(
                id=ref_id, path="",
                stored_hash=None, status=EvidenceStatus.MISSING,
                error=f"Referenced by finding but file not found",
            ))

    # Mark unreferenced
    for rec in records:
        if rec.status == EvidenceStatus.VALID and rec.id not in referenced_ids:
            rec.status = EvidenceStatus.UNREFERENCED

    # Tally
    def count(s: EvidenceStatus) -> int:
        return sum(1 for r in records if r.status == s)

    return VerificationReport(
        run_id=run_id,
        total=len(records),
        valid=count(EvidenceStatus.VALID),
        missing=count(EvidenceStatus.MISSING),
        modified=count(EvidenceStatus.MODIFIED),
        unreferenced=count(EvidenceStatus.UNREFERENCED),
        no_hash=count(EvidenceStatus.NO_HASH),
        records=records,
    )


def verify_legacy_artifacts(artifacts_dir: Path) -> VerificationReport:
    """
    Verify legacy evidence in artifacts/evidence/ (pre-run-directory structure).
    Used for backward compatibility with existing runs.
    """
    evidence_dir = artifacts_dir / "evidence"
    records: List[EvidenceRecord] = []

    if not evidence_dir.exists():
        return VerificationReport(run_id="legacy", total=0, valid=0,
                                  missing=0, modified=0, unreferenced=0, no_hash=0)

    for evd_path in sorted(evidence_dir.glob("EVD-*.json")):
        try:
            evd = json.loads(evd_path.read_text(encoding="utf-8"))
        except Exception as e:
            records.append(EvidenceRecord(
                id=evd_path.stem, path=str(evd_path),
                stored_hash=None, status=EvidenceStatus.MISSING,
                error=str(e),
            ))
            continue

        evd_id      = evd.get("id", evd_path.stem)
        stored_hash = evd.get("hash_sha256", "")

        if not stored_hash:
            records.append(EvidenceRecord(
                id=evd_id, path=str(evd_path),
                stored_hash=None, status=EvidenceStatus.NO_HASH,
            ))
            continue

        content = evd.get("content", "")
        if isinstance(content, (dict, list)):
            content_str = json.dumps(content, sort_keys=True, ensure_ascii=False)
        else:
            content_str = str(content)

        computed = _sha256_of_content(content_str)
        status = EvidenceStatus.VALID if computed == stored_hash else EvidenceStatus.MODIFIED

        records.append(EvidenceRecord(
            id=evd_id, path=str(evd_path),
            stored_hash=stored_hash[:16] + "…",
            computed_hash=computed[:16] + "…",
            status=status,
        ))

    def count(s: EvidenceStatus) -> int:
        return sum(1 for r in records if r.status == s)

    return VerificationReport(
        run_id="legacy",
        total=len(records),
        valid=count(EvidenceStatus.VALID),
        missing=count(EvidenceStatus.MISSING),
        modified=count(EvidenceStatus.MODIFIED),
        unreferenced=count(EvidenceStatus.UNREFERENCED),
        no_hash=count(EvidenceStatus.NO_HASH),
        records=records,
    )
