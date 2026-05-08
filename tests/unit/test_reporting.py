"""Unit tests for reporting — schema validation and content correctness."""
import json
import pytest
from cyber_range.reporting.generator import build_json_report, build_md_report, REPORT_SCHEMA_VERSION


_SAMPLE_FINDINGS = [
    {"id": "FND-001", "technique_id": "T1078", "asset": "iam", "severity": "critical",
     "detection_status": "gap", "score": 100.0, "summary": "Credential exposure"},
    {"id": "FND-002", "technique_id": "T1059", "asset": "api", "severity": "high",
     "detection_status": "gap", "score": 87.0, "summary": "Command injection"},
    {"id": "FND-003", "technique_id": "T1082", "asset": "lab", "severity": "medium",
     "detection_status": "detected", "score": 40.0, "summary": "Discovery"},
]


class TestJsonReportSchema:
    def test_required_keys_present(self):
        r = build_json_report("RUN-001", "config.yaml", _SAMPLE_FINDINGS, {}, ["T1078", "T1059"])
        for key in ("schema_version", "report_type", "generated_at", "run",
                    "executive_summary", "findings", "limitations"):
            assert key in r, f"Missing key: {key}"

    def test_schema_version(self):
        r = build_json_report("RUN-001", "c.yaml", [], {}, [])
        assert r["schema_version"] == REPORT_SCHEMA_VERSION

    def test_executive_summary_keys(self):
        r = build_json_report("RUN-001", "c.yaml", _SAMPLE_FINDINGS, {}, ["T1078", "T1059"])
        es = r["executive_summary"]
        for key in ("findings_total", "critical_count", "high_count",
                    "coverage_pct", "detection_gap_pct"):
            assert key in es

    def test_coverage_clamped(self):
        """coverage_pct must never exceed 100."""
        r = build_json_report("R", "c.yaml", _SAMPLE_FINDINGS * 10, {}, ["T1078", "T1059"])
        assert r["executive_summary"]["coverage_pct"] <= 100.0

    def test_gap_pct_clamped(self):
        r = build_json_report("R", "c.yaml", _SAMPLE_FINDINGS, {}, [])
        assert 0 <= r["executive_summary"]["detection_gap_pct"] <= 100.0

    def test_empty_findings(self):
        r = build_json_report("R", "c.yaml", [], {}, [])
        assert r["executive_summary"]["findings_total"] == 0
        assert r["executive_summary"]["coverage_pct"] == 0.0

    def test_json_serializable(self):
        r = build_json_report("R", "c.yaml", _SAMPLE_FINDINGS, {}, ["T1078"])
        # Must not raise
        json.dumps(r)

    def test_run_id_preserved(self):
        r = build_json_report("MY-RUN-123", "c.yaml", [], {}, [])
        assert r["run"]["run_id"] == "MY-RUN-123"


class TestMarkdownReport:
    def test_contains_executive_summary(self):
        r = build_json_report("R", "c.yaml", _SAMPLE_FINDINGS, {}, ["T1078"])
        md = build_md_report(r)
        assert "Executive Summary" in md

    def test_contains_run_id(self):
        r = build_json_report("RUN-XYZ", "c.yaml", [], {}, [])
        md = build_md_report(r)
        assert "RUN-XYZ" in md

    def test_contains_limitations(self):
        r = build_json_report("R", "c.yaml", [], {}, [])
        md = build_md_report(r)
        assert "Limitations" in md

    def test_findings_appear(self):
        r = build_json_report("R", "c.yaml", _SAMPLE_FINDINGS, {}, [])
        md = build_md_report(r)
        assert "Critical" in md
        assert "FND-001" in md

    def test_scores_clamped_in_report(self):
        findings = [{"id":"F1","technique_id":"T1078","asset":"a","severity":"critical",
                     "detection_status":"gap","score":105.6,"summary":"test"}]
        r = build_json_report("R", "c.yaml", findings, {}, ["T1078"])
        md = build_md_report(r)
        # Should not contain "105" — score must be clamped to 100
        assert "105" not in md
