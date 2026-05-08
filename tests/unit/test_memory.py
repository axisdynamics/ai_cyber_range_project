"""Unit tests for Hermes cross-run memory."""
import json, pytest
from pathlib import Path
from cyber_range.agents.memory import AgentMemory


@pytest.fixture
def mem(tmp_path):
    return AgentMemory(tmp_path / "test_memory.db")


def _run(run_id="RUN-001", findings_count=5, gap_pct=60.0):
    return {"run_id": run_id, "status": "success",
            "findings_count": findings_count, "critical_count": 1,
            "coverage_pct": 80.0, "detection_gap_pct": gap_pct, "profile": "local_lab"}

def _finding(fid, tech, asset, det="gap", score=80, repro=True):
    return {"id": fid, "technique_id": tech, "asset": asset,
            "detection_status": det, "severity": "high", "score": score,
            "reproducible": repro}


class TestAgentMemory:
    def test_remember_run(self, mem):
        mem.remember_run(_run())
        assert mem.stats()["total_runs"] == 1

    def test_multiple_runs(self, mem):
        for i in range(3):
            mem.remember_run(_run(f"RUN-{i:03d}"))
        assert mem.stats()["total_runs"] == 3

    def test_remember_findings(self, mem):
        mem.remember_run(_run())
        mem.remember_findings("RUN-001", [
            _finding("F1", "T1078", "iam_role_demo"),
            _finding("F2", "T1059", "api_gateway"),
        ])
        assert mem.stats()["total_findings"] == 2

    def test_gap_accumulation(self, mem):
        mem.remember_run(_run("RUN-001"))
        mem.remember_run(_run("RUN-002"))
        mem.remember_findings("RUN-001", [_finding("F1","T1078","iam","gap",100)])
        mem.remember_findings("RUN-002", [_finding("F2","T1078","iam","gap",100)])
        gaps = mem.get_persistent_gaps(min_occurrences=2)
        assert any(g.technique_id == "T1078" for g in gaps)

    def test_no_gap_if_detected(self, mem):
        mem.remember_run(_run("RUN-001"))
        mem.remember_findings("RUN-001", [_finding("F1","T1078","iam","detected",80)])
        gaps = mem.get_all_gaps()
        assert not any(g.technique_id == "T1078" for g in gaps)

    def test_learning_updates(self, mem):
        mem.remember_run(_run("RUN-001"))
        mem.remember_findings("RUN-001", [_finding("F1","T1078","iam","gap",90,True)])
        l = mem.get_technique_learning("T1078")
        assert l is not None
        assert l.total_runs == 1
        assert l.gap_rate == 1.0
        assert l.reproducible_rate == 1.0

    def test_priority_techniques(self, mem):
        mem.remember_run(_run("R1"))
        mem.remember_findings("R1", [
            _finding("F1","T1078","iam","gap",100),
            _finding("F2","T1059","api","detected",50),
        ])
        prio = mem.get_priority_techniques(["T1078","T1059","T1082"])
        assert prio[0] == "T1078"  # highest gap rate first

    def test_clear(self, mem):
        mem.remember_run(_run())
        mem.clear()
        assert mem.stats()["total_runs"] == 0
        assert mem.stats()["total_findings"] == 0

    def test_run_history(self, mem):
        for i in range(5):
            mem.remember_run(_run(f"RUN-{i:03d}"))
        h = mem.get_run_history(limit=3)
        assert len(h) == 3

    def test_stats(self, mem):
        s = mem.stats()
        for key in ("total_runs","total_findings","persistent_gaps","techniques_seen","db_path"):
            assert key in s
