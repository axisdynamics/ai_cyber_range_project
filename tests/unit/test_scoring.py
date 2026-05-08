"""Unit tests for scoring engine. All percentage outputs must be in [0, 100]."""
import pytest
from cyber_range.scoring.engine import (
    risk_score, coverage_pct, detection_gap_pct,
    confidence_score, severity_counts, remediation_priority, clamp,
)


class TestClamp:
    def test_normal_value(self):       assert clamp(50.0) == 50.0
    def test_above_100(self):          assert clamp(105.6) == 100.0
    def test_below_0(self):            assert clamp(-5.0) == 0.0
    def test_exactly_0(self):          assert clamp(0.0) == 0.0
    def test_exactly_100(self):        assert clamp(100.0) == 100.0
    def test_large_positive(self):     assert clamp(9999.0) == 100.0
    def test_large_negative(self):     assert clamp(-9999.0) == 0.0


class TestRiskScore:
    def test_critical_detected_reproducible(self):
        s = risk_score("critical", 5, detected=True, reproducible=True)
        assert 0 <= s <= 100

    def test_low_not_detected(self):
        s = risk_score("low", 1, detected=False, reproducible=False)
        assert 0 <= s <= 100

    def test_always_clamped(self):
        s = risk_score("critical", 5, detected=False, reproducible=True, evasion_rate=1.0)
        assert 0 <= s <= 100

    def test_unknown_severity_defaults(self):
        s = risk_score("", 3, detected=False, reproducible=False)
        assert 0 <= s <= 100

    def test_critical_higher_than_low(self):
        hi = risk_score("critical", 5, detected=False, reproducible=True)
        lo = risk_score("low", 1, detected=True, reproducible=False)
        assert hi > lo

    def test_zero_evasion_rate(self):
        s = risk_score("high", 4, detected=False, reproducible=True, evasion_rate=0.0)
        assert 0 <= s <= 100

    def test_returns_float(self):
        assert isinstance(risk_score("medium", 3, True, True), float)


class TestCoveragePct:
    def test_zero_when_no_scope(self):
        assert coverage_pct(["T1078"], []) == 0.0

    def test_zero_when_no_findings(self):
        assert coverage_pct([], ["T1078", "T1059"]) == 0.0

    def test_full_coverage(self):
        assert coverage_pct(["T1078", "T1059"], ["T1078", "T1059"]) == 100.0

    def test_partial_coverage(self):
        pct = coverage_pct(["T1078"], ["T1078", "T1059"])
        assert pct == 50.0

    def test_never_exceeds_100(self):
        """Key regression: cannot exceed 100% regardless of finding count."""
        pct = coverage_pct(
            ["T1078", "T1078", "T1078", "T1059", "T1059", "T1003"],
            ["T1078", "T1059"],
        )
        assert pct == 100.0

    def test_out_of_scope_technique_ignored(self):
        """Findings for techniques outside scope don't increase coverage."""
        pct = coverage_pct(["T1999"], ["T1078", "T1059"])
        assert pct == 0.0

    def test_result_in_range(self):
        for n in range(1, 6):
            pct = coverage_pct(["T1078"] * n, ["T1078"])
            assert 0 <= pct <= 100


class TestDetectionGapPct:
    def test_empty_findings(self):   assert detection_gap_pct([]) == 0.0
    def test_all_gap(self):
        fs = [{"detection_status": "gap"}] * 5
        assert detection_gap_pct(fs) == 100.0
    def test_none_gap(self):
        fs = [{"detection_status": "detected"}] * 5
        assert detection_gap_pct(fs) == 0.0
    def test_partial(self):
        fs = [{"detection_status": "gap"}, {"detection_status": "detected"}]
        assert detection_gap_pct(fs) == 50.0
    def test_always_clamped(self):
        # Inject a degenerate finding
        fs = [{"detection_status": "gap"}] * 1000
        assert 0 <= detection_gap_pct(fs) <= 100


class TestConfidenceScore:
    def test_base_minimum(self):
        s = confidence_score(False, False, False)
        assert s == 0.40

    def test_full_confidence(self):
        s = confidence_score(True, True, True)
        assert s == 1.0

    def test_always_01(self):
        for repro in (True, False):
            for evid in (True, False):
                for ver in (True, False):
                    s = confidence_score(repro, evid, ver)
                    assert 0.0 <= s <= 1.0


class TestSeverityCounts:
    def test_empty(self):
        c = severity_counts([])
        assert all(v == 0 for v in c.values())

    def test_all_critical(self):
        fs = [{"severity": "critical"}] * 3
        assert severity_counts(fs)["critical"] == 3

    def test_unknown_goes_to_informational(self):
        fs = [{"severity": "banana"}]
        c = severity_counts(fs)
        assert c["informational"] == 1

    def test_mixed(self):
        fs = [{"severity": s} for s in ["critical", "high", "medium", "low", "informational"]]
        c = severity_counts(fs)
        assert c["critical"] == 1
        assert c["high"] == 1


class TestRemediationPriority:
    def test_critical_always_1(self):   assert remediation_priority("critical", 100, False) == 1
    def test_high_gap_is_1(self):       assert remediation_priority("high", 80, True) == 1
    def test_high_no_gap_is_2(self):    assert remediation_priority("high", 80, False) == 2
    def test_medium_gap_is_2(self):     assert remediation_priority("medium", 60, True) == 2
    def test_medium_no_gap_is_3(self):  assert remediation_priority("medium", 60, False) == 3
    def test_low_is_4(self):            assert remediation_priority("low", 30, False) == 4
    def test_informational_is_4(self):  assert remediation_priority("informational", 0, False) == 4
