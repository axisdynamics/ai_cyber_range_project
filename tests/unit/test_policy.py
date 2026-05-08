"""Unit tests for policy enforcement."""
import pytest
from cyber_range.config.schema import CyberRangeConfig, EngagementConfig
from cyber_range.policy.enforcer import PolicyEnforcer, PolicyVerdict, PolicyViolationError


def make_cfg(**kwargs) -> CyberRangeConfig:
    """Create a minimal safe config for testing."""
    return CyberRangeConfig(engagement=EngagementConfig(**kwargs))


class TestTechniquePolicy:
    def test_allowed_technique(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_technique("T1078")
        assert d.allowed

    def test_hardcoded_blocked(self):
        e = PolicyEnforcer(make_cfg())
        for t in ("T1485", "T1561", "T1529"):
            d = e.check_technique(t)
            assert not d.allowed, f"{t} should be blocked"

    def test_config_blocked_technique(self):
        e = PolicyEnforcer(make_cfg(blocked_techniques=["T1485","T1561","T1529","T1059"]))
        assert not e.check_technique("T1059").allowed

    def test_invalid_format(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_technique("NOT_A_TECHNIQUE")
        assert not d.allowed

    def test_valid_format_variants(self):
        e = PolicyEnforcer(make_cfg())
        assert e.check_technique("T1078").allowed
        assert e.check_technique("T1059.003").allowed


class TestAssetPolicy:
    def test_no_authorized_list_allows_anything(self):
        e = PolicyEnforcer(make_cfg(authorized_assets=[]))
        assert e.check_asset("iam_role_demo").allowed

    def test_authorized_asset_allowed(self):
        e = PolicyEnforcer(make_cfg(authorized_assets=["iam_role_demo"]))
        assert e.check_asset("iam_role_demo").allowed

    def test_unauthorized_asset_blocked(self):
        e = PolicyEnforcer(make_cfg(authorized_assets=["iam_role_demo"]))
        assert not e.check_asset("external_host").allowed

    def test_external_ip_blocked(self):
        e = PolicyEnforcer(make_cfg())
        assert not e.check_asset("8.8.8.8").allowed

    def test_internal_ip_allowed(self):
        e = PolicyEnforcer(make_cfg())
        assert e.check_asset("192.168.1.1").allowed

    def test_external_domain_blocked(self):
        e = PolicyEnforcer(make_cfg())
        assert not e.check_asset("target.amazonaws.com").allowed


class TestScenarioPolicy:
    def test_valid_scenario_allowed(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_scenario("iam_role_demo", "T1078")
        assert d.allowed

    def test_blocked_technique_blocks_scenario(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_scenario("iam_role_demo", "T1485")
        assert not d.allowed

    def test_external_asset_blocks_scenario(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_scenario("8.8.8.8", "T1078")
        assert not d.allowed


class TestAssertAllowed:
    def test_raises_on_blocked(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_technique("T1485")
        with pytest.raises(PolicyViolationError):
            e.assert_allowed(d)

    def test_no_raise_on_allowed(self):
        e = PolicyEnforcer(make_cfg())
        d = e.check_technique("T1078")
        e.assert_allowed(d)  # should not raise


class TestAllowExternalTargets:
    def test_cannot_set_external_true(self):
        """allow_external_targets=true must never be accepted."""
        with pytest.raises(Exception):
            CyberRangeConfig(engagement=EngagementConfig(allow_external_targets=True))
