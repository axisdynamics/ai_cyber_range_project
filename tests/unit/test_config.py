"""Unit tests for configuration validation."""
import pytest
import tempfile
from pathlib import Path
from cyber_range.config.schema import CyberRangeConfig, load_config, EngagementConfig


class TestConfigDefaults:
    def test_safe_defaults(self):
        cfg = CyberRangeConfig()
        assert cfg.engagement.allow_external_targets is False
        assert "T1485" in cfg.engagement.blocked_techniques
        assert "T1561" in cfg.engagement.blocked_techniques
        assert "T1529" in cfg.engagement.blocked_techniques

    def test_default_log_level(self):
        cfg = CyberRangeConfig()
        assert cfg.log_level == "INFO"

    def test_default_llm_mode(self):
        cfg = CyberRangeConfig()
        assert cfg.llm.mode == "deterministic"


class TestConfigValidation:
    def test_external_targets_rejected(self):
        with pytest.raises(Exception, match="allow_external_targets"):
            CyberRangeConfig(engagement=EngagementConfig(allow_external_targets=True))

    def test_invalid_log_level(self):
        with pytest.raises(Exception):
            CyberRangeConfig(log_level="TRACE")

    def test_invalid_profile(self):
        with pytest.raises(Exception):
            CyberRangeConfig(profile="hacker_mode")

    def test_invalid_llm_mode(self):
        with pytest.raises(Exception):
            from cyber_range.config.schema import LLMConfig
            CyberRangeConfig(llm=LLMConfig(mode="openai_real"))

    def test_invalid_technique_id_format(self):
        with pytest.raises(Exception):
            CyberRangeConfig(engagement=EngagementConfig(blocked_techniques=["NOT_T_FORMAT"]))

    def test_destructive_techniques_always_blocked(self):
        """Destructive techniques cannot be removed from blocked list via config."""
        cfg = CyberRangeConfig(engagement=EngagementConfig(blocked_techniques=["T1190"]))
        assert "T1485" in cfg.engagement.blocked_techniques
        assert "T1561" in cfg.engagement.blocked_techniques


class TestLoadConfig:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config(Path("/nonexistent/config.yaml"))

    def test_valid_yaml(self, tmp_path):
        cfg_file = tmp_path / "test.yaml"
        cfg_file.write_text("profile: local_lab\nlog_level: DEBUG\n")
        cfg = load_config(cfg_file)
        assert cfg.log_level == "DEBUG"

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        cfg_file = tmp_path / "bad.yaml"
        cfg_file.write_text("allow_external_targets: true\n")
        with pytest.raises(ValueError):
            load_config(cfg_file)

    def test_empty_yaml_uses_defaults(self, tmp_path):
        cfg_file = tmp_path / "empty.yaml"
        cfg_file.write_text("")
        cfg = load_config(cfg_file)
        assert cfg.engagement.allow_external_targets is False
