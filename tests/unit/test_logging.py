"""Unit tests for structured JSONL logger."""
import json
from pathlib import Path
import pytest
from cyber_range.logging.structured import StructuredLogger, _redact


class TestRedact:
    def test_redacts_api_key(self):
        d = {"api_key": "super_secret", "message": "hello"}
        r = _redact(d)
        assert r["api_key"] == "[REDACTED]"
        assert r["message"] == "hello"

    def test_redacts_token(self):
        d = {"token": "abc123"}
        assert _redact(d)["token"] == "[REDACTED]"

    def test_redacts_password(self):
        assert _redact({"password": "secret"})["password"] == "[REDACTED]"

    def test_nested_redaction(self):
        d = {"auth": {"api_key": "x", "user": "alice"}}
        r = _redact(d)
        assert r["auth"]["api_key"] == "[REDACTED]"
        assert r["auth"]["user"] == "alice"

    def test_list_redaction(self):
        d = {"tokens": [{"token": "abc"}, {"token": "xyz"}]}
        r = _redact(d)
        for item in r["tokens"]:
            assert item["token"] == "[REDACTED]"

    def test_safe_values_preserved(self):
        d = {"severity": "critical", "count": 42, "flag": True}
        r = _redact(d)
        assert r["severity"] == "critical"
        assert r["count"] == 42

    def test_none_passthrough(self):
        assert _redact(None) is None

    def test_string_synthetic_token_redacted(self):
        s = "AUTH_OK: SYNTHETIC_VALID_TOKEN some text"
        r = _redact(s)
        assert "SYNTHETIC_VALID_TOKEN" not in r


class TestStructuredLogger:
    def test_writes_jsonl(self, tmp_path):
        log_file = tmp_path / "test.jsonl"
        with StructuredLogger(run_id="RUN-TEST", log_path=log_file) as logger:
            logger.info("test_event", "Test message", phase="test")

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "test_event"
        assert entry["level"] == "INFO"
        assert entry["run_id"] == "RUN-TEST"
        assert entry["phase"] == "test"
        assert "timestamp" in entry

    def test_multiple_levels(self, tmp_path):
        log_file = tmp_path / "test.jsonl"
        with StructuredLogger(run_id="R", log_path=log_file, min_level="DEBUG") as logger:
            logger.debug("ev", "debug msg")
            logger.info("ev", "info msg")
            logger.warning("ev", "warn msg")
            logger.error("ev", "error msg")

        lines = log_file.read_text().strip().split("\n")
        levels = [json.loads(l)["level"] for l in lines]
        assert levels == ["DEBUG", "INFO", "WARNING", "ERROR"]

    def test_min_level_filters(self, tmp_path):
        log_file = tmp_path / "test.jsonl"
        with StructuredLogger(run_id="R", log_path=log_file, min_level="WARNING") as logger:
            logger.debug("ev", "debug")   # filtered
            logger.info("ev", "info")     # filtered
            logger.warning("ev", "warn")  # included
            logger.error("ev", "error")   # included

        lines = [l for l in log_file.read_text().strip().split("\n") if l]
        assert len(lines) == 2

    def test_secrets_not_logged(self, tmp_path):
        log_file = tmp_path / "test.jsonl"
        with StructuredLogger(run_id="R", log_path=log_file) as logger:
            logger.info("ev", "msg", api_key="super_secret", user="alice")

        content = log_file.read_text()
        assert "super_secret" not in content
        assert "[REDACTED]" in content

    def test_context_kwargs(self, tmp_path):
        log_file = tmp_path / "test.jsonl"
        with StructuredLogger(run_id="R", log_path=log_file) as logger:
            logger.info("ev", "msg", asset="iam_role", technique="T1078")

        entry = json.loads(log_file.read_text().strip())
        assert entry["context"]["asset"] == "iam_role"
        assert entry["context"]["technique"] == "T1078"

    def test_no_path_no_error(self):
        logger = StructuredLogger(run_id="R", log_path=None)
        logger.info("ev", "no file — should not raise")
        logger.close()

    def test_dir_created_if_missing(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "logs.jsonl"
        with StructuredLogger(run_id="R", log_path=nested) as logger:
            logger.info("ev", "msg")
        assert nested.exists()
