"""
cyber_range.logging.structured
================================
Structured JSONL logger.

Every log entry is a JSON line with:
    timestamp, run_id, phase, level, event, message, context

Sensitive field names are redacted automatically.
Secrets are never written to disk.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Fields that should never be logged
_SENSITIVE_KEYS = frozenset({
    "api_key", "apikey", "api-key", "token", "secret", "password",
    "passwd", "credential", "authorization", "auth_token", "private_key",
    "access_key", "secret_key", "session_token", "aws_secret",
})

_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(SYNTHETIC_VALID_TOKEN|sk-[a-zA-Z0-9]{20,}|"
    r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*|"
    r"(?:api[-_]?key|token)\s*[:=]\s*\S+)"
)


def _redact(obj: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive values from a dict/list."""
    if depth > 10:
        return obj
    if isinstance(obj, dict):
        return {
            k: "[REDACTED]" if k.lower().replace("-", "_") in _SENSITIVE_KEYS else _redact(v, depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(i, depth + 1) for i in obj]
    if isinstance(obj, str):
        return _SENSITIVE_VALUE_RE.sub("[REDACTED]", obj)
    return obj


class StructuredLogger:
    """
    Writes structured JSONL logs to a file and optionally to stderr.

    Usage:
        logger = StructuredLogger(run_id="RUN-abc", log_path=Path("logs.jsonl"))
        logger.info("scenario_started", "Starting T1078 on iam_role_demo",
                    phase="simulation", asset="iam_role_demo")
        logger.warning("policy_check", "Technique T1485 blocked")
        logger.error("phase_failed", "Evidence collection failed", exc="...")
    """

    LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}

    def __init__(
        self,
        run_id:      str  = "unknown",
        log_path:    Optional[Path] = None,
        min_level:   str  = "INFO",
        stderr:      bool = False,
    ):
        self.run_id    = run_id
        self.log_path  = log_path
        self.min_level = self.LEVELS.get(min_level.upper(), 20)
        self.stderr    = stderr
        self._file     = None

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(log_path, "a", encoding="utf-8", buffering=1)

    def _emit(self, level: str, event: str, message: str, phase: str = "", **context: Any) -> None:
        if self.LEVELS.get(level, 0) < self.min_level:
            return

        entry = _redact({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id":    self.run_id,
            "phase":     phase,
            "level":     level,
            "event":     event,
            "message":   message,
            "context":   context or {},
        })

        line = json.dumps(entry, ensure_ascii=False, default=str)
        if self._file:
            self._file.write(line + "\n")
        if self.stderr:
            print(line, file=sys.stderr)

    def debug(self, event: str, message: str, phase: str = "", **ctx: Any) -> None:
        self._emit("DEBUG", event, message, phase, **ctx)

    def info(self, event: str, message: str, phase: str = "", **ctx: Any) -> None:
        self._emit("INFO", event, message, phase, **ctx)

    def warning(self, event: str, message: str, phase: str = "", **ctx: Any) -> None:
        self._emit("WARNING", event, message, phase, **ctx)

    def error(self, event: str, message: str, phase: str = "", **ctx: Any) -> None:
        self._emit("ERROR", event, message, phase, **ctx)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> "StructuredLogger":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# Global no-op logger for modules that haven't been given a real logger
_NOOP = StructuredLogger()


def get_noop_logger() -> StructuredLogger:
    return _NOOP
