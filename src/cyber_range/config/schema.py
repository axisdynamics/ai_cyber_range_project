"""
cyber_range.config.schema
=========================
Validated configuration model using Pydantic v2.
All config values are validated before any pipeline phase runs.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


# ── Technique ID format ────────────────────────────────────────────────────────
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

BLOCKED_TECHNIQUES_DEFAULT = ["T1485", "T1561", "T1529"]

ALLOWED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
ALLOWED_LLM_MODES  = {"anthropic", "deterministic", "disabled"}
ALLOWED_PROFILES   = {"local_lab", "purple_team", "blue_team_validation"}


class LLMConfig(BaseModel):
    mode:    str = Field(default="deterministic",   description="LLM mode: anthropic | deterministic | disabled")
    model:   str = Field(default="claude-sonnet-4-20250514")
    timeout: int = Field(default=20, ge=1, le=120)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ALLOWED_LLM_MODES:
            raise ValueError(f"llm.mode must be one of {ALLOWED_LLM_MODES}, got '{v}'")
        return v


class RetentionConfig(BaseModel):
    max_runs:         int = Field(default=50,  ge=1)
    max_age_days:     int = Field(default=90,  ge=1)
    compress_old:     bool = Field(default=False)


class EngagementConfig(BaseModel):
    allow_external_targets: bool        = Field(default=False)
    authorized_assets:      List[str]   = Field(default_factory=list)
    blocked_techniques:     List[str]   = Field(default_factory=lambda: list(BLOCKED_TECHNIQUES_DEFAULT))
    chain_depth:            int         = Field(default=6, ge=1, le=12)
    max_scenarios:          int         = Field(default=200, ge=1)
    timeout_seconds:        int         = Field(default=300, ge=10, le=3600)

    @field_validator("blocked_techniques", mode="before")
    @classmethod
    def validate_techniques(cls, v: List[str]) -> List[str]:
        for t in v:
            if not _TECHNIQUE_RE.match(t):
                raise ValueError(f"Invalid technique ID format: '{t}'. Expected T#### or T####.###")
        return v

    @model_validator(mode="after")
    def ensure_destructive_blocked(self) -> "EngagementConfig":
        for t in BLOCKED_TECHNIQUES_DEFAULT:
            if t not in self.blocked_techniques:
                self.blocked_techniques.append(t)
        return self


class CyberRangeConfig(BaseModel):
    """Root configuration model. All fields have safe defaults."""

    version:    str = Field(default="1.0")
    profile:    str = Field(default="local_lab", description="Scenario profile")

    engagement: EngagementConfig = Field(default_factory=EngagementConfig)
    llm:        LLMConfig        = Field(default_factory=LLMConfig)
    retention:  RetentionConfig  = Field(default_factory=RetentionConfig)

    # Paths
    artifacts_dir:      str = Field(default="artifacts")
    data_dir:           str = Field(default="python_orchestrator/data")
    reports_dir:        str = Field(default="python_orchestrator/reports")

    # Operational
    log_level:          str  = Field(default="INFO")
    dry_run:            bool = Field(default=False)
    deterministic_seed: int  = Field(default=42)

    # API
    api_key_enabled:    bool = Field(default=False)
    cors_allowlist:     List[str] = Field(default_factory=list)

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v not in ALLOWED_PROFILES:
            raise ValueError(f"profile must be one of {ALLOWED_PROFILES}, got '{v}'")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        v = v.upper()
        if v not in ALLOWED_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {ALLOWED_LOG_LEVELS}")
        return v

    @model_validator(mode="after")
    def no_external_targets_safety_check(self) -> "CyberRangeConfig":
        if self.engagement.allow_external_targets:
            raise ValueError(
                "allow_external_targets=true is not permitted. "
                "This system operates on local authorized fixtures only."
            )
        return self

    def artifacts_path(self, base: Path | None = None) -> Path:
        root = base or Path.cwd()
        return root / self.artifacts_dir

    def runs_path(self, base: Path | None = None) -> Path:
        return self.artifacts_path(base) / "runs"


def load_config(path: Path, project_root: Path | None = None) -> CyberRangeConfig:
    """Load and validate config from YAML. Raises ValueError with clear message on failure."""
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    # Map legacy keys for backward compat
    if "engagement_perimeter" in raw and "engagement" not in raw:
        raw["engagement"] = raw.pop("engagement_perimeter")
    if "allow_external_targets" in raw and "engagement" not in raw:
        raw["engagement"] = {"allow_external_targets": raw.pop("allow_external_targets")}

    try:
        return CyberRangeConfig(**raw)
    except Exception as e:
        raise ValueError(f"Invalid configuration in {path}: {e}") from e
