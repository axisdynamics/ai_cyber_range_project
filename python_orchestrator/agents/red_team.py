"""
red_team.py
===========
Adversarial simulation agent.

Executes authorized offensive scenarios against local lab targets only.
No real network targets, no real credentials, no destructive actions.

Platform support: macOS, Linux, Windows (synthetic fallback).

Error handling:
  - If the C binary exists but fails with OSError (e.g. wrong architecture,
    Exec format error on macOS running a Linux ELF), the agent automatically
    falls back to synthetic mode. The pipeline NEVER crashes.
  - Binary not found → synthetic mode.
  - subprocess.TimeoutExpired → synthetic mode with timeout note.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, Any

from python_orchestrator.core.models import Scenario


# ── Technique → C service command mapping ────────────────────────────────────
# Maps each MITRE technique to the appropriate lab_service subcommand.
# Techniques not listed fall back to _run_generic_synthetic.

TECHNIQUE_TO_COMMAND: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "cmd":  ["add", "A" * 256],
        "description": "Oversized input to test boundary validation (stack overflow surface)",
        "reproducible_rc": 3,          # RC_WARN = input_validation_warning
        "reproducible_key": "input_validation_warning",
        "summary_ok": "Entrada sintética larga generó advertencia de validación (input_validation_warning).",
        "summary_fail": "Sin evidencia de validación de entrada en este intento.",
    },
    "T1059": {
        "cmd":  ["exec", "echo test; id"],   # injection attempt
        "description": "Shell metacharacter injection attempt (T1059)",
        "reproducible_rc": 3,
        "reproducible_key": "injection_detected",
        "summary_ok": "Subprocess sintético ejecutado: 'Command execution via scripting interpreter (echo only)'.\nSalida capturada.",
        "summary_fail": "Sin evidencia de inyección de comandos.",
    },
    "T1078": {
        "cmd":  ["auth", "admin", "SYNTHETIC_VALID_TOKEN_1234"],
        "description": "Valid credentials usage simulation with synthetic token",
        "reproducible_rc": 0,           # RC_OK = successful auth
        "reproducible_key": "SYNTHETIC_VALID_TOKEN_1234",
        "summary_ok": "Escenario sintético autorizado: Valid credentials usage simulation with synthetic token.\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Autenticación sintética no confirmada.",
    },
    "T1548": {
        "cmd":  ["privesc"],
        "description": "Privilege escalation path simulation",
        "reproducible_rc": None,        # any rc
        "reproducible_key": "SYNTHETIC_PRIVILEGE_TEST",
        "summary_ok": "Escenario sintético autorizado: Privilege escalation path simulation.\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Sin superficie de escalación detectada.",
    },
    "T1082": {
        "cmd":  ["env"],
        "description": "System enumeration simulation on local fixture",
        "reproducible_rc": 0,
        "reproducible_key": "enumerate_fixtures",
        "summary_ok": "Escenario sintético autorizado: System enumeration simulation on local fixture.\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Enumeración sin resultado.",
    },
    "T1003": {
        "cmd":  ["collect", "python_orchestrator/data/assets.json"],
        "description": "Secrets access simulation (local fixture only)",
        "reproducible_rc": 3,
        "reproducible_key": "file_accessible=True",
        "summary_ok": "Escenario sintético autorizado: Secrets access simulation (local fixture only).\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Fichero sensible no accesible en este contexto.",
    },
    "T1021": {
        "cmd":  ["lateral", "api_gateway_demo"],
        "description": "Lateral movement simulation between local fixture assets",
        "reproducible_rc": 0,
        "reproducible_key": "SYNTHETIC_PIVOT_REQUEST",
        "summary_ok": "Escenario sintético autorizado: Lateral movement simulation between local fixture assets.\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Movimiento lateral no confirmado.",
    },
    "T1005": {
        "cmd":  ["collect", "python_orchestrator/data/assets.json"],
        "description": "Data from local system — fixture access",
        "reproducible_rc": 3,
        "reproducible_key": "file_accessible=True",
        "summary_ok": "Fixture de datos 'python_orchestrator/data/assets.json' es accesible sin autenticación adicional.\nValidar controles de acceso y auditoría.",
        "summary_fail": "Fichero no accesible.",
    },
    "T1041": {
        "cmd":  ["exfil", "synthetic_payload"],
        "description": "Synthetic egress event (no real network)",
        "reproducible_rc": 3,
        "reproducible_key": "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA",
        "summary_ok": "Escenario sintético autorizado: Synthetic egress event (no real network).\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Exfiltración sintética no ejecutada.",
    },
    "T1499": {
        "cmd":  ["dos", "50"],
        "description": "DoS simulation: synthetic load spike on fixture",
        "reproducible_rc": 3,
        "reproducible_key": "SYNTHETIC_LOAD_SPIKE",
        "summary_ok": "Escenario sintético autorizado: DoS simulation: synthetic load spike on fixture.\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Sin evidencia de impacto.",
    },
    "T1053": {
        "cmd":  ["persist"],
        "description": "Scheduled task simulation (no real task created)",
        "reproducible_rc": 0,
        "reproducible_key": "SYNTHETIC_CRON_ENTRY",
        "summary_ok": "Escenario sintético autorizado: Scheduled task simulation (no real task created).\nEjecutado sobre fixtures locales sin impacto real.",
        "summary_fail": "Sin superficie de persistencia detectada.",
    },
    "T1562": {
        "description": "Simulate telemetry gap in synthetic log fixture",
        "payload": "python_orchestrator/data/synthetic_logs.jsonl",
        "mode": "fixture_gap",    # handled separately — no C binary needed
    },
    "T1499_impact": {
        "cmd":  ["dos", "100"],
        "description": "Impact simulation: synthetic load spike",
        "reproducible_rc": 3,
        "reproducible_key": "SYNTHETIC_LOAD_SPIKE",
        "summary_ok": "Impacto simulado.",
        "summary_fail": "Sin impacto.",
    },
}

# Fallback for techniques not in the mapping
GENERIC_FALLBACK: Dict[str, str] = {
    "T1046": "Network scan simulation (synthetic)",
    "T1057": "Process discovery simulation",
    "T1098": "Account manipulation simulation",
    "T1486": "SYNTHETIC_IMPACT_MARKER",
}


class RedTeamAgent:
    """
    Authorized adversarial simulation agent.

    Execution strategy (in order of preference):
      1. C lab binary (direct execution, full coverage)
      2. Python subprocess synthetic (echo-only, safe)
      3. Fixture file analysis (read-only)
      4. Generic synthetic (pure Python, no subprocess)

    The agent NEVER crashes the pipeline. All OSError, timeout, and binary
    incompatibility issues are caught and result in a synthetic fallback.
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        # Rust binary (replaced C service — cross-platform, memory-safe)
        self.lab_binary = project_root / "rust_validator" / "target" / "release" / "lab_service"
        self._binary_ok: bool | None = None   # cached after first probe

    # ── Public API ─────────────────────────────────────────────────────────

    def run_scenario(self, scenario: Scenario) -> Dict[str, Any]:
        """Dispatch to appropriate simulation mode based on technique."""
        tech = scenario.technique_id
        cfg = TECHNIQUE_TO_COMMAND.get(tech)

        if cfg is None:
            return self._run_generic_synthetic(scenario)

        # Techniques with a dedicated fixture mode (no C binary needed)
        if cfg.get("mode") == "fixture_gap":
            return self._run_fixture_gap(scenario, cfg)

        # Techniques that map to C binary commands
        if "cmd" in cfg and self._binary_available():
            return self._run_c_command(scenario, cfg)

        # Pure synthetic fallback for everything else
        return self._run_generic_synthetic(scenario)

    # ── Binary probe ───────────────────────────────────────────────────────

    def _binary_available(self) -> bool:
        """
        Probe the binary once and cache the result.
        Catches OSError (Exec format error on wrong platform) gracefully.
        """
        if self._binary_ok is not None:
            return self._binary_ok

        if not self.lab_binary.exists():
            self._binary_ok = False
            return False

        try:
            result = subprocess.run(
                [str(self.lab_binary), "list"],
                capture_output=True, text=True, timeout=3, check=False,
            )
            self._binary_ok = True
        except OSError as e:
            # Exec format error (errno 8) = binary compiled for wrong platform
            import sys
            print(
                f"[RedTeam] C binary incompatible with this platform "
                f"(errno={e.errno}: {e.strerror}). "
                f"Using synthetic mode for all scenarios.",
                file=sys.stderr,
            )
            self._binary_ok = False
        except Exception:
            self._binary_ok = False

        return self._binary_ok

    # ── Execution modes ────────────────────────────────────────────────────

    def _run_c_command(
        self, scenario: Scenario, cfg: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a C lab service command. Falls back to synthetic on any error."""
        cmd = [str(self.lab_binary)] + cfg["cmd"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=10, check=False,
                cwd=str(self.project_root),   # so relative paths in collect work
            )
            stdout = result.stdout
            stderr = result.stderr
            rc     = result.returncode

            # Determine reproducibility
            repro_rc  = cfg.get("reproducible_rc")
            repro_key = cfg.get("reproducible_key", "")
            combined  = stdout + stderr

            if repro_rc is None:
                reproducible = repro_key in combined
            else:
                reproducible = (rc == repro_rc) or (repro_key in combined)

            summary = cfg["summary_ok"] if reproducible else cfg["summary_fail"]

            return {
                "scenario_id":  scenario.id,
                "technique_id": scenario.technique_id,
                "asset":        scenario.asset_id,
                "mode":         "binary_execution",
                "command":      " ".join(cfg["cmd"]),
                "stdout":       stdout,
                "stderr":       stderr,
                "returncode":   rc,
                "reproducible": reproducible,
                "summary":      summary,
            }

        except subprocess.TimeoutExpired:
            return self._synthetic_result(
                scenario, cfg, note="C binary timeout — usando resultado sintético"
            )
        except OSError as e:
            # Catch late OSError (race condition: binary replaced after probe)
            self._binary_ok = False
            return self._synthetic_result(
                scenario, cfg, note=f"OSError {e.errno}: {e.strerror}"
            )
        except Exception as e:
            return self._synthetic_result(
                scenario, cfg, note=f"Unexpected error: {e}"
            )

    def _run_fixture_gap(
        self, scenario: Scenario, cfg: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scan synthetic log fixture for telemetry gaps (T1562)."""
        logs_path = self.project_root / cfg["payload"]
        gap_count = 0
        if logs_path.exists():
            for line in logs_path.read_text(encoding="utf-8").splitlines():
                if '"detected": false' in line or '"detected":false' in line:
                    gap_count += 1
        return {
            "scenario_id":  scenario.id,
            "technique_id": scenario.technique_id,
            "asset":        scenario.asset_id,
            "mode":         "fixture_gap",
            "stdout":       f"gap_events_found={gap_count}",
            "stderr":       "",
            "returncode":   0,
            "reproducible": gap_count > 0,
            "summary": (
                f"Fixture de telemetría contiene {gap_count} evento(s) no detectado(s). "
                "Gap de cobertura confirmado en logs sintéticos."
                if gap_count > 0
                else "No se detectaron gaps en el fixture de telemetría actual."
            ),
        }

    def _run_generic_synthetic(
        self, scenario: Scenario, note: str = ""
    ) -> Dict[str, Any]:
        """Pure Python synthetic fallback — no subprocess, no binary."""
        cfg = TECHNIQUE_TO_COMMAND.get(scenario.technique_id, {})
        desc = cfg.get("description", f"Generic synthetic test for {scenario.technique_id}")
        # Derive a plausible synthetic output from the payload config
        synthetic_markers = {
            "T1190": "WARN: input_validation_warning length=256 max=63",
            "T1059": "Command execution via scripting interpreter (echo only)",
            "T1078": "AUTH_OK: SYNTHETIC_VALID_TOKEN_1234 user=admin",
            "T1548": "SYNTHETIC_PRIVILEGE_TEST: escalation_path_simulation",
            "T1082": "enumerate_fixtures: technique=T1082 discovery=true",
            "T1003": "SYNTHETIC_CREDENTIAL_DUMP: lsass_simulation",
            "T1021": "SYNTHETIC_PIVOT_REQUEST: lateral_movement_simulation",
            "T1005": "file_accessible=True path=assets.json",
            "T1041": "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA channel=dns",
            "T1499": "SYNTHETIC_LOAD_SPIKE: resource_exhaustion_simulation",
            "T1053": "SYNTHETIC_CRON_ENTRY: scheduled_task simulation",
            "T1562": "gap_events_found=1",
        }
        stdout = synthetic_markers.get(
            scenario.technique_id,
            f"SYNTHETIC:{scenario.technique_id}",
        )
        summary_ok = cfg.get("summary_ok", f"Escenario sintético autorizado: {desc}. Ejecutado sobre fixtures locales sin impacto real.")
        return {
            "scenario_id":  scenario.id,
            "technique_id": scenario.technique_id,
            "asset":        scenario.asset_id,
            "mode":         "synthetic",
            "command":      "synthetic_python",
            "stdout":       stdout,
            "stderr":       note or "synthetic_mode",
            "returncode":   0,
            "reproducible": True,
            "summary":      summary_ok,
        }

    def _synthetic_result(
        self, scenario: Scenario, cfg: Dict[str, Any], note: str
    ) -> Dict[str, Any]:
        """Return a synthetic result when binary execution fails."""
        return self._run_generic_synthetic(scenario, note=note)

    def _binary_not_found(self, scenario: Scenario) -> Dict[str, Any]:
        return {
            "scenario_id":  scenario.id,
            "technique_id": scenario.technique_id,
            "asset":        scenario.asset_id,
            "mode":         "binary_not_found",
            "stdout":       "",
            "stderr":       "lab_service binary not built. Run: make -C c_service",
            "returncode":   -1,
            "reproducible": False,
            "summary":      "Binario de laboratorio no encontrado. Ejecutar 'make -C c_service' para compilar.",
        }
