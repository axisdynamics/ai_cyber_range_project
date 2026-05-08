"""
poc_builder.py
==============
Generates structured, reproducible Proof-of-Concept artifacts for confirmed findings.

A PoCArtifact contains:
  - Prerequisites
  - Step-by-step reproduction guide (synthetic, within lab scope)
  - Expected output / indicators of compromise
  - A remediation hint
  - An integrity hash over the steps

All PoCs are scoped to the lab environment — they use synthetic fixtures
and local services only. No real-world systems are targeted.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any

from python_orchestrator.core.models import (
    Asset, Technique, Finding, PoCArtifact, PoCStep,
)


# Step templates per technique
TECHNIQUE_POC_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "title": "Exploit Public-Facing Application (Input Validation PoC)",
        "description": (
            "Demonstrates that the target service fails to properly validate "
            "oversized or malformed input, leading to anomalous behavior."
        ),
        "prerequisites": [
            "Access to the lab service binary or API endpoint",
            "HTTP client or CLI tool (curl, requests)",
        ],
        "steps": [
            ("Confirm service is running",
             "./lab_service status",
             "Service responds with 'OK' or similar health check"),
            ("Send normal-length input",
             "./lab_service add 'normalinput123'",
             "Service accepts input without error"),
            ("Send oversized input (boundary test)",
             "python3 -c \"print('A'*256)\" | ./lab_service add -",
             "Service logs an input_validation_warning or returns error code 3"),
            ("Capture evidence",
             "./lab_service add 'A'*512 2>&1 | tee poc_evidence.txt",
             "Evidence file created with full stdout/stderr"),
        ],
        "ioc": [
            "Process returncode 3 from lab_service",
            "Presence of 'input_validation_warning' in stderr",
            "Abnormally large argv[1] value in process audit log",
        ],
        "remediation_hint": (
            "Apply strict input length validation at service entry point. "
            "Add automated fuzz testing to CI pipeline. "
            "Enable AddressSanitizer in debug builds."
        ),
    },
    "T1059": {
        "title": "Command and Scripting Interpreter (Unsafe Automation PoC)",
        "description": (
            "Demonstrates that an automation path accepts unsanitized user input "
            "and passes it directly to a shell interpreter."
        ),
        "prerequisites": [
            "Access to the automation pipeline configuration",
            "Ability to inject parameters into workflow inputs",
        ],
        "steps": [
            ("Identify automation entry point",
             "grep -r 'subprocess\\|os.system\\|shell=True' .",
             "List of files with shell invocation patterns"),
            ("Craft a payload with metacharacters",
             "payload = 'legitimate_input; id'",
             "Payload string created"),
            ("Submit payload via authorized fixture",
             "python3 -c \"import subprocess; subprocess.run(['echo', 'payload_test'])\"",
             "Command executes; observe if isolation is enforced"),
            ("Verify output in audit log",
             "cat synthetic_logs.jsonl | grep 'execution'",
             "Execution event present with full command captured"),
        ],
        "ioc": [
            "Shell metacharacters in process arguments",
            "Unexpected child process spawned from automation service",
            "Command audit log entry with ; or | in args",
        ],
        "remediation_hint": (
            "Replace shell=True with explicit argument lists. "
            "Implement allowlist for accepted command inputs. "
            "Add SAST rule to flag unsafe subprocess patterns in CI."
        ),
    },
    "T1562": {
        "title": "Impair Defenses (Telemetry Gap PoC)",
        "description": (
            "Simulates a scenario where defensive telemetry is missing "
            "due to a configuration gap, allowing attacker actions to go unlogged."
        ),
        "prerequisites": [
            "Access to synthetic log data",
            "Knowledge of which assets should generate telemetry",
        ],
        "steps": [
            ("Establish telemetry baseline",
             "wc -l synthetic_logs.jsonl",
             "Baseline event count recorded"),
            ("Simulate telemetry gap",
             "python3 -c \"import json; [print(json.dumps({'asset': 'LOCAL_C', 'detected': False})) for _ in range(5)]\"",
             "Gap events generated"),
            ("Check if SIEM would correlate gap",
             "grep '\"detected\": false' synthetic_logs.jsonl | wc -l",
             "Count of undetected events visible"),
            ("Compare against detection threshold",
             "python3 scripts/check_coverage.py --asset local_c_lab_service",
             "Coverage report shows gap percentage"),
        ],
        "ioc": [
            "Absence of expected telemetry for a known-active asset",
            "Agent health heartbeat missing for >5 minutes",
            "SIEM rule modification timestamp changed unexpectedly",
        ],
        "remediation_hint": (
            "Implement agent health monitoring with alerting on telemetry gaps. "
            "Add SIEM rule to alert on 'absence of expected events' within time windows. "
            "Enforce immutable logging to separate storage."
        ),
    },
    "T1005": {
        "title": "Data from Local System (Unauthorized Data Access PoC)",
        "description": (
            "Demonstrates that sensitive fixture files are accessible without "
            "appropriate access controls or monitoring."
        ),
        "prerequisites": [
            "Filesystem access to the asset's data directory",
        ],
        "steps": [
            ("List data files",
             "ls -la python_orchestrator/data/",
             "Data files listed with permissions"),
            ("Attempt read of sensitive fixture",
             "cat python_orchestrator/data/assets.json",
             "File contents readable (should require authorization)"),
            ("Check for access logging",
             "cat synthetic_logs.jsonl | grep 'data_access'",
             "Verify whether read event was logged"),
            ("Validate data classification labels",
             "python3 -c \"import json; d=json.load(open('python_orchestrator/data/assets.json')); [print(a['data_classification']) for a in d['assets']]\"",
             "Classification labels present and correct"),
        ],
        "ioc": [
            "Mass file read events from non-standard process",
            "Access to data_classification='confidential' files from unexpected user",
            "Absence of data_access event in audit log after confirmed read",
        ],
        "remediation_hint": (
            "Apply filesystem ACLs to restrict data directory access. "
            "Implement file access auditing via auditd or eBPF. "
            "Ensure all data files carry classification metadata."
        ),
    },
    "T1041": {
        "title": "Exfiltration Over C2 Channel (Synthetic Egress PoC)",
        "description": (
            "Uses only synthetic fixtures to validate whether egress controls "
            "would detect an attempt to exfiltrate staged data."
        ),
        "prerequisites": [
            "Synthetic egress event generation script",
            "Egress monitoring/DLP configuration",
        ],
        "steps": [
            ("Stage synthetic data",
             "echo 'SENSITIVE_DATA_PLACEHOLDER' > /tmp/staged_data.txt",
             "Staged file created (synthetic content only)"),
            ("Simulate DNS exfil pattern",
             "python3 -c \"print('Simulated DNS query: exfil.attacker.invalid')\"",
             "DNS query pattern logged"),
            ("Simulate HTTPS upload pattern",
             "python3 -c \"print('Simulated POST to https://exfil.invalid/upload size=1024')\"",
             "Upload event logged"),
            ("Check DLP/egress alerts",
             "cat synthetic_logs.jsonl | grep 'egress'",
             "Verify detection of egress events"),
        ],
        "ioc": [
            "Large outbound transfer to unknown external endpoint",
            "DNS queries to newly-registered or randomized domains",
            "HTTPS POST to non-allow-listed destination",
        ],
        "remediation_hint": (
            "Implement egress allowlisting at network layer. "
            "Add DLP rules for outbound transfers above threshold. "
            "Enable DNS sinkhole or monitoring for anomalous query patterns."
        ),
    },
}

DEFAULT_POC_TEMPLATE = {
    "title": "Generic Technique PoC",
    "description": "Generic proof-of-concept for technique validation within authorized lab scope.",
    "prerequisites": ["Authorized access to lab environment"],
    "steps": [
        ("Setup", "# Configure lab environment", "Lab environment ready"),
        ("Execute (synthetic)", "# Run synthetic test fixture", "Test executed"),
        ("Collect evidence", "# Capture output and logs", "Evidence collected"),
        ("Validate", "# Verify finding is reproducible", "Finding confirmed"),
    ],
    "ioc": ["Technique-specific indicators captured in lab output"],
    "remediation_hint": "Apply appropriate compensating controls as recommended by hardening agent.",
}


class PoCBuilder:
    """Builds structured, reproducible PoC artifacts for confirmed findings."""

    def build(
        self,
        finding: Finding,
        asset: Asset,
        tech: Technique,
    ) -> PoCArtifact:
        tmpl = TECHNIQUE_POC_TEMPLATES.get(tech.id, DEFAULT_POC_TEMPLATE)

        steps: List[PoCStep] = []
        for i, (desc, cmd, expected) in enumerate(tmpl["steps"], start=1):
            steps.append(PoCStep(
                order=i,
                description=desc,
                command_or_action=self._inject_context(cmd, asset),
                expected_output=expected,
            ))

        # Integrity hash over step content
        steps_json = json.dumps([s.to_dict() for s in steps], sort_keys=True)
        steps_hash = hashlib.sha256(steps_json.encode()).hexdigest()[:16]

        poc_id = f"POC-{finding.id}-{steps_hash[:8].upper()}"

        return PoCArtifact(
            id=poc_id,
            finding_id=finding.id,
            technique_id=tech.id,
            asset_id=asset.id,
            title=f"[{tech.id}] {tmpl['title']} — {asset.name}",
            description=tmpl["description"],
            prerequisites=list(tmpl["prerequisites"]),
            steps=steps,
            indicators_of_compromise=list(tmpl["ioc"]),
            remediation_hint=tmpl["remediation_hint"],
            reproducible=finding.reproducible,
            created_at=datetime.utcnow().isoformat(),
            sha256_steps=steps_hash,
        )

    @staticmethod
    def _inject_context(cmd: str, asset: Asset) -> str:
        """Inject asset context into command placeholders."""
        return cmd.replace("ASSET_ID", asset.id).replace("ASSET_NAME", asset.name)
