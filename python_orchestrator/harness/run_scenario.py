"""
run_scenario.py
===============
CLI para ejecutar un escenario del engagement backlog usando el HarnessOrchestrator.

Uso:
    python3 -m python_orchestrator.harness.run_scenario
    python3 -m python_orchestrator.harness.run_scenario --scenario-id 4
    python3 -m python_orchestrator.harness.run_scenario --list
    python3 -m python_orchestrator.harness.run_scenario --verify
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from python_orchestrator.harness.harness_orchestrator import HarnessOrchestrator
from python_orchestrator.harness.session_manager import SessionManager


CYAN  = '\033[0;36m'
GREEN = '\033[0;32m'
YELLOW= '\033[1;33m'
RED   = '\033[0;31m'
BOLD  = '\033[1m'
DIM   = '\033[2m'
RESET = '\033[0m'


def print_banner():
    print(f"\n{RED}{BOLD}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}{BOLD}║   AI CYBER RANGE — HARNESS ORCHESTRATOR                  ║{RESET}")
    print(f"{RED}{BOLD}║   Patrón Líder → Red Team → Blue Team                   ║{RESET}")
    print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════╝{RESET}\n")


def list_scenarios():
    sm = SessionManager()
    data = sm.load_backlog()
    scenarios = data.get("scenarios", [])
    print(f"\n{BOLD}Engagement Backlog:{RESET}")
    print(f"{'ID':>3}  {'Status':12}  {'Asset':30}  {'Técnica':8}  {'Priority':8}")
    print("─" * 75)
    for s in scenarios:
        status = s.get("status", "?")
        color = {
            "pending":     CYAN,
            "in_progress": YELLOW,
            "done":        GREEN,
            "blocked":     RED,
        }.get(status, DIM)
        print(f"{s['id']:>3}  {color}{status:12}{RESET}  {s['asset']:30}  {s['technique_id']:8}  {s.get('priority','?')}")
    pending = sum(1 for s in scenarios if s["status"] == "pending")
    done    = sum(1 for s in scenarios if s["status"] == "done")
    print(f"\n{GREEN}{done} done{RESET} · {CYAN}{pending} pending{RESET}\n")


def verify_harness():
    sm = SessionManager()
    errors = sm.verify_harness()
    print(f"\n{BOLD}Harness verification:{RESET}")
    if not errors:
        print(f"  {GREEN}[✓] Arnés en estado sano.{RESET}\n")
        return 0
    for e in errors:
        print(f"  {RED}[✗] {e}{RESET}")
    print()
    return 1


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AI Cyber Range — Harness Runner")
    parser.add_argument("--scenario-id", type=int, help="ID del escenario a ejecutar (default: el siguiente pending)")
    parser.add_argument("--list",   action="store_true", help="Listar todos los escenarios")
    parser.add_argument("--verify", action="store_true", help="Verificar estado del arnés")
    parser.add_argument("--quiet",  action="store_true", help="Output reducido")
    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return

    if args.verify:
        sys.exit(verify_harness())

    # Verify before running
    rc = verify_harness()
    if rc != 0:
        print(f"{RED}[✗] Arnés en estado inválido. Corrige antes de ejecutar.{RESET}\n")
        sys.exit(1)

    orch = HarnessOrchestrator()
    result = orch.run_single_scenario(
        scenario_id=args.scenario_id,
        verbose=not args.quiet,
    )

    print(f"\n{'─'*60}")
    verdict_color = GREEN if result.verdict == "APPROVED" else (YELLOW if result.verdict == "BLOCKED" else RED)
    print(f"\n{BOLD}Resultado:{RESET} {verdict_color}{result.verdict}{RESET}")
    print(f"  Scenario:   #{result.scenario_id}")
    print(f"  Finding:    {result.finding_id or '—'}")
    print(f"  Evidencias: {result.evidence_count}")
    print(f"  Duración:   {result.duration_seconds:.2f}s")
    if result.impl_ref:
        print(f"  Impl:       {DIM}{result.impl_ref}{RESET}")
    if result.review_ref:
        print(f"  Review:     {DIM}{result.review_ref}{RESET}")
    if result.notes:
        print(f"  Notas:      {DIM}{result.notes}{RESET}")

    print()
    sys.exit(0 if result.verdict == "APPROVED" else 1)


if __name__ == "__main__":
    main()
