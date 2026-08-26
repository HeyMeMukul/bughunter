#!/usr/bin/env python3
"""
Result Quality Gate — Improvement #2: Worker Result Quality Gates
=================================================================
Validates Worker result files against a schema and checks for completeness.
Flags inconsistencies between result claims and state.json data.

Usage:
    python3 tools/result_quality_gate.py results/result-NNN-*.md
    python3 tools/result_quality_gate.py --validate-state
    python3 tools/result_quality_gate.py --check-consistency

Exit codes: 0 = passed, 1 = failed, 2 = warnings
"""

import sys
import os
import json
import re
import argparse
from pathlib import Path
from datetime import datetime, timezone

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
RESULTS_DIR = FRAMEWORK_ROOT / "results"
ENGAGEMENT_DIR = FRAMEWORK_ROOT / "engagement"

# ─── State JSON Schema ────────────────────────────────────────────────────────

STATE_SCHEMA = {
    "engagement": {
        "required_keys": ["program", "target", "started", "status", "current_focus"],
        "valid_statuses": ["not_started", "active", "paused", "complete"],
        "valid_focus": [
            "phase_0_recon",
            "phase_1_spidering",
            "phase_2_mapping",
            "phase_3_testing",
            "phase_4_validating",
            "phase_5_reporting",
        ],
    },
    "recon": {
        "required_keys": ["status", "subdomains_found", "live_hosts"],
        "valid_statuses": ["not_started", "in_progress", "complete"],
    },
    "spider": {
        "required_keys": ["status", "endpoints_total", "hidden_endpoints_found"],
        "valid_statuses": ["not_started", "in_progress", "complete"],
    },
    "mapping": {
        "required_keys": [
            "status",
            "endpoints_mapped",
            "endpoints_pending",
            "hypotheses_generated_total",
            "high_confidence_count",
        ],
    },
    "testing": {
        "required_keys": [
            "status",
            "hypotheses_total",
            "hypotheses_tested",
            "hypotheses_confirmed",
            "hypotheses_negative",
            "high_priority_pending",
        ],
    },
    "validating": {"required_keys": ["status", "validated_count", "pending"]},
    "reporting": {"required_keys": ["status", "reports_written", "pending"]},
}

# Required sections per result phase
RESULT_REQUIRED_SECTIONS = {
    "1": [
        "## Status:",
        "## Commands Executed",
        "## Output Files Created",
        "## Notable Counts",
        "## Errors / Notes",
        "## State Updates Needed",
    ],
    "2": [
        "## Status:",
        "## Endpoints Mapped",
        "## High-Priority Hypotheses Generated",
        "## Cross-Endpoint Observations",
        "## Operational Notes",
        "## State Updates Needed",
    ],
    "3": [
        "## Status:",
        "## Confidence:",
        "## Hypothesis Tested",
        "## Skill Phases Executed",
        "## Evidence",
        "## Verdict",
        "## Incidental Signals",
        "## State Updates Needed",
    ],
    "4": [
        "## Validation Status:",
        "## CVSS v3.1",
        "## Reproduction Steps",
        "## Impact Analysis",
        "## Chain Potential",
        "## Affected Endpoints",
        "## Evidence Files",
    ],
}

# ─── Helpers ─────────────────────────────────────────────────────────────────


def load_state() -> dict:
    with open(STATE_FILE) as f:
        return json.load(f)


def extract_phase_from_result(content: str) -> str:
    """Guess phase from result content."""
    if "Spidering Complete" in content or "spider.sh" in content.lower():
        return "1"
    if "Mapping Batch" in content or "Endpoints Mapped" in content:
        return "2"
    if "Testing HYP-" in content or "Hypothesis Tested" in content:
        return "3"
    if "Validated Finding" in content or "Validation Status" in content:
        return "4"
    return "unknown"


# ─── Validation Checks ────────────────────────────────────────────────────────


class GateResult:
    def __init__(self, name: str):
        self.name = name
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0


def validate_state_schema() -> GateResult:
    """Validate state.json against required schema."""
    gate = GateResult("state.json schema")
    print("\n[CHECK] Validating state.json schema...")

    try:
        state = load_state()
    except FileNotFoundError:
        gate.errors.append("state.json not found")
        return gate
    except json.JSONDecodeError as e:
        gate.errors.append(f"state.json is not valid JSON: {e}")
        return gate

    gate.info.append("state.json is valid JSON")

    for section, rules in STATE_SCHEMA.items():
        if section not in state:
            gate.errors.append(f"Missing top-level section: '{section}'")
            continue

        section_data = state[section]

        for key in rules.get("required_keys", []):
            if key not in section_data:
                gate.errors.append(f"state.json['{section}'] missing key: '{key}'")

        if "valid_statuses" in rules:
            status = section_data.get("status", "")
            if status not in rules["valid_statuses"]:
                gate.errors.append(
                    f"state.json['{section}'].status = '{status}' "
                    f"(valid: {rules['valid_statuses']})"
                )

        if "valid_focus" in rules:
            focus = section_data.get("current_focus", "")
            if focus and focus not in rules["valid_focus"]:
                gate.warnings.append(
                    f"state.json.engagement.current_focus = '{focus}' "
                    f"(valid: {rules['valid_focus']})"
                )

    # Validate findings array
    if "findings" not in state:
        gate.warnings.append("state.json has no 'findings' array")
    else:
        for i, finding in enumerate(state["findings"]):
            for key in ["id", "type", "endpoint", "severity", "status"]:
                if key not in finding:
                    gate.warnings.append(f"findings[{i}] missing key: '{key}'")

    gate.info.append("state.json schema validation complete")
    return gate


def check_result_completeness(result_path: Path) -> GateResult:
    """Check a Worker result file for required sections."""
    gate = GateResult(result_path.name)
    print(f"\n[CHECK] Validating result: {result_path.name}")

    try:
        content = result_path.read_text()
    except FileNotFoundError:
        gate.errors.append(f"Result file not found: {result_path}")
        return gate

    phase = extract_phase_from_result(content)
    gate.info.append(f"Detected phase: {phase}")

    required = RESULT_REQUIRED_SECTIONS.get(phase, [])
    if not required:
        gate.warnings.append(
            f"Unknown phase detected — cannot validate required sections. "
            "Manual review needed."
        )
        return gate

    for section in required:
        if section not in content:
            gate.errors.append(f"Missing required section: '{section}'")
        else:
            gate.info.append(f"Section present: '{section}'")

    # Phase-specific extra checks
    if phase == "3":
        # Must have a clear verdict
        if "CONFIRMED" not in content and "NEGATIVE" not in content and "PARTIAL" not in content:
            gate.errors.append(
                "Phase 3 result has no clear CONFIRMED/NEGATIVE/PARTIAL verdict"
            )

        # Evidence must include actual HTTP request/response
        if "HTTP/1.1" not in content and "HTTP/2" not in content:
            gate.errors.append(
                "Phase 3 result has no HTTP request/response evidence — "
                "evidence section appears incomplete"
            )

    if phase == "4":
        # Must have CVSS score
        if "CVSS:3.1/" not in content:
            gate.errors.append(
                "Phase 4 validation result missing CVSS v3.1 vector string"
            )

        # Must have evidence files listed
        if "poc/" not in content:
            gate.warnings.append(
                "Phase 4 result has no poc/ evidence file references"
            )

    return gate


def check_state_consistency() -> GateResult:
    """Check for inconsistencies between state.json claims and actual files."""
    gate = GateResult("state consistency")
    print("\n[CHECK] Checking state.json consistency with actual files...")

    try:
        state = load_state()
    except Exception as e:
        gate.errors.append(f"Cannot load state.json: {e}")
        return gate

    # 1. If spider says complete, sitemap must exist
    spider = state.get("spider", {})
    if spider.get("status") == "complete":
        sitemap_path = spider.get("sitemap_path")
        if sitemap_path:
            full_path = FRAMEWORK_ROOT / sitemap_path
            if not full_path.exists():
                gate.errors.append(
                    f"state.json says spider complete with sitemap at '{sitemap_path}' "
                    "but file does not exist"
                )
        else:
            gate.warnings.append(
                "Spider marked complete but no sitemap_path in state.json"
            )

    # 2. Mapping: endpoints_mapped vs actual profile files
    mapping = state.get("mapping", {})
    mapped_count = mapping.get("endpoints_mapped", 0)
    actual_profiles = list((ENGAGEMENT_DIR / "mapping").glob("EP-*.profile.yaml"))
    actual_count = len(actual_profiles)

    if abs(mapped_count - actual_count) > 2:
        gate.warnings.append(
            f"state.json says {mapped_count} endpoints mapped, "
            f"but {actual_count} profile files exist in engagement/mapping/ "
            f"(delta: {abs(mapped_count - actual_count)})"
        )
    else:
        gate.info.append(
            f"Mapping count consistent: {mapped_count} in state, "
            f"{actual_count} profile files"
        )

    # 3. Testing: hypotheses_confirmed vs actual confirmed files
    testing = state.get("testing", {})
    confirmed_count = testing.get("hypotheses_confirmed", 0)
    actual_confirmed = list((ENGAGEMENT_DIR / "findings").glob("*.confirmed.md"))
    actual_confirmed_count = len(actual_confirmed)

    if abs(confirmed_count - actual_confirmed_count) > 1:
        gate.warnings.append(
            f"state.json says {confirmed_count} confirmed hypotheses, "
            f"but {actual_confirmed_count} .confirmed.md files exist "
            f"(delta: {abs(confirmed_count - actual_confirmed_count)})"
        )

    # 4. Check "Phase X COMPLETE" claim vs state counters
    # If Worker result says "Phase 2 COMPLETE" but endpoints_pending is not empty
    results_dir = RESULTS_DIR
    if results_dir.exists():
        for result_file in results_dir.glob("result-*-mapping*.md"):
            content = result_file.read_text()
            if "COMPLETE" in content:
                pending = mapping.get("endpoints_pending", [])
                if pending:
                    gate.warnings.append(
                        f"Result '{result_file.name}' claims mapping COMPLETE "
                        f"but state.json still has {len(pending)} pending endpoints: "
                        f"{pending[:3]}{'...' if len(pending) > 3 else ''}"
                    )

    return gate


# ─── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Result quality gate for the bug bounty framework"
    )
    parser.add_argument(
        "result_files",
        nargs="*",
        type=Path,
        help="Result file(s) to validate",
    )
    parser.add_argument(
        "--validate-state",
        action="store_true",
        help="Validate state.json schema only",
    )
    parser.add_argument(
        "--check-consistency",
        action="store_true",
        help="Check consistency between state.json and actual files",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all checks: state schema + consistency + all result files",
    )
    args = parser.parse_args()

    gates: list[GateResult] = []

    if args.validate_state or args.all:
        gates.append(validate_state_schema())

    if args.check_consistency or args.all:
        gates.append(check_state_consistency())

    if args.result_files:
        for rf in args.result_files:
            gates.append(check_result_completeness(Path(rf)))
    elif args.all and RESULTS_DIR.exists():
        for rf in sorted(RESULTS_DIR.glob("result-*.md")):
            gates.append(check_result_completeness(rf))

    if not gates:
        parser.print_help()
        sys.exit(1)

    # ── Summary ──
    print(f"\n{'═'*60}")
    print("QUALITY GATE SUMMARY")
    print(f"{'═'*60}")
    passed = sum(1 for g in gates if g.passed)
    failed = len(gates) - passed
    print(f"  Checks run:  {len(gates)}")
    print(f"  Passed:      {passed}")
    print(f"  Failed:      {failed}")

    for gate in gates:
        status = "✓ PASS" if gate.passed else "✗ FAIL"
        warn_str = f" ({len(gate.warnings)} warnings)" if gate.warnings else ""
        print(f"  {status}{warn_str}: {gate.name}")

    worst = max((g.exit_code for g in gates), default=0)
    sys.exit(worst)


if __name__ == "__main__":
    main()
