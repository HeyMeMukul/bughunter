#!/usr/bin/env python3
"""
Task Validator — Improvement #1: Validation Layer Between Lead and Worker
=========================================================================
Pre-dispatch validation that checks:
  1. Task file is well-formed (required sections present)
  2. Referenced files exist (endpoint profiles, skill files)
  3. Credentials/sessions not expired (check state.json timestamps)
  4. Task scope is reasonable (endpoint count limits, etc.)
  5. Hypothesis not already tested (deduplication)

Usage:
    python3 tools/task_validator.py tasks/task-NNN-*.md
    python3 tools/task_validator.py --all-pending

Exit codes: 0 = valid, 1 = invalid (do NOT dispatch), 2 = warning (review before dispatch)
"""

import sys
import os
import json
import re
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
TASKS_DIR = FRAMEWORK_ROOT / "tasks"
RESULTS_DIR = FRAMEWORK_ROOT / "results"
SKILLS_DIR = FRAMEWORK_ROOT / "skills"
ENGAGEMENT_DIR = FRAMEWORK_ROOT / "engagement"

REQUIRED_TASK_SECTIONS = ["## Phase:", "## Status:", "## Objective"]
REQUIRED_SKILL_REFS = {
    "2": "skills/mapping/SKILL.md",
    # Phase 3 skill is dynamic — just verify the path exists
}

# Sessions older than this trigger a warning
SESSION_EXPIRY_HOURS = 8

# Max endpoints per mapping batch
MAX_MAPPING_BATCH = 5

# ─── Helpers ─────────────────────────────────────────────────────────────────


def load_state() -> dict:
    """Load and return state.json; return {} on failure."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [WARN] Could not read state.json: {e}", file=sys.stderr)
        return {}


def load_task(task_path: Path) -> str:
    """Load task file content."""
    with open(task_path) as f:
        return f.read()


def extract_phase(content: str) -> str:
    """Extract phase number from task content."""
    m = re.search(r"## Phase:\s*(\d)", content)
    return m.group(1) if m else "unknown"


def extract_skill_ref(content: str) -> str | None:
    """Extract skill file reference from task content."""
    m = re.search(r"(?:Load|Skill File|skills/):\s*(skills/[^\s\n]+)", content)
    if m:
        return m.group(1)
    # Also match bare `Load: skills/...` lines
    m = re.search(r"Load:\s*(skills/\S+)", content)
    return m.group(1) if m else None


def extract_hypothesis_id(content: str) -> str | None:
    """Extract HYP-XXX from a Phase 3 task."""
    m = re.search(r"\b(HYP-\d{3})\b", content)
    return m.group(1) if m else None


def extract_profile_refs(content: str) -> list[str]:
    """Extract all EP-XXX.profile.yaml references."""
    return re.findall(r"(engagement/mapping/EP-\d+\.profile\.yaml)", content)


def extract_endpoint_ids(content: str) -> list[str]:
    """Extract EP-XXX endpoint IDs listed in the task."""
    return re.findall(r"\bEP-(\d{3})\b", content)


def parse_session_timestamp(ts_str: str | None) -> datetime | None:
    """Parse an ISO timestamp string into a datetime object."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─── Validation Checks ───────────────────────────────────────────────────────


class ValidationResult:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 1
        if self.warnings:
            return 2
        return 0


def check_task_structure(content: str, result: ValidationResult):
    """Check #1: Task file must have required sections."""
    for section in REQUIRED_TASK_SECTIONS:
        if section not in content:
            result.errors.append(f"Missing required section: '{section}'")

    if "## Status: PENDING" not in content:
        result.warnings.append(
            "Task status is not 'PENDING' — may be a stale/already-dispatched task"
        )


def check_referenced_files(content: str, result: ValidationResult):
    """Check #2: All referenced files must exist."""
    # Skill file reference
    skill_ref = extract_skill_ref(content)
    if skill_ref:
        skill_path = FRAMEWORK_ROOT / skill_ref
        if not skill_path.exists():
            result.errors.append(f"Skill file not found: {skill_ref}")
        else:
            result.info.append(f"Skill file OK: {skill_ref}")

    # Endpoint profile references
    for profile_ref in extract_profile_refs(content):
        profile_path = FRAMEWORK_ROOT / profile_ref
        if not profile_path.exists():
            result.errors.append(f"Endpoint profile not found: {profile_ref}")
        else:
            result.info.append(f"Profile OK: {profile_ref}")

    # Hidden endpoints / WAF fingerprint references
    for path_pattern in [
        "engagement/spider/waf/waf_fingerprint.json",
        "engagement/spider/fuzz/hidden_endpoints.json",
    ]:
        if path_pattern in content:
            full_path = FRAMEWORK_ROOT / path_pattern
            if not full_path.exists():
                result.warnings.append(
                    f"Referenced file not found (non-critical): {path_pattern}"
                )


def check_session_freshness(content: str, state: dict, result: ValidationResult):
    """Check #3: Session credentials must not be expired."""
    sessions = state.get("sessions", {})
    now = datetime.now(timezone.utc)
    expiry_threshold = timedelta(hours=SESSION_EXPIRY_HOURS)

    for session_key, session_data in sessions.items():
        last_verified = parse_session_timestamp(session_data.get("last_verified"))
        if last_verified is None:
            # No timestamp — warn only if session is referenced in the task
            if session_key in content or session_data.get("role", "") in content:
                result.warnings.append(
                    f"Session '{session_key}' has no last_verified timestamp — "
                    "verify cookie is fresh before dispatching"
                )
            continue

        age = now - last_verified
        if age > expiry_threshold:
            hours_old = age.total_seconds() / 3600
            result.warnings.append(
                f"Session '{session_key}' last verified {hours_old:.1f}h ago "
                f"(threshold: {SESSION_EXPIRY_HOURS}h) — may be expired. "
                "Re-extract cookies before dispatching."
            )
        else:
            result.info.append(
                f"Session '{session_key}' verified {age.total_seconds() / 60:.0f}m ago — OK"
            )


def check_mapping_batch_size(content: str, phase: str, result: ValidationResult):
    """Check #4: Mapping tasks must not exceed MAX_MAPPING_BATCH endpoints."""
    if phase != "2":
        return
    endpoint_ids = extract_endpoint_ids(content)
    if len(endpoint_ids) > MAX_MAPPING_BATCH:
        result.errors.append(
            f"Mapping batch too large: {len(endpoint_ids)} endpoints "
            f"(max: {MAX_MAPPING_BATCH}). Split into smaller batches."
        )
    elif len(endpoint_ids) == 0:
        result.warnings.append(
            "No EP-XXX endpoint IDs found in mapping task — verify task is correctly formatted."
        )
    else:
        result.info.append(
            f"Mapping batch size: {len(endpoint_ids)} endpoints (within limit)"
        )


def check_hypothesis_not_duplicate(
    content: str, phase: str, state: dict, result: ValidationResult
):
    """Check #5: Hypothesis must not already be tested."""
    if phase != "3":
        return

    hyp_id = extract_hypothesis_id(content)
    if not hyp_id:
        result.warnings.append("No HYP-XXX hypothesis ID found in Phase 3 task.")
        return

    # Check state.json testing section
    testing = state.get("testing", {})
    tested_ids = testing.get("tested_hypothesis_ids", [])
    if hyp_id in tested_ids:
        result.errors.append(
            f"Hypothesis {hyp_id} has already been tested "
            "(found in state.json testing.tested_hypothesis_ids). "
            "Do NOT re-dispatch."
        )
        return

    # Check for existing result files
    result_patterns = [
        f"engagement/findings/{hyp_id}.confirmed.md",
        f"engagement/findings/{hyp_id}.negative.md",
        f"engagement/findings/{hyp_id}.partial.md",
    ]
    for rp in result_patterns:
        rp_path = FRAMEWORK_ROOT / rp
        if rp_path.exists():
            result.errors.append(
                f"Hypothesis {hyp_id} already has a result file: {rp}. "
                "Do NOT re-dispatch."
            )
            return

    result.info.append(f"Hypothesis {hyp_id} is not yet tested — OK to dispatch")


def check_phase_prerequisites(content: str, phase: str, state: dict, result: ValidationResult):
    """Check that the necessary upstream phase data exists before dispatching."""
    if phase == "3":
        # Testing requires mapping profiles referenced in the task
        profiles = extract_profile_refs(content)
        if not profiles:
            result.warnings.append(
                "Phase 3 task has no endpoint profile references — "
                "testing without baseline context may produce false positives."
            )

    if phase == "4":
        # Validation requires a confirmed finding file
        hyp_ids = re.findall(r"\b(HYP-\d{3})\b", content)
        find_ids = re.findall(r"\b(FIND-\d{3})\b", content)
        for fid in find_ids:
            validated_path = FRAMEWORK_ROOT / "engagement" / "findings" / f"{fid}.validated.md"
            confirmed_path = FRAMEWORK_ROOT / "engagement" / "findings"
            # Look for any HYP-XXX.confirmed.md that maps to this finding
            confirmed_files = list(confirmed_path.glob("*.confirmed.md"))
            if not confirmed_files:
                result.warnings.append(
                    f"No confirmed finding files exist yet — "
                    "validation task dispatched before any finding is confirmed?"
                )


# ─── Main ─────────────────────────────────────────────────────────────────────


def validate_task(task_path: Path) -> ValidationResult:
    """Run all validation checks on a task file. Return a ValidationResult."""
    result = ValidationResult()
    print(f"\n{'─'*60}")
    print(f"Validating: {task_path.name}")
    print(f"{'─'*60}")

    try:
        content = load_task(task_path)
    except FileNotFoundError:
        result.errors.append(f"Task file not found: {task_path}")
        return result

    state = load_state()
    phase = extract_phase(content)
    result.info.append(f"Phase: {phase}")

    # Run all checks
    check_task_structure(content, result)
    check_referenced_files(content, result)
    check_session_freshness(content, state, result)
    check_mapping_batch_size(content, phase, result)
    check_hypothesis_not_duplicate(content, phase, state, result)
    check_phase_prerequisites(content, phase, state, result)

    # Print results
    for msg in result.info:
        print(f"  ✓  {msg}")
    for msg in result.warnings:
        print(f"  ⚠  {msg}")
    for msg in result.errors:
        print(f"  ✗  {msg}")

    if result.is_valid:
        if result.warnings:
            print(f"\n  → RESULT: VALID WITH WARNINGS (review before dispatching)")
        else:
            print(f"\n  → RESULT: VALID — safe to dispatch")
    else:
        print(f"\n  → RESULT: INVALID — do NOT dispatch ({len(result.errors)} error(s))")

    return result


def validate_all_pending() -> int:
    """Validate all PENDING task files in the tasks/ directory."""
    task_files = sorted(TASKS_DIR.glob("task-*.md"))
    if not task_files:
        print("No task files found in tasks/")
        return 0

    results = {}
    for task_file in task_files:
        results[task_file.name] = validate_task(task_file)

    # Summary
    print(f"\n{'═'*60}")
    print("VALIDATION SUMMARY")
    print(f"{'═'*60}")
    valid_count = sum(1 for r in results.values() if r.is_valid)
    invalid_count = len(results) - valid_count
    print(f"  Total tasks: {len(results)}")
    print(f"  Valid:       {valid_count}")
    print(f"  Invalid:     {invalid_count}")

    # Return worst exit code
    return max((r.exit_code for r in results.values()), default=0)


def main():
    parser = argparse.ArgumentParser(
        description="Pre-dispatch task validation for the bug bounty framework"
    )
    parser.add_argument(
        "task_files",
        nargs="*",
        type=Path,
        help="Task file(s) to validate (e.g., tasks/task-001-spider.md)",
    )
    parser.add_argument(
        "--all-pending",
        action="store_true",
        help="Validate all pending task files in tasks/",
    )
    args = parser.parse_args()

    if args.all_pending:
        sys.exit(validate_all_pending())
    elif args.task_files:
        worst_code = 0
        for task_path in args.task_files:
            r = validate_task(Path(task_path))
            worst_code = max(worst_code, r.exit_code)
        sys.exit(worst_code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()

