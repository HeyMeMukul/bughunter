#!/usr/bin/env python3
"""
State Manager — Improvements #4, #8, #11: Enhanced state.json with locking,
concurrency control, session expiry, token budget tracking, and error recovery.

Features:
  - last_updated_by + timestamp tracking
  - worker_active lock flag
  - Session expiry auto-detection
  - Token budget estimation and warning
  - Task timeout tracking
  - Atomic state updates with backup

Usage:
    python3 tools/state_manager.py status
    python3 tools/state_manager.py lock-worker "task-042-test-HYP-007.md"
    python3 tools/state_manager.py unlock-worker
    python3 tools/state_manager.py check-sessions
    python3 tools/state_manager.py token-budget --add-task 3 "Phase 3 test"
    python3 tools/state_manager.py update-session session_a --verified-now
    python3 tools/state_manager.py task-timeout --check
"""

import sys
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
STATE_BACKUP = FRAMEWORK_ROOT / "state.json.bak"

# Token budget estimates per task type (rough tokens consumed per Worker task)
TOKEN_ESTIMATES = {
    "phase_0": 1500,
    "phase_0_recon": 1500,
    "phase_1": 5000,
    "phase_2_per_endpoint": 2500,
    "phase_3_per_hypothesis": 3000,
    "phase_3_5_exploitation": 2500,
    "phase_4_per_finding": 2000,
    "m9_chain_synthesis": 2000,
    "report_writing": 5000,
    "dorking": 1500,
    "sequential_thinking": 2500,
}

TOKEN_WARNING_THRESHOLD = 800_000   # Warn when approaching context limit
SESSION_EXPIRY_HOURS = 8


# ─── Core I/O ─────────────────────────────────────────────────────────────────

def load_state() -> dict:
    """Load state.json atomically."""
    try:
        return json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        print("[ERROR] state.json not found. Run setup.sh first.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] state.json is malformed: {e}", file=sys.stderr)
        sys.exit(1)


def save_state(state: dict, updated_by: str = "state_manager") -> None:
    """
    Save state.json atomically:
    1. Write to backup
    2. Update metadata
    3. Write to main file
    """
    # Backup current state
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_BACKUP)

    # Update metadata
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.setdefault("_meta", {})
    state["_meta"]["last_updated_by"] = updated_by
    state["_meta"]["last_updated_at"] = now

    STATE_FILE.write_text(json.dumps(state, indent=2))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─── Commands ────────────────────────────────────────────────────────────────


def cmd_status(state: dict) -> None:
    """Print a human-readable status summary."""
    eng = state.get("engagement", {})
    meta = state.get("_meta", {})

    print("=" * 60)
    print("ENGAGEMENT STATUS")
    print("=" * 60)
    print(f"  Program:       {eng.get('program', '?')}")
    print(f"  Target:        {eng.get('target', '?')}")
    print(f"  Status:        {eng.get('status', '?')}")
    print(f"  Current focus: {eng.get('current_focus', '?')}")
    print(f"  Started:       {eng.get('started', '?')}")
    print()

    # Concurrency status
    worker_lock = state.get("_concurrency", {})
    if worker_lock.get("worker_active"):
        print(f"  🔒 Worker ACTIVE: {worker_lock.get('active_task', '?')}")
        print(f"     Started: {worker_lock.get('task_started_at', '?')}")
        # Check for timeout
        started = parse_ts(worker_lock.get("task_started_at"))
        if started:
            elapsed = datetime.now(timezone.utc) - started
            if elapsed > timedelta(hours=1):
                print(f"  ⚠️  TIMEOUT: Worker has been running for {elapsed}")
    else:
        print("  ✅ Worker: idle")
    print()

    # Phase stats
    for phase in ["spider", "mapping", "testing", "validating", "reporting"]:
        d = state.get(phase, {})
        status = d.get("status", "not_started")
        icon = {"complete": "✅", "in_progress": "🔄", "not_started": "⬜"}.get(
            status, "?"
        )
        extra = ""
        if phase == "mapping":
            extra = f" ({d.get('endpoints_mapped', 0)} mapped / {d.get('endpoints_pending', []).__len__()} pending)"
        elif phase == "testing":
            extra = (
                f" ({d.get('hypotheses_tested', 0)} tested, "
                f"{d.get('hypotheses_confirmed', 0)} confirmed)"
            )
        elif phase == "validating":
            extra = f" ({d.get('validated_count', 0)} validated)"
        print(f"  {icon} {phase.upper()}: {status}{extra}")

    # Token budget
    budget = state.get("_token_budget", {})
    if budget:
        consumed = budget.get("estimated_consumed", 0)
        limit = budget.get("context_limit", TOKEN_WARNING_THRESHOLD)
        pct = (consumed / limit * 100) if limit else 0
        icon = "⚠️" if pct > 80 else "✅"
        print()
        print(f"  {icon} Token budget: ~{consumed:,} / {limit:,} ({pct:.0f}%)")

    # Last update
    if meta:
        print()
        print(
            f"  Last updated by: {meta.get('last_updated_by', '?')} "
            f"at {meta.get('last_updated_at', '?')}"
        )


def cmd_lock_worker(state: dict, task_name: str) -> None:
    """Set the worker_active lock."""
    conc = state.setdefault("_concurrency", {})
    if conc.get("worker_active"):
        existing = conc.get("active_task", "?")
        print(f"[ERROR] Worker is already active on: {existing}")
        print("  Use 'unlock-worker' first if the previous task is truly complete.")
        sys.exit(1)

    conc["worker_active"] = True
    conc["active_task"] = task_name
    conc["task_started_at"] = now_iso()

    save_state(state, updated_by=f"lock-worker:{task_name}")
    print(f"✅ Worker locked for task: {task_name}")


def cmd_unlock_worker(state: dict) -> None:
    """Release the worker_active lock."""
    conc = state.setdefault("_concurrency", {})
    if not conc.get("worker_active"):
        print("[INFO] Worker was not locked — nothing to do.")
        return

    task = conc.get("active_task", "?")
    started = parse_ts(conc.get("task_started_at"))
    duration = ""
    if started:
        elapsed = datetime.now(timezone.utc) - started
        duration = f" (ran for {elapsed})"

    conc["worker_active"] = False
    conc["last_completed_task"] = task
    conc["last_completed_at"] = now_iso()
    conc.pop("active_task", None)
    conc.pop("task_started_at", None)

    save_state(state, updated_by="unlock-worker")
    print(f"✅ Worker unlocked. Completed task: {task}{duration}")


def cmd_check_sessions(state: dict) -> None:
    """Check all sessions for expiry."""
    sessions = state.get("sessions", {})
    if not sessions:
        print("[WARN] No sessions in state.json")
        return

    now = datetime.now(timezone.utc)
    any_expired = False

    print("SESSION STATUS:")
    for session_key, session_data in sessions.items():
        last_verified = parse_ts(session_data.get("last_verified"))
        if last_verified is None:
            print(f"  ⚠️  {session_key}: no last_verified timestamp")
            any_expired = True
            continue

        age = now - last_verified
        hours_old = age.total_seconds() / 3600

        if age > timedelta(hours=SESSION_EXPIRY_HOURS):
            print(
                f"  ❌ {session_key}: EXPIRED ({hours_old:.1f}h old, "
                f"threshold {SESSION_EXPIRY_HOURS}h)"
            )
            print(
                f"     Action: Run `python3 tools/cdp_browser.py extract-cookies "
                f"--port {session_data.get('browser_port', '?')}` to refresh"
            )
            # Auto-flag in state
            session_data["status"] = "expired"
            any_expired = True
        else:
            remaining = timedelta(hours=SESSION_EXPIRY_HOURS) - age
            print(
                f"  ✅ {session_key}: valid ({hours_old:.1f}h old, "
                f"{remaining.seconds // 3600}h remaining)"
            )

    if any_expired:
        save_state(state, updated_by="check-sessions")
        print("\n⚠️  Some sessions may be expired. Re-extract cookies before dispatching tasks.")
        sys.exit(2)


def cmd_update_session(state: dict, session_key: str, verified_now: bool) -> None:
    """Update session last_verified timestamp."""
    sessions = state.setdefault("sessions", {})
    if session_key not in sessions:
        print(f"[ERROR] Session '{session_key}' not found in state.json")
        sys.exit(1)

    if verified_now:
        sessions[session_key]["last_verified"] = now_iso()
        sessions[session_key]["status"] = "active"
        save_state(state, updated_by=f"update-session:{session_key}")
        print(f"✅ Session '{session_key}' marked as verified at {now_iso()}")


def cmd_token_budget(state: dict, phase: str | None, description: str | None) -> None:
    """Add token consumption estimate and check budget."""
    budget = state.setdefault("_token_budget", {
        "context_limit": TOKEN_WARNING_THRESHOLD,
        "estimated_consumed": 0,
        "task_log": [],
    })

    if phase and description:
        estimate = TOKEN_ESTIMATES.get(phase, 3000)
        budget["estimated_consumed"] = budget.get("estimated_consumed", 0) + estimate
        budget.setdefault("task_log", []).append({
            "description": description,
            "phase": phase,
            "tokens_estimated": estimate,
            "at": now_iso(),
        })
        save_state(state, updated_by="token-budget")
        print(f"Added ~{estimate:,} tokens for: {description}")

    consumed = budget.get("estimated_consumed", 0)
    limit = budget.get("context_limit", TOKEN_WARNING_THRESHOLD)
    pct = (consumed / limit * 100) if limit else 0

    print(f"\nToken Budget:")
    print(f"  Consumed: ~{consumed:,}")
    print(f"  Limit:    {limit:,}")
    print(f"  Used:     {pct:.1f}%")

    if pct > 90:
        print("  🚨 CRITICAL: >90% of token budget used. Summarize old results immediately.")
    elif pct > 80:
        print("  ⚠️  WARNING: >80% of token budget used. Consider summarizing context.")
    else:
        print("  ✅ Token budget OK")


def cmd_check_task_timeout(state: dict) -> None:
    """Check if the active Worker task has exceeded a timeout threshold."""
    conc = state.get("_concurrency", {})
    if not conc.get("worker_active"):
        print("No active Worker task — nothing to check.")
        return

    task = conc.get("active_task", "?")
    started = parse_ts(conc.get("task_started_at"))
    if not started:
        print("Worker is active but has no task_started_at timestamp.")
        return

    elapsed = datetime.now(timezone.utc) - started
    timeout = timedelta(minutes=int(state.get("_settings", {}).get("worker_timeout_minutes", 90)))

    print(f"Active task: {task}")
    print(f"Started: {conc.get('task_started_at')}")
    print(f"Elapsed: {elapsed}")
    print(f"Timeout: {timeout}")

    if elapsed > timeout:
        print(f"\n⚠️  TIMEOUT: Task has exceeded {timeout}!")
        print("  Action: Log the stuck Worker and dispatch the next task.")
        # Log the timeout
        state.setdefault("_timeouts", []).append({
            "task": task,
            "started_at": conc.get("task_started_at"),
            "detected_at": now_iso(),
            "elapsed_minutes": int(elapsed.total_seconds() / 60),
        })
        # Force unlock
        conc["worker_active"] = False
        save_state(state, updated_by="task-timeout")
        sys.exit(1)
    else:
        remaining = timeout - elapsed
        print(f"  ✅ OK — {remaining} remaining before timeout")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="State manager for the bug bounty framework"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Print engagement status summary")

    # lock-worker
    lock_p = subparsers.add_parser("lock-worker", help="Lock worker for a task")
    lock_p.add_argument("task_name", help="Task file name being dispatched")

    # unlock-worker
    subparsers.add_parser("unlock-worker", help="Release worker lock after task completion")

    # check-sessions
    subparsers.add_parser("check-sessions", help="Check session freshness")

    # update-session
    upd_p = subparsers.add_parser("update-session", help="Update session timestamp")
    upd_p.add_argument("session_key", help="Session key (e.g., session_a)")
    upd_p.add_argument(
        "--verified-now",
        action="store_true",
        help="Mark session as verified right now",
    )

    # token-budget
    tb_p = subparsers.add_parser("token-budget", help="Token budget management")
    tb_p.add_argument("--add-task", metavar="PHASE", help="Phase type to add estimate for")
    tb_p.add_argument("description", nargs="?", help="Task description for log")

    # task-timeout
    tt_p = subparsers.add_parser("task-timeout", help="Check/handle task timeouts")
    tt_p.add_argument("--check", action="store_true", help="Check current task timeout")

    args = parser.parse_args()
    state = load_state()

    if args.command == "status":
        cmd_status(state)
    elif args.command == "lock-worker":
        cmd_lock_worker(state, args.task_name)
    elif args.command == "unlock-worker":
        cmd_unlock_worker(state)
    elif args.command == "check-sessions":
        cmd_check_sessions(state)
    elif args.command == "update-session":
        cmd_update_session(state, args.session_key, args.verified_now)
    elif args.command == "token-budget":
        cmd_token_budget(state, args.add_task, args.description)
    elif args.command == "task-timeout":
        if args.check:
            cmd_check_task_timeout(state)


if __name__ == "__main__":
    main()
