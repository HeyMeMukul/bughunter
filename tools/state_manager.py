#!/usr/bin/env python3
"""
State Manager — Improvements #4, #8, #11: Enhanced state.json with locking,
concurrency control, session expiry, token budget tracking, and error recovery.

Features:
  - last_updated_by + timestamp tracking
  - worker_active lock flag
  - Session expiry auto-detection
  - Token budget reservation, actual OmniRoute usage sync, and warning
  - Bounded multi-worker slot tracking
  - Task timeout tracking
  - Atomic state updates with backup

Usage:
    python3 tools/state_manager.py status
    python3 tools/state_manager.py lock-worker "task-042-test-HYP-007.md"
    python3 tools/state_manager.py unlock-worker
    python3 tools/state_manager.py check-sessions
    python3 tools/state_manager.py token-budget --add-task phase_3_per_hypothesis "Phase 3 test"
    python3 tools/state_manager.py token-budget --sync-log /path/to/omniroute-log.json
    python3 tools/state_manager.py update-session session_a --verified-now
    python3 tools/state_manager.py task-timeout --check
"""

import sys
import json
import shutil
import argparse
import os
import fcntl
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone, timedelta

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
STATE_BACKUP = FRAMEWORK_ROOT / "state.json.bak"
STATE_LOCK_FILE = FRAMEWORK_ROOT / ".state.lock"

# Token budget estimates per task type (rough tokens consumed per Worker task)
TOKEN_ESTIMATES = {
    "phase_0": 1500,
    "phase_0_recon": 1500,
    "phase_1": 5000,
    "phase_2_per_endpoint": 2500,
    "phase_3_per_hypothesis": 3000,
    "phase_3_testing": 3000,
    "phase_3_5_exploitation": 2500,
    "phase_4_per_finding": 2000,
    "phase_4_validation": 2000,
    "phase_4_per_finding_validation": 2000,
    "m9_chain_synthesis": 2000,
    "report_writing": 5000,
    "dorking": 1500,
    "sequential_thinking": 2500,
}

# These are deliberately separate: one request's context window is not the same as
# the cumulative session budget, and a rough task estimate is not actual usage.
DEFAULT_SESSION_TOKEN_BUDGET = 800_000
DEFAULT_REQUEST_CONTEXT_LIMIT = 128_000
TOKEN_WARNING_THRESHOLD = DEFAULT_SESSION_TOKEN_BUDGET
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


@contextmanager
def state_lock():
    """Serialize state read-modify-write operations across Worker processes."""
    with STATE_LOCK_FILE.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def save_state(state: dict, updated_by: str = "state_manager") -> None:
    """Backup and atomically replace state.json. Call while holding state_lock()."""
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_BACKUP)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.setdefault("_meta", {})
    state["_meta"]["last_updated_by"] = updated_by
    state["_meta"]["last_updated_at"] = now
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.replace(tmp, STATE_FILE)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_token_budget(budget: dict) -> dict:
    """Migrate legacy estimates and initialize accurate usage fields."""
    if "estimated_reserved_tokens" not in budget:
        budget["estimated_reserved_tokens"] = budget.get("estimated_consumed", 0)
    budget.setdefault("actual_input_tokens", 0)
    budget.setdefault("actual_output_tokens", 0)
    budget.setdefault("actual_cache_read_tokens", 0)
    budget.setdefault("actual_total_tokens", 0)
    budget.setdefault("last_usage_sync_at", None)
    budget.setdefault("last_usage_sync_source", None)
    budget.setdefault("request_context_limit", DEFAULT_REQUEST_CONTEXT_LIMIT)
    budget.setdefault("session_budget_tokens", DEFAULT_SESSION_TOKEN_BUDGET)
    budget.setdefault("task_log", [])
    return budget


def parse_usage_log(path: str) -> dict:
    """Read an OmniRoute request-log export and return actual usage totals."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("logs", payload if isinstance(payload, list) else [])
    input_tokens = sum(int((r.get("tokens") or {}).get("in") or 0) for r in rows)
    output_tokens = sum(int((r.get("tokens") or {}).get("out") or 0) for r in rows)
    cache_read = sum(int((r.get("tokens") or {}).get("cacheRead") or 0) for r in rows)
    return {
        "records": len(rows),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read,
        "total_tokens": input_tokens + output_tokens,
        "source": str(path),
    }


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
    active_tasks = worker_lock.get("active_tasks", {})
    if worker_lock.get("worker_active") and not active_tasks:
        legacy = worker_lock.get("active_task") or "legacy-worker"
        active_tasks = {legacy: {"started_at": worker_lock.get("task_started_at"), "slot": 1}}
    if active_tasks:
        max_workers = int(state.get("_settings", {}).get("parallel_workers", 1))
        print(f"  🔒 Workers ACTIVE: {len(active_tasks)}/{max_workers}")
        for task, info in active_tasks.items():
            print(f"     Slot {info.get('slot', '?')}: {task} (started {info.get('started_at', '?')})")
    elif worker_lock.get("worker_active"):
        print(f"  🔒 Worker ACTIVE: {worker_lock.get('active_task', '?')}")
        print(f"     Started: {worker_lock.get('task_started_at', '?')}")
    else:
        print("  ✅ Workers: idle")
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
        budget = ensure_token_budget(budget)
        actual = budget.get("actual_total_tokens", 0)
        reserved = budget.get("estimated_reserved_tokens", 0)
        session_limit = budget.get("session_budget_tokens", DEFAULT_SESSION_TOKEN_BUDGET)
        context_limit = budget.get("request_context_limit", DEFAULT_REQUEST_CONTEXT_LIMIT)
        pct = (actual / session_limit * 100) if session_limit else 0
        icon = "⚠️" if pct > 80 else "✅"
        print()
        print(f"  {icon} Actual session usage: {actual:,} / {session_limit:,} ({pct:.1f}%)")
        print(f"     Input: {budget.get('actual_input_tokens', 0):,} | Output: {budget.get('actual_output_tokens', 0):,} | Cache-read: {budget.get('actual_cache_read_tokens', 0):,}")
        print(f"     Estimated reservations: {reserved:,} | Per-request context limit: {context_limit:,}")

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
    settings = state.setdefault("_settings", {})
    max_workers = max(1, int(settings.get("parallel_workers", 1)))
    active = conc.setdefault("active_tasks", {})
    # Migrate the legacy single-worker representation once.
    if conc.get("worker_active") and not active:
        legacy = conc.get("active_task") or "legacy-worker"
        active[legacy] = {"started_at": conc.get("task_started_at") or now_iso(), "slot": 1}
    if task_name in active:
        print(f"[ERROR] Worker task is already active: {task_name}")
        sys.exit(1)
    if len(active) >= max_workers:
        print(f"[ERROR] Worker capacity is full: {len(active)}/{max_workers}")
        print("  Increase _settings.parallel_workers only for independent, bounded tasks.")
        sys.exit(1)
    used_slots = {int(v.get("slot", 0)) for v in active.values()}
    slot = next((n for n in range(1, max_workers + 1) if n not in used_slots), len(active) + 1)
    active[task_name] = {"started_at": now_iso(), "slot": slot}
    conc["worker_active"] = True
    conc["active_task"] = task_name
    conc["task_started_at"] = active[task_name]["started_at"]

    save_state(state, updated_by=f"lock-worker:{task_name}")
    print(f"✅ Worker slot {slot}/{max_workers} locked for task: {task_name}")


def cmd_unlock_worker(state: dict, task_name: str | None = None) -> None:
    """Release one named worker slot, or the legacy/first slot if omitted."""
    conc = state.setdefault("_concurrency", {})
    if not conc.get("worker_active"):
        print("[INFO] Worker was not locked — nothing to do.")
        return

    active = conc.setdefault("active_tasks", {})
    # Migrate a legacy single-worker lock before resolving the requested task.
    if conc.get("active_task") and not active:
        legacy = conc.get("active_task")
        active[legacy] = {"started_at": conc.get("task_started_at") or now_iso(), "slot": 1}
    task = task_name or conc.get("active_task") or (next(iter(active)) if active else "?")
    if task not in active:
        print("[INFO] Worker task was not found — nothing to unlock.")
        return
    started = parse_ts(active[task].get("started_at"))
    duration = ""
    if started:
        elapsed = datetime.now(timezone.utc) - started
        duration = f" (ran for {elapsed})"
    slot = active[task].get("slot", "?")
    active.pop(task, None)
    conc["worker_active"] = bool(active)
    conc["active_task"] = next(iter(active), None)
    conc["task_started_at"] = active.get(conc["active_task"], {}).get("started_at") if conc["active_task"] else None
    conc["last_completed_task"] = task
    conc["last_completed_at"] = now_iso()

    save_state(state, updated_by="unlock-worker")
    print(f"✅ Worker slot {slot} unlocked. Completed task: {task}{duration}")


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


def cmd_token_budget(state: dict, phase: str | None, description: str | None, sync_log: str | None) -> None:
    """Reserve estimates or synchronize actual usage from an OmniRoute log export."""
    budget = ensure_token_budget(state.setdefault("_token_budget", {}))
    if phase and description:
        if phase not in TOKEN_ESTIMATES:
            known = ", ".join(sorted(TOKEN_ESTIMATES))
            print(f"[ERROR] Unknown task type '{phase}'. Use one of: {known}", file=sys.stderr)
            sys.exit(1)
        estimate = TOKEN_ESTIMATES[phase]
        budget["estimated_reserved_tokens"] += estimate
        budget["task_log"].append({
            "description": description,
            "phase": phase,
            "tokens_reserved": estimate,
            "at": now_iso(),
        })
        save_state(state, updated_by="token-budget-reserve")
        print(f"Reserved ~{estimate:,} tokens for: {description}")

    if sync_log:
        usage = parse_usage_log(sync_log)
        budget["actual_input_tokens"] = usage["input_tokens"]
        budget["actual_output_tokens"] = usage["output_tokens"]
        budget["actual_cache_read_tokens"] = usage["cache_read_tokens"]
        budget["actual_total_tokens"] = usage["total_tokens"]
        budget["last_usage_sync_at"] = now_iso()
        budget["last_usage_sync_source"] = usage["source"]
        budget["task_log"].append({"type": "usage-sync", **usage, "at": now_iso()})
        save_state(state, updated_by="token-budget-sync")
        print(f"Synced actual usage from {sync_log}: {usage['total_tokens']:,} tokens")

    actual = budget.get("actual_total_tokens", 0)
    limit = budget.get("session_budget_tokens", DEFAULT_SESSION_TOKEN_BUDGET)
    pct = (actual / limit * 100) if limit else 0
    print("\nToken Budget:")
    print(f"  Actual input:  {budget.get('actual_input_tokens', 0):,}")
    print(f"  Actual output: {budget.get('actual_output_tokens', 0):,}")
    print(f"  Cache-read:    {budget.get('actual_cache_read_tokens', 0):,}")
    print(f"  Actual total:  {actual:,}")
    print(f"  Session limit: {limit:,}")
    print(f"  Used:          {pct:.1f}%")
    print(f"  Reservations:  {budget.get('estimated_reserved_tokens', 0):,} (not actual usage)")
    if pct > 90:
        print("  🚨 CRITICAL: actual usage exceeds 90% of session budget.")
    elif pct > 80:
        print("  ⚠️  WARNING: actual usage exceeds 80% of session budget.")
    else:
        print("  ✅ Actual session budget OK")


def cmd_check_task_timeout(state: dict) -> None:
    """Check each active Worker slot against the configured timeout."""
    conc = state.get("_concurrency", {})
    active = conc.get("active_tasks", {})
    if not active and conc.get("worker_active"):
        task = conc.get("active_task", "?")
        active = {task: {"started_at": conc.get("task_started_at")}}
    if not active:
        print("No active Worker task — nothing to check.")
        return

    timeout = timedelta(minutes=int(state.get("_settings", {}).get("worker_timeout_minutes", 90)))
    now = datetime.now(timezone.utc)
    timed_out = []
    for task, info in list(active.items()):
        started = parse_ts(info.get("started_at"))
        if not started:
            print(f"⚠️  {task}: active but missing started_at")
            continue
        elapsed = now - started
        if elapsed > timeout:
            print(f"⚠️  TIMEOUT: {task} exceeded {timeout} (elapsed {elapsed})")
            state.setdefault("_timeouts", []).append({
                "task": task,
                "started_at": info.get("started_at"),
                "detected_at": now_iso(),
                "elapsed_minutes": int(elapsed.total_seconds() / 60),
            })
            timed_out.append(task)
        else:
            print(f"✅ {task}: {timeout - elapsed} remaining")

    for task in timed_out:
        active.pop(task, None)
    if timed_out:
        conc["active_tasks"] = active
        conc["worker_active"] = bool(active)
        conc["active_task"] = next(iter(active), None)
        conc["task_started_at"] = active.get(conc["active_task"], {}).get("started_at") if conc["active_task"] else None
        save_state(state, updated_by="task-timeout")
        sys.exit(1)


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
    unlock_p = subparsers.add_parser("unlock-worker", help="Release one worker slot after task completion")
    unlock_p.add_argument("task_name", nargs="?", help="Specific active task name to release")

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
    tb_p = subparsers.add_parser("token-budget", help="Token budget reservation and actual-usage sync")
    tb_p.add_argument("--add-task", metavar="PHASE", help="Task type to reserve an estimate for")
    tb_p.add_argument("--sync-log", metavar="PATH", help="Sync actual input/output/cache usage from an OmniRoute JSON export")
    tb_p.add_argument("description", nargs="?", help="Task description for log")

    # task-timeout
    tt_p = subparsers.add_parser("task-timeout", help="Check/handle task timeouts")
    tt_p.add_argument("--check", action="store_true", help="Check current task timeout")

    args = parser.parse_args()
    mutating_commands = {"lock-worker", "unlock-worker", "check-sessions", "update-session", "token-budget", "task-timeout"}
    if args.command in mutating_commands:
        with state_lock():
            state = load_state()
            if args.command == "lock-worker":
                cmd_lock_worker(state, args.task_name)
            elif args.command == "unlock-worker":
                cmd_unlock_worker(state, args.task_name)
            elif args.command == "check-sessions":
                cmd_check_sessions(state)
            elif args.command == "update-session":
                cmd_update_session(state, args.session_key, args.verified_now)
            elif args.command == "token-budget":
                cmd_token_budget(state, args.add_task, args.description, args.sync_log)
            elif args.command == "task-timeout" and args.check:
                cmd_check_task_timeout(state)
    else:
        state = load_state()
        if args.command == "status":
            cmd_status(state)


if __name__ == "__main__":
    main()
