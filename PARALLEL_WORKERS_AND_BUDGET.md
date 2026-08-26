# Parallel Workers and Token Budgeting

## What changed

The framework now distinguishes three different quantities:

| Quantity | Meaning |
|---|---|
| `request_context_limit` | Maximum intended size of one Lead or Worker prompt. This is not a cumulative budget. |
| `estimated_reserved_tokens` | A rough planning reservation added before dispatch. It is not a measurement of model usage. |
| `actual_total_tokens` | `input + output` usage synchronized from an OmniRoute request-log export. |

The default state allows **two Worker slots**. The lock is task-named, so two independent tasks can be reserved without one Worker accidentally unlocking the other.

## Safe parallelism

Parallelize only tasks that are independent and have separate output paths. Good examples include mapping two unrelated endpoints, extracting evidence from two existing artifacts, classifying two hypothesis groups, or preparing two report sections from already-validated evidence.

Do not parallelize the same live probe, account mutation, SSRF/OAST callback, WebSocket escalation, destructive action, shared-state write, or final validation. A Worker task must have a scope hash, explicit request cap, deadline, stop condition, and unique result/artifact path. The Lead merges results and writes shared aggregate state after the Workers finish.

## Reserving worker slots

```bash
python3 tools/state_manager.py lock-worker tasks/task-001-map-EP-003.md
python3 tools/state_manager.py lock-worker tasks/task-002-map-EP-004.md

# Start the two independent Worker commands only if the client supports concurrent subagents.
# Otherwise use two bounded sessions; do not place both tasks into one giant prompt.

python3 tools/state_manager.py unlock-worker tasks/task-001-map-EP-003.md
python3 tools/state_manager.py unlock-worker tasks/task-002-map-EP-004.md
```

If a third task is attempted while two slots are active, the command fails closed. Increase `_settings.parallel_workers` only after measuring provider capacity and ensuring the tasks are truly independent.

## Token-budget commands

Reserve a task estimate:

```bash
python3 tools/state_manager.py token-budget \
  --add-task phase_3_per_hypothesis \
  "Test HYP-021"
```

The accepted task types are listed by the script. Unknown types fail rather than silently receiving the old default estimate of 3,000 tokens.

Synchronize actual usage from an OmniRoute JSON export:

```bash
python3 tools/state_manager.py token-budget \
  --sync-log /path/to/omniroute-request-log.json
```

The command records total input, output, cache-read, and combined token usage. Re-running it with a larger export replaces the actual counters with the totals for that export; it does not double-count the same log.

Check status:

```bash
python3 tools/state_manager.py status
```

Read the fields as follows:

```text
Actual session usage       → actual_total_tokens / session_budget_tokens
Estimated reservations     → planning only
Per-request context limit  → request_context_limit
```

An exported six-hour sample in this audit contained 90.59M input tokens and 154K output tokens. That historical sample must not be synced into a fresh engagement’s state file as though it were the current session. Keep usage exports outside the distributable framework and sync only the time window you intend to govern.

## Context-minimizing Worker packet

Each Worker should receive:

```text
task_id, phase, scope_hash
one endpoint or one hypothesis group
relevant artifact paths and hashes
short phase summary
allowed tools
maximum requests and deadline
expected result schema
```

It should not receive the entire Lead transcript, all skills, every MCP schema, raw browser snapshots, or complete HTTP bodies. Large artifacts remain on disk and are referenced by path and selected evidence lines.

## Resume rule

`/resume` should load `state.json` and indexes first. It should load one phase skill only after identifying the next task. Start a new session at phase boundaries and use the state/artifact references to reconstruct only the required context.
