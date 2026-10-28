# AGENTS.md — Framework Agent Configuration

This file describes the AI agents used in this bug bounty framework and how to operate them with opencode.

> **Framework v4.1.0** — OmniRoute-routed Lead/Worker execution, shared skill contract, read-only gateway doctor, provenance-aware disclosed-report seed corpus, and stronger evidence/scope gates. The original v4 workflow remains available in the surrounding files.

## Agent Architecture (Single Session)

| Agent | Role | Model | How It Runs |
|-------|------|-------|-------------|
| **Lead** | Strategic coordinator. Plans, analyzes, dispatches tasks, writes reports, runs M9 chain synthesis, and prioritizes hypotheses. | `opencode-go/muse-spark-1.3-contributor` (variant `high`) | Primary agent in opencode session (`agent.build` in `opencode.json`) |
| **Worker** | Tactical executor. Runs tools (recon, spider, mapping, testing, validation), writes structured results, and stays inside one hypothesis. | `opencode-go/muse-spark-1.3-contributor` (variant `default`) | Spawned as subagent via `/worker` command (`agent.general` in `opencode.json`) |
| **Fallback** | Manual fallback for both Lead and Worker on 429/5xx, capacity, or degraded quality. | `opencode-go/deepseek-v4.1-flash` | Switch with `--model opencode-go/deepseek-v4.1-flash` or set in `config/omniroute.policy.json` `routes.cheap_fallback`; retry once with bounded backoff |

**No separate terminals needed for normal use.** Lead runs as the primary agent and Workers are spawned on-demand. The default configuration permits two bounded Worker slots for independent tasks; if the client executes slash commands serially, use separate bounded sessions rather than pretending tasks are parallel.

**Autonomous continuation:** After authorization and scope are established, the Lead must write, validate, reserve, dispatch, process, and follow up on authorized tasks without waiting for manual slash-command invocation. A reserved slot is not a running Worker; the Lead must dispatch it and require a result or typed failure artifact. Recoverable failures trigger diagnosis, one corrected retry, an alternate safe method, or independent-task continuation. The Lead pauses only for scope/authorization ambiguity, out-of-scope access, destructive or irreversible actions, missing approval, unrefreshable credentials, or unbounded impact. **Whenever a hard gate needs a human in the loop, the Lead starts `tools/operator_ping.sh "<need>" loop` so it keeps beeping until answered, states the need, and keeps hunting unblocked work — never silent standby.**

## Agent Discipline — LEAD vs WORKER (NEVER VIOLATE)

The two-agent architecture is NOT optional. It is the single most important factor in token efficiency. **70% of token waste comes from Lead (Muse Spark 1.3 high / Build) doing Worker (Muse Spark 1.3 default / General) work.**

| Lead (Muse Spark high / Build) does | Worker (Muse Spark default / General) does | ❌ NEVER do as Lead |
|------------------------|----------------------------|---------------------|
| Strategic planning | Endpoint probing | `bash` / `curl` commands |
| Chain synthesis (M9) | Browser interaction | Playwright evaluate/navigate |
| Task validation + dispatch | API testing | GitHub code search |
| Hypothesis prioritization | Mapping new surfaces | JS source analysis |
| Report writing | Testing hypotheses | Recon execution |
| State management | Parameter discovery | Secret scanning |
| Reading Worker results | Running tools | Raw tool output analysis |

**Every tactical operation costs ~3x more tokens when executed as Lead (Pro) instead of Worker (Flash).**

For ALL exploratory/heavy work: write a task file → validate with `task_validator.py` → lock with `state_manager.py` → dispatch `/worker`, `/map`, `/test`, `/spider`, or `/recon`.

Lead only does: plan, dispatch, read Worker results, prioritize, chain synthesis, write reports.

## Bounded Parallel Work

The Lead should fill available independent slots automatically. It must never parallelize a shared live probe, account mutation, SSRF/OAST callback, WebSocket escalation, shared-state write, destructive action, or final validation. Every task has a maximum request budget, deadline, scope hash, artifact path, and stop condition. After a failure, the Lead records the failure class and retry count, spawns a read-only diagnosis Worker when needed, and continues with corrected or independent work rather than abandoning the engagement after one failure.


Use parallel Workers only for independent tasks with separate task files and artifact paths. Good candidates are endpoint profiling, read-only evidence extraction, hypothesis classification, and report-evidence preparation. Keep live probes, account mutations, SSRF/OAST callbacks, WebSocket escalation, shared-state writes, and final validation serialized. Each task must have a scope hash, request cap, deadline, stop condition, and named result file.

Reserve and release slots by task name:

```bash
python3 tools/state_manager.py lock-worker tasks/task-001-map-EP-003.md
python3 tools/state_manager.py lock-worker tasks/task-002-map-EP-004.md
python3 tools/state_manager.py unlock-worker tasks/task-001-map-EP-003.md
python3 tools/state_manager.py unlock-worker tasks/task-002-map-EP-004.md
```

The Lead merges Worker results and is the only agent that performs cross-task chain reasoning or writes shared aggregate state.

## MCP Servers (Always-On Tools)

| Server | Purpose | Config | Free? |
|--------|---------|--------|-------|
| **Playwright MCP** | Browser automation — navigate, click, fill forms, screenshots, DOM analysis, cookie management | `npx @playwright/mcp@latest` | Yes |
| **Burp Suite MCP** | HTTP testing — request crafting, Intruder (race conditions), Collaborator (OOB), passive scanning | `http://127.0.0.1:9876/sse` | Requires Burp Pro |
| **GitHub MCP** | Code search — leaked secrets, internal configs, API endpoints in target repos | `npx @modelcontextprotocol/server-github` | Yes (PAT token) |
| **Brave Search MCP** | Web dorking — automated subdomain discovery, exposed panel search, leaked data | `npx @anthropic/mcp-server-brave-search` | Yes (free 2K/mo) |
| **Memory MCP** | Persistent knowledge graph — program profiles, FP patterns, chains, WAF intel across sessions | `npx @modelcontextprotocol/server-memory` | Yes (local) |
| **Sequential Thinking MCP** | Multi-step reasoning — complex chain synthesis, pivot analysis, business logic mapping | `npx @anthropic/mcp-server-sequential-thinking` | Yes (local) |

All are configured in `opencode.json` and available to all agents. OmniRoute is the local inference gateway; its base URL and key are loaded from the ignored `engagement/.creds.sh`. API keys for GitHub and Brave Search remain there as well. Free/web-session routes must receive only sanitized context unless explicitly approved.

## How to Run

### Starting a New Engagement

```bash
# 1. Setup (creates dirs, launches Chrome sessions)
./setup.sh "https://target.com" "program-name"

# 2. Manually log in to both Chrome windows (attacker + victim)

# 3. Start opencode (Lead is the primary agent)
opencode

# 4. First message: load state and indexes first; do not load every historical file
# "Read state.json and the current phase indexes. Dispatch the next bounded task set."

# Lead will automatically spawn Worker subagents via /recon, /worker, /spider,
# /map, /test, /validate commands as needed. You supervise.
```

### Resuming an Engagement

```bash
./setup.sh --resume
opencode /resume
```

### Checking Status

```bash
./setup.sh --status
# Or within opencode:
/status
```

## Available Commands

| Command | Agent | Description |
|---------|-------|-------------|
| `/recon` | Worker (general) | Run Phase 0 infrastructure reconnaissance |
| `/dork` | Worker (general) | GitHub + Brave Search dorking for leaked data, subdomains |
| `/think` | Lead (build) | Sequential multi-step reasoning for complex chain analysis |
| `/worker` | Worker (general) | Execute a framework task (spider, mapping, testing, validation) |
| `/spider` | Worker (general) | Run Phase 1 spidering |
| `/map` | Worker (general) | Run Phase 2 mapping on endpoints |
| `/test` | Worker (general) | Run Phase 3 vulnerability testing |
| `/validate` | Worker (general) | Run Phase 4 finding validation |
| `/status` | Lead (build) | Show current engagement status |
| `/resume` | Lead (build) | Resume engagement from last session |

## Phase Workflow

```
Phase 0: RECON     → Infrastructure enumeration (subdomains, ports, tech, cloud, email)
Phase 1: SPIDERING → 5 tools (spider, comprehension, path_fuzzer, waf_detect, param_discover)
Phase 2: MAPPING   → Per-endpoint deep analysis with light probing (M1-M8 + M9 chain synthesis)
Phase 3: TESTING   → OOB-first hypothesis-driven vulnerability confirmation
Phase 4: VALIDATING → Clean reproduction with report-ready evidence
Phase 5: REPORTING → Professional report generation (Lead only)
```

## File Structure

```
opencode.json          ← OmniRoute-routed agent and MCP configuration
OMNIROUTE_SETUP.md      ← Gateway setup, free-only policy, and data-handling rules
SKILL_HARDENING.md      ← Skill contract, gaps, and evaluation plan
AGENTS.md              ← This file
state.json             ← Engagement state (single source of truth)
master_prompt.md       ← Thinking foundation for both agents
lead_prompt.md         ← Lead agent instructions
worker_prompt.md       ← Worker agent instructions
target_prompt.md       ← Current engagement scope/rules
methodology.md         ← Testing philosophy
phases/                → Phase workflow documentation
skills/                → Vulnerability-specific skill files + shared contract
config/omniroute.policy.json ← Route/data-class policy
knowledge/              → Curated patterns + provenance-aware corpus seed
tools/                 → Automation scripts
engagement/            → All engagement artifacts (spider, mapping, findings, reports)
tasks/                 → Lead-generated task files
results/               → Worker-generated result files
```

## New Tools (v4.0.0)

| Tool | Purpose | Description |
|------|---------|-------------|
| `tools/recon/subdomain_enum.sh` | Phase 0 | Passive + active + permutation subdomain enumeration |
| `tools/recon/port_scan.sh` | Phase 0 | Port scanning, service fingerprinting, NSE vuln detection |
| `tools/recon/tech_detect.sh` | Phase 0 | Technology stack, CMS, CDN/WAF, API framework detection |
| `tools/recon/cloud_enum.sh` | Phase 0 | S3/Azure/GCP buckets, K8s endpoints, email security |
| `tools/recon/master_recon.sh` | Phase 0 | Recon orchestrator — unified recon.json output |
| `tools/nuclei_runner.sh` | Phase 1/3 | Nuclei vulnerability scanning with tech-stack-matched templates |
| `tools/interactsh_launcher.sh` | Phase 3 | OOB testing harness (start, generate payloads, poll callbacks) |
| `tools/sqlmap_runner.sh` | Phase 3.5 | Safe SQLMap integration — only on confirmed SQLi |
| `tools/secret_scanner.sh` | Phase 0/1 | GitHub secret scanning via trufflehog + dorking |
| `tools/response_diff.py` | Phase 2/3 | Automated 3-way baseline comparison + noise elimination |
| `tools/oob_validator.py` | Phase 3 | OOB callback validation + payload correlation |
| `tools/chain_automation.py` | Phase 2 | Automated M9 chain synthesis from endpoint profiles |
| `tools/fp_database.py` | Phase 3/4 | False positive pattern database with confidence adjustment |
| `tools/model_router.py` | All | Lead (Muse Spark 1.3 high) vs Worker (Muse Spark 1.3 default) task classification with fallback to DeepSeek V4.1 Flash |
| `tools/omniroute_doctor.py` | Setup | Read-only gateway, health, and model/candidate checks |
| `tools/skill_lint.py` | CI | Enforces skill metadata, gates, checkpoints, and summary coverage |
| `tools/knowledge_ingest.py` | KB | Imports redacted public metadata above a bounty threshold into NDJSON |

## Existing Tools (v3.2.0)

| Tool | Purpose | Description |
|------|---------|-------------|
| `tools/task_validator.py` | Dispatch | Pre-dispatch task validation (structure, files, sessions, dedup) |
| `tools/result_quality_gate.py` | Verification | Worker result schema validation + state consistency checks |
| `tools/hypothesis_deduplicator.py` | Dedup | Cross-endpoint hypothesis dedup + priority list generation |
| `tools/state_manager.py` | State | Worker slots, session expiry, token-budget reservations, actual OmniRoute usage sync, and task timeouts |
| `tools/spider_to_mapping_handoff.py` | Handoff | Auto-generate prioritized endpoint list from spider outputs |
| `tools/external_intel.py` | Intel | GitHub dorking, Shodan lookup, CVE checking |
| `tools/multi_target.py` | Multi | Multi-domain target management and cross-target correlation |

## Tool Usage in Workflow

```bash
# Phase 0 — Infrastructure Recon:
./tools/recon/master_recon.sh --target example.com --output-dir engagement/

# After recon completes:
python3 tools/nuclei_runner.sh --targets engagement/recon/subdomains/alive_hosts.txt --mode tech-stack --output-dir engagement/recon/nuclei/
python3 tools/secret_scanner.sh --target example.com --output-dir engagement/recon/secrets/

# After spider completes:
python3 tools/spider_to_mapping_handoff.py

# After mapping batches:
python3 tools/hypothesis_deduplicator.py
python3 tools/chain_automation.py --mapping-dir engagement/mapping/

# Phase 3 OOB Testing:
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
./tools/interactsh_launcher.sh generate --type ssrf --output-dir engagement/oob/
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
python3 tools/oob_validator.py --callbacks engagement/oob/oob_callbacks.json --payloads engagement/oob/oob_payloads.json

# Phase 3.5 Exploitation (only on confirmed findings):
./tools/sqlmap_runner.sh --url "https://target.com/api?id=1" --param id --output-dir engagement/findings/sqli_exploit/

# Response comparison:
python3 tools/response_diff.py --mode compare --baseline-valid <valid> --baseline-invalid <invalid> --probe <probe>

# False positive tracking:
python3 tools/fp_database.py add --hypothesis-id HYP-001 --vuln-type idor --confidence LOW --reason "No actual auth bypass"

# OmniRoute gateway checks (read-only):
python3 tools/omniroute_doctor.py --channel auto/coding:free --channel auto/reasoning:free

# Legacy task classification (provider selection is now OmniRoute):
python3 tools/model_router.py --task mapping_execution

# Skill contract check:
python3 tools/skill_lint.py skills

# Before every dispatch:
python3 tools/task_validator.py tasks/task-NNN-*.md
python3 tools/state_manager.py lock-worker "task-NNN-*.md"

# After every Worker result:
python3 tools/state_manager.py unlock-worker
python3 tools/result_quality_gate.py results/result-NNN-*.md

# Session management:
python3 tools/state_manager.py check-sessions

# Token budget:
python3 tools/state_manager.py token-budget

# Multi-target:
python3 tools/multi_target.py init --targets "api.example.com,admin.example.com"
python3 tools/multi_target.py correlate
```

## Lint and Verification

After making changes to framework files, verify:
- `./setup.sh --status` runs without errors
- `python3 tools/omniroute_doctor.py` passes when OmniRoute is running
- `python3 tools/skill_lint.py skills` is reviewed; any failures are either fixed or explicitly waived
- `python3 tools/knowledge_ingest.py` produces valid NDJSON and no secrets/PII markers
- `python3 -c "import json; json.load(open('state.json'))"` validates state.json
- `bash -n setup.sh` syntax-checks setup.sh
- `bash -n tools/recon/master_recon.sh` syntax-checks recon orchestrator
- `bash -n tools/nuclei_runner.sh` syntax-checks nuclei runner
- `bash -n tools/interactsh_launcher.sh` syntax-checks OOB harness
- `bash -n tools/secret_scanner.sh` syntax-checks secret scanner
- `bash -n tools/spider/spider.sh` syntax-checks spider.sh
- `bash -n tools/path_fuzzer.sh` syntax-checks path_fuzzer.sh
- `bash -n tools/waf_detect.sh` syntax-checks waf_detect.sh
- `bash -n tools/param_discover.sh` syntax-checks param_discover.sh
- `python3 -m py_compile tools/cdp_browser.py` syntax-checks cdp_browser.py
- `python3 -m py_compile tools/response_diff.py` syntax-checks response_diff.py
- `python3 -m py_compile tools/oob_validator.py` syntax-checks oob_validator.py
- `python3 -m py_compile tools/chain_automation.py` syntax-checks chain_automation.py
- `python3 -m py_compile tools/fp_database.py` syntax-checks fp_database.py
- `python3 -m py_compile tools/model_router.py` syntax-checks model_router.py
- `python3 -m py_compile tools/task_validator.py` syntax-checks task_validator.py
- `python3 -m py_compile tools/result_quality_gate.py` syntax-checks result_quality_gate.py
- `python3 -m py_compile tools/hypothesis_deduplicator.py` syntax-checks hypothesis_deduplicator.py
- `python3 -m py_compile tools/state_manager.py` syntax-checks state_manager.py
- `python3 -m py_compile tools/spider_to_mapping_handoff.py` syntax-checks spider_to_mapping_handoff.py
- `python3 -m py_compile tools/external_intel.py` syntax-checks external_intel.py
- `python3 -m py_compile tools/multi_target.py` syntax-checks multi_target.py
- `python3 tools/state_manager.py status` verifies state.json schema
