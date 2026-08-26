# Operator Guide — Complete Step-by-Step Manual (v4.0.0)

This is YOUR manual. Read it once, keep it open during hunts.

> **Updated for v4.0.0** — "The GOATED Framework". Phase 0 infrastructure recon, 6 MCP servers (Playwright, Burp, GitHub, Brave Search, Memory, Sequential Thinking), nuclei + interactsh integration, 13 new vulnerability skills, OOB-first testing, chain automation, false positive learning, disclosed report knowledge base, model routing (Pro for strategy, Flash for execution), token-optimized skill summaries.

---

## The Framework In One Picture

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                        │
│  YOU (Operator) — ONE opencode session                                │
│   │                                                                    │
│   ├── opencode CLI (Lead = primary agent)                             │
│   │      ├── Reads: lead_prompt.md, target_prompt.md, state.json      │
│   │      ├── Writes: tasks/task-NNN.md, state.json updates            │
│   │      ├── Runs: task_validator, state_manager, deduplicator, etc.  │
│   │      ├── Spawns Worker subagents via /worker command              │
│   │      └── Reports authored by Lead (Phase 5)                       │
│   │                                                                    │
│   ├── Worker subagent (spawned on demand)                             │
│   │      ├── Reads: worker_prompt.md, ONE task, ONE skill SUMMARY     │
│   │      └── Writes: results/result-NNN.md, profiles, findings        │
│   │                                                                    │
│   ├── MCP Servers (6 always-on tools)                                  │
│   │      ├── Playwright MCP — browser automation                        │
│   │      ├── Burp Suite MCP — HTTP testing (port 9876)                 │
│   │      ├── GitHub MCP — code + secret search (needs PAT token)       │
│   │      ├── Brave Search MCP — automated web dorking                  │
│   │      ├── Memory MCP — persistent knowledge graph (local)           │
│   │      └── Sequential Thinking MCP — chain reasoning (local)         │
│   │                                                                    │
│   │                                                                    │
│   ├── Chrome Session A (port 9222) — Attacker (manual login)          │
│   ├── Chrome Session B (port 9223) — Victim (manual login)            │
│   │                                                                    │
│   └── Shared filesystem: your engagement's bugbounty-ai-framework/    │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

### What Changed in v4.0.0

The framework now follows a **7-phase workflow** (was 5). Phase 0 (Infrastructure Recon) runs FIRST — subdomain enumeration, port scanning, tech detection, cloud enumeration. This expands the attack surface 5-10x before you ever hit the web app.

New capabilities:
- **6 MCP servers** (was 2): GitHub for code/secret search, Brave Search for automated dorking, Memory for persistent program profiles, Sequential Thinking for chain synthesis
- **Nuclei integration**: Automated CVE/vulnerability scanning with tech-stack-matched templates
- **OOB-first testing**: Every blind vulnerability (SSRF, blind XSS, blind SQLi) tests OOB callbacks FIRST
- **13 new vulnerability skills**: NoSQL injection, Subdomain Takeover, Host Header Injection, MFA Bypass, and 9 more
- **False positive elimination**: Pattern database + confidence adjustment + automated response diffing
- **Chain automation**: `chain_automation.py` replaces manual M9 synthesis
- **Model routing**: Pro for strategic decisions (chain analysis, reporting), Flash for tactical execution (tools, testing)
- **Knowledge base**: Disclosed report patterns + triage intelligence + mental model training

The validate → lock → dispatch → unlock → quality-gate cycle from v3.2.0 is preserved and now includes Phase 0 tasks.

---

## Prerequisites (One-Time Setup)

```bash
# 1. Chrome with remote debugging support
sudo apt update && sudo apt install -y google-chrome-stable

# 2. Python for CDP tool + new tools (all stdlib — no extra packages needed)
pip install websockets --break-system-packages
# Optional: pip install pyyaml  (improves hypothesis_deduplicator profile parsing)

# 3. Basic tools
sudo apt install -y curl jq python3 git

# 4. Make all scripts executable
cd <your-engagement>/bugbounty-ai-framework
chmod +x tools/spider/spider.sh tools/spider/spider_comprehension.sh \
         tools/path_fuzzer.sh tools/param_discover.sh tools/waf_detect.sh \
         tools/cdp_browser.py setup.sh

# 5. Verify all new tools compile
python3 -m py_compile tools/task_validator.py tools/result_quality_gate.py \
    tools/hypothesis_deduplicator.py tools/state_manager.py \
    tools/spider_to_mapping_handoff.py tools/external_intel.py tools/multi_target.py
echo "All tools OK"
```

### Optional — External Intelligence API Keys

Set these in your shell environment for richer intelligence gathering:

```bash
# GitHub dorking (10 req/min without token, 30/min with)
export GITHUB_TOKEN="ghp_your_personal_access_token"

# Shodan lookup for exposed services
export SHODAN_API_KEY="your_shodan_api_key"
```

---

## Starting a New Engagement — Full Walkthrough

### Step 1: Setup and Target Prompt

```bash
cd ~/BugBounty/<program>/bugbounty-ai-framework

# Option A: Use setup.sh (recommended — resets state + creates dirs)
./setup.sh "https://target.com" "program-name"

# Option B: Manual reset
python3 -c "
import json
state = json.load(open('state.json'))
state['engagement'] = {
    'program': 'Program Name',
    'target': 'https://target.com',
    'started': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'status': 'active',
     'current_focus': 'phase_0_recon'
}
# Reset phase sections
for phase in ['spider','mapping','testing','validating','reporting']:
    state[phase]['status'] = 'not_started'
state['findings'] = []
state['chains_identified'] = []
state['_concurrency'] = {'worker_active': False, 'active_task': None, 'task_started_at': None}
state['_token_budget'] = {'context_limit': 800000, 'estimated_consumed': 0, 'task_log': []}
json.dump(state, open('state.json','w'), indent=2)
print('state.json reset')
"
rm -f tasks/task-*.md results/result-*.md 2>/dev/null
rm -rf engagement/spider/* engagement/mapping/* engagement/findings/* engagement/reports/* 2>/dev/null
```

Fill in `target_prompt.md` with scope, credentials, rate limits, required headers.

### Step 2: Multi-Target Setup (Optional — skip for single target)

If the program has multiple domains (api.target.com, admin.target.com, etc.):

```bash
python3 tools/multi_target.py init \
    --targets "api.target.com,www.target.com,admin.target.com"

# Verify setup
python3 tools/multi_target.py status
```

### Step 3: Launch Chrome Sessions

```bash
# Session A — Attacker (port 9222, left window)
google-chrome \
    --remote-debugging-port=9222 \
    --user-data-dir=/tmp/chrome-session-a \
    --no-first-run \
    --no-default-browser-check \
    --window-size=1280,900 \
    --window-position=0,0 \
    "https://target.com/login" &

sleep 3

# Session B — Victim (port 9223, right window)
google-chrome \
    --remote-debugging-port=9223 \
    --user-data-dir=/tmp/chrome-session-b \
    --no-first-run \
    --no-default-browser-check \
    --window-size=1280,900 \
    --window-position=1300,0 \
    "https://target.com/login" &
```

**NOW: Manually log in to both Chrome windows.**
- Left window (9222) → log in as ATTACKER account
- Right window (9223) → log in as VICTIM account

**Verify sessions work:**
```bash
curl -s http://localhost:9222/json/version | jq '.Browser'
curl -s http://localhost:9223/json/version | jq '.Browser'
# Both should return Chrome version info

# Extract and verify cookies
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/spider/cookies_a.txt --format header
python3 ./tools/cdp_browser.py extract-cookies --port 9223 \
    --output engagement/spider/cookies_b.txt --format header
cat engagement/spider/cookies_a.txt  # Should show session cookies
```

**Mark sessions as fresh in state.json:**
```bash
python3 tools/state_manager.py update-session session_a --verified-now
python3 tools/state_manager.py update-session session_b --verified-now
```

### Step 4: Check Engagement Status

```bash
# Quick status check — do this before every session
python3 tools/state_manager.py status
```

Expected output for a fresh engagement:
```
============================================================
ENGAGEMENT STATUS
============================================================
  Program:       program-name
  Target:        https://target.com
  Status:        active
  Current focus: phase_0_recon

  ✅ Worker: idle

  ⬜ SPIDER: not_started
  ⬜ MAPPING: not_started (0 mapped / 0 pending)
  ⬜ TESTING: not_started (0 tested, 0 confirmed)
  ⬜ VALIDATING: not_started (0 validated)
  ⬜ REPORTING: not_started

  ✅ Token budget: ~0 / 800,000 (0%)
```

### Step 5: Start Lead Agent

```bash
cd <your-engagement>/bugbounty-ai-framework
opencode
```

**First message to Lead (copy-paste this exactly):**
```
Read these files in order:
1. master_prompt.md — your thinking foundation
2. lead_prompt.md — your coordinator role (v4.0.0)
3. target_prompt.md — this engagement's scope and rules
4. methodology.md — testing philosophy
5. bug_bounty_master_methodology_lean.md — reasoning patterns
6. phases/PHASE_ARCHITECTURE.md — 7-phase workflow
7. state.json — current progress

After reading, run:
  python3 tools/state_manager.py status
  python3 tools/state_manager.py check-sessions

Then initialize the engagement and dispatch Phase 0 Recon FIRST. Then Phase 1 Spidering.
Write the task to tasks/task-001-spider.md, validate it with
task_validator.py, lock the worker, then spawn a Worker subagent.
```

---

## The Main Loop (What Happens Automatically)

The Lead now runs a strict cycle for every Worker dispatch:

```
┌─────────────────────────────────────────────────────────────┐
│  LEAD decides next task                                       │
│    │                                                          │
│    ▼                                                          │
│  python3 tools/task_validator.py tasks/task-NNN-*.md         │
│    │  exit 0 = valid    exit 1 = FIX IT    exit 2 = review   │
│    │                                                          │
│    ▼                                                          │
│  python3 tools/state_manager.py lock-worker "task-NNN-*.md"  │
│    │  (prevents double-dispatch, records start time)          │
│    │                                                          │
│    ▼                                                          │
│  /worker "Execute tasks/task-NNN-*.md"                       │
│    │  Worker executes → writes result                         │
│    │                                                          │
│    ▼                                                          │
│  python3 tools/state_manager.py unlock-worker                │
│  python3 tools/result_quality_gate.py results/result-NNN-*.md│
│    │  exit 0 = update state    exit 1 = investigate first     │
│    │                                                          │
│    ▼                                                          │
│  Lead reads result → updates state.json → decides next task  │
│    │                                                          │
│    └─────────────────────────────────────────────────────────┘
```

**You supervise this loop. You don't need to manually run any of these commands** — the Lead does it. But you should understand what's happening so you can intervene when needed.

---

## Phase-by-Phase Operation

## Phase-by-Phase Operation

The framework follows a 7-phase workflow. Phase 0 (Infrastructure Recon) is MANDATORY and runs FIRST.

### Phase 0: Infrastructure Recon (~10-30 minutes)

The Worker runs `tools/recon/master_recon.sh` which orchestrates 4 tools:

| Tool | What It Finds |
|------|---------------|
| `subdomain_enum.sh` | Subdomains (passive + active + permutations), live hosts, takeover candidates |
| `port_scan.sh` | Open ports, service fingerprinting, NSE vulnerability detection |
| `tech_detect.sh` | Technology stack, CMS, CDN/WAF, API frameworks |
| `cloud_enum.sh` | S3/Azure/GCP buckets, K8s endpoints, email security (SPF/DMARC) |

**Output:** `engagement/recon/recon.json` — unified summary. Lead reads ONLY the summary (~500 tokens), not raw tool output.

**Dispatch:** Write `tasks/task-NNN-recon.md` referencing `skills/recon-infra/SKILL.md`.

Spawn Worker: `/recon "Run Phase 0 against target.com"`

**Critical:** Found public S3 buckets? Subdomain takeover candidates? Exposed K8s? These are INSTANT reportable findings. Flag immediately.

### Phase 1: Spidering (~30-60 minutes)

**What happens automatically:**
1. Lead writes task file → validates it → locks worker → spawns Worker
2. Worker runs 5 spider tools (spider.sh, spider_comprehension.sh, path_fuzzer.sh, waf_detect.sh, param_discover.sh)
3. Worker writes result → Lead unlocks worker → Lead runs quality gate
4. **Lead runs `spider_to_mapping_handoff.py`** automatically — generates `ENDPOINT-PRIORITY-LIST.md`
5. Lead optionally runs `external_intel.py` for CVE checks and GitHub dorking

**Your role:** Just watch. If spider completes, check:
```bash
# Verify spider outputs exist
ls engagement/spider/auth/ engagement/spider/unauth/
cat engagement/mapping/ENDPOINT-PRIORITY-LIST.md | head -50

# Check if external intel ran (if enabled)
cat engagement/spider/external_intel.md 2>/dev/null
cat engagement/spider/cve_matches.json 2>/dev/null | python3 -m json.tool | grep "cve_id"
```

**If spider found Critical CVEs:** Tell Lead:
```
external_intel.py found Critical CVEs in the tech stack.
Review engagement/spider/external_intel.md and factor into testing priority.
Check if these versions are actually patched before adding to hypotheses.
```

**Multi-target:** If you set up multiple targets:
```bash
# Generate parallel spider commands for all targets
python3 tools/multi_target.py spider-all
# Copy and run the output in a separate terminal
```

### Phase 2: Mapping (~2-6 hours)

**What happens automatically:**
1. Lead reads `ENDPOINT-PRIORITY-LIST.md` (NOT the raw sitemap)
2. Lead dispatches batches of 3-5 endpoints (Batch 1, Batch 2, etc.) — task stubs are pre-generated
3. After each batch: Lead runs `hypothesis_deduplicator.py` → reads `HYPOTHESIS-PRIORITY.md`
4. Lead only dispatches testing on hypotheses from the **Active** table in HYPOTHESIS-PRIORITY.md

**Your role:** Between batches, Lead will report HIGH-confidence hypotheses. You steer:

```
# To continue mapping:
Continue with Batch 2 as planned.

# To pivot to testing:
We have 2 HIGH-confidence critical hypotheses. Stop mapping,
test these first, then return to mapping.

# To check dedup status:
```
```bash
# Check hypothesis priority list
cat engagement/mapping/HYPOTHESIS-PRIORITY.md
```

**Signs of a healthy mapping phase:**
- `engagement/mapping/EP-XXX.profile.yaml` files accumulating
- HYPOTHESIS-PRIORITY.md shows mostly "unique" status hypotheses
- Duplicate table is small (expected — similar endpoints often share vuln patterns)

### Phase 3: Testing (variable)

**What happens automatically:**
1. Lead reads `HYPOTHESIS-PRIORITY.md` for dispatch order
2. Lead validates task (checks: hypothesis not in `tested_hypothesis_ids`, profile exists, session fresh)
3. Worker reads SUMMARY.md first (quick-reference), then SKILL.md only if needed
4. After result: Lead updates `tested_hypothesis_ids`, runs deduplicator propagation if confirmed

**Your role:** Watch for confirmed findings. If HIGH severity confirmed:
```
Prioritize validating FIND-XXX immediately — Critical severity.
Don't test more hypotheses until it's validated.
```

**If Worker stops with `partial` (stop condition):**
```bash
# Check if worker is stuck
python3 tools/state_manager.py task-timeout --check

# Read stop condition details in the result
cat results/result-NNN-test-HYP-XXX.md | grep -A 5 "Stop Condition"
```

Tell Lead:
```
Worker returned partial on HYP-XXX. Stop condition type: [transient/permanent].
[If transient]: Retry the same task in 10 minutes.
[If permanent]: Skip HYP-XXX, dispatch next hypothesis from HYPOTHESIS-PRIORITY.md.
```

**Common stop conditions and handling:**

| Condition | Type | Action |
|-----------|------|--------|
| `5xx_cascade` | Transient | Wait 10min, retry (max 2x) |
| `session_expired` | Transient | Re-extract cookies, then retry |
| `waf_blocked` | Permanent | Skip or try alternate bypass |
| `step_limit` | Transient | Dispatch follow-up task from where Worker stopped |

### Phase 4: Validating (~30 min per finding)

**What happens automatically:**
1. Lead extracts fresh cookies before validation task
2. Worker reproduces from scratch (fresh session, exact reproduction steps)
3. Worker calculates CVSS v3.1 and documents chain potential
4. Quality gate checks: CVSS vector present, poc/ files referenced

**Your role:** Review each validated finding:
```bash
cat engagement/findings/FIND-XXX.validated.md
# Check: CVSS score justified? Steps reproducible? Data redacted?
```

If reproduction failed:
```
Validation failed for FIND-XXX. Do NOT debug it during validation.
Mark as validation_failed and log in state.json.
We'll investigate manually before submitting.
```

### Phase 5: Reporting (Lead only, ~30-60 min per report)

**What happens:** Lead reads validated findings + writes professional report.

**Your role:** Final human review before submission:
- [ ] All reproduction steps clear and numbered?
- [ ] CVSS score matches severity claim?
- [ ] No real user PII in the report?
- [ ] Evidence files referenced exist?
- [ ] Chain context noted if applicable?
- [ ] Required program header included (X-HackerOne-Handle, etc.)?

```bash
cat engagement/reports/<finding>.report.md
```

Then submit on HackerOne / Bugcrowd!

---

## Handling Common Situations

### Session expired mid-task

**Detection:** `state_manager.py check-sessions` shows ❌ EXPIRED.

```bash
# Re-extract cookies manually
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/spider/cookies_a.txt --format header
python3 ./tools/cdp_browser.py extract-cookies --port 9223 \
    --output engagement/spider/cookies_b.txt --format header

# Update session timestamp
python3 tools/state_manager.py update-session session_a --verified-now
python3 tools/state_manager.py update-session session_b --verified-now
```

Tell Lead:
```
Sessions re-extracted and verified. Update state.json session cookies,
then continue with the next task.
```

If Chrome itself is stale (page shows login screen): manually re-login in Chrome first, then re-extract.

### Worker appears stuck (no result after 90+ minutes)

```bash
# Check if worker lock is still active
python3 tools/state_manager.py task-timeout --check
# Will auto-force-unlock if timeout exceeded and log to state.json._timeouts
```

Tell Lead:
```
Worker timeout detected. Force-unlock has been applied.
Dispatch next priority task from HYPOTHESIS-PRIORITY.md.
Log the stuck task to next_session.notes.
```

### Quality gate fails after Worker result

```bash
# Read what failed
python3 tools/result_quality_gate.py results/result-NNN-*.md
```

Common failures and fixes:

| Failure | Cause | Fix |
|---------|-------|-----|
| Missing `## Verdict` | Worker forgot verdict section | Tell Worker to re-read worker_prompt.md result format and add it |
| No HTTP evidence | Worker summarized instead of quoting | Tell Worker to re-do Phase 3 with exact request/response |
| Missing CVSS vector | Phase 4 result incomplete | Tell Worker to add CVSS calculation to the validated finding |
| Mapping count delta | Worker overcounted mapped endpoints | Lead should recount actual profile files |

### Hypothesis deduplicator finds too many duplicates

```bash
cat engagement/mapping/HYPOTHESIS-PRIORITY.md
# Look at the Duplicates table
```

This is normal for apps with many similar endpoints. Tell Lead:
```
The deduplicator shows N duplicate hypotheses. Test only the primary
hypothesis for each pattern. If confirmed, auto-mark the duplicates
as propagated via: hypothesis_deduplicator.py --mark-confirmed HYP-XXX
```

### Lead keeps dispatching LOW confidence hypotheses

Tell Lead:
```
Check HYPOTHESIS-PRIORITY.md — skip anything in the Deferred table.
Only dispatch from Active and Propagated tables.
We have [N] HIGH-confidence items not yet tested.
```

### Token budget approaching limit

```bash
python3 tools/state_manager.py token-budget
# If >80% → summarize
```

Tell Lead:
```
Token budget is at X%. Before continuing:
1. Summarize all result files older than 24h into a one-paragraph note in state.json
2. Drop the full result content from your context — you have state.json as truth
3. Continue with the highest-priority pending task only
```

### You want to run external intelligence checks

```bash
# CVE check against detected tech stack
python3 tools/external_intel.py --target target.com \
    --tech-stack "nginx/1.18.0,express/4.17,openssl/3.0.2" \
    --cve-check

# Full check (GitHub + Shodan + CVE) — requires API keys
python3 tools/external_intel.py --target target.com --all

# Review results
cat engagement/spider/external_intel.md
```

---

## Resuming Next Day

```bash
# 1. Re-launch Chrome
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-session-a "https://target.com" &
google-chrome --remote-debugging-port=9223 --user-data-dir=/tmp/chrome-session-b "https://target.com" &

# 2. Check if you're still logged in — if not, re-login manually

# 3. Re-extract cookies and mark as fresh
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/spider/cookies_a.txt --format header
python3 ./tools/cdp_browser.py extract-cookies --port 9223 \
    --output engagement/spider/cookies_b.txt --format header
python3 tools/state_manager.py update-session session_a --verified-now
python3 tools/state_manager.py update-session session_b --verified-now

# 4. Status check before starting
python3 tools/state_manager.py status
python3 tools/state_manager.py check-sessions

# 5. Start Lead
cd <your-engagement>/bugbounty-ai-framework
opencode
```

**Resume message to Lead:**
```
Resume engagement.

Run:
  python3 tools/state_manager.py status
  python3 tools/state_manager.py check-sessions

Read state.json and next_session.priority for what to focus on.
Check HYPOTHESIS-PRIORITY.md for the current dispatch queue.
What is the next task?
```

---

## Token Budget Reference (v4.0.0)

### Lead Agent (Read ONCE per session)
- master_prompt.md + lead_prompt.md + target_prompt.md + methodology.md + phases/PHASE_ARCHITECTURE.md + state.json
- **Lead startup total: ~6,000 tokens** (v4.0.0 optimized — Lead reads recon.json SUMMARY, not raw tool output)

> **v4.0.0 optimization:** Lead reads `recon.json` summary ONLY (~500 tokens) vs raw spider/recon output (~5,000). `chain_automation.py` replaces manual 15K token M9 chain synthesis. SUMMARY.md skill cards save ~300 tokens per task.

### Worker Agent
- worker_prompt.md + task file + SUMMARY.md (first, ~40 lines) + SKILL.md (only if needed, ~300-600 lines)

### Token Budget Estimates per Task Type

| Task | Estimated Tokens | Model |
|------|-----------------|-------|
| Phase 0 (recon) | ~1,500 | Flash |
| Phase 1 (full spider) | ~5,000 | Flash |
| Phase 2 (per endpoint mapping) | ~2,500 | Flash |
| Phase 3 (per hypothesis test) | ~3,000 | Flash |
| Phase 3.5 (exploitation) | ~2,500 | Flash |
| Phase 4 (per finding validation) | ~2,000 | Flash |
| M9 chain synthesis | ~2,000 | Pro (automated) |
| Phase 5 (report writing) | ~5,000 | Pro |
| `/dork` (GitHub + Brave Search) | ~1,500 | Flash |
| `/think` (Sequential Reasoning) | ~2,500 | Pro |

**Context Limit:** 800,000 tokens | **Warn:** 80% (640K) | **Block:** 90% (720K)

The `state_manager.py token-budget` command tracks these automatically.

---

## Complete File Structure (v4.0.0)

```
bugbounty-ai-framework/
├── master_prompt.md             ← Thinking framework (both agents)
├── lead_prompt.md               ← Lead's role, v4.0.0 dispatch patterns
├── worker_prompt.md             ← Worker's role, OOB-first testing
├── target_prompt.md             ← Current engagement details
├── methodology.md               ← Testing philosophy
├── bug_bounty_master_methodology_lean.md  ← Reasoning patterns
├── state.json                   ← Engagement state v3.0.0 (Lead updates)
├── opencode.json                ← Agent/MCP/command configuration
│
├── phases/
│   └── PHASE_ARCHITECTURE.md   ← 7-phase workflow detail
│
├── tools/                       ← All automation tools
│   ├── recon/                   ← [v4.0.0] Phase 0 infrastructure recon
│   │   ├── master_recon.sh      ← Recon orchestrator
│   │   ├── subdomain_enum.sh    ← Subdomain discovery
│   │   ├── port_scan.sh         ← Port scanning + service detection
│   │   ├── tech_detect.sh       ← Technology stack fingerprinting
│   │   └── cloud_enum.sh        ← Cloud bucket + K8s + email security
│   ├── nuclei_runner.sh         ← [v4.0.0] Nuclei vulnerability scanner
│   ├── interactsh_launcher.sh   ← [v4.0.0] OOB testing harness
│   ├── sqlmap_runner.sh         ← [v4.0.0] Safe SQLMap (Phase 3.5 only)
│   ├── secret_scanner.sh        ← [v4.0.0] Trufflehog + GitHub dorking
│   ├── response_diff.py         ← [v4.0.0] Automated response comparison
│   ├── oob_validator.py         ← [v4.0.0] OOB callback validation
│   ├── chain_automation.py      ← [v4.0.0] Automated M9 chain synthesis
│   ├── fp_database.py           ← [v4.0.0] False positive pattern DB
│   ├── model_router.py          ← [v4.0.0] Pro vs Flash task routing
│   │
│   ├── spider/
│   │   ├── spider.sh            ← Master crawler
│   │   └── spider_comprehension.sh ← Source maps, webpack, API specs
│   ├── cdp_browser.py           ← Chrome DevTools bridge
│   ├── path_fuzzer.sh           ← Hidden path discovery
│   ├── waf_detect.sh            ← WAF fingerprinting
│   ├── param_discover.sh        ← Hidden parameter discovery
│   │
│   ├── task_validator.py        ← Pre-dispatch task validation
│   ├── result_quality_gate.py   ← Worker result schema validation
│   ├── hypothesis_deduplicator.py ← Cross-endpoint hypothesis dedup
│   ├── state_manager.py         ← Worker locking, sessions, token budget
│   ├── spider_to_mapping_handoff.py ← Auto priority list from spider output
│   ├── external_intel.py        ← CVE checks, GitHub dorking, Shodan
│   └── multi_target.py          ← Multi-domain target management
│
├── skills/                      ← 51 vulnerability + MCP skills
│   ├── index.md                 ← Skill graph navigation
│   ├── recon-infra/             ← [v4.0.0] Phase 0 recon skill
│   ├── github-mcp/              ← [v4.0.0] GitHub MCP skill
│   ├── brave-search-mcp/        ← [v4.0.0] Brave Search MCP skill
│   ├── memory-mcp/              ← [v4.0.0] Memory MCP skill
│   ├── sequential-thinking/     ← [v4.0.0] Sequential Thinking MCP skill
│   ├── nosqli/                  ← [v4.0.0] NoSQL injection
│   ├── subdomain-takeover/      ← [v4.0.0] Subdomain takeover
│   ├── host-header-injection/   ← [v4.0.0] Host header injection
│   ├── mfa-bypass/              ← [v4.0.0] MFA/2FA bypass
│   ├── bfla/                    ← [v4.0.0] Broken Function-Level Auth
│   ├── crlf-injection/          ← [v4.0.0] CRLF injection
│   ├── xpath-injection/         ← [v4.0.0] XPATH injection
│   ├── pdf-ssrf/                ← [v4.0.0] PDF generation SSRF
│   ├── oauth-ato/               ← [v4.0.0] OAuth account takeover
│   ├── email-spoofing/          ← [v4.0.0] Email spoofing
│   ├── postmessage/             ← [v4.0.0] postMessage security
│   ├── webrtc-leak/             ← [v4.0.0] WebRTC IP leaking
│   ├── dependency-confusion/    ← [v4.0.0] Dependency confusion
│   │
│   ├── mapping/                 ← Phase 2: M1-M8 per-endpoint profiling
│   ├── chaining/                ← M9 chain synthesis patterns
│   ├── idor/ sqli/ xss/ ssrf/   ← Core vulnerability skills
│   └── <25 other vuln skills>
│
├── knowledge/                   ← [v4.0.0] Mental model training
│   ├── INDEX.md                 ← Knowledge base index
│   ├── disclosed_reports/       ← Patterns from real H1 reports
│   │   ├── idor_patterns.md
│   │   ├── ssrf_patterns.md
│   │   └── chain_patterns.md
│   └── triage_intelligence/     ← What triagers actually accept
│       └── h1_acceptance_patterns.md
│
├── tasks/                       ← Lead-generated task files
│   └── templates/
│       ├── example-task-000-recon.md   ← [v4.0.0] Phase 0 template
│       └── example-task-001-spider.md  ← Phase 1 template
│
├── results/                     ← Worker-generated result files
│
└── engagement/                  ← All per-engagement artifacts
    ├── recon/                   ← [v4.0.0] Phase 0 outputs
    │   ├── recon.json           ← Unified recon summary
    │   ├── subdomains/          ← Subdomain enumeration output
    │   ├── ports/               ← Port scan output
    │   ├── tech/                ← Technology detection output
    │   └── cloud/               ← Cloud enumeration output
    ├── spider/
    │   ├── unauth/sitemap.json
    │   ├── auth/sitemap.json
    │   ├── fuzz/hidden_endpoints.json
    │   └── waf/waf_fingerprint.json
    ├── mapping/                 ← EP-XXX.profile.yaml + priority lists
    ├── findings/                ← HYP-XXX.confirmed.md + FIND-XXX.validated.md
    └── reports/                 ← Final bug bounty reports
        └── <finding>.report.md
```

---

## Daily Checklist (v3.2.0)

### Before Starting a Session

- [ ] Chrome sessions launched (ports 9222, 9223)
- [ ] Manually logged in to both Chrome windows
- [ ] Cookies extracted and marked fresh: `python3 tools/state_manager.py update-session session_a --verified-now`
- [ ] Status check: `python3 tools/state_manager.py status`
- [ ] Sessions check: `python3 tools/state_manager.py check-sessions`
- [ ] Worker not stuck from last session: verify `_concurrency.worker_active == false` in state.json

### During the Session

- [ ] Observe the validate → lock → dispatch → unlock → quality-gate cycle
- [ ] Watch for quality gate failures — investigate before ignoring
- [ ] Monitor token budget: `python3 tools/state_manager.py token-budget`
- [ ] Check for incidental signals in Worker results
- [ ] After every mapping batch: check `engagement/mapping/HYPOTHESIS-PRIORITY.md`

### End of Session

- [ ] Verify no worker lock stuck: `python3 tools/state_manager.py status`
- [ ] Tell Lead to update `state.json.next_session.priority`
- [ ] Note expired sessions, WAF changes, or rate limit hits
- [ ] Check token budget remaining for next session
- [ ] Commit any private notes about the target

---

## New Tool Quick Reference (v3.2.0)

```bash
# ─── PRE-DISPATCH VALIDATION ───────────────────────────────────────────
python3 tools/task_validator.py tasks/task-NNN-*.md
# → exit 0: valid, dispatch safe
# → exit 1: invalid, fix task first
# → exit 2: warnings, review before dispatching

python3 tools/task_validator.py --all-pending
# → validates all task files in tasks/

# ─── STATE MANAGEMENT ──────────────────────────────────────────────────
python3 tools/state_manager.py status
# → full engagement status summary

python3 tools/state_manager.py check-sessions
# → session freshness check (exit 2 if expired)

python3 tools/state_manager.py update-session session_a --verified-now
# → mark session as freshly verified

python3 tools/state_manager.py lock-worker "task-042-test-HYP-007.md"
# → set worker_active = true, record task + start time

python3 tools/state_manager.py unlock-worker
# → set worker_active = false, record completion

python3 tools/state_manager.py task-timeout --check
# → check if active task exceeded 90min, force-unlock if so

python3 tools/state_manager.py token-budget
# → show current consumption vs limit

# ─── RESULT QUALITY GATE ───────────────────────────────────────────────
python3 tools/result_quality_gate.py results/result-NNN-*.md
# → validate Worker result completeness and schema

python3 tools/result_quality_gate.py --validate-state
# → validate state.json schema

python3 tools/result_quality_gate.py --check-consistency
# → check state.json claims vs actual files

python3 tools/result_quality_gate.py --all
# → run everything (state schema + consistency + all results)

# ─── HYPOTHESIS DEDUPLICATION ──────────────────────────────────────────
python3 tools/hypothesis_deduplicator.py
# → reads all EP-*.profile.yaml → writes HYPOTHESIS-PRIORITY.md

python3 tools/hypothesis_deduplicator.py --dry-run
# → print to stdout instead of file

python3 tools/hypothesis_deduplicator.py \
    --mark-confirmed HYP-007 \
    --similar-endpoints EP-003,EP-007
# → propagate a confirmed pattern to similar endpoints

# ─── SPIDER-TO-MAPPING HANDOFF ─────────────────────────────────────────
python3 tools/spider_to_mapping_handoff.py
# → auto-detect sitemap → write ENDPOINT-PRIORITY-LIST.md

python3 tools/spider_to_mapping_handoff.py \
    --sitemap engagement/spider/auth/sitemap.json \
    --max-batch 5
# → explicit sitemap + batch size

# ─── EXTERNAL INTELLIGENCE ─────────────────────────────────────────────
python3 tools/external_intel.py --target example.com --cve-check \
    --tech-stack "nginx/1.18.0,log4j/2.14.1"
# → check tech stack for known CVEs

python3 tools/external_intel.py --target example.com --github-dork
# → search GitHub for hardcoded credentials

python3 tools/external_intel.py --target example.com --all
# → CVE + GitHub + Shodan (API keys required for GitHub/Shodan)

# ─── MULTI-TARGET ──────────────────────────────────────────────────────
python3 tools/multi_target.py init \
    --targets "api.example.com,admin.example.com,app.example.com"
# → initialize multi-target configuration

python3 tools/multi_target.py spider-all
# → print parallel spidering commands for all targets

python3 tools/multi_target.py correlate
# → cross-target JWT/ID/admin correlation analysis

python3 tools/multi_target.py status
# → per-target progress

# ─── STANDARD VERIFICATION ─────────────────────────────────────────────
python3 -c "import json; json.load(open('state.json'))" && echo "state.json valid"
python3 -m py_compile tools/cdp_browser.py && echo "cdp_browser.py OK"
bash -n tools/spider/spider.sh && echo "spider.sh OK"
```

---

## The Honest Truth (Updated for v3.2.0)

The framework now has proper operational hardening:
- ✅ **No silent failures** — quality gates catch bad results before state is corrupted
- ✅ **No wasted Worker cycles** — pre-dispatch validation blocks malformed tasks
- ✅ **No duplicate work** — hypothesis deduplicator prevents re-testing the same pattern
- ✅ **No session confusion** — `state_manager.py` tracks freshness and auto-warns
- ✅ **No token waste** — SUMMARY.md cards + handoff scripts keep context lean
- ✅ **No getting lost** — token budget tracking warns before context overflow
- ✅ **Multi-domain ready** — multi_target.py handles complex programs with 5+ subdomains

What it still requires from you:
- Manual Chrome logins (unavoidable — web sessions need real interaction)
- Reviewing quality gate failures that need judgment (automated gates catch structure, not content)
- Final report review before submission (always needs a human eye)

Methodology + disciplined tooling = bugs found. Let's hunt.

---

## Quick Start (TL;DR for experienced operators)

```bash
# 1. Setup
./setup.sh "https://target.com" "program-name"
chmod +x tools/*.py

# 2. Chrome
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-a "https://target.com" &
google-chrome --remote-debugging-port=9223 --user-data-dir=/tmp/chrome-b "https://target.com" &
# → Log in manually to both

# 3. Extract + mark sessions
python3 tools/cdp_browser.py extract-cookies --port 9222 --output engagement/spider/cookies_a.txt --format header
python3 tools/cdp_browser.py extract-cookies --port 9223 --output engagement/spider/cookies_b.txt --format header
python3 tools/state_manager.py update-session session_a --verified-now
python3 tools/state_manager.py update-session session_b --verified-now

# 4. Status check
python3 tools/state_manager.py status && python3 tools/state_manager.py check-sessions

# 5. Start
opencode
# → Send the startup message from "Step 5: Start Lead Agent" above
```
