# bughunter — AI Bug Bounty Framework

> Lead / Worker autonomous hunting. 7 phases. 51 skills. 29+ tools. OOB-first. Chain-aware. Token-disciplined.

![version](https://img.shields.io/badge/version-v4.5.0-blue) ![phases](https://img.shields.io/badge/phases-7-green) ![skills](https://img.shields.io/badge/skills-51-orange) ![lead](https://img.shields.io/badge/Lead-muse--spark--1.3--high-purple) ![worker](https://img.shields.io/badge/Worker-muse--spark--1.3--default-purple)

`bughunter` is an opinionated `opencode`-native framework for high-signal bug bounty hunting. One Lead session plans, validates, dispatches and synthesizes. Bounded Worker subagents execute one task at a time — recon, spider, mapping, testing, validation — and return structured artifacts. The Lead never probes; Workers never plan.

This repo is currently `0527e52` (`Migrate Lead/Worker to Muse Spark 1.3 Contributor`) on `main`, tracking `HeyMeMukul/bughunter`.

---

## Table of Contents

- [Why bughunter](#why-bughunter)
- [How it works](#how-it-works)
- [7-phase workflow](#7-phase-workflow)
- [Skills](#skills)
- [Tools](#tools)
- [MCP servers](#mcp-servers)
- [Models](#models)
- [Knowledge base](#knowledge-base)
- [Quick start](#quick-start)
- [Usage guide](#usage-guide)
- [Commands](#commands)
- [File structure](#file-structure)
- [State, slots and budget](#state-slots-and-budget)
- [Critical rules](#critical-rules)
- [Verification](#verification)

---

## Why bughunter

Manual hunting misses attack surface. Single-agent AI burns tokens on raw HTTP and produces untestable findings.

bughunter fixes this with:

- **Phase discipline:** Recon before spider. Spider before mapping. Mapping before testing. Smart overlap where safe.
- **Tool-first mechanical work:** Tools emit JSON. Lead reads JSON, not raw traffic. ~92% token saving in Phase 1.
- **OOB-first testing:** Every Phase 3 hypothesis starts with out-of-band callbacks (`interactsh` / Burp Collaborator).
- **Business-context mapping (M2.5) + M9 chain synthesis:** Endpoints get `business_function`, `impact_floor/ceiling`, chains get built across primitives.
- **False-positive learning:** `response_diff.py` + `fp_database.py` + mandatory Negative Verdict gates.
- **Two-account safety:** Attacker Chrome `:9222` + victim Chrome `:9223` for real auth-matrix testing.

---

## How it works

```
YOU (operator) — ONE opencode session
 |
 +- Lead (primary, agent.build) — BRAIN
 |    reads: lead_prompt.md, master_prompt.md, target_prompt.md, state.json
 |    writes: tasks/task-NNN-*.md, state.json updates
 |    runs: task_validator.py, state_manager.py, result_quality_gate.py,
 |           hypothesis_deduplicator.py, spider_to_mapping_handoff.py, chain_automation.py
 |    spawns: /recon /spider /map /test /validate /worker (max 2 bounded slots)
 |    owns: M9 chains, reports, cross-task reasoning
 |
 +- Worker (subagent, agent.general) — HANDS
      reads: worker_prompt.md, ONE task file, ONE skill (SUMMARY.md first)
      runs: recon/spider/probing/testing tools, browser, Burp
      writes: results/result-NNN-*.md + phase artifacts
```

**Lead never does:** `bash`/`curl` probing, Playwright navigate/evaluate, API testing, recon execution, JS analysis, secret scanning. ~3x token cost if violated.

**Worker never does:** read `lead_prompt.md`, `methodology.md`, other tasks/skills, cross-task chaining, state merges.

**Autonomous continuation:** after scope + auth are established, Lead writes → validates → locks → dispatches → processes without waiting for manual slash commands. Recoverable failures get diagnosis Worker → one corrected retry → alternate safe method → continue. Hard gates (scope ambiguity, out-of-scope, destructive action, missing approval, credential refresh, unbounded impact) pause and start:

```bash
./tools/operator_ping.sh "<exact need>" loop
```

Full contracts: `AGENTS.md`, `lead_prompt.md`, `worker_prompt.md`, `master_prompt.md`, `methodology.md`, `phases/PHASE_ARCHITECTURE.md`.

---

## 7-phase workflow

| Phase | What | Driven by | Key output |
|-------|------|-----------|------------|
| 0. Recon | Subdomains, ports, tech, cloud, email security | Worker + `tools/recon/master_recon.sh` | `engagement/recon/recon.json` |
| 1. Spidering | Surface discovery + comprehension, fuzz, WAF, params | Worker + 5 tools | `sitemap.json`, `understanding/`, `hidden_endpoints.json`, `waf_fingerprint.json` |
| 2. Mapping | Per-endpoint M1-M8 + M2.5 business context + M9 chains | Worker + `skills/mapping/SKILL.md` | `engagement/mapping/EP-XXX.profile.yaml`, `CHAIN-INVENTORY.md` |
| 3. Testing | OOB-first per-hypothesis testing | Worker + `skills/<vuln>/SKILL.md` | `engagement/findings/HYP-XXX.<status>.md` |
| 3.5 Exploitation | Safe auto-exploit for confirmed only | Worker + `sqlmap_runner.sh`, `nuclei_runner.sh` | `FIND-XXX.exploited.md` |
| 4. Validating | Clean repro, no skill | Worker | `FIND-XXX.validated.md` |
| 5. Reporting | Professional impact-led reports | Lead only | `engagement/reports/<slug>.report.md` |

Smart overlap: test an endpoint as soon as *its* mapping completes, even while other endpoints still map. Never parallelize live probes, account mutations, SSRF/OAST callbacks, WebSocket escalation, shared-state writes, or final validation.

---

## Skills

51 `SKILL.md` + summary cards in `skills/`. Index: `skills/index.md`. Contract: `skills/_shared/SKILL_CONTRACT.md`. Lint: `tools/skill_lint.py`.

**Recon / Mapping / Chaining**

- `recon-infra`, `recon`, `mapping`, `chaining`, `browser-sessions`, `session-management`

**MCP helpers**

- `burp-mcp`, `github-mcp`, `brave-search-mcp`, `memory-mcp`, `sequential-thinking`

**Injection**

- `sqli`, `nosqli`, `xss`, `ssti`, `command-injection`, `ldap-injection`, `xpath-injection`, `ssi-injection`, `xxe`

**Auth / Access**

- `idor`, `bfla`, `oauth`, `oauth-ato`, `jwt`, `mfa-bypass`, `mass-assignment`, `session-management`

**Server-side**

- `ssrf`, `pdf-ssrf`, `path-traversal`, `file-upload`, `deserialization`, `http-smuggling`, `race-condition`, `websocket`, `graphql`, `cloud-misconfig`, `subdomain-takeover`, `dependency-confusion`

**Client-side / Logic**

- `csrf`, `cors`, `open-redirect`, `postmessage`, `webrtc-leak`, `cache-poisoning`, `host-header-injection`, `crlf-injection`, `business-logic`, `email-spoofing`, `prototype-pollution`, `report-writing`

Worker loads `SUMMARY.md` (~40 lines) first, full `SKILL.md` only if needed.

---

## Tools

29 top-level + `recon/` + `spider/` + `mapping/`. Make executable after clone.

**Phase 0 — `tools/recon/` (all mandatory via `master_recon.sh`)**

- `subdomain_enum.sh` — passive + active + permutation, takeover candidates
- `port_scan.sh` — naabu + nmap + NSE
- `tech_detect.sh` — stack, CMS, CDN/WAF, API
- `cloud_enum.sh` — S3/Azure/GCP, K8s, SPF/DMARC/DKIM
- `master_recon.sh` — orchestrator → `recon.json`

**Phase 1**

- `spider/spider.sh` — BFS crawl, JS endpoints, source maps, robots/sitemap
- `spider/spider_comprehension.sh` — `.map` rebuild, webpack chunks, `sw.js`, `/.well-known/`, Swagger/GraphQL, CSP map, Wayback
- `path_fuzzer.sh` — admin, debug, VCS, backups
- `waf_detect.sh` — fingerprint + bypasses
- `param_discover.sh` — hidden params
- `cdp_browser.py` — `extract-cookies`, `capture-network`, `extract-links`, `exec-js`, `extract-storage`, `extract-forms`, `screenshot`, `auth-recon`
- `api_spider.py` — API enumeration

**Phase 2–3**

- `spider_to_mapping_handoff.py` — priority queue → `ENDPOINT-PRIORITY-LIST.md`
- `hypothesis_deduplicator.py` — cross-endpoint dedup + `HYPOTHESIS-PRIORITY.md`
- `chain_automation.py` — M9 synthesis
- `interactsh_launcher.sh` — `start | generate --type ssrf | poll`, OOB harness
- `oob_validator.py` — callback ↔ payload correlation
- `nuclei_runner.sh` — tech-matched templates
- `sqlmap_runner.sh` — Phase 3.5 only, safe wrapper
- `secret_scanner.sh` — trufflehog + dorking
- `response_diff.py` — 3-way baseline + noise elimination
- `external_intel.py` — GitHub/Shodan/CVE
- `fp_database.py` — FP patterns + confidence
- `model_router.py` — Lead/Worker routing
- `report_generator.py`, `validate_high_bounty.py`

**Ops / Quality**

- `state_manager.py` — `status`, `lock-worker`, `unlock-worker`, `check-sessions`, `token-budget`, `task-timeout`
- `task_validator.py` — pre-dispatch gate (exit 0/1/2)
- `result_quality_gate.py` — post-result schema + state consistency
- `omniroute_doctor.py` — read-only gateway check
- `skill_lint.py`, `knowledge_ingest.py`, `multi_target.py`, `test_suite.sh`, `operator_ping.sh`

---

## MCP servers

Configured in `opencode.json:mcp`, all enabled:

| Server | Command / URL | Use |
|--------|---------------|-----|
| playwright | `npx @playwright/mcp@latest --caps core,pdf,vision,devtools,storage,network` | SPA crawl, DOM XSS, screenshots |
| burp | `http://127.0.0.1:9876/sse` | Precise requests, Intruder race, Collaborator OOB — needs Burp Pro |
| github | `npx -y @modelcontextprotocol/server-github` | Code/secret/config search — needs PAT |
| brave-search | `npx -y @modelcontextprotocol/server-brave-search` | Dorking, subdomains, leaks — 2K/mo free |
| memory | `npx -y @modelcontextprotocol/server-memory` | Program profiles, FP, chains across sessions |
| sequential-thinking | `npx -y @modelcontextprotocol/server-sequential-thinking` | Chain synthesis, pivot analysis |

---

## Models

Pinned in `opencode.json` + `config/omniroute.policy.json`:

- **Lead:** `opencode-go/muse-spark-1.3-contributor` variant `high` — strategy, chains, reports
- **Worker:** `opencode-go/muse-spark-1.3-contributor` variant `default` — execution
- **Fallback both:** `opencode-go/deepseek-v4.1-flash` — on 429/5xx/capacity, retry once with bounded backoff

Legacy `omniroute/auto/reasoning:free`, `auto/coding:free`, `omniroute-cheap/auto/coding:cheap` remain for compatibility, not defaults. `top model` = Lead, `small_model` = fallback. Raw HTTP/PII stays local-only; free/cheap routes get sanitized context only. Health: `python3 tools/omniroute_doctor.py`.

---

## Knowledge base

`knowledge/` — provenance-aware, redaction-first, hypothesis priors only (not proof/permission).

- `corpus_seed/hackerone_paid_gt100.ndjson` — 2810 public records bounty >$100
- `corpus_seed/expanded_high_bounty_gt1000.ndjson` — 929 records >$1000 + 8 curated methodologies
- `disclosed_reports/` — `idor`, `ssrf`, `auth_bypass`, `business_logic`, `xss`, `chain`, `rce_patterns.md`
- `triage_intelligence/` — `h1_acceptance`, `bugcrowd_acceptance`, `impact_thresholds`, `duplicate_reasons.md`
- `SCHEMA.md`, `INGESTION_PLAN.md`, `INDEX.md`, `HIGH_BOUNTY_EXPANSION.md`
- Ingest: `python3 tools/knowledge_ingest.py` (NDJSON, no secrets/PII)

---

## Quick start

60-second version:

```bash
./setup.sh "https://target.com" "program-name"
# log in to both Chrome windows (attacker :9222, victim :9223)
opencode
# first message:
# Read state.json and the current phase indexes. Dispatch the next bounded task set.
```

Full manual: `OPERATOR_GUIDE.md`. Agent contract: `AGENTS.md`. Gateway: `OMNIROUTE_SETUP.md`.

Prerequisites: `curl`, `python3`, `jq`, `npx`, Chrome, `chmod +x tools/*.sh tools/recon/*.sh tools/spider/*.sh`. Optional: Burp Pro (`:9876`), `GITHUB_TOKEN`, `BRAVE_API_KEY`, `SHODAN_API_KEY` in `engagement/.creds.sh` (`chmod 600`, never committed).

---

## Usage guide

### 1. Start a program

```bash
./setup.sh "https://target.com" "program-name"
./setup.sh --status
```

Creates dirs, `state.json` (schema v3.0.0, never overwrites existing without `--reset --force`), launches Chrome. Fill `target_prompt.md` scope, check `state.json`, then `opencode`.

### 2. Run Lead + Workers

In `opencode` (Lead is primary):

- `/status` — phase progress, findings, next action
- `/recon` — Phase 0 → `engagement/recon/recon.json`
- `nuclei + secret scan` after recon:
  ```bash
  ./tools/nuclei_runner.sh --targets engagement/recon/subdomains/alive_hosts.txt --mode tech-stack --output-dir engagement/recon/nuclei/
  ./tools/secret_scanner.sh --target example.com --output-dir engagement/recon/secrets/
  ```
- `/spider` — Phase 1 → `sitemap.json`, `understanding/`, `hidden_endpoints.json`, `waf_fingerprint.json`
- `python3 tools/spider_to_mapping_handoff.py` — priority queue
- `/map` — Phase 2 batches (max 5 endpoints) → `EP-XXX.profile.yaml`
- `python3 tools/hypothesis_deduplicator.py` then `python3 tools/chain_automation.py --mapping-dir engagement/mapping/`
- `/test` — Phase 3 OOB-first:
  ```bash
  ./tools/interactsh_launcher.sh start --output-dir engagement/oob/
  ./tools/interactsh_launcher.sh generate --type ssrf --output-dir engagement/oob/
  ./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
  python3 tools/oob_validator.py --callbacks engagement/oob/oob_callbacks.json --payloads engagement/oob/oob_payloads.json
  ```
- Phase 3.5 only on confirmed: `./tools/sqlmap_runner.sh --url "https://target.com/api?id=1" --param id --output-dir engagement/findings/sqli_exploit/`
- `/validate` — Phase 4 clean PoC
- Reports — Lead only → `engagement/reports/`
- `/think` — chain/pivot reasoning, `/browser`, `/burp`, `/dork`, `/worker` as needed

Every dispatch:

```bash
python3 tools/task_validator.py tasks/task-NNN-*.md
python3 tools/state_manager.py lock-worker tasks/task-NNN-*.md
# ... worker runs ...
python3 tools/result_quality_gate.py results/result-NNN-*.md
python3 tools/state_manager.py unlock-worker
```

### 3. Resume / multi-target / budget

```bash
./setup.sh --resume
opencode /resume

python3 tools/state_manager.py status
python3 tools/state_manager.py check-sessions
python3 tools/state_manager.py token-budget
python3 tools/state_manager.py token-budget --sync-log <omniroute-jsonl>

python3 tools/multi_target.py init --targets "api.example.com,admin.example.com"
python3 tools/multi_target.py correlate
```

### 4. Safety

- Phase 0 first. OOB-first. WAF-aware payloads from fingerprint.
- `target_prompt.md` scope is law: destructive NO, real-user NO, zero-day NEVER.
- Secrets only in ignored `engagement/.creds.sh`. Redact evidence for free/cheap routes.
- Two slots max for independent tasks. Serialize live probes, mutations, OAST, WebSocket, final validation.

---

## Commands

| Command | Agent | Description |
|---------|-------|-------------|
| `/recon` | Worker | Phase 0 infra recon |
| `/dork` | Worker | GitHub + Brave dorking |
| `/spider` | Worker | Phase 1 spidering |
| `/map` | Worker | Phase 2 mapping |
| `/test` | Worker | Phase 3 testing |
| `/validate` | Worker | Phase 4 validation |
| `/think` | Lead | Chain reasoning |
| `/browser` | Worker | Playwright automation |
| `/burp` | Worker | Burp HTTP analysis |
| `/worker` | Worker | General task |
| `/status` | Lead | Engagement status |
| `/resume` | Lead | Resume session |

---

## File structure

```
opencode.json          <- Lead/Worker models + MCP + commands
AGENTS.md              <- agent discipline + tool table
lead_prompt.md         <- Lead coordinator
worker_prompt.md       <- Worker executor
master_prompt.md       <- thinking foundation (Three Questions)
target_prompt.md       <- scope for this program
methodology.md         <- testing philosophy
phases/                <- workflow docs
skills/                <- 51 vulnerability + infra skills
config/omniroute.policy.json <- route/data-class policy
knowledge/             <- disclosed patterns + triage intel
tools/                 <- automation (recon/spider/mapping/testing/ops)
engagement/            <- IGNORED: recon/spider/mapping/findings/reports/oob
tasks/                 <- Lead task files
results/               <- Worker results
state.json             <- single source of truth (v3.0.0)
```

---

## State, slots and budget

`state.json` keys: `engagement`, `sessions`, `recon`, `spider`, `mapping`, `testing`, `validating`, `reporting`, `findings`, `chains_identified`, `blocked_chars`, `waf_observations`, `next_session`, `_meta`, `_concurrency`, `_token_budget`, `_timeouts`, `_tech_stack`, `_settings`, `_confidence_calibration`.

Per-engagement budget (800k limit, warn 80%, block 90%):

| Phase | Lead high | Worker default |
|-------|-----------|----------------|
| Startup | 6,000 | 1,000 |
| Recon | 500 | 1,000 |
| Spider | 3,000 | 2,000 |
| Mapping/batch | 2,000 | 2,500/endpoint |
| Testing/hyp | 1,500 | 3,000 |
| Exploit | 500 | 2,000/finding |
| Validate | 1,000 | 2,000/finding |
| Report | 5,000 | — |
| M9 auto | 2,000 | — |

---

## Critical rules

1. Phase 0 first — expands surface 5-10x.
2. OOB-first every Phase 3.
3. high = strategy, default = execution. Fallback to Flash on 429/5xx.
4. No phase skipping. Tool-first. WAF-aware.
5. SUMMARY first. `state.json` is truth. Two Chromes. Redact.

---

## Verification

```bash
./setup.sh --status
python3 tools/omniroute_doctor.py --channel auto/coding:free --channel auto/reasoning:free
python3 tools/skill_lint.py skills
python3 -c "import json; json.load(open('state.json'))"
bash -n setup.sh
python3 tools/state_manager.py status
```

Full history: `CHANGELOG.md` (v4.5.0 → v2.x). Install notes: `INSTALL_v3.1.md`. Hardening: `SKILL_HARDENING.md`.
