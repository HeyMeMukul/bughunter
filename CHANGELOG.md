# Changelog — Framework v4 (The GOATED Framework)

## v4.5.0 — Program Template Defaults (September 2026)

### Fresh engagement initialization
- **Updated:** `setup.sh` now initializes `_settings.parallel_workers` to `2`, explicit concurrency state, and complete token-budget fields for every fresh program copy.
- **Updated:** `tools/state_manager.py` defaults missing slot settings to `2` without overriding an existing program’s explicit value.
- **Preserved:** existing program copies and active `state.json` files are never overwritten automatically; use `setup.sh --reset` only when intentionally starting a fresh engagement.

---

## v4.4.0 — Autonomous Continuation + Failure Recovery (August 2026)

### Lead/Worker orchestration
- **Added:** autonomous continuation after authorization and scope are established; the Lead dispatches validated tasks without waiting for manual slash-command invocation.
- **Added:** bounded recovery ladder with failure classification, read-only diagnosis Workers, corrected retries, alternate safe methods, and independent-task continuation.
- **Added:** explicit distinction between RESERVED and RUNNING Worker slots and required result or typed failure artifacts.
- **Updated:** hard-stop boundaries remain for scope ambiguity, missing authorization, sensitive credentials/data, destructive or irreversible actions, and unbounded impact.
- **Updated:** `lead_prompt.md`, `worker_prompt.md`, and `AGENTS.md` with the new continuation contract.

---

## v4.3.0 — Bounded Parallel Workers + Accurate Usage (August 2026)

### Orchestration
- **Added:** two-slot default Worker capacity for independent tasks.
- **Updated:** `tools/state_manager.py` with named worker slots, per-task unlock, timeout handling for parallel tasks, interprocess locking, and atomic state replacement.
- **Updated:** `lead_prompt.md`, `AGENTS.md`, and `phases/PHASE_ARCHITECTURE.md` with safe parallelism rules and compact Worker task packets.

### Token accounting
- **Fixed:** legacy `estimated_consumed` was only a rough reservation and was incorrectly presented as consumption.
- **Added:** distinct `request_context_limit`, `session_budget_tokens`, `estimated_reserved_tokens`, and actual input/output/cache-read counters.
- **Added:** `token-budget --sync-log <path>` for reconciling actual OmniRoute JSON log usage.
- **Fixed:** unknown task types now fail instead of silently receiving a default estimate.
- **Added:** `PARALLEL_WORKERS_AND_BUDGET.md` operator guide.

---

## v4.1.0 — OmniRoute + Evidence-First Skills (August 2026)

### Routing and cost controls
- **Updated:** `opencode.json` routes Lead and Worker through a local OmniRoute OpenAI-compatible provider.
- **Added:** default free-only model aliases with offline-friendly scoring, coding-safe compression, near-zero budget, and strict budget fallback.
- **Added:** isolated opt-in `omniroute-cheap` provider for sanitized low-cost work.
- **Added:** `OMNIROUTE_SETUP.md`, `config/omniroute.policy.json`, and read-only `tools/omniroute_doctor.py`.

### Skill hardening
- **Added:** `skills/_shared/SKILL_CONTRACT.md` with authorization, baseline, negative-verdict, session, evidence, redaction, and stop rules.
- **Added:** `tools/skill_lint.py` to detect missing metadata, checkpoints, safety gates, summaries, and size limits.
- **Updated:** `master_prompt.md`, `worker_prompt.md`, and `target_prompt.md` with bounded execution and provider/data provenance requirements.

### Knowledge base
- **Added:** `knowledge/SCHEMA.md` and `knowledge/INGESTION_PLAN.md` for provenance-aware, redaction-first retrieval and evaluation.
- **Added:** `tools/knowledge_ingest.py` and a metadata-only seed of 2,810 public HackerOne index records with bounty > $100.
- **Updated:** `knowledge/INDEX.md` to expose the corpus and warn that historical reports are hypothesis priors, not proof or permission.

---

## v4.0.0 — "The GOATED Framework" (August 2026)

Complete framework overhaul. 80+ new files, 40+ modified files. 
7-phase architecture with infrastructure recon, OOB-first testing, tool integration, 
13 new vulnerability skills, false positive learning, disclosed report knowledge base, 
token-optimized model routing (Pro for strategy, Flash for execution).

### Phase 0: Infrastructure Reconnaissance (NEW)
- **Added:** `tools/recon/subdomain_enum.sh` — Passive + active + permutation subdomain enumeration
- **Added:** `tools/recon/port_scan.sh` — Port scanning with naabu + nmap service detection + NSE vuln scanning
- **Added:** `tools/recon/tech_detect.sh` — Technology stack fingerprinting, CMS detection, CDN/WAF, API detection
- **Added:** `tools/recon/cloud_enum.sh` — S3/Azure/GCP bucket enumeration, K8s detection, email security (SPF/DMARC/DKIM)
- **Added:** `tools/recon/master_recon.sh` — Phase 0 orchestrator, unified recon.json output
- **Added:** `skills/recon-infra/SKILL.md` + `SUMMARY.md` — Worker skill for Phase 0 execution
- **Added:** `tasks/templates/example-task-000-recon.md` — Phase 0 task template
- **Updated:** 7-phase architecture in all prompts and configuration files
- **Updated:** `state.json` — Added `recon` phase section (schema v3.0.0)
- **Updated:** `opencode.json` — Added `/recon` command
- **Updated:** `setup.sh` — Recon directory creation, tool permissions

### Phase 1: Tool Integration (NEW)
- **Added:** `tools/nuclei_runner.sh` — Nuclei integration with tech-stack-matched template selection
- **Added:** `tools/interactsh_launcher.sh` — OOB testing harness (start, generate payloads, poll for callbacks)
- **Added:** `tools/sqlmap_runner.sh` — Safe SQLMap wrapper for Phase 3.5 exploitation only
- **Added:** `tools/secret_scanner.sh` — GitHub secret scanning via trufflehog + dorking
- **Added:** `tools/response_diff.py` — Automated 3-way baseline comparison, noise elimination
- **Added:** `tools/oob_validator.py` — OOB callback validation + payload correlation

### Phase 2: 13 New Vulnerability Skills (NEW)
- **Added:** `skills/nosqli/` — MongoDB, Redis, Firebase, CouchDB injection
- **Added:** `skills/subdomain-takeover/` — DNS takeover detection (S3, GitHub Pages, Heroku, 15+ services)
- **Added:** `skills/host-header-injection/` — Password reset poisoning, cache poisoning, SSRF via Host
- **Added:** `skills/mfa-bypass/` — Response manipulation, direct endpoint access, rate limit bypass, OAuth skip
- **Added:** `skills/bfla/` — Broken Function-Level Authorization (admin endpoint access)
- **Added:** `skills/crlf-injection/` — HTTP response splitting, log forging, header injection
- **Added:** `skills/xpath-injection/` — XPATH auth bypass, blind extraction, error-based detection
- **Added:** `skills/pdf-ssrf/` — wkhtmltopdf LFI/SSRF, PDF generator exploitation
- **Added:** `skills/oauth-ato/` — Deepened OAuth: CSRF→account linking, PKCE bypass, implicit flow
- **Added:** `skills/email-spoofing/` — SPF/DMARC analysis, SMTP header injection
- **Added:** `skills/postmessage/` — postMessage source bypass, cross-origin data theft
- **Added:** `skills/webrtc-leak/` — Internal IP leaking, STUN/TURN enumeration
- **Added:** `skills/dependency-confusion/` — Private package name scanning, registry checks
- All 13 skills include `SKILL.md` + `SUMMARY.md` with OOB-first testing methodology

### Phase 3: Architecture Upgrades (NEW)
- **Added:** `tools/chain_automation.py` — Automated M9 chain synthesis (replaces manual Lead analysis)
- **Added:** `tools/fp_database.py` — False positive pattern database with confidence adjustment
- **Added:** `tools/model_router.py` — Pro vs Flash model routing based on task complexity
- **Added:** All existing testing skills updated with OOB-first Phase 1
- **Updated:** `lead_prompt.md` — Phase 0 coordination, Phase 3.5 exploitation dispatch, model routing

### Phase 4: False Positive Elimination
- **Added:** `tools/fp_database.py` — Historical FP tracking, per-vuln-type confidence adjustment
- **Added:** `tools/response_diff.py` — Automated signal vs noise validation
- **Updated:** All testing skills — Mandatory "Negative Verdict" gate phase
- **Updated:** `state.json` — `_fp_tracking` compatible with confidence calibration

### Phase 5: Mental Model Training
- **Added:** `knowledge/INDEX.md` — Knowledge base index with trust boundary principles
- **Added:** `knowledge/disclosed_reports/idor_patterns.md` — 6 IDOR patterns from real reports
- **Added:** `knowledge/disclosed_reports/ssrf_patterns.md` — 7 SSRF patterns with bounty amounts
- **Added:** `knowledge/disclosed_reports/chain_patterns.md` — 10 real chains with disclosed bounties ($5K-$110K)
- **Added:** `knowledge/triage_intelligence/h1_acceptance_patterns.md` — What H1 triagers actually accept/reject
- **Added:** `setup.sh` creates `knowledge/` directory structure

### Phase 6: Token Optimization
- **Added:** `tools/model_router.py` — Task complexity scoring → Pro (>=5) or Flash (<5)
- **Added:** 27 new `SUMMARY.md` files — 40-line quick-reference cards for all skills
- **Added:** Lead reads recon.json summary ONLY (~500 tokens) vs raw tool output (~5000 tokens)
- **Estimated savings:** 40-60% token reduction per engagement

### Summary: Framework Growth

| Metric | v3.2.0 | v4.0.0 | Change |
|--------|--------|--------|--------|
| Phases | 5 | 7 | +2 (Phase 0, Phase 3.5) |
| Skills | 32 | 45 | +13 new skills |
| Tools | 13 | 22 | +9 new tools |
| Python tools | 8 | 11 | +3 |
| Bash tools | 5 | 11 | +6 |
| Knowledge files | 0 | 5 | NEW |
| SUMMARY.md cards | 4 | 31 | +27 |
| Total files | ~144 | ~230 | +86 files |

---

## v3.2.0 — Operational Hardening & Intelligence (July 2026)

13 targeted improvements addressing reliability, efficiency, and intelligence gathering.
Zero architectural changes — fully backwards-compatible with v3.1 engagements.

### Improvement #1 — Pre-Dispatch Task Validation
**Added:** `tools/task_validator.py`
- Checks task file structure (required sections present, status is PENDING)
- Verifies all referenced files exist (skill files, endpoint profiles)
- Validates session freshness against `last_verified` timestamps
- Rejects tasks referencing already-tested hypotheses (prevents duplicate dispatch)
- Enforces mapping batch size limit (default: 5 endpoints max)
- Exit codes: 0=valid, 1=invalid (block dispatch), 2=warnings (review before dispatch)

**Updated:** `lead_prompt.md` — mandatory pre-dispatch validation step before every Worker task.

### Improvement #2 — Worker Result Quality Gates
**Added:** `tools/result_quality_gate.py`
- Validates result file structure against per-phase required sections schema
- Phase 3: requires HTTP evidence + clear CONFIRMED/NEGATIVE/PARTIAL verdict
- Phase 4: requires CVSS v3.1 vector string + poc/ evidence references
- State consistency check: compares state.json claims vs actual file counts
- Detects "Phase X COMPLETE" claims inconsistent with pending items in state.json

**Updated:** `lead_prompt.md` — quality gate runs after every Worker result, before state update.

### Improvement #3 — Hypothesis Deduplication and Pruning
**Added:** `tools/hypothesis_deduplicator.py`
- Reads all `EP-*.profile.yaml` files and extracts hypotheses
- Identifies same vuln_type + param across multiple endpoints → marks lower-priority as duplicates
- "Tested once, applies to similar" rule: confirmed vuln propagates to similar URL patterns
- Enforces `MAX_LOW_CONFIDENCE_PER_ENDPOINT = 3` cap on LOW hypotheses per endpoint
- Outputs `engagement/mapping/HYPOTHESIS-PRIORITY.md` with prioritized dispatch order
- `--mark-confirmed HYP-XXX --similar-endpoints EP-003,EP-007` propagates a confirmation

**Updated:** `lead_prompt.md` — deduplicator runs after mapping batches and after confirmations.

### Improvement #4 — Enhanced state.json with Concurrency Control
**Updated:** `state.json` schema v2.0.0 — new fields:
- `sessions[].last_verified` — ISO timestamp for session freshness tracking
- `_meta` — `last_updated_by`, `last_updated_at`, `schema_version`, `framework_version`
- `_concurrency` — `worker_active` bool, `active_task`, `task_started_at`, `last_completed_task`
- `_timeouts` — log of timed-out Worker tasks
- `testing.tested_hypothesis_ids` — array for dedup tracking

**Added:** `tools/state_manager.py` — CLI for all state operations.

### Improvement #5 — N/A (covered by parallel worker design in #4 + future roadmap)

### Improvement #6 — Automated Spider-to-Mapping Handoff
**Added:** `tools/spider_to_mapping_handoff.py`
- Reads `sitemap.json` + `hidden_endpoints.json` + `waf_fingerprint.json`
- Scores endpoints by priority (fuzzer-discovered, writable methods, high-value paths, ID params)
- Groups into configurable batches (default: 5 endpoints per batch)
- Generates `engagement/mapping/ENDPOINT-PRIORITY-LIST.md` with ready-to-copy task stubs
- Generates `engagement/mapping/endpoint_inventory.json` for machine-readable access
- **Saves ~5,000 Lead tokens per engagement** (Lead reads 1 priority list vs raw sitemap)

### Improvement #7 — Improved Skill File Loading Strategy
**Added:** Skill summary cards (`SUMMARY.md`) for major vuln skills:
- `skills/idor/SUMMARY.md` — IDOR workflow + key payloads + stop signals (~40 lines)
- `skills/sqli/SUMMARY.md` — SQLi detection order + WAF bypass checklist
- `skills/xss/SUMMARY.md` — context→payload map + WAF bypasses
- `skills/ssrf/SUMMARY.md` — probe order + URL bypass variants

**Updated:** `worker_prompt.md` — two-step skill loading: read SUMMARY.md first, load SKILL.md only if needed. Reference `techniques.md` sub-files only when workflow specifies it.

### Improvement #8 — Error Recovery and Retry Logic
**Updated:** `worker_prompt.md`:
- Explicit `Stop Condition` section in every result (type, retry recommended, retry guidance)
- Transient vs permanent failure classification (502/503 = retry; WAF block all variants = permanent)

**Updated:** `lead_prompt.md`:
- Decision algorithm handles `partial` with stop condition: transient → retry after 10min (max 2), permanent → skip + dispatch next
- Worker lock force-release on timeout via `state_manager.py`

**Updated:** `tools/state_manager.py`:
- `task-timeout --check` command detects stuck Workers
- Force-unlocks timed-out workers and logs to `state.json._timeouts`

### Improvement #9 — Finding Confidence Calibration
**Updated:** `state.json` — new `_confidence_calibration` section:
- `accuracy_by_confidence` — tracks `tested` + `confirmed` per HIGH/MEDIUM/LOW tier
- `accuracy_by_vuln_type` — tracks per vulnerability type

**Updated:** `lead_prompt.md` — Lead updates calibration stats after each confirmed/negative result.
Over time this enables data-driven confidence weighting per program and vuln type.

### Improvement #10 — External Intelligence Integration
**Added:** `tools/external_intel.py`
- **CVE checking:** Embedded curated CVE database for nginx, apache, express, Spring, Log4j, OpenSSL, Grafana, GitLab, and 10+ other products. Compares detected tech stack versions.
- **GitHub dorking:** API search for hardcoded secrets/credentials referencing the target domain. Uses `GITHUB_TOKEN` env var for higher rate limits.
- **Shodan lookup:** Exposed services on non-standard ports. Uses `SHODAN_API_KEY` env var.
- Outputs `engagement/spider/external_intel.md` + `engagement/spider/cve_matches.json`

**Updated:** `state.json` — `spider.external_intel` section tracks what was run.

### Improvement #11 — Token Budget Management
**Updated:** `state.json` — new `_token_budget` section with `context_limit`, `estimated_consumed`, `task_log`.
**Updated:** `_settings` — configurable `worker_timeout_minutes`, `session_expiry_hours`, `max_mapping_batch`, etc.

**Added:** `tools/state_manager.py` `token-budget` command:
- Pre-built token estimates per task type (phase_1, phase_2_per_endpoint, phase_3_per_hypothesis, m9_chain_synthesis, etc.)
- Warns at 80% consumed, blocks at 90% consumed

**Updated:** `lead_prompt.md` — token budget checked at startup and after every dispatch.

### Improvement #12 — N/A (skipped in original spec, numbered to match user's list)

### Improvement #13 — Multi-Target Support
**Added:** `tools/multi_target.py`
- `init --targets` — adds multiple domains to `state.json.targets` with auto-detected labels (api/admin/www/etc.)
- `spider-all` — generates parallel spidering bash commands for all targets
- `correlate` — cross-target correlation: JWT sharing, same ID formats, admin surface presence
- `status` — per-target spider/mapping/testing progress
- Creates target-specific output dirs: `engagement/spider/targets/<label>/`, `engagement/mapping/targets/<label>/`

### Files Changed
```
Modified:
  AGENTS.md                     → v3.2.0 docs, new tool table, extended lint section
  lead_prompt.md                → All 13 improvements integrated into decision algorithm
  worker_prompt.md              → Skill loading strategy, stop conditions, result format
  state.json                    → Schema v2.0.0 with all new fields

Added:
  tools/task_validator.py       → Improvement #1
  tools/result_quality_gate.py  → Improvement #2
  tools/hypothesis_deduplicator.py → Improvement #3
  tools/state_manager.py        → Improvements #4 + #8 + #11
  tools/spider_to_mapping_handoff.py → Improvement #6
  tools/external_intel.py       → Improvement #10
  tools/multi_target.py         → Improvement #13
  skills/idor/SUMMARY.md        → Improvement #7
  skills/sqli/SUMMARY.md        → Improvement #7
  skills/xss/SUMMARY.md         → Improvement #7
  skills/ssrf/SUMMARY.md        → Improvement #7
```

---

## v3.1 — Comprehension & Chaining (May 2026)

Additive augmentations to v3. No phase renames, no architectural changes. Designed to fix the "vulnerability with no impact" failure mode that produced rejected reports in earlier engagements.

### What Changed

#### New: Application Comprehension (Phase 1 augmentation)
**Added:** `tools/spider/spider_comprehension.sh` — companion to spider.sh
- Source map FULL recovery (reconstructs .ts/.tsx/.js from .map files into `understanding/sources/`)
- Webpack chunk enumeration (lazy-loaded chunks the entry bundle doesn't reference)
- Service worker analysis (`/sw.js`, `/service-worker.js` — often contain API route tables)
- `/.well-known/` probing (security.txt, openid-configuration, jwks.json, app-site-association)
- Swagger / OpenAPI / GraphQL introspection discovery
- CSP trusted-hosts extraction (third-party trust map for chain synthesis)
- Archive.org wayback enumeration (historical/removed endpoints)
- Outputs `engagement/spider/<auth>/understanding/` consumed by Phase 2

**Why:** spider.sh discovers endpoints. spider_comprehension.sh helps the agent understand what the application *does*. Without comprehension, mapping produces technically-correct findings with no business-impact framing.

**Updated:** `skills/recon/SKILL.md` — added Step 8 (Deep Application Comprehension) as mandatory before Phase 2.

#### New: Business-Context Analysis (Phase 2 augmentation, M2.5)
**Updated:** `skills/mapping/SKILL.md`
- Added M2.5 phase: every endpoint profile now includes `business_function`, `data_classification`, `trust_boundaries`
- Hypothesis generation now requires `impact_floor` (standalone severity ceiling) and `impact_ceiling` (with chain amplification)
- Hypotheses with both floor and ceiling at informational get `drop_unless_chain_found: true` — these don't burn Phase 3 testing budget unless M9 produces a chain that uses them

**Why:** the framework was generating "test for IDOR on /api/static/banner.png" because it had no concept of what an endpoint *was for*. With business_function classification, low-value endpoints get deprioritized and high-value ones get the deep treatment.

#### New: Chain Synthesis Skill (Phase 2 M9)
**Added:** `skills/chaining/` — 5 files, ~120KB
- `SKILL.md` — reasoning core: gadget mental model, 5-phase workflow (Inventory → Forward → Backward → Construct → Impact Model)
- `forward_patterns.md` — "I have primitive X, what amplifies it?" — catalog by gadget type
- `backward_patterns.md` — "I want impact Y, what primitives do I need?" — catalog by target impact
- `canonical_examples.md` — 18 real disclosed chains with citations (Meta $111,750 path traversal+DLL, Sam Curry's Starbucks BFF, Capital One SSRF→IMDS, OAuth+open-redirect, CORS→ATO patterns, etc.)
- `business_impact_mapping.md` — technical-to-business translation framework, anti-patterns, Cleartax-specific reframings

**Added M9 phase to mapping:** engagement-level chain synthesis runs after per-endpoint mapping completes. Lead (not Worker) holds the full inventory in context and runs the chaining skill. Produces `engagement/mapping/CHAIN-INVENTORY.md` and `engagement/mapping/CHAINS-NNN.hypothesis.md` files.

**Updated:** `lead_prompt.md` — added M9 instructions, smart-overlap rule extended to chain-aware priority

#### Updated: skills/index.md
- Registered `[[chaining]]` entry under Recon & Mapping section
- Updated `[[recon]]` and `[[mapping]]` descriptions to reflect new capabilities

### What Did NOT Change
- v3 phase architecture preserved (Spidering → Mapping → Testing → Validating → Reporting)
- No phase renames (Vaibhav's explicit direction: augment in place, no v4 branding)
- spider.sh untouched — augmentation is a separate companion script
- All 31 existing vulnerability skills unchanged
- state.json schema unchanged (chain hypotheses live in mapping/ output files)
- Smart overlap rule preserved (extended, not replaced)

### Migration

For existing engagements (e.g. Cleartax mid-flight):
- New EP-XXX.profile.yaml files will include the new fields; old ones are backward-compatible
- M9 can be run on the existing 19 mapped endpoints to identify chain opportunities for the 3 unsubmitted findings (FIND-301 CORS, FIND-306 PubNub, FIND-503 telemetry)
- `business_impact_mapping.md` contains Cleartax-specific reframings for those three findings — use before submission

---

## v3.0 — Phase-Based Rewrite (May 2026)

Major architectural rewrite from single-phase Lead-Worker to disciplined 5-phase workflow.

### What Changed

#### New: 5-Phase Architecture
Replaced the old "single recon → single test cycle → reports" pattern with disciplined phases:

```
Phase 1: SPIDERING    (tool-driven, no probing)
Phase 2: MAPPING      (skill-driven, per-endpoint deep analysis)
Phase 3: TESTING      (vuln-skill-driven, per-hypothesis)
Phase 4: VALIDATING   (reproduction-only, no skill needed)
Phase 5: REPORTING    (Lead-only, no Worker)
```

**Smart overlap rule:** Lead can dispatch Testing for an endpoint as soon as Mapping completes for THAT endpoint — even while other endpoints are still being mapped. This preserves parallelism within the 2-agent constraint.

#### New: Tool-Driven Spidering
**Added:** `tools/spider/spider.sh` — Master spider tool
- Crawls pages BFS with configurable max
- Extracts URLs from HTML (href, src, action)
- Parses JS files for endpoints (fetch, axios, string patterns)
- Checks for source maps (.map files) — gold mine for SPA targets
- Detects secret patterns (TYPE only, never values)
- Processes robots.txt and sitemap.xml
- Outputs structured `sitemap.json` (200-line agent input vs 5000+ lines of manual curl)

**Token savings:** ~92% reduction for Phase 1 work (the agent reads ONE JSON file instead of crawling manually).

#### New: Expanded CDP Browser Tool
**Added:** `tools/cdp_browser.py` — Chrome DevTools Protocol bridge
- `extract-cookies` (netscape/header/json formats)
- `capture-network` (record requests for N seconds while you click)
- `extract-links` (after JS render)
- `exec-js` (run arbitrary JavaScript in page context)
- `extract-storage` (localStorage + sessionStorage)
- `extract-forms` (forms + field structures)
- `screenshot` (PoC capture)
- `navigate` (drive browser to URLs)
- `auth-recon` (FULL authenticated recon: navigate + extract + network capture)

Previously had cookie extraction only. Now supports complete browser automation for SPAs and complex authenticated flows.

#### New: Mapping Skill (Phase 2)
**Added:** `skills/mapping/SKILL.md` — Per-endpoint deep analysis skill
- Phase M1: Baseline capture (auth + unauth + invalid)
- Phase M2: Parameter classification (DB_LOOKUP / DB_WRITE / DB_AUTH / API_PASSTHROUGH / CLIENT_ONLY / UNKNOWN)
- Phase M3: Authentication & authorization analysis
- Phase M4: Harmless probing (one probe per parameter)
- Phase M5: Reflection context analysis (three-probe XSS analysis)
- Phase M6: Passive findings capture (inline, no extra requests)
- Phase M7: Cross-endpoint signal detection
- Phase M8: Hypothesis generation (with HIGH/MEDIUM/LOW confidence)

Produces structured `EP-XXX.profile.yaml` per endpoint. The Lead reads profiles to dispatch surgical Testing tasks.

Modeled on the company's reference mapping pattern but adapted for our two-agent constraint.

#### Rewritten: Lead Prompt
**Replaced:** `lead_prompt.md` — Phase-based coordinator
- Explicit phase awareness (knows which phase each task belongs to)
- Per-phase dispatch templates
- Hypothesis prioritization scoring (Confidence × Impact × 1/Competition)
- Smart overlap rules (when to dispatch testing alongside mapping)
- Reporting phase (Lead-only, no Worker dispatch)
- Comprehensive state.json schema for engagement tracking

Token cost on startup: ~430 lines (up from ~210 in old version, but with much more capability)

#### Rewritten: Worker Prompt
**Replaced:** `worker_prompt.md` — Phase-aware executor
- Phase-specific execution patterns (different templates for Phase 1/2/3/4)
- Strict scope lock (one hypothesis, one batch, one finding)
- Output template per phase
- First-contact rule (no truncation on first URL access)
- Stop conditions (5+ 5xx errors, session expiry, WAF blocks)

Token cost per task: ~280 lines startup + 430-830 lines per task (task + skill + profile). Worker stays surgical.

#### Rewritten: Master Prompt
**Replaced:** `master_prompt.md` — Thinking foundation for both agents
- The Three Questions ("What is the developer ASSUMING?", trust boundaries, real impact)
- Internal monologue pattern
- Phase workflow overview
- Pointer to role-specific prompts

#### Rewritten: Recon Skill
**Replaced:** `skills/recon/SKILL.md` (old version saved as `SKILL.md.old`)
- Now focuses on Phase 1 tool orchestration only
- Removed manual crawling instructions (tool handles it)
- Removed probing/testing instructions (Phase 2/3 territory)
- Added explicit tool invocation patterns
- Common issues + solutions section

#### Rewritten: Operator Guide
**Replaced:** `OPERATOR_GUIDE.md` — Full step-by-step manual
- Complete workflow walkthrough
- Phase-by-phase operation
- Exact commands to type in Lead/Worker terminals
- Common situation handling
- Resume-next-day procedure
- Token budget breakdown
- Critical file locations
- Daily checklist

#### Rewritten: Setup Script
**Replaced:** `setup.sh` — Phase-aware engagement initialization
- Initializes state.json with phase-based schema
- Creates phase directories
- Verifies prerequisites (curl, python3, jq, websockets, chrome)
- Launches both Chrome sessions on ports 9222 (attacker) and 9223 (victim)
- Provides next-steps instructions

#### Rewritten: Task Templates
**Replaced:** `tasks/templates/README.md` — Task templates per phase
- Phase 1 spidering template
- Phase 2 mapping template (with cross-endpoint context fields)
- Phase 3 testing template (IDOR + SQLi examples)
- Phase 4 validating template
- Naming convention reference

#### Rewritten: State Schema
**Replaced:** `state.json` — Phase-based engagement state
- Per-phase status tracking (spider/mapping/testing/validating/reporting)
- Hypothesis tracking (total/tested/confirmed/negative)
- Cross-engagement context (blocked_chars, waf_observations, chains_identified)
- Session A/B tracking for two-account workflows

#### Updated: Skills Index
**Updated:** `skills/index.md` — Reflects phase architecture
- Maps each phase to relevant skills
- Adds mapping skill to category list
- Adds browser-sessions skill prominently

### What Stayed the Same

- All 29 vulnerability skills (idor, sqli, xss, ssrf, etc.) — these remain best-in-class
- `methodology.md` — testing philosophy is timeless
- `bug_bounty_master_methodology_lean.md` — reasoning patterns are universal
- `skill-gen-prompt.md` — meta-prompt for creating new skills
- `target_prompt.md` template structure
- `skills/browser-sessions/SKILL.md` — CDP usage from agent perspective
- `skills/report-writing/SKILL.md` — report standards
- File-based Lead-Worker communication pattern

### Migration Notes

If resuming an old engagement:
1. The old `state.json` schema is incompatible with v3
2. Old `engagement/` artifacts may need reorganizing into spider/mapping/findings/reports
3. Re-run `./setup.sh` to initialize fresh — old engagement data lives in engagement/

### Performance Comparison

| Aspect | v2 (Old) | v3 (Phase-Based) |
|--------|----------|------------------|
| Recon phase agent tokens | ~5,000 lines | ~200 lines (tool does work) |
| Mapping quality | Mixed with recon | Dedicated phase with structured profiles |
| Testing precision | Agent decides mid-stream | Lead dispatches per hypothesis |
| Chain detection | Often missed | Lead's job between phases 3-4 |
| Resume capability | Hard | state.json shows exact phase + queue |
| Worker per-task tokens | ~3,400 lines | ~430-830 lines (92% reduction) |

### Key Files Added

```
phases/
└── PHASE_ARCHITECTURE.md         (~13K, defines workflow)

tools/
├── spider/spider.sh              (~18K, master spider)
└── cdp_browser.py                (~20K, CDP automation)

skills/
└── mapping/SKILL.md              (~14K, per-endpoint analysis)

engagement/
└── README.md                     (~2K, structure reference)
```

### Key Files Rewritten

```
lead_prompt.md                    (~20K, phase-based coordinator)
worker_prompt.md                  (~13K, phase-aware executor)
master_prompt.md                  (~10K, thinking foundation)
OPERATOR_GUIDE.md                 (~18K, step-by-step manual)
USAGE.md                          (~3K, quick reference)
setup.sh                          (~7K, phase-aware init)
skills/recon/SKILL.md             (~13K, tool orchestration)
state.json                        (~1.3K, phase-based schema)
tasks/templates/README.md         (~9K, per-phase templates)
```

---

## v2.x — Lead/Worker Architecture (Previous)

Lead-Worker file-based communication. Single recon phase. Vulnerability skills for testing. Report writing skill. 29 vulnerability skills covering OWASP Top 10+ and beyond.

(Preserved in `skills/recon/SKILL.md.old` for reference.)
