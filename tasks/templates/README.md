# Task Templates — Phase-Based Framework

Templates the Lead uses to dispatch tasks. Copy the relevant template, fill in specifics, save to `tasks/task-NNN-description.md`.

---

## Phase 1 — Spidering Template

```markdown
# Task NNN — Phase 1: Spidering

## Status: PENDING
## Phase: 1 (Spidering)
## Worker Role: Tool Runner

## Objective
Run the spider tool to discover the attack surface. Both unauthenticated and authenticated.

## Commands to Run (in order)

### 1. Extract cookies from CDP (if logged in to Chrome)
```bash
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/spider/cookies_a.txt --format header

python3 ./tools/cdp_browser.py extract-cookies --port 9223 \
    --output engagement/spider/cookies_b.txt --format header
```

### 2. Unauthenticated spider
```bash
./tools/spider/spider.sh "<target-url>" \
    --header "X-HackerOne-Handle: <username>" \
    --output-dir engagement/spider/unauth
```

### 3. Authenticated spider (Session A)
```bash
COOKIE=$(cat engagement/spider/cookies_a.txt)
./tools/spider/spider.sh "<target-url>" \
    --auth-cookie "$COOKIE" \
    --header "X-HackerOne-Handle: <username>" \
    --output-dir engagement/spider/auth
```

### 4. CDP authenticated recon (for SPA coverage)
```bash
python3 ./tools/cdp_browser.py auth-recon --port 9222 \
    --base-url "<target-url>" \
    --max-pages 30 \
    --output-dir engagement/spider/cdp_recon
```

## What to Report
Write a brief result to `results/result-NNN-spider.md`:
- Sitemap paths created
- Endpoint counts (unauth vs auth)
- Source maps found
- Secret pattern types detected
- Interesting paths from robots.txt
- Any errors encountered

Do NOT analyze the sitemap content. Lead will do that.
```

---

## Phase 2 — Mapping Template

```markdown
# Task NNN — Phase 2: Mapping (Batch X)

## Status: PENDING
## Phase: 2 (Mapping)
## Worker Role: Mapper

## Objective
Map these endpoints using `skills/mapping/SKILL.md`. Produce intelligence profiles.

## Endpoints to Map

### EP-XXX: <method> <path>
- Discovered from: <source>
- Parameters: <list>
- Priority rationale: <why this endpoint warrants mapping>

### EP-YYY: <method> <path>
...

(Map 3-5 endpoints per batch)

## Credentials
- Session A (attacker) cookie: see `engagement/spider/cookies_a.txt`
- Session B (victim) cookie: see `engagement/spider/cookies_b.txt`
- Mandatory header: X-HackerOne-Handle: <username>

## Context

### Already-Mapped Endpoints (for cross-endpoint signal detection)
- EP-001 (POST /api/login) — see `engagement/mapping/EP-001.profile.yaml`
- EP-002 (GET /api/me) — see `engagement/mapping/EP-002.profile.yaml`

### Known WAF Behavior
- <from state.json if any>

### Known Blocked Characters
- <from state.json if any>

## Skill File
Load: `skills/mapping/SKILL.md`
Execute: All phases M1-M8 for EACH endpoint above.

## Time Budget
~10-20 minutes per endpoint. If you exceed 30 min on one endpoint, move to the next.

## What to Report
For each endpoint:
1. Write profile to `engagement/mapping/EP-XXX.profile.yaml` per skill format
2. Save baseline responses to `engagement/mapping/EP-XXX/baseline_*.raw`

After all endpoints in this batch are mapped, write `results/result-NNN-mapping.md`:
- Endpoints mapped (count, list)
- HIGH confidence hypotheses generated (with IDs and rationale)
- Cross-endpoint observations (potential chains)
- Aggregate passive findings
- Any operational issues
```

---

## Phase 3 — Testing Template (IDOR Example)

```markdown
# Task NNN — Phase 3: Testing HYP-XXX

## Status: PENDING
## Phase: 3 (Testing)
## Hypothesis: HYP-XXX

## Hypothesis Details
**Type:** IDOR
**Target:** `id` (path param) at GET /api/users/{id}
**Endpoint Profile:** `engagement/mapping/EP-003.profile.yaml`
**Confidence (from mapping):** HIGH
**Priority Score:** P1

## Key Facts from Mapping Profile (already established)
- Authenticated baseline: 200, 1247 bytes, returns PII
- Unauthenticated: 401 (auth enforced)
- ID pattern: sequential integer (visible IDs: 100, 101, 102)
- Your user_id (Session A): 100
- Test target user_id (Session B): 101

DO NOT re-baseline these. Use the profile data.

## Credentials
- Session A (attacker): `engagement/spider/cookies_a.txt`
- Session B (victim): `engagement/spider/cookies_b.txt`
- Mandatory header: X-HackerOne-Handle: <username>

## Skill File
Load: `skills/idor/SKILL.md`
Execute: Phase 1 (Baseline using profile data) + Phase 2 (Confirmation)
If HIGH confidence after Phase 2 → proceed to Phase 3 (Exploitation), demonstrate ONE example only

## Test ONLY This Hypothesis
- DO NOT test other vulnerabilities on this endpoint
- DO NOT explore other endpoints
- If you see signals for other hypotheses → note in `incidental_signals` section
- Stay scope-locked

## What to Report
Write to: `engagement/findings/HYP-XXX.<status>.md`
Where <status> is: `confirmed` | `negative` | `partial`

Use the Phase 3 result template from `worker_prompt.md`.
Include:
- Status and confidence
- Exact request/response evidence (REDACT real user data)
- Skill phases executed
- Verdict
- Incidental signals (if any)
- State updates needed
```

---

## Phase 3 — Testing Template (SQLi Example)

```markdown
# Task NNN — Phase 3: Testing HYP-XXX (SQLi)

## Status: PENDING
## Phase: 3 (Testing)
## Hypothesis: HYP-XXX

## Hypothesis Details
**Type:** SQL Injection
**Target:** `id` (path param) at GET /api/users/{id}
**Endpoint Profile:** `engagement/mapping/EP-003.profile.yaml`
**Confidence (from mapping):** HIGH
**Evidence from mapping:** Type-mismatch probe `abc` triggered `PG::InvalidTextRepresentation` error

## Key Context
- Database: PostgreSQL (confirmed via error)
- Auth required: yes
- Session: `engagement/spider/cookies_a.txt`

## Skill File
Load: `skills/sqli/SKILL.md`
Execute: Phase 1 (Confirmation) + Phase 2 (Type Detection) + Phase 3 (Exploitation)
If filter detected → also load `skills/sqli/filter_bypass.md`

## Test ONLY SQLi on This Parameter
Don't test other parameters on this endpoint. Don't pivot to other endpoints.

## What to Report
Write to: `engagement/findings/HYP-XXX.<status>.md`
Include:
- Exact payloads used and responses
- Type of SQLi confirmed (boolean blind, time-based, UNION, etc.)
- Database fingerprinting
- ONE example of data extraction (don't dump full DB — Lead decides if more needed)
- Stop conditions encountered
```

---

## Phase 4 — Validating Template

```markdown
# Task NNN — Phase 4: Validating FIND-XXX

## Status: PENDING
## Phase: 4 (Validating)
## Finding to Validate: FIND-XXX

## Original Finding
File: `engagement/findings/HYP-XXX.confirmed.md`

## Objective
Re-confirm this finding with FRESH session. Capture clean evidence. Calculate CVSS.

## Step 1: Refresh Session
Cookies may have expired since testing. Extract fresh:
```bash
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/findings/FIND-XXX/fresh_cookies.txt --format header
```

If browser session also expired, the operator needs to manually re-login first.

## Step 2: Follow Reproduction Steps EXACTLY
Use the reproduction steps from `HYP-XXX.confirmed.md`. Do NOT improvise or modify.

If reproduction fails:
- Mark as `validation_failed`
- Document what differed
- Do NOT try to fix or extend — Lead will investigate

## Step 3: Capture Evidence
For each step:
- Save exact HTTP request to: `engagement/findings/FIND-XXX/poc/step_N_request.txt`
- Save exact HTTP response to: `engagement/findings/FIND-XXX/poc/step_N_response.txt`

Redact real user data with `[REDACTED]` placeholders. Test account data is fine to keep.

## Step 4: Calculate CVSS v3.1
Use the standard calculator. Document the vector string and reasoning for each metric.

## Step 5: Impact Analysis
Document:
- What can an attacker actually DO with this finding?
- How many users/records affected (estimate)?
- Business consequence
- Worst-case exploitation scenario

## Step 6: Chain Check
Read all other confirmed findings. Could this be chained with another?
If yes → document the chain.

## What to Report
Write to: `engagement/findings/FIND-XXX.validated.md`

Use the Phase 4 result template from `worker_prompt.md`.
Include CVSS, reproduction steps, evidence files, impact analysis, chain potential.
```

---

## Phase 5 — Reporting (Lead-Only)

Phase 5 is handled by the Lead directly. No Worker task is dispatched. The Lead:
1. Reads `engagement/findings/FIND-XXX.validated.md`
2. Reads `skills/report-writing/SKILL.md`
3. Reads `target_prompt.md` for program-specific format
4. Writes report to `engagement/reports/<finding-slug>.report.md`

See `lead_prompt.md` for reporting standards.

---

## Generic Task Structure

Every task file follows this structure:

```markdown
# Task NNN — <Phase>: <Short Description>

## Status: PENDING | IN_PROGRESS | COMPLETE
## Phase: <1-5>
## Worker Role: <Tool Runner | Mapper | Tester | Validator>

## Objective
<One sentence on what the task accomplishes>

## Context
<Everything the Worker needs:>
- Relevant profile files
- Credentials
- Prior findings/observations
- Skill file references
- Output paths

## Instructions
<Specific steps to execute>

## What to Report
<Output file path and structure>

## Scope Lock
<Reminder of what NOT to do — one hypothesis, one endpoint, etc.>
```

---

## Naming Convention

Task files:
```
tasks/task-001-spider.md
tasks/task-002-mapping-batch-1.md
tasks/task-003-mapping-batch-2.md
tasks/task-004-test-hyp-007-idor-users.md
tasks/task-005-test-hyp-008-sqli-users.md
tasks/task-006-validate-find-001.md
tasks/task-007-mapping-batch-3.md  # smart overlap — continue mapping
```

Result files mirror task numbers:
```
results/result-001-spider.md
results/result-002-mapping-batch-1.md
...
```

Engagement output files use semantic names:
```
engagement/mapping/EP-003.profile.yaml
engagement/findings/HYP-007.confirmed.md
engagement/findings/FIND-001.validated.md
engagement/reports/idor-users-endpoint.report.md
```
