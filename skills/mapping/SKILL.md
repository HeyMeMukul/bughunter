---
name: mapping
description: Per-endpoint deep analysis (M1-M8) plus cross-endpoint chain synthesis (M9). For each endpoint, produces a profile capturing business function, data classification, trust boundaries, parameter classification, harmless-probe signals, and hypotheses with impact floor/ceiling. After all per-endpoint profiles are complete, M9 invokes the [[chaining]] skill to build a gadget inventory and synthesize cross-endpoint chains that turn low-severity gadgets into paid critical findings. Use when Phase 1 spidering is complete.
---

# Mapping Skill — Per-Endpoint Intelligence Gathering

## What This Skill Is

You are the Mapping Worker. You receive ONE endpoint (or small group of related endpoints) from the Lead and produce a complete intelligence profile.

You map. You don't exploit. The distinction matters: an injection probe like `'` or `{{7*7}}` observes server behavior without accessing anyone's data — that is mapping. Changing `id=100` to `id=101` IS the attack itself — that is testing, not mapping.

## What You Produce

For EACH endpoint you map, write a YAML profile to:
```
engagement/mapping/<endpoint-id>.profile.yaml
```

The structure is fixed (see end of this skill). The Lead reads these profiles to dispatch Testing workers.

---

## Execution Sequence

Follow these phases in order. Do NOT skip phases. Do NOT add new phases.

### Phase M1: Baseline Capture (MANDATORY first)

Establish what NORMAL looks like for this endpoint. Every subsequent observation is compared to this baseline.

**Make 3 distinct baseline requests:**

1. **Valid authenticated request** (if endpoint requires auth)
   - Use session cookie from `state.json`
   - Use a known-valid parameter value (e.g., your own user_id)
   - Record: status, response size in bytes, response time, content-type, response summary (1 sentence)

2. **Valid UNAUTHENTICATED request** (always test this — even on "authenticated" endpoints)
   - Remove the session cookie
   - Same parameter values
   - Record: status, size, response summary
   - **This is THE most important baseline.** If an "authenticated" endpoint returns data unauthenticated, you've found a critical access control issue.

3. **Invalid input request**
   - Use a clearly invalid value (e.g., `id=99999999`)
   - Same auth state as #1
   - Record: status, size, response summary

**Save all three raw responses** to `engagement/mapping/<endpoint-id>/baseline_<type>.raw` for evidence.

### Phase M2: Parameter Discovery & Classification

For EVERY parameter the endpoint accepts:

1. **Identify ALL parameter locations:**
   - Path parameters (e.g., `/users/{id}`)
   - Query parameters (after `?`)
   - Body parameters (form-data, JSON, multipart)
   - Headers the application reads (e.g., `X-User-ID`, `X-Tenant-ID`)
   - Cookies (besides session)

2. **For each parameter, classify its DB interaction type:**
   
   | Type | When to assign |
   |------|----------------|
   | `DB_LOOKUP` | Response content changes meaningfully when value changes (search, fetch by ID, filter) |
   | `DB_WRITE` | Endpoint creates/updates/deletes records (form submit, profile update, comment post) |
   | `DB_AUTH` | Used in credential or session validation (username, password fields) |
   | `API_PASSTHROUGH` | Forwarded to a downstream service (microservice architecture indicators) |
   | `CLIENT_ONLY` | Used purely client-side (UI preferences, no response content change) |
   | `UNKNOWN` | Cannot determine — mark for closer inspection |

3. **For each parameter, record the pattern:**
   - `sequential` — integers that increment (1, 2, 3...)
   - `uuid` — UUID v4 format
   - `hash` — random-looking hex string
   - `enum` — fixed set of values (status: active/inactive/pending)
   - `freetext` — user-supplied strings
   - `numeric` — non-sequential numbers

4. **For each parameter, test if it echoes in the response:**
   - Send a unique marker like `MAPPROBE_<random>_TEST` as the value
   - Check response body for the marker
   - Record: `echoes_in_response: yes_html_body | yes_attribute | yes_js_string | yes_url | no`

### Phase M2.5: Business-Context Analysis (NEW — feeds chain synthesis)

Before classifying parameters technically, name what this endpoint **does** for the business. Most "vulnerabilities with no impact" exist because the worker mapped the endpoint technically but not functionally. The impact ceiling of any finding here depends on what the endpoint represents in the application's user flows.

Answer these three questions, all going into the profile:

1. **`business_function`**: what user flow does this endpoint participate in? Pick the most specific:
   - `auth.login`, `auth.signup`, `auth.password_reset`, `auth.mfa`, `auth.session_management`
   - `account.profile`, `account.email_change`, `account.deletion`, `account.preferences`
   - `payment.checkout`, `payment.refund`, `payment.subscription`, `payment.payout`
   - `kyc.identity_verification`, `kyc.document_upload`
   - `admin.user_management`, `admin.tenant_management`, `admin.audit`
   - `data.export`, `data.import`, `data.search`
   - `notification.delivery`, `notification.subscription`
   - `messaging.send`, `messaging.receive`
   - `file.upload`, `file.download`, `file.processing`
   - `integration.webhook`, `integration.oauth_callback`, `integration.sso`
   - `analytics.telemetry` (low-impact-by-default unless it drives operational decisions)
   - `static.content` (lowest impact bucket — informational only)
   - `unknown` — flag for Lead to clarify before continuing

2. **`data_classification`**: what category of data does this endpoint return or process? Pick all that apply:
   - `pii` — names, emails, phone numbers, addresses
   - `pii_sensitive` — government IDs, SSN, passport numbers, financial account numbers
   - `auth_material` — tokens, session IDs, password hashes, MFA seeds, recovery codes
   - `financial` — transactions, balances, payment methods
   - `health` — medical records, prescriptions (HIPAA scope)
   - `business_secrets` — internal pricing, customer lists, partner data
   - `metadata` — counts, aggregates, non-identifying stats
   - `public` — content intended to be publicly accessible
   - `none` — endpoint returns no data (write-only, side-effect-only)

3. **`trust_boundaries`**: who can call this endpoint and who can the call act on behalf of?
   - `caller_privilege`: `anonymous` | `user` | `verified_user` | `admin` | `service_account`
   - `acts_on`: `self` | `same_tenant` | `cross_tenant` | `system_wide`
   - `crossing_boundary`: does the endpoint cross a trust boundary? (e.g., anonymous endpoint reading authenticated data, user endpoint reading cross-tenant data) — `yes`/`no`

This data is what M9 (Chain Synthesis) consumes when building the gadget inventory. Without it, the agent cannot reason about impact ceilings — only about technical correctness.

**Rule:** if you cannot answer `business_function` from the response and the URL alone, you have not understood the endpoint. Re-read the response, check the spider's `understanding/` folder for source-map evidence of which feature uses this endpoint, and only proceed when you can name the business function.



This is where most critical bugs live. Test methodically:

1. **Does the endpoint enforce authentication?**
   - Compare authenticated baseline (M1.1) vs unauthenticated baseline (M1.2)
   - If unauthenticated returns same data → CRITICAL signal: `unauth_access_to_data`
   - If unauthenticated returns 401/403 → auth enforced
   - If unauthenticated returns different/partial data → note the differential

2. **What auth mechanism is used?**
   - Session cookie? Note the cookie name and format
   - Bearer token? Note token format (JWT? opaque? signed?)
   - API key in header? Note header name
   - Custom header? (`X-Auth-Token`, etc.)

3. **Does unauthenticated response leak ANY data?**
   - Sometimes 401/403 responses still leak via error messages
   - Sometimes the response body still contains structural information
   - Record: `unauth_leaks_data: yes/no` with description

### Phase M4: Harmless Probing

Send context-appropriate harmless probes to detect injection candidates. **One probe per parameter per probe type. No spraying.**

For each parameter, choose ONE primary probe type based on its DB classification:

| Param Context | Probe | What to Observe |
|---------------|-------|-----------------|
| `DB_LOOKUP` with integer | `abc` (string in numeric slot) | 500 error, DB error string, empty result |
| `DB_LOOKUP` with string | `a'` (single quote) | SQL syntax error, malformed-query response |
| `DB_WRITE` with string | `MAPPROBE_<random>` (unique marker) | Marker appears in subsequent reads = stored |
| `DB_AUTH` username | `nonexistentuser'` (single quote only — NOT `admin'--`) | Error differential vs unknown user |
| Reflected param | `MAPPROBE<>"'TEST` | Check which chars are encoded |
| URL param | `http://127.0.0.1/` | Internal request indication |
| File path | `....//....//etc/hostname` | File-read error or traversed path response |
| Template field | `{{7*7}}` or `${7*7}` | Response contains `49` = evaluated |
| OS command | `test;echo MAPPROBE_OK` | `MAPPROBE_OK` in response = executed |
| Redirect param | `?param=https://example.com` | 302 with example.com in Location |

**Record for each probe:**
- The probe sent
- Full response status and body excerpt (if differs from baseline)
- Whether evaluation evidence is present
- Result classification: `CONFIRMED_SIGNAL` | `POSSIBLE_SIGNAL` | `NO_SIGNAL` | `BLOCKED_BY_WAF`

### Phase M5: Reflection Context Analysis (for echoing params)

If a parameter echoes in the response, run the **three-probe XSS reflection analysis**:

**Probe 1 — Plain reflection:** Send `MAPPROBE123`. Does it appear?
- No → mark `NOT_REFLECTED`, skip Probes 2 and 3
- Yes → proceed

**Probe 2 — Special character encoding:** Send `MAP<>"'&TEST`
- Record exactly how each character is rendered
- Classify: `UNENCODED` | `HTML_ENCODED` | `URL_ENCODED` | `STRIPPED` | `PARTIAL_ENCODE`

**Probe 3 — Context breakout:**
Based on WHERE the input appears, send a context-specific probe:
- HTML body context: `<b>BOLDTEST</b>` — does `<b>` render?
- Attribute context: `" onmouseover="alert(1)` — does attribute close?
- JS string context: `';alert(1)//` — does string close?
- URL/href context: `javascript:void` — appears in href?

Record: what was sent, exact response excerpt, whether breakout succeeded.

### Phase M6: Passive Findings Capture

While doing M1-M5, capture these **inline** (no extra requests needed):

**From response headers:**
- `Content-Security-Policy` — missing or weak (unsafe-inline, unsafe-eval, wildcards)
- `Strict-Transport-Security` — missing on HTTPS or max-age too short
- `X-Frame-Options` — missing or weak
- `X-Content-Type-Options` — missing nosniff
- `Set-Cookie` — missing HttpOnly/Secure/SameSite on session cookies
- `Access-Control-Allow-Origin` — wildcard or origin reflection
- `Cache-Control` — missing no-store on sensitive responses
- `Server` / `X-Powered-By` — version disclosure

**From response body:**
- Stack traces or framework error pages
- Internal file paths in error messages
- Hardcoded secrets visible in HTML
- Sensitive data in unexpected places

**From cookie attributes:**
- Session cookie without HttpOnly → XSS escalation risk
- Session cookie without Secure on HTTPS → MITM risk
- Session cookie SameSite=None without Secure → invalid config

### Phase M7: Cross-Endpoint Signal Detection

Compare this endpoint's findings to others already mapped:

1. **Does this endpoint reveal information another endpoint needs?**
   - User IDs, internal UUIDs, resource identifiers in this response that could chain into IDOR elsewhere
   
2. **Does this endpoint share a pattern with another?**
   - Same auth mechanism, same parameter naming, same response structure
   - If one was vulnerable, this one likely is too

3. **Are there state-changing operations that could chain?**
   - Profile update → if reflected somewhere → stored XSS
   - File upload → if served back → various

Record cross-endpoint observations in the profile's `cross_endpoint_signals` section.

### Phase M8: Hypothesis Generation

Now you have all the data. Generate hypotheses for this endpoint with **confidence levels**.

**Confidence rules:**
- `HIGH`: Direct evidence (SQL error, eval'd template, echo with breakout, unauth data exposure)
- `MEDIUM`: Strong indicators (DB-backed param, sequential IDs, encoded reflection, sensitive feature)
- `LOW`: Coverage hypothesis (parameter type warrants checking even without specific signal)

**Generate hypotheses for:**
- Every `DB_LOOKUP/DB_WRITE/DB_AUTH/API_PASSTHROUGH/UNKNOWN` param → SQLi hypothesis
- Every parameter that echoes (anything but `NOT_REFLECTED`) → XSS hypothesis
- Every sequential/predictable ID + auth-required endpoint → IDOR hypothesis
- Every URL-accepting param → SSRF hypothesis
- Every file-path param → Path Traversal hypothesis
- Every template-rendered field → SSTI hypothesis
- Every state-changing POST without CSRF token → CSRF hypothesis
- Every auth endpoint → auth bypass hypotheses
- Every unauth_access_to_data signal → Broken Access Control (CRITICAL)

**Each hypothesis must specify:**
- vuln class + endpoint + specific input vector (not "test for IDOR" — "IDOR on `id` (path param) at GET /users/{id}")
- Evidence observed (what you saw that supports it)
- Confidence (HIGH/MEDIUM/LOW)
- Suggested skill file (from skills/)
- **`impact_floor`** — what triage will accept if this hypothesis is confirmed *standalone*. Map from `business_function` + `data_classification`:
  - `auth_material` returned + `crossing_boundary: yes` → floor is `critical` (auth bypass / ATO direct)
  - `pii_sensitive` returned + `acts_on: cross_tenant` → floor is `high`
  - `pii` returned + `acts_on: cross_tenant` → floor is `high`
  - `pii` returned + `acts_on: same_tenant` → floor is `medium`
  - `metadata` or `public` only → floor is `low` or `informational`
- **`impact_ceiling`** — what this hypothesis could become if chained with other gadgets in the engagement. If unclear, write `to_be_determined_at_M9`. Examples:
  - Self-XSS hypothesis with `auth_material` in `localStorage` (from spider understanding/) → ceiling is `critical` (ATO via login CSRF chain)
  - Open redirect on a domain that has an OAuth flow → ceiling is `critical` (token theft via redirect_uri bypass)
  - CORS reflection on an endpoint returning `auth_material` → ceiling is `critical` (cross-origin token read)

**Hypotheses with `impact_floor: informational` AND `impact_ceiling: informational` should be marked `drop_unless_chain_found: true`.** These get re-examined at M9. Most "no-impact" findings the framework currently produces fall into this bucket — they should not be dispatched to Phase 3 testing on their own.

---

## Phase M9: Cross-Endpoint Chain Synthesis (ENGAGEMENT-LEVEL — runs ONCE after all M1-M8 complete)

**This phase is different.** M1-M8 are per-endpoint and run for every endpoint independently. M9 runs **once per engagement**, by the Lead, after every dispatched endpoint has a profile file. It synthesizes chains across the entire profile set.

### When M9 runs

- All M1-M8 worker dispatches have completed
- Every endpoint in `engagement/spider/auth/sitemap.json` has a corresponding `engagement/mapping/EP-XXX.profile.yaml`
- No `mapping_status: in_progress` profiles remain
- BEFORE any Phase 3 (Testing) dispatch

If Phase 3 testing has already started for some high-confidence single-endpoint hypotheses, that's fine — M9 runs in parallel and produces additional chain hypotheses that Phase 3 picks up next.

### How M9 runs

The Lead (not a Worker) loads `skills/chaining/SKILL.md` and follows its 5-phase workflow:

1. **Gadget Inventory** — scan every EP-XXX.profile.yaml for gadgets matching the catalog in `skills/chaining/SKILL.md` Phase 1. Write `engagement/mapping/CHAIN-INVENTORY.md`.
2. **Forward Synthesis** — for each gadget, walk `skills/chaining/forward_patterns.md` to find amplifiers present in inventory. Produces candidate chains.
3. **Backward Synthesis** — for each Critical/High impact category the program pays for, walk `skills/chaining/backward_patterns.md` to identify required primitive sets. Search inventory for matches.
4. **Chain Construction** — write each viable chain as `engagement/mapping/CHAINS-NNN.hypothesis.md`. Apply priority scoring formula.
5. **Impact Modeling** — for each chain, write the business-impact statement using `skills/chaining/business_impact_mapping.md` templates. Done before any Phase 3 dispatch.

### M9 outputs

- `engagement/mapping/CHAIN-INVENTORY.md` — gadget catalog with G-XXX IDs referencing source EP-XXX profiles
- `engagement/mapping/CHAINS-NNN.hypothesis.md` — one file per chain hypothesis, with priority score and components
- (optional) `engagement/mapping/CHAIN-GAPS.md` — list of primitive gaps that, if probed, would unlock additional chains. Becomes new mapping tasks to dispatch back to Workers.

### M9 stop conditions

- All `impact_floor: critical|high` hypotheses (single-endpoint) plus all chain hypotheses scored above the priority threshold (typically 12 per the chaining skill formula) are documented
- Remaining inventory has been examined for chain-gap probes; gap-probe tasks dispatched if any high-value chains are one primitive away

### Smart-overlap rule still applies

Once M9 produces chain hypotheses, individual chains can be dispatched to Phase 3 immediately — no need to wait for all chains to be enumerated. The Lead picks the highest-priority chain, dispatches it, and continues M9 work in parallel.



### What You DO
- Send harmless probes (markers, structurally-meaningful inputs that don't access others' data)
- Baseline every endpoint with auth and unauth variants
- Classify every parameter
- Detect signals and generate hypotheses
- Capture passive findings inline

### What You DON'T Do
- Don't change identifier VALUES (no `id=100` → `id=101` testing — that's Testing's job)
- Don't bruteforce paths (no gobuster, no ffuf — Spider tool handles discovery)
- Don't run vulnerability scanners (no nikto, no nuclei, no sqlmap)
- Don't "explore other endpoints" — stick to your assigned endpoint(s)
- Don't exploit findings — generate hypotheses for Testing workers

### Scope Lock
You receive ONE endpoint (or small group). You map that endpoint completely. If you discover signals for OTHER endpoints, note them in `cross_endpoint_signals` and let the Lead decide. Do NOT go map other endpoints on your own initiative.

### Stop Conditions
- Application returns 5+ consecutive 5xx errors → STOP, mark as `operational_halt`
- Session expires mid-mapping → STOP, request fresh session from Lead
- WAF blocks all probes → mark as `waf_blocked`, complete the profile with what you have, suggest WAF bypass testing

---

## Output Format (CRITICAL)

Write the profile to `engagement/mapping/<endpoint-id>.profile.yaml`. Use this EXACT structure:

```yaml
endpoint_id: EP-001
url: /api/users/{id}
methods_observed: [GET, PUT, DELETE]
mapped_at: "2026-05-13T10:30:00Z"

business_context:                           # NEW — feeds chain synthesis (M9)
  business_function: account.profile
  data_classification: [pii, auth_material]
  trust_boundaries:
    caller_privilege: user
    acts_on: self                           # vs same_tenant, cross_tenant, system_wide
    crossing_boundary: no                   # set yes if endpoint crosses a trust boundary
  worst_case_realistic: "Reading another user's full profile (PII + recovery email) enables targeted phishing and account recovery attacks."

baseline:
  valid_authenticated:
    status: 200
    size_bytes: 1247
    response_summary: "Returns user object with email, name, role"
    content_type: "application/json"
  valid_unauthenticated:
    status: 401
    size_bytes: 87
    response_summary: "Unauthorized error"
  invalid_id:
    status: 404
    size_bytes: 56
    response_summary: "Not found"

parameters:
  - name: id
    location: path
    type: integer
    pattern: sequential
    db_classification: DB_LOOKUP
    echoes_in_response: no
    probe_results:
      string_in_numeric_slot:
        probe: "abc"
        result: "500 with PG::InvalidTextRepresentation error"
        classification: CONFIRMED_SIGNAL
        evidence: "Stack trace exposed PostgreSQL backend"
  
  - name: fields
    location: query
    type: string
    pattern: enum
    db_classification: CLIENT_ONLY
    echoes_in_response: yes_html_body
    reflection_analysis:
      probe1: "MAPPROBE123 appeared verbatim"
      probe2: "MAP<>\"'&TEST appeared with all chars HTML-encoded"
      probe2_classification: HTML_ENCODED
      probe3: "<b>BOLDTEST</b> rendered as literal text"
      breakout_succeeded: false

auth_analysis:
  endpoint_enforces_auth: true
  auth_mechanism: "JSESSIONID cookie"
  unauth_response_status: 401
  unauth_leaks_data: false
  unauth_response_size: 87

signals_detected:
  - signal: "sequential_integer_id"
    confidence: HIGH
    implies: IDOR_candidate
    evidence: "id increments by 1 across visible users"
  
  - signal: "PII_in_response"
    confidence: HIGH
    implies: impact_multiplier_for_IDOR
    evidence: "Response contains email, phone, full_name fields"
  
  - signal: "SQL_error_disclosure"
    confidence: HIGH
    implies: SQLi_candidate
    evidence: "PostgreSQL error visible in 500 response to type-mismatch probe"

passive_findings:
  - finding: "Cache-Control missing on PII response"
    severity: low
    evidence: "GET /api/users/5 response has no Cache-Control header"
  - finding: "Server header discloses version"
    severity: info
    evidence: "Server: nginx/1.18.0"

cross_endpoint_signals:
  related_endpoints: ["EP-005", "EP-012"]
  observations:
    - "EP-012 (/api/search) returns user UUIDs - could chain into IDOR here"
    - "EP-005 uses same JSESSIONID format - auth model is consistent"
  potential_chains:
    - "If EP-005 (search) leaks UUIDs and this endpoint accepts UUIDs, chain is possible"

hypotheses_generated:
  - id: HYP-001
    type: IDOR
    target: "id (path param) at GET /api/users/{id}"
    confidence: HIGH
    rationale: "Sequential integer ID + PII response + auth enforced (so cross-user access = critical)"
    suggested_skill: "skills/idor/SKILL.md"
    priority: P1
    impact_floor: high                       # NEW — confirmed standalone gets this
    impact_ceiling: critical                 # NEW — if chained with mass assignment / cross-tenant
    drop_unless_chain_found: false
  
  - id: HYP-002
    type: SQL_Injection
    target: "id (path param) at GET /api/users/{id}"
    confidence: HIGH
    rationale: "Type mismatch triggered PostgreSQL error - parameterized queries questionable"
    suggested_skill: "skills/sqli/SKILL.md"
    priority: P1
    impact_floor: critical
    impact_ceiling: critical
    drop_unless_chain_found: false
  
  - id: HYP-003
    type: IDOR
    target: "id (path param) at PUT /api/users/{id}"
    confidence: HIGH
    rationale: "Write IDOR has higher impact than read IDOR - test PUT method"
    suggested_skill: "skills/idor/SKILL.md"
    priority: P1
    impact_floor: high
    impact_ceiling: critical                 # If mass assignment + write IDOR → role escalation
    drop_unless_chain_found: false

mapping_status: complete
mapping_notes: "Endpoint thoroughly mapped. HIGH priority for testing due to PII + sequential IDs."
```

---

## Quick Reference: What Goes Where

| Observation | Profile Field |
|------------|---------------|
| HTTP status of normal request | `baseline.valid_authenticated.status` |
| What param type expects | `parameters[].type` |
| Whether endpoint needs auth | `auth_analysis.endpoint_enforces_auth` |
| SQL error in response | `signals_detected` + hypothesis |
| Missing CSP header | `passive_findings` |
| Sequential IDs observed | `signals_detected` |
| Marker echoed in response | `parameters[].reflection_analysis` |
| User UUIDs visible in another endpoint | `cross_endpoint_signals.observations` |
| Test for IDOR planned | `hypotheses_generated` |

---

## Time Budget

Mapping ONE endpoint typically takes:
- M1 (Baseline): 3 requests, 1-2 min
- M2 (Param classification): 1 request per param + 1 echo test, 2-3 min
- M2.5 (Business context): Reasoning from baseline + spider understanding/, 1-2 min
- M3 (Auth analysis): Uses M1 data, 30 sec
- M4 (Harmless probing): 1 probe per param, 3-5 min
- M5 (Reflection if applicable): 3 probes per reflecting param, 2-3 min per
- M6 (Passive findings): Zero extra requests, just record from M1-M5 responses
- M7 (Cross-endpoint): Comparison thinking, 1 min
- M8 (Hypotheses with impact floor/ceiling): 2-3 min to generate and write

**Total per endpoint: ~12-22 minutes of focused work.**

For an endpoint with no parameters and no echoing, mapping is fast (5-7 min).
For a complex endpoint with 10 parameters, mapping is thorough (30+ min) but produces deep intelligence.

**M9 (Chain Synthesis) is engagement-level, not per-endpoint:** Lead runs M9 ONCE after all per-endpoint profiles complete. Typical M9 effort: 30-60 minutes for a 20-50 endpoint engagement, producing 3-10 chain hypotheses. This is the highest-ROI hour in the entire framework — it converts the "low-impact gadget" findings the framework used to produce into the chained criticals it now produces.

---

## Cross-Skill Links

- [[chaining]] — Loaded by Lead at M9 (engagement-level). Builds gadget inventory from EP-XXX.profile.yaml files, synthesizes forward and backward chains, writes CHAINS-NNN.hypothesis.md files. The reason `business_context` and `impact_floor`/`impact_ceiling` fields exist in this skill's output.
- [[recon]] — Phase 1 predecessor. Worker reads `engagement/spider/auth/sitemap.json` AND `engagement/spider/understanding/` to identify endpoints to map. The `understanding/` folder informs M2.5 business-context analysis.
- [[idor]], [[sqli]], [[xss]], [[ssrf]], [[cors]], [[idor]], [[mass-assignment]], [[oauth]], etc. — Vulnerability skills loaded in Phase 3 based on hypotheses this skill generates.
