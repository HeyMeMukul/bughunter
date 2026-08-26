#---
name: ldap-injection-pentesting
description: Professional LDAP Injection testing methodology. Use when testing parameters that interact with LDAP directories — login forms, search fields, user lookups, directory queries. Provides systematic baseline establishment, injection confirmation with confidence scoring, context classification, and exploitation routing. Focuses on distinguishing real signal from noise and knowing when to stop.
---

# LDAP Injection Pentesting

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (5 samples)   (probes+classify)  (declare secure)     (use guides)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

**Goal:** Understand normal behavior before touching anything injectable.

### Process

Test the parameter with 5 legitimate values — mix of valid and invalid:

```
Param: [name], Context: [login / search / lookup]

Valid value (e.g., username=alice, search=john):
  Time:    [avg]ms ±[stddev]ms
  Length:  [bytes] ±[variance]
  Status:  [HTTP code]
  Pattern: [e.g., "login success", "3 results returned", "profile rendered"]

Invalid value (e.g., username=ZZZNOTAUSER, search=XYZXYZXYZ):
  Time:    [avg]ms ±[stddev]ms
  Length:  [bytes] ±[variance]
  Status:  [HTTP code]
  Pattern: [e.g., "invalid credentials", "no results", "user not found"]
```

**Why both valid and invalid:** LDAP injection typically works by forcing filters to evaluate TRUE regardless of what the actual value is. You need both poles of behavior to detect manipulation.

**Comparison thresholds:**
- Time: ±50ms = same, >100ms = different, >500ms = significant
- Length: ±2% = same, >5% = different, >20% = significant
- Content: semantic comparison matters more than raw bytes

**Re-baseline if:** Session changes, caching detected, response patterns shift mid-test.

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[PARAM]    {name}, [CONTEXT] {login / search / lookup}
[VALID]    Time: {avg}ms, Length: {bytes}, Pattern: {description}
[INVALID]  Time: {avg}ms, Length: {bytes}, Pattern: {description}
[LDAP-SIGNALS] {error strings / response patterns / none observed}
[DECISION] {Proceed to Phase 2 / Re-baseline needed}
```

---

## Phase 2: Confirmation — Injection Verification & Context Classification

**Goal:** Verify LDAP injection with HIGH confidence and classify the injection context (auth vs search, in-band vs blind) to route to the correct exploitation path.

**Confidence levels:**
- HIGH: 3/3 tests consistent → proceed ✓
- MEDIUM: 2/3 consistent → retest before proceeding
- LOW: Inconsistent → try a different approach

**Attempt limits:**
- Max 5 payload variations per injection technique
- Total max: 15 requests before concluding no boolean signal
- If no boolean signal after 15 requests → skip to Step 2.4 (blind timing)

### Step 2.1: Special Character Probe

Send LDAP metacharacters individually. Each sent in isolation, compared against both baselines:

```
Test 1: param=*              → wildcard — may return all/many entries
Test 2: param=)              → closes filter — may cause parse error
Test 3: param=(              → opens filter — may cause parse error
Test 4: param=\              → escape char — may cause error or be stripped
Test 5: param=)(objectClass= → filter escape attempt — behavioral shift?
```

| Result | Interpretation |
|--------|---------------|
| Response changes vs invalid baseline | Metacharacter processed — signal |
| Error message leaks LDAP syntax | LDAP parsing exposed — HIGH signal |
| Response unchanged across all tests | Characters may be filtered |
| HTTP 400/500 on specific chars only | Selective processing — MEDIUM signal |

### Step 2.2: Boolean Logic Test — Login Context

Inject filter logic that should produce unconditionally true results:

```
TRUE condition (should behave like a valid login):
  username=*)(objectClass=*        password=[anything]
  username=admin)(|(cn=*           password=[anything]

FALSE condition (control — should behave like invalid):
  username=ZZZNOTAUSER             password=[anything]
```

Run TRUE condition 3 times. If it produces a login-like response when the baseline invalid does not → **HIGH confidence**.

### Step 2.3: Boolean Logic Test — Search Context

Inject filter logic that toggles between all-results and no-results:

```
TRUE (wildcard — should return results):
  param=*

TRUE-scoped (should return entry if exists):
  param=admin)(|(objectClass=*)(objectClass=XXXXXXINVALID

FALSE (logically impossible match):
  param=admin)(|(objectClass=XXXXXXINVALID)(objectClass=YYYYY
```

- TRUE matches valid baseline → FALSE matches invalid baseline → **HIGH confidence**
- Wildcard `*` returns significantly more results than single lookup → **MEDIUM confidence**

### Step 2.4: Blind Timing Detection

If no boolean signal after 15 attempts, try timing-based detection before concluding negative:

LDAP doesn't have a native SLEEP() function. Timing attacks work by forcing expensive operations:

```
Expensive (should be slower):
  param=*)(|(objectClass=*         → triggers full directory scan
  param=admin*                     → wildcard prefix scan

Normal:
  param=admin                      → exact match, fast
```

Run expensive vs normal 5 times each. If >200ms consistent difference → timing-based blind viable.

### Step 2.5: Context Classification

**Only proceed here if Steps 2.1–2.4 produced at least MEDIUM confidence or a clear metacharacter signal.**

```
Is the parameter used for authentication?
  YES → Authentication path
  NO  → Search/Lookup path
```

**For Authentication context**, identify which field is injectable:
- Test username and password fields independently with filter injection
- Check for null bind (credentials absent entirely)
- See `ldap_authbypass.md` for detailed techniques

**For Search/Lookup context**, check output visibility:

```
Does the application return LDAP data in the response?
  YES → In-band path: wildcard `*` returns more records, attributes visible
        → see ldap_search_extraction.md
  NO  → Blind context: establish TRUE/FALSE boolean baseline
        → see ldap_blind_extraction.md
```

**Indicators of visible output:** Directory-style data in response, multiple results with attributes (name, email, department), wildcard `*` returns more records than specific value.

**Indicators of blind context:** Generic success/fail message, search returns only count not content, static template regardless of results.

### Classification Confidence

- HIGH: 5/5 or 4/5 consistent results
- MEDIUM: 3/5 consistent — validate before exploitation
- LOW: <3/5 — reassess approach

**Proceed to exploitation with HIGH or validated MEDIUM only.**

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[SPECIAL-CHARS] {which caused behavioral change / "none"}
[BOOLEAN-TRUE]  {payload} → Length: {x}, Pattern: {y}
[BOOLEAN-FALSE] {payload} → Length: {x}, Pattern: {y}
[RUNS]          {X}/3 consistent
[TIMING]        {expensive vs normal avg ms / "not tested" / "no difference"}
[CONFIDENCE]    {HIGH / MEDIUM / LOW}
[CONTEXT]       {auth / search-inband / search-blind / unknown}
[SIGNAL]        {what changed from baseline, or "nothing"}
[DECISION]      {Proceed to Phase 4 with path / No signal → Phase 3}
```

---

## Phase 3: Negative Verdict

**Goal:** Formally conclude that the parameter is not vulnerable to LDAP injection after exhaustive testing.

### When to Issue Negative Verdict

Issue a negative verdict when ALL of the following are true:
- Special character probes (Step 2.1) produced no behavioral change
- Boolean logic tests (Steps 2.2–2.3) showed TRUE/FALSE payloads producing identical responses
- Timing detection (Step 2.4) showed no consistent >200ms difference between expensive and normal queries
- If authentication context: both username and password fields tested independently with no bypass signal
- If search context: wildcard produces no expansion, operator injection no additional results, boolean blind TRUE/FALSE responses differ by <5% across 5 samples
- WAF bypass attempts (if applicable, see `ldap_filter_bypass.md`) have been exhausted

### Negative Verdict Template

```
[LDAP-NEGATIVE]
[PARAMETER] {name}
[ENDPOINT]  {URL}
[CONTEXT]   {auth / search / both tested}
[STEPS-RUN]
  - Special char probes: {result}
  - Boolean logic (login): {result or N/A}
  - Boolean logic (search): {result or N/A}
  - Timing detection: {result}
  - Auth field testing: {username result, password result, or N/A}
  - In-band search: {wildcard expansion result or N/A}
  - Boolean blind: {TRUE/FALSE diff or N/A}
  - WAF bypass: {result or N/A}
[SIGNAL]     None — all responses within baseline variance
[CONCLUSION] No LDAP injection vulnerability detected. Parameter cleared.
[ACTION]     Do not proceed to Phase 4. Move to next target.
```

> **NOTE:** A negative verdict is a valid and important finding. It confirms the parameter was tested and is not vulnerable.

---

## Phase 4: Exploitation

**Goal:** Demonstrate maximum impact through controlled, progressive escalation.

**Only enter Phase 4 if Phase 2 produced HIGH or MEDIUM confidence on a specific path.**

| Confirmed Path | Reference File |
|---------------|----------------|
| Authentication bypass | `ldap_authbypass.md` |
| In-band search extraction | `ldap_search_extraction.md` |
| Boolean blind extraction | `ldap_blind_extraction.md` |
| Filters blocking payloads | `ldap_filter_bypass.md` |

### Escalation Order (All Paths)

1. **Confirm injection** — Prove bypass or one attribute read with minimum payloads
2. **Enumerate schema** — Identify objectClass types, available attributes
3. **Extract sensitive attributes** — Passwords/hashes, email, group memberships
4. **Privilege escalation surface** — Admin group membership, other account takeover

### Stop Conditions

| Condition | Action |
|-----------|--------|
| Auth bypass demonstrated once | **STOP.** Report CRITICAL. |
| Password hash extracted (partial sufficient) | **STOP.** Report CRITICAL. |
| Admin group membership confirmed | **STOP.** Report CRITICAL. |
| Sensitive PII dumped (email, phone, etc.) | Report HIGH. Stop bulk extraction. |
| Enumeration only (usernames) | Report MEDIUM. |
| WAF blocking all payloads | See `ldap_filter_bypass.md`, max 10 attempts |

---

## Reporting

When exploitation is successful, report concisely:

```
[LDAP-CONFIRMED]
[PARAMETER] {name}
[ENDPOINT]  {URL}
[CONTEXT]   {auth bypass / in-band search / blind extraction}
[MAX-IMPACT] {auth bypass / password hash extraction / PII dump / enumeration}
[SEVERITY]  {CRITICAL / HIGH / MEDIUM}
[WORKING-PAYLOAD(S)]
  {final payload(s) that achieved max impact}
[DATA-EXTRACTED] {summary — e.g., "SSHA hash prefix extracted", "3 admin accounts enumerated"}
```

> **NOTE:** Do not generate a full narrative report. The reporting agent handles full report generation. Only state that exploitation succeeded and provide the final working payload(s).

---

## Global Stop Conditions

**Halt immediately if:**

- **3+ consecutive 5xx errors** — Application or directory instability
- **Account lockout mechanism triggered** — Stop all auth testing immediately, coordinate
- **Response time >5x baseline** — Directory overload risk
- **HTTP 429 or CAPTCHA** — Rate limiting triggered
- **Baseline becomes unstable** — Re-baseline; if still unstable, stop

Document the incident and coordinate with stakeholders before resuming.

---

## LDAP Metacharacter Reference

| Char | LDAP Meaning | Injection Use |
|------|-------------|---------------|
| `*` | Wildcard | Match any value, dump entries |
| `(` | Open group | Open new filter expression |
| `)` | Close group | Close existing expression prematurely |
| `\` | Escape char | Escape metacharacters (or inject raw) |
| `\00` | Null byte | Terminate filter string early |
| `&` | AND operator | `(&(cn=x)(pw=y))` |
| `\|` | OR operator | `(\|(cn=x)(cn=y))` |
| `!` | NOT operator | `(!(cn=admin))` |

**LDAP hex escapes** (used in filter values):
- `*` → `\2a` | `(` → `\28` | `)` → `\29` | `\` → `\5c` | NUL → `\00`

---

## WAF/Filter Indicators

- 403/406 on payloads containing `*`, `(`, `)`, `\`
- Metacharacters stripped/encoded in response
- Wildcard `*` returns same count as exact match
- Selective blocking — some chars pass, others don't

**Action:** See `ldap_filter_bypass.md`, re-baseline with bypass payload, reassess confidence.

---

## Things to Do

- Establish baseline first (5 samples, both valid and invalid)
- Test username AND password fields independently for auth context
- Identify context type (auth vs search) before choosing payloads
- Run each payload 3–5 times — single-sample results are unreliable
- Re-baseline if environment changes
- Monitor stop conditions continuously throughout

## Things Not to Do

- No progression with LOW confidence
- No bulk extraction without explicit scope approval
- No account lockout risks without pre-coordination
- No assumptions about filter structure without probing
- No skipping Phase 2 to go directly to exploitation
- No continuing when baseline becomes unstable

---

## Reference Files

- **Auth bypass**: `ldap_authbypass.md`
- **In-band search extraction**: `ldap_search_extraction.md`
- **Boolean blind extraction**: `ldap_blind_extraction.md`
- **Filter/WAF bypass**: `ldap_filter_bypass.md`
