---
name: sqli-pentesting
description: Professional SQL Injection testing methodology. Use when testing parameters for SQL injection vulnerabilities. Provides systematic baseline establishment, injection confirmation with confidence scoring, and type classification. Focuses on distinguishing signal from noise and knowing when to stop.
---

# SQL Injection Pentesting

## Workflow

```
1. BASELINE → 2. CONFIRM → 3. CLASSIFY → 4. EXPLOIT
   (5 samples)   (3+ tests)   (assess type)  (use guides)
   
   Stop conditions checked at every step ↓
```

## Phase 1: Baseline

**Goal:** Understand normal behavior to detect anomalies.

**Process:**
1. Test parameter with 5 legitimate values (valid + invalid)
2. Record for each:
   - Response time (ms) - calculate average & std dev
   - Response length (bytes)
   - HTTP status
   - Unique content patterns

**Document:**
```
Param: [name], Context: [numeric/string]

Existing record (e.g., id=1 that returns data):
  Time: [avg]ms ±[stddev]ms
  Length: [bytes] ±[variance]
  Pattern: [e.g., "user profile rendered"]

Non-existent record (e.g., id=99999):
  Time: [avg]ms ±[stddev]ms  
  Length: [bytes] ±[variance]
  Pattern: [e.g., "no results" or empty]
```

**Why both:** Distinguishing existing vs non-existent is critical for AND/OR operator selection in time-based testing (Phase 3).

**Comparison thresholds (adjust for high-latency targets):**
- Time: ±50ms = same, >100ms = different, >500ms = significant
- Length: ±2% = same, >5% = different, >20% = significant
- Content: semantic comparison (same data vs different vs error)

**Re-baseline if:** Session changes, response patterns shift, rate limiting, caching behavior changes.

## Phase 2: Confirm Injection

**Goal:** Verify SQL injection with HIGH confidence.

**Confidence levels:**
- HIGH: 3/3 tests consistent, proceed ✓
- MEDIUM: 2/3 tests consistent, retest
- LOW: Inconsistent, try different approach

**Proceed to Phase 3 with HIGH confidence. If no boolean signal detected, proceed to Phase 3 Step B2 directly.**

**Attempt limits:**
- Max 5 payload variations per context (numeric/string)
- Max 2 quote types for string context
- Total max: 15 requests before concluding no boolean signal

**No boolean signal:**
- All context types tested with LOW confidence → No boolean signal detected
- No boolean differentiation across quote types → No boolean signal detected
- Proceed to Phase 3 Step B2 for time-based detection before concluding

### For Numeric Context

Test true/false logic:

```
TRUE test:  param=N AND 1=1  (should match baseline)
FALSE test: param=N AND 1=2  (should differ from baseline)
```

Run each 3 times. If TRUE matches baseline AND FALSE differs → HIGH confidence.

### For String Context

Determine quote type, then test:

```
Single quotes:
TRUE:  param=value' AND 'a'='a
FALSE: param=value' AND 'a'='b

Double quotes:
TRUE:  param=value" AND "a"="a
FALSE: param=value" AND "a"="b
```

Run each 3 times. If TRUE matches baseline AND FALSE differs → HIGH confidence.

### No Syntax Errors

Don't send broken SQL during confirmation. Use clean AND/OR logic only.

**Why:** Syntax errors create noise indistinguishable from application errors. Clean boolean logic produces predictable, measurable outcomes.

## Phase 3: Classify Type

**Goal:** Identify which exploitation method works.

**With HIGH confidence from Phase 2, route based on observability. If Phase 2 produced no boolean signal (LOW confidence across all contexts), enter directly at Step B2 for time-based detection.**

### Decision: Is Query Output Visible?

First, determine if the application renders SQL query results in the response.

**Indicators of visible output:**
- Dynamic content changes based on query (user profiles, product listings, search results)
- Data from the database appears directly in HTML/JSON response

**Indicators of blind context:**
- Static responses (login success/failure, generic messages)
- No reflection of queried data in response

```
Output visible?
  YES → In-Band path (Step A)
  NO  → Blind path (Step B)
```

### Step A: In-Band (Output Visible)

**A1. Check for Error Messages**

Send a single quote `'` or double quote `"`.

- **Verbose SQL error displayed** → Error-based SQLi viable
- **No error / generic error** → Continue to A2

**A2. Test UNION Capability**

Determine column count, then attempt UNION SELECT with marker:
```
ORDER BY n (increment until error to find column count)
UNION SELECT 1,2,3,...,n--  (look for numbers in response)
UNION SELECT 'xMARKERx',2,3,...,n-- (look for marker in response)
```

- **Marker visible in response** → UNION-based SQLi viable
- **No marker visible** → Fall back to Blind path (Step B)

### Step B: Blind (No Visible Output)

**B1. Assess Boolean Differences**

From Phase 2, you already have TRUE/FALSE response data.

- **Content/length differs >20%** → Boolean-based blind viable
- **Minimal/no content difference** → Continue to B2

**B2. Test Time-Based**

**CRITICAL - Operator Selection Rule:**

```
IF baseline value EXISTS (record found):
   Use AND operator
   Example: valid_id AND SLEEP(3)
   Logic: TRUE AND SLEEP → executes

IF baseline value DOESN'T EXIST (no record):
   Use OR operator  
   Example: invalid_id OR SLEEP(3)
   Logic: FALSE OR SLEEP → must evaluate (no short-circuit)
```

**Why:** SQL short-circuits. FALSE AND X skips X. FALSE OR X must evaluate X.

**Test (run 5 times):**
- Delay condition → should add ~3s to response
- No-delay condition → baseline timing

- **Delays consistent** → Time-based blind viable, see `time_sqli.md`
- **Delays inconsistent** → Network jitter or not injectable

> **NEGATIVE VERDICT** — Phase 2 (boolean) + Phase 3 B2 (time-based) exhausted
>
> No boolean differentiation and no consistent time delays after completing both detection methods. Parameter is not vulnerable to SQL injection. Do not proceed to Phase 4.

### Classification Confidence

- HIGH: 5/5 or 4/5 consistent results
- MEDIUM: 3/5 consistent, validate with additional tests
- LOW: <3/5 consistent, reassess approach

**Proceed to exploitation with HIGH or validated MEDIUM only.**

**Type preference when multiple viable:** Error-based > UNION > Boolean > Time (speed/reliability)

## Stop Conditions

**Halt immediately if:**

- **3+ consecutive 5xx errors** → Application instability
- **Response time >5x baseline** → Service degradation
- **HTTP 429 / CAPTCHA** → Rate limiting
- **Account lockout warnings** → Stop, coordinate
- **Baseline becomes unstable** → Re-baseline fails, environmental issue

Document incident and coordinate with stakeholders.

## Encoding

URL-encode payloads appropriately:
- Space: `%20` or `+`
- Single quote: `%27`
- Double quote: `%22`
- Comment: `%23` (#) or `--`

Some WAFs trigger on decoded values, others on encoded. Test both if filtered.

## WAF/Filters

**Indicators:** 403/406 blocks, timeouts, "blocked" messages, selective filtering.

**Action:** See `filter_bypass.md`, then re-baseline and reassess confidence.

## Things to Do

- Establish baseline first (5 samples, statistical rigor)
- Use clean SQL logic in confirmation
- Check value validity before choosing AND/OR for time-based
- Test 3+ times, calculate confidence
- Re-baseline when environment changes
- Monitor stop conditions continuously
- Proceed only with sufficient confidence

## Things Not to Do

- No syntax errors during confirmation (Phase 2)
- No progression with LOW confidence
- No time delays >3 seconds
- No testing during instability
- No assumptions without validation
- No baseline violations

## Reference Files

After classification with sufficient confidence:
- **Error-based**: `error_sqli.md`
- **UNION-based**: `union_sqli.md`
- **Boolean-based blind**: `boolean_sqli.md`
- **Time-based blind**: `time_sqli.md`
- **Filter/WAF bypass**: `filter_bypass.md`