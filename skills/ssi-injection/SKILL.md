---
name: testing-ssi-injection
description: "Tests for Server-Side Include (SSI) injection vulnerabilities from confirmed injection points through maximum demonstrated impact. Covers directive injection detection via echo probes, file inclusion escalation, exec-based RCE confirmation, and routes to ESI testing when CDN/cache infrastructure is suspected. Triggers when testing parameters that reflect user input into HTML pages potentially served by Apache mod_include, Nginx SSI module, or IIS."
---

# SSI Injection Testing Methodology

## Reference Files

When CDN, cache proxy, or surrogate infrastructure detected; ESI testing needed Read [ESI.md](ESI.md) 

---

## Mental Model

SSI injection is a **web-server-level** vulnerability, not an application-level one. The web server (Apache `mod_include`, Nginx `ssi on`, IIS) scans HTML files for `<!--#directive -->` comments and executes them *before* serving the page to the client. If user input lands in a server-parsed HTML page without sanitization, the attacker's SSI directives execute with the web server process's privileges.

**The critical prerequisite:** User input must be *reflected into an HTML page that the web server parses for SSI directives.* No reflection = no SSI injection, period. This is the first thing to verify and the earliest STOP condition.

**Why SSI behaves as binary:** Either the server parses SSI directives in the page context where input is reflected, or it doesn't. There's no partial parsing, no sandbox, no restricted mode for directive evaluation itself. If an `echo` probe evaluates, the injection point is confirmed — the only remaining question is which directives the server's configuration permits (echo only → include → exec → RCE). The `Options` directive (Apache) or equivalent controls this ceiling.

**Key distinction from SSTI:** SSI operates at the web server layer *before* the application framework processes templates. The directive syntax (`<!--#...-->`) is HTML-comment-based, entirely distinct from template engine syntax (`{{...}}`, `${...}`). A parameter vulnerable to SSTI may not be vulnerable to SSI and vice versa — they require independent testing.

---

## Phase 1: Baseline Establishment

**Goal:** Record the normal response profile and verify input reflection before any SSI-specific testing.

### Step 1.1: Send Benign Marker

Send a unique alphanumeric string (e.g., `SSITESTMARKER8472`) through the target parameter. Record:

- HTTP status code
- Response body length (bytes)
- Response time (ms)
- Whether the marker appears in the response body
- Where exactly in the HTML it appears (attribute value, text node, HTML comment, inside a tag)

### Step 1.2: Test Invalid Input

Send a clearly invalid but non-malicious value (e.g., `INVALIDINPUT000`) and record the same profile. You need two baselines — valid-input response and invalid-input response — to distinguish vulnerability signal from generic input handling later.

### Step 1.3: Check Reflection Stability

Send the benign marker 2-3 times. Compare responses. If response length or content varies across identical requests, caching or load balancing is active — note this as a confounding factor and account for it in Phase 2 comparisons.

### Step 1.4: Extension and Header Observation

From the attack surface model's output and observed responses, note:

- Does the page use `.shtml`, `.shtm`, or `.stm` extension? (positive signal for SSI parsing)
- `Server` header indicating Apache, Nginx, or IIS
- Any `X-Powered-By` or custom headers suggesting SSI-capable infrastructure

**Important:** Absence of SSI-specific extensions means nothing — Apache's `XBitHack` directive or blanket `Options +Includes` can enable SSI parsing on any `.html` file.

### Step 1.5: Character Acceptance Test

SSI directives require `<`, `!`, `-`, `#`, `=`, `"`, `>`. Send a test string containing these characters (e.g., `test<!--#test="val"-->end`) and check:

- All characters present in response → no filtering on SSI-relevant characters
- Some characters stripped or HTML-encoded → note which ones (constrains later phases)
- Request blocked entirely → WAF or input validation active

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[MARKER] SSITESTMARKER8472 → Status: {code}, Length: {bytes}, Time: {ms}
[REFLECTION] {Present at {location} / Not reflected}
[INVALID-INPUT] Status: {code}, Length: {bytes}
[STABILITY] {Stable / Variable — caching suspected}
[EXTENSIONS] {.shtml observed / standard .html / other}
[SERVER] {Apache / Nginx / IIS / Unknown}
[CHAR-FILTER] {None / Characters filtered: {list} / Request blocked}
[DECISION] {Proceed to Phase 2 / STOP — no reflection}
```

> **STOP:** If your benign marker does not appear anywhere in the response body — neither in the immediate response nor in secondary reflection points (profile pages, admin panels, logs) — SSI injection is not possible at this parameter. SSI requires the injected directive to appear in a server-parsed HTML page. Document and move on.

---

## Phase 2: Confirmation

**Goal:** Establish HIGH confidence that SSI directives are being parsed and executed at this injection point.

### Confidence Definitions for SSI

| Level | Evidence Required |
|-------|-------------------|
| **HIGH** | An SSI echo probe returns the evaluated server variable (e.g., actual date/time, document filename) instead of the raw directive text. Reproduced at least twice with different variables. |
| **MEDIUM** | The SSI directive disappears from the response (consumed but output suppressed), OR a server error is returned that differs from both baselines, suggesting the directive reached a parser. |
| **LOW** | The directive is reflected unchanged. Server may support SSI (e.g., `.shtml` extension), but no evidence of parsing at this injection point. |

### Step 2.1: Primary Echo Probe

Inject the simplest SSI echo directive:

```
<!--#echo var="DATE_LOCAL" -->
```

Compare the response against **both** baselines:

| Response | Interpretation | Confidence |
|----------|----------------|------------|
| Current date/time string appears where the directive was injected | SSI active and executing | HIGH |
| Directive text is gone (consumed) but no date appears | SSI may be parsing but suppressing output | MEDIUM |
| Raw `<!--#echo var="DATE_LOCAL" -->` appears in HTML source | SSI not parsing this context | LOW |
| Server error (500) different from invalid-input baseline | Directive reached parser but errored | MEDIUM |
| Request blocked (403/WAF page) | Filter detected the directive | See Filter Evasion below |

### Step 2.2: Secondary Echo Probes

If Step 2.1 is MEDIUM or ambiguous, try additional echo targets — some configurations restrict certain variables:

```
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="SERVER_SOFTWARE" -->
```

Also try the definitive `set`+`echo` proof — if the server returns your custom value, it is irrefutably executing SSI directives:

```
<!--#set var="ssiproof" value="SSI_CONFIRMED_8472" --><!--#echo var="ssiproof" -->
```

If `SSI_CONFIRMED_8472` appears in the response → HIGH confidence, zero ambiguity.

### Step 2.3: Environment Dump

If echo probes succeeded:

```
<!--#printenv -->
```

This returns ALL server environment variables. If it works, you immediately have information disclosure — potentially including database credentials, API keys, internal paths, cloud tokens. Note: `printenv` is sometimes disabled even when `echo` works; a blank or error response does not downgrade your echo-based confirmation.

### Step 2.4: Blind/Timing Detection

If all probes return unchanged but you still suspect SSI is active (e.g., `.shtml` extension, Apache with `mod_include` confirmed, directives are consumed but produce no output):

```
<!--#exec cmd="sleep 5" -->
```

If the response is delayed by ~5 seconds → SSI exec is active. This jumps you directly to HIGH confidence and confirms the exec directive works simultaneously.

**Cap:** Maximum 15 requests in Phase 2 before concluding. If 15 probes produce no signal differentiable from baselines, proceed to the Negative Verdict gate.

### Filter Evasion Reasoning

If probes are blocked (403, stripped, or modified), reason about **what** is being filtered before trying bypasses:

**Isolate the trigger component:**
- Send just `<!--` alone — blocked? The filter targets HTML comments broadly.
- Send `<!--#` — blocked? The filter specifically targets the SSI directive prefix.
- Send `exec` or `cmd` as plain text — blocked? The filter targets execution keywords but may allow echo/include directives.

**Evasion approaches** (try only after identifying what triggers the filter):

1. **URL-encode the critical character:** `<!--%23echo var="DATE_LOCAL" -->` (encodes `#`). Works when the server URL-decodes input before embedding it into the page, but the WAF inspects the raw request.
2. **Double URL-encode** if the server decodes twice: `%253C!--%2523echo...`
3. **Case variation:** `<!--#ECHO var="DATE_LOCAL" -->` — SSI parsing is typically case-insensitive for directive names; WAF rules often aren't.
4. **Whitespace variation:** Extra spaces or tab characters between directive name and parameters: `<!--#echo  var="DATE_LOCAL" -->`
5. **Alternate quotes:** Single quotes: `<!--#echo var='DATE_LOCAL' -->`

**Hard stop on evasion:** If 3 structurally distinct evasion approaches (e.g., encoding, case, whitespace — not three variations of encoding) all produce the same blocked response, the filter is robust against SSI directives at this injection point. Document the filter behavior and proceed to the Negative Verdict gate — do not keep iterating.

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[ECHO-DATE] {evaluated value / raw directive / consumed / error / blocked}
[ECHO-DOCNAME] {result}
[SET-ECHO] {custom value returned / not returned / not tested}
[PRINTENV] {environment dump / error / blocked / not tested}
[BLIND-TIMING] {delay observed / no delay / not tested}
[FILTER] {none / trigger identified: {component} / full directive blocked}
[EVASION] {approaches tried and results, or "not needed"}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to Negative Verdict gate / Retest different approach / STOP}
```

---

## Negative Verdict Gate

**This is mandatory before entering Phase 3.** Even when the result seems obvious, explicitly evaluate the evidence.

### True Negative Conditions for SSI

A **true negative** requires ALL of the following:

1. Input reflection was confirmed in Phase 1 (the directive text reaches the page)
2. At least 3 distinct echo probes returned the raw directive text unchanged — not consumed, not errored, literally reflected as-is in the HTML source
3. The `set`+`echo` combination did not produce the custom value
4. No timing anomaly was observed on the exec sleep probe (or exec probe was not blocked by a filter)
5. If filters were detected, at least 3 structurally distinct evasion techniques were attempted with identical blocked responses

If all conditions are met → **true negative:**

```
[VULN-NEGATIVE]
[PARAMETER] {name}
[STEPS-RUN] Phase 1 baseline + reflection confirmed; Phase 2: {list every probe and result}
[SIGNAL] {what was observed, or "nothing — all directives reflected as raw HTML comments"}
[CONCLUSION] SSI directives are not being parsed at this injection point. All probes returned as literal HTML comments without evaluation. The web server is not processing SSI in this page context.
[ACTION] Parameter cleared. Do not proceed to exploitation.
```

### Inconclusive Conditions

If ANY of the following are true, the result is **inconclusive**, not negative:

- Directive text disappears from response (consumed but no output) → SSI may be active with output suppression
- Server errors differ from the invalid-input baseline → directive may be reaching a parser
- Filters blocked probes before they could be evaluated → untested, not disproven
- Session became invalid during testing (see Session Re-verification)
- Only 1-2 probes were tested before stopping

Inconclusive requires a decision: try a different injection point, different delivery vector (header injection vs. parameter), or different evasion technique. If no alternatives remain, document as **inconclusive** and stop. Do NOT convert inconclusive to negative.

> **STOP:** If a true negative verdict is issued, do not proceed to Phase 3 under any reinterpretation of the evidence.

---

## Phase 3: Exploitation

**Only entered after HIGH confidence from Phase 2 and no negative verdict issued.**

Exploitation escalates progressively. Each step builds on confirmed success of the previous step. Do not skip ahead.

### Step 3.1: Information Disclosure Assessment

Assess what Phase 2 has already disclosed:

- `DATE_LOCAL`, `LAST_MODIFIED` → Low/Info (timestamp disclosure)
- `DOCUMENT_NAME`, `DOCUMENT_URI` → Medium (path disclosure — reveals server filesystem structure)
- `SERVER_SOFTWARE` → Medium (version disclosure — enables targeted exploits)
- `printenv` succeeded → **High** (environment dump — check for credentials, API keys, internal IPs, cloud tokens)

### Step 3.2: File Inclusion

Attempt to read sensitive files through the `include` directive. Two forms exist with different path resolution:

- **`file=`** — Relative path from the current document's directory. On Apache, cannot traverse above `ServerRoot` by default.
- **`virtual=`** — Server-relative path (URL-style). More flexible, can reference any path the server would serve.

**Reasoning about which to try first:** If Phase 2 echo probes revealed the document path (via `DOCUMENT_URI`), use it to calculate relative paths. If the full path is unknown, prefer `virtual` first since it uses absolute server paths and is less dependent on knowing the current directory.

| Response | Interpretation | Next Step |
|----------|----------------|-----------|
| File contents appear in response | File inclusion confirmed | Record severity, try next high-value file |
| Server error unlike baseline | Include directive parsed but access denied or path invalid | Try alternate path or `virtual` instead of `file` |
| SSI error message (`[an error occurred...]`) | Include directive is recognized but restricted | exec may still work; proceed to Step 3.3 |
| No change from baseline | Include directive may be disabled entirely | Proceed to Step 3.3 |

**Reasoning about target files:** What to read depends on what you've already learned. If `SERVER_SOFTWARE` revealed Apache on Linux, `/etc/passwd` confirms file read. If `DOCUMENT_URI` revealed the app lives in `/var/www/app/`, look for configuration files relative to that path. If the echo phase revealed environment variables with database references, look for connection configuration files. Reason from context, don't follow a fixed list.

### Step 3.3: Command Execution

The `exec` directive is the highest-impact SSI capability. If it succeeds, this is RCE.

```
<!--#exec cmd="id" -->
```

| Response | Interpretation | Severity |
|----------|----------------|----------|
| Command output appears (e.g., `uid=33(www-data)`) | **RCE confirmed** | **CRITICAL** |
| SSI error message, different from include errors | exec directive parsed but blocked by config (`Options -ExecCGI`) | exec disabled — max impact from echo/include |
| No change from baseline | exec not available | Stop escalation |

> **STOP on RCE confirmation.** If `id` or `whoami` output appears, you have confirmed Critical severity. Document the finding. Do not proceed to reverse shells or further chained execution unless explicitly authorized and within scope.

### Step 3.4: Post-RCE Context (only if scope explicitly authorizes)

If exec works and scope permits deeper impact demonstration:

1. **Confirm OS** — Already known from echo vars or `id` output
2. **Assess network position** — `<!--#exec cmd="ip addr" -->` or `<!--#exec cmd="ipconfig" -->` `[EXTERNAL INFRA REQUIRED]` if pivoting beyond this
3. **Reverse shell** — OS-appropriate payload via the exec directive, which passes commands directly to the system shell `[EXTERNAL INFRA REQUIRED]`

> **STOP after first confirmed command execution.** Demonstrate impact, document, yield to reporting pipeline.

### Reasoning Checkpoint

```
[PHASE-3] Exploitation
[INFO-DISCLOSURE] {variables disclosed and severity}
[FILE-INCLUSION] {files read / directive restricted / disabled}
[EXEC] {RCE confirmed with output / exec disabled / not tested}
[MAX-IMPACT] {Critical: RCE / High: file read + env dump / Medium: path disclosure / Low: date only}
[DECISION] {Document finding at {severity} / Escalate with authorization / STOP}
```

---

## Phase 4: ESI Assessment

**When to enter this phase:** ESI testing is warranted when ANY of the following are observed:

- `Surrogate-Control` header present in any response
- Application sits behind a known CDN/cache (Akamai, Fastly, Varnish, Squid)
- Response headers indicate caching proxy infrastructure (`X-Cache`, `Via`, `Age`, `X-Varnish`)
- SSI was negative in Phases 1-3 but infrastructure suggests server-side markup processing

**If none of these signals are present**, skip this phase.

Read [ESI.md](ESI.md) for the full ESI detection and exploitation methodology, including the software capability matrix that determines which attack paths are possible for each surrogate type.

### Reasoning Checkpoint

```
[PHASE-4] ESI Assessment
[SURROGATE-SIGNALS] {headers observed / CDN identified / none}
[DECISION] {Enter ESI testing per ESI.md / Skip — no surrogate infrastructure detected}
```

---

## Session Re-verification

### When to Re-verify

Pause and re-verify session validity whenever:

- A response returns 401/403 when previous identical requests returned 200
- Response body length shifts by >20% compared to baseline with no payload change
- Multiple consecutive requests return errors that differ from both baselines
- You've made >50 requests without re-checking
- After any exec probe that might trigger IDS/WAF defensive escalation

### How to Re-verify

1. Re-send the exact benign marker request from Phase 1, Step 1.1
2. Compare against the recorded Phase 1 baseline (status, length, content, timing)
3. If the baseline response matches within normal variance → session is valid, continue
4. If the response differs meaningfully → session state has changed

### What to Do on Failure

If session re-verification fails:

1. **STOP the current phase immediately**
2. Document which requests were made during the potentially invalid session
3. **Do NOT count those requests as evidence** for or against the vulnerability — they are tainted
4. Attempt to re-establish the session (re-authenticate, obtain new token)
5. If the session cannot be restored, document the session failure and stop testing this parameter
6. **Never conclude a parameter is not vulnerable based on results obtained during an invalid session**

### Why This Matters for SSI Testing Specifically

- WAFs may escalate blocking after detecting SSI directive patterns in requests, causing all subsequent probes to appear to "fail" when they're actually blocked at the WAF layer before reaching the server
- SSI injection into HTTP headers (User-Agent, Referer) may trigger different WAF rules than parameter-based injection, causing mid-session blocking changes
- The binary nature of SSI (works or doesn't) means a few false negatives from a dead session can prematurely close a parameter that is actually vulnerable — there's no "partial signal" to keep you investigating

---

## Things to Do

- **Always compare against baseline.** Never evaluate a response in isolation. A 500 error is only meaningful if the baseline was 200. A blank body is only meaningful if the baseline had content. Both the valid-input and invalid-input baselines matter.
- **Log every phase transition** using the reasoning checkpoint format. This forces you to articulate your evidence before proceeding, catching premature escalation.
- **Re-verify session validity at every phase boundary** and whenever response patterns shift unexpectedly.
- **Stop at the first confirmed high-impact result.** If exec returns `id` output, document Critical and stop. Do not chain to reverse shell unless scope explicitly authorizes it.
- **Treat MEDIUM confidence as a pivot signal,** not an escalation signal. MEDIUM means "try a different detection approach" — not "proceed cautiously with exploitation."
- **Issue an explicit negative verdict** before closing any parameter, even when it seems obviously not vulnerable. The structured format forces verification of your own reasoning.
- **Distinguish "SSI not parsed" from "SSI parsed but restricted."** The first is a true negative. The second is a **confirmed vulnerability with limited impact** — still a finding worth documenting. When echo works but include/exec don't, that's a Medium-severity information disclosure finding.
- **Record the SSI error message format** if one appears (typically `[an error occurred while processing this directive]`). This is the server's SSI error string — its presence confirms SSI parsing is active, even when the specific directive is blocked.

---

## Things Not to Do

- **Do not interpret a disappeared directive as a negative.** If the SSI directive text is consumed (absent from response) rather than reflected literally, that suggests parsing occurred — it's MEDIUM confidence, not a negative.
- **Do not proceed to exploitation on MEDIUM confidence.** If the directive disappeared but no evaluated output appeared, try the `set`+`echo` proof or a different echo variable before escalating.
- **Do not try more than 3 structural categories of filter evasion.** If URL encoding, case variation, and whitespace manipulation all produce the same blocked response, that bypass surface is exhausted. Move to a structurally different delivery vector or accept the filter.
- **Do not attribute WAF blocks to SSI being absent.** A 403 on an SSI probe means the filter caught it before it reached the server, not that SSI isn't active. A blocked probe is untested, not disproven.
- **Do not issue a negative verdict when the result is inconclusive.** If probes were blocked by a WAF, the result is "untested behind filters," not "SSI not present." These are different conclusions with different implications.
- **Do not run exec probes while session re-verification is pending or has failed.** Exec results from a dead session are meaningless and could create a false negative on the most critical escalation path.
- **Do not test for SSI on a parameter that has no HTML reflection.** SSI requires the directive to appear in a server-parsed page. No reflection = no SSI. This is a Phase 1 STOP, not something to work around.
- **Do not spray all echo/include/exec payloads simultaneously.** Progressive escalation means confirming echo works, then trying include, then exec. Each step should only begin after the previous step's result is analyzed.
- **Do not conflate SSI with SSTI.** Different vulnerability class, different injection syntax, different processing layer, different exploitation path. Test them independently.
- **Do not assume `printenv` failure means limited impact.** `printenv` may be disabled while `include` and `exec` still work. The SSI configuration controls each directive type independently.

---

## Severity Reference

| Demonstrated Impact | Severity | Condition |
|---------------------|----------|-----------|
| OS command execution via exec | **Critical** | `<!--#exec cmd="id" -->` returns command output |
| Sensitive file read (credentials, shadow, config) | **High** | `<!--#include -->` returns file contents with secrets |
| Environment variable dump with secrets | **High** | `<!--#printenv -->` reveals DB creds, API keys, tokens |
| ESI cookie theft bypassing httpOnly | **High** | ESI exfiltrates session cookies `[EXTERNAL INFRA REQUIRED]` |
| File path / document structure disclosure | **Medium** | `DOCUMENT_URI` or `DOCUMENT_NAME` reveals internal paths |
| SSI confirmed active, exec + include disabled | **Medium** | Echo directives evaluate but no escalation path available |
| Date/time or server version disclosure only | **Low/Info** | Only `DATE_LOCAL` or `SERVER_SOFTWARE` disclosed |

---

## Worked Examples

### Example 1: SSI to RCE on Apache .shtml

```
[PHASE-1] Baseline
[MARKER] SSITESTMARKER8472 → Status: 200, Length: 3841, Time: 45ms
[REFLECTION] Present in <p> tag body
[INVALID-INPUT] Status: 200, Length: 3820
[STABILITY] Stable across 3 requests
[EXTENSIONS] .shtml page
[SERVER] Apache/2.4.52
[CHAR-FILTER] None — all SSI characters accepted
[DECISION] Proceed to Phase 2

[PHASE-2] Confirmation
[ECHO-DATE] "Thursday, 05-Mar-2026 14:32:18 EST" — evaluated
[SET-ECHO] "SSI_CONFIRMED_8472" returned in response
[PRINTENV] Full environment dump — DB_PASSWORD, AWS_SECRET_KEY visible
[CONFIDENCE] HIGH
[DECISION] No negative verdict → Proceed to Phase 3

[PHASE-3] Exploitation
[INFO-DISCLOSURE] printenv revealed DB credentials and AWS keys → HIGH
[FILE-INCLUSION] <!--#include virtual="/etc/passwd" --> → file contents returned
[EXEC] <!--#exec cmd="id" --> → "uid=33(www-data) gid=33(www-data)"
[MAX-IMPACT] Critical: RCE confirmed
[DECISION] STOP — Document Critical finding
```

### Example 2: SSI Confirmed, Exec Disabled

```
[PHASE-1] Baseline → Status: 200, Length: 2105, Reflection: comment form echo
[PHASE-2] ECHO-DATE: "March 5, 2026" — evaluated. SET-ECHO: confirmed.
         PRINTENV: "[an error occurred while processing this directive]"
         CONFIDENCE: HIGH → Proceed to Phase 3
[PHASE-3] FILE-INCLUSION: "[an error occurred...]" EXEC: "[an error occurred...]"
         MAX-IMPACT: Medium — SSI active, echo works, include+exec restricted by config
```

### Example 3: No Signal — True Negative

```
[PHASE-1] Baseline
[MARKER] SSITESTMARKER8472 → Status: 200, Length: 5230, Time: 52ms
[REFLECTION] Present in <div class="comment">
[CHAR-FILTER] None
[DECISION] Proceed to Phase 2

[PHASE-2] Confirmation
[ECHO-DATE] Raw directive reflected unchanged
[ECHO-DOCNAME] Raw directive reflected unchanged
[SET-ECHO] Raw directive reflected unchanged
[PRINTENV] Raw directive reflected unchanged
[BLIND-TIMING] No delay on exec sleep probe
[CONFIDENCE] LOW
[DECISION] Proceed to Negative Verdict gate

[VULN-NEGATIVE]
[PARAMETER] comment_body
[STEPS-RUN] Phase 1 baseline confirmed reflection; Phase 2: echo DATE_LOCAL (raw), echo DOCUMENT_NAME (raw), echo SERVER_SOFTWARE (raw), set+echo (raw), printenv (raw), exec sleep (no delay) — 6 probes, 0 signal
[SIGNAL] Nothing — all directives reflected as literal HTML comments
[CONCLUSION] SSI directives are not parsed at this injection point. All probes returned as-is. True negative — probes were delivered and reflected, just not processed.
[ACTION] Parameter cleared. Do not proceed to exploitation.
```

### Example 4: WAF Blocks Probes — Inconclusive

```
[PHASE-1] Baseline → Status: 200, Length: 4102, Reflection: search results
         CHAR-FILTER: "<!--#" triggers 403 WAF page
[PHASE-2] All probes blocked: echo (403), URL-encode # (403), case variation (403), double-encode (403)
         CONFIDENCE: Cannot establish — all probes blocked before evaluation

[RESULT] INCONCLUSIVE — not negative
[PARAMETER] search_query
[REASON] WAF blocks all SSI directive patterns before reaching server. Cannot confirm or deny.
[ACTION] Document as inconclusive. Retest via different vector if available. Otherwise, close as untestable.
```
