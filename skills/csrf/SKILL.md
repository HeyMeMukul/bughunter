---
name: csrf-testing
description: Professional CSRF (Cross-Site Request Forgery) testing methodology. Use when testing state-changing endpoints for CSRF vulnerabilities including missing protection, token flaws, SameSite bypasses, JSON/API CSRF, and Referer validation issues. Covers systematic detection, bypass techniques, and PoC generation.
---

# CSRF Pentesting

## What Is This?

You are testing whether an application properly protects state-changing actions from cross-site request forgery. CSRF occurs when an attacker tricks a victim's browser into making unwanted requests to a site where the victim is authenticated.

**Impact of CSRF:**
- Account takeover (email/password change)
- Unauthorized transactions
- Data modification
- Privilege escalation (if admin is targeted)

## Core Concept

CSRF exploits the browser's automatic inclusion of credentials (cookies, basic auth) with requests. If a state-changing action only relies on these automatic credentials, an attacker's page can trigger that action.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (surface)     (test flaws)     (declare secure)      (PoC + chain)
   
   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Identify Attack Surface

### What Am I Doing?
Finding all state-changing actions that could be targeted and documenting the protection mechanisms in place.

### Why?
CSRF only affects actions that change state. Read-only operations are not CSRF targets.

### Process

**Step 1: Map state-changing endpoints**

Look for actions that:
- Modify user data (profile, settings, email, password)
- Perform transactions (purchases, transfers)
- Change permissions (add users, change roles)
- Modify application state (create, update, delete)

**Step 2: Document each endpoint**

```
Endpoint: [URL]
Method: [GET/POST/PUT/DELETE]
Parameters: [list]
Action: [what it does]
Requires Auth: [YES/NO]
```

**Step 3: Note the protection mechanism**

For each endpoint, identify:
- CSRF token in form/request?
- Custom headers required?
- Referer/Origin validation?
- SameSite cookie attribute?

### Protection Types

| Protection | How to Identify |
|------------|-----------------|
| CSRF Token | Hidden field `csrf_token`, `_token`, `authenticity_token` |
| Custom Header | Request requires `X-Requested-With`, `X-CSRF-Token` |
| SameSite Cookie | Check `Set-Cookie` header for `SameSite` attribute |
| Referer Validation | Removing/modifying Referer causes failure |
| Origin Validation | Request fails without correct Origin header |
| Double-Submit Cookie | Token in cookie AND request body/header |
| None | No visible protection |

### Decision Tree

```
Is there a CSRF token in the request?
  YES → Go to token_bypass.md
  NO  ↓

Is SameSite cookie set?
  Strict → Go to samesite_bypass.md
  Lax   → Go to samesite_bypass.md
  None/Missing → Likely vulnerable, test directly
  
Is Referer/Origin validated?
  YES → Go to referer_origin.md
  NO  → Likely vulnerable, test directly

Is it a JSON/API endpoint?
  YES → Go to json_api_csrf.md
  NO  → Test with standard form submission
```

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[ENDPOINTS] {count} state-changing endpoints identified
[PROTECTIONS] {summary of protections per endpoint}
[DECISION] {Proceed to Phase 2 / No state-changing actions — STOP}
```

> **STOP:** If no state-changing actions are found, there is nothing to target. Document as "No CSRF attack surface" and stop.

---

## Phase 2: Confirmation — Test for Flaws

### What Am I Doing?
Systematically testing for weaknesses in the protection mechanism.

### Why?
Protections are often implemented incorrectly. Systematic testing finds these flaws.

### Quick Tests (Before Deep Dive)

**Test 1: Remove protection entirely**
- Delete CSRF token parameter
- Remove custom headers
- Does request still succeed?

**Test 2: Empty value**
- Set token to empty string
- Does request still succeed?

**Test 3: Change request method**
- Switch POST to GET (or vice versa)
- Does protection still apply?

**Test 4: Different content type**
- Change `application/json` to `text/plain`
- Does server still process it?

### Detailed Testing

Based on protection type, refer to:
- Token issues: [token_bypass.md](token_bypass.md)
- SameSite issues: [samesite_bypass.md](samesite_bypass.md)
- JSON/API issues: [json_api_csrf.md](json_api_csrf.md)
- Header validation: [referer_origin.md](referer_origin.md)
- Special scenarios: [special_cases.md](special_cases.md)

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[TESTS-RUN] {list of tests performed per endpoint}
[RESULTS] {which tests passed/failed}
[BYPASS-FOUND] {Yes — describe / No}
[DECISION] {Bypass found → Phase 4 / All tests failed → Phase 3}
```

---

## Phase 3: Negative Verdict — Declare Secure

### What Am I Doing?
Formally concluding that the endpoint's CSRF protection is sound after exhaustive testing.

### Why?
A clear negative verdict prevents wasted effort on further testing and provides documentation that the endpoint was properly evaluated.

### When to Issue Negative Verdict

Issue a negative verdict when ALL of the following are true:
- CSRF token is present, validated server-side, and tied to the user session
- Token cannot be removed, emptied, or substituted with another user's token
- Method switching (POST ↔ GET) does not bypass protection
- SameSite cookie attribute is properly set (if applicable)
- Referer/Origin validation is strict (if applicable)
- All relevant sub-file techniques (token_bypass.md, samesite_bypass.md, etc.) have been attempted and failed

### Negative Verdict Template

```
[CSRF-NEGATIVE]
[ENDPOINT] {URL}
[METHOD] {HTTP method}
[ACTION] {what the endpoint does}
[PROTECTION] {protection type(s) in place}
[TESTS-RUN]
  - Token removal: {result}
  - Empty token: {result}
  - Arbitrary token: {result}
  - Cross-user token: {result}
  - Method switch: {result}
  - SameSite bypass: {result or N/A}
  - Referer/Origin bypass: {result or N/A}
  - Content-type manipulation: {result or N/A}
[SIGNAL] None — all bypass attempts failed
[CONCLUSION] CSRF protection is properly implemented. Endpoint is not vulnerable.
[ACTION] Endpoint cleared for CSRF. Do not proceed to Phase 4.
```

> **NOTE:** A negative verdict is a valid and important finding. It confirms the endpoint was tested and is secure.

---

## Phase 4: Exploitation — PoC Generation & Chaining

### What Am I Doing?
Creating a working proof of concept that demonstrates the vulnerability, and exploring chaining opportunities.

### Why?
A working PoC proves exploitability and helps developers understand the issue.

### PoC Requirements

A valid CSRF PoC must:
1. Be hosted on a different origin than the target
2. Trigger the action when victim visits the page
3. Work without victim interaction (auto-submit)

### PoC Templates

**HTML Form (POST):**
```html
<html>
<body>
<form id="csrf" action="TARGET_URL" method="POST">
  <input type="hidden" name="param1" value="value1">
  <input type="hidden" name="param2" value="value2">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

**Image Tag (GET):**
```html
<img src="TARGET_URL?param1=value1&param2=value2">
```

**Fetch API (with credentials):**
```html
<script>
fetch('TARGET_URL', {
  method: 'POST',
  credentials: 'include',
  body: 'param1=value1&param2=value2',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'}
});
</script>
```

### Common Chains

**CSRF + XSS:**
- XSS can read CSRF tokens from page
- XSS on same origin bypasses all CSRF protections
- Stored XSS + CSRF = persistent attack

**CSRF + Subdomain Takeover:**
- Control sibling subdomain
- Bypass SameSite=Strict via same-site context
- Set cookies for parent domain

**CSRF + Clickjacking:**
- Frame the action
- Trick user into clicking
- Bypasses some token schemes

**CSRF + Open Redirect:**
- Chain with token leakage via redirect
- Capture tokens in Referer header

### Severity Classification

| Action Compromised | Severity |
|--------------------|----------|
| Account takeover (password/email change) | CRITICAL |
| Administrative actions | CRITICAL |
| Financial transactions | HIGH-CRITICAL |
| Data modification | MEDIUM-HIGH |
| Preference changes | LOW-MEDIUM |
| Logout | LOW |

---

## Reporting

When exploitation is successful, report concisely:

```
[CSRF-CONFIRMED]
[ENDPOINT] {URL}
[METHOD] {HTTP method}
[ACTION] {what action was forged}
[BYPASS] {protection bypass used, if any}
[SEVERITY] {CRITICAL / HIGH / MEDIUM / LOW}
[WORKING-PAYLOAD(S)]
  {final PoC HTML / request that works}
[CHAIN] {if combined with other vulns, describe}
```

> **NOTE:** Do not generate a full narrative report. The reporting agent handles full report generation. Only state that exploitation succeeded and provide the final working payload(s).

---

## Stop Conditions

**Halt testing if:**

- **Rate limiting** — Account locked or requests throttled
- **No state-changing actions found** — Nothing to target
- **Strong protection verified** — Token properly validated, tied to session (issue Negative Verdict)
- **WAF blocking** — Consistent blocks on test requests

---

## Things to Do

- Map all state-changing endpoints first
- Test one variable at a time
- Verify successful exploitation with different browser
- Document token behavior (regeneration, expiry)
- Test both authenticated and unauthenticated paths
- Check if token is tied to session

## Things Not to Do

- Skip baseline (missing endpoints = missed vulns)
- Assume protection exists (always verify)
- Only test obvious endpoints (test all state changes)
- Ignore low-impact CSRF (document all findings)
- Test only POST (GET can be vulnerable too)

---

## Reference Files

| When | File |
|------|------|
| CSRF token present | [token_bypass.md](token_bypass.md) |
| SameSite cookie set | [samesite_bypass.md](samesite_bypass.md) |
| JSON/API endpoint | [json_api_csrf.md](json_api_csrf.md) |
| Referer/Origin checked | [referer_origin.md](referer_origin.md) |
| Multi-step, login, logout | [special_cases.md](special_cases.md) |
