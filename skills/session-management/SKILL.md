---
name: testing-session-management
description: Session management vulnerability testing — how the application creates, maintains, validates, and destroys user sessions. Use when evaluating any stateful authentication mechanism. Covers session fixation, token entropy and prediction, lifecycle flaws (expiration, invalidation on logout/password change/privilege change), concurrent sessions, cookie security attributes, and session sharing across subdomains.
---

# Session Management Testing

Session management flaws are distinct from authentication bypass — the user authenticates correctly, but the session mechanism itself has flaws that allow unauthorized access. These vulnerabilities are often missed because they require lifecycle testing, not single-request testing.

## Reference Files

- [attacks.md](./attacks.md) — Session fixation, prediction techniques, cookie attribute exploitation, SameSite bypass

## Mental Model

A session token is a capability. Whoever has the token IS the user (from the server's perspective). Session management answers these questions:
1. **Creation:** How is the token generated? Is it random enough?
2. **Transmission:** How is it sent? Is it protected in transit?
3. **Storage:** How is it stored on the client? Can attackers read it?
4. **Validation:** How does the server verify the token belongs to this user?
5. **Rotation:** When does the token change? (After login? Privilege change?)
6. **Invalidation:** When is the token destroyed? (Logout? Password change? Timeout?)

**Each of these is an attack surface.**

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (analyze session)  (test flaws)    (declare secure)     (demonstrate hijack)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Session Analysis

### Step 1.1: Identify the Session Token
Where is the session identifier?
- Cookie (name?)
- Authorization header (Bearer token?)
- Custom header (X-Auth-Token?)
- URL parameter (rare, but exists — security issue in itself)
- Request body (also unusual)

### Step 1.2: Token Format Analysis
```
Cookie: sess=abc123
     → Random string? Length?
Cookie: sess=eyJhbGc...
     → JWT (see [[jwt]])
Cookie: sess=Mzc5MzI=
     → Base64-encoded? Decode and analyze.
Cookie: sess=user123_timestamp_hash
     → Structured? Predictable?
```

### Step 1.3: Cookie Security Attributes
Examine the Set-Cookie header:
```
Set-Cookie: sessionid=abc; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=target.com
```

| Attribute | Required? | If Missing |
|-----------|-----------|-----------|
| `HttpOnly` | Yes | Session can be stolen via XSS |
| `Secure` | Yes (HTTPS) | Session sent over HTTP → MITM theft |
| `SameSite=Lax/Strict` | Yes | CSRF possible |
| `Domain` scope | Narrow | Broad domain = shared with all subdomains (subdomain XSS steals session) |
| `Path` scope | Narrow | Broad path = leaked to unrelated endpoints |

### Step 1.4: Entropy Analysis
Collect 20+ session tokens (logout, login repeatedly). Analyze:
- Length (bits of entropy)
- Character set
- Sequential patterns
- Timestamp-like components
- Similar prefixes/suffixes (indicates predictability)

```bash
# Collect tokens
for i in {1..20}; do
  token=$(curl -s -X POST https://target.com/login -d "user=test&pass=test" -c - | grep sessionid | awk '{print $7}')
  echo "$token"
done > tokens.txt

# Check for patterns
sort tokens.txt | head -10  # sorted
```

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[TOKEN-LOCATION] {cookie / header / body}
[TOKEN-FORMAT] {random / JWT / structured}
[ENTROPY] {appears random / patterns visible}
[COOKIE-ATTRIBUTES] {HttpOnly / Secure / SameSite status}
[DOMAIN-SCOPE] {narrow / broad}
[DECISION] {Proceed — potential flaws identified}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Session Management |
|-------|----------------------|
| HIGH | Session predictable, or not rotated on login, or not invalidated after security-relevant action |
| MEDIUM | Cookie attributes missing but exploitation requires additional conditions |
| LOW | Session properly managed throughout lifecycle |

### Step 2.1: Session Fixation Test

**The test:**
1. As unauthenticated user, visit the site. Note the session cookie value (call it TOKEN_A).
2. Authenticate (login).
3. Check the session cookie value after login.
4. Is it the SAME (TOKEN_A) or did it change?

If the same → fixation possible. An attacker who sets TOKEN_A on a victim's browser (via subdomain cookie, XSS, or URL parameter if the app accepts that) will have the victim's session after they log in.

### Step 2.2: Session Not Invalidated on Logout

1. Log in → save the session token.
2. Log out.
3. Replay a request with the saved token. Does it still work?

If it works → session not invalidated. A stolen token remains valid indefinitely.

### Step 2.3: Session Not Invalidated on Password Change

1. Log in on Browser A (save token).
2. Log in on Browser B with the same account.
3. From Browser B, change the password.
4. From Browser A, make a request. Does the old session still work?

If it works → password change doesn't invalidate sessions. An attacker who steals a session cannot be kicked out by changing the password.

### Step 2.4: Session Not Invalidated on Privilege Change

1. Log in as a regular user (save token A).
2. Have admin change your role to admin.
3. Using token A, does the session now have admin privileges?
4. Conversely: admin demotes a user → does the user's existing session lose privileges?

### Step 2.5: Concurrent Session Testing

Can the same account have unlimited parallel sessions? Some applications should enforce a limit (banking, healthcare). Missing this control = session theft goes undetected.

### Step 2.6: Session Prediction/Brute-Force

If entropy analysis (Phase 1) showed patterns:
- Sequential IDs → guess adjacent session IDs
- Timestamp-based → generate tokens for a narrow time window
- Short tokens (<64 bits) → brute-force feasibility depends on rate limiting

### Step 2.7: Cookie Scope Exploitation

If `Domain=.target.com` (broad scope):
- XSS on `blog.target.com` can steal session cookies for `app.target.com`
- Subdomain takeover on any subdomain = session theft

If `Path=/` (broad path):
- Session cookies sent to every path, including user-content paths where XSS may be achievable

### Step 2.8: SameSite Bypass (if CSRF-relevant)

If SameSite is Strict, cross-site requests don't include the cookie. But:
- GET requests from top-level navigation still include SameSite=Lax cookies
- Subdomains under the same site DO include the cookie
- JavaScript on the same site (XSS) can use the cookie

**Max confirmation attempts: 10.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[FLAW] {fixation / invalidation / prediction / scope / attributes}
[TEST-RESULT] {specific behavior observed}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Session token changes on authentication
- Sufficient entropy (128+ bits of randomness)
- Invalidated on logout AND password change AND role change
- Cookie attributes properly set (Secure, HttpOnly, SameSite)
- Narrow domain/path scope
- No session ID in URLs ever

---

## Phase 3: Exploitation

### Level 1: Session Hijack Demonstration
Using the confirmed flaw, demonstrate access to another session.

**Stop condition:** Session hijack demonstrated → STOP.

---

## Things to Do
- Check token rotation on EVERY transition: login, logout, password change, role change, MFA enable/disable
- Collect 20+ tokens for entropy analysis — one sample is insufficient
- Test concurrent session handling — unlimited sessions = security weakness
- Check cookie scope (domain, path) — broad scope amplifies XSS impact

## Things Not to Do
- Do not assume JWT-based sessions are immune to these flaws (see [[jwt]] for JWT-specific tests)
- Do not report missing cookie attributes alone as high severity without demonstrating exploitation
- Do not skip logout/password-change testing — it's where persistent account compromise lives

## Cross-Skill Links
- [[jwt]] — JWT is a session mechanism with its own attack surface
- [[xss]] — Missing HttpOnly + XSS = session theft
- [[csrf]] — SameSite cookie attribute is the CSRF defense
- [[oauth]] — OAuth sessions have additional failure modes
