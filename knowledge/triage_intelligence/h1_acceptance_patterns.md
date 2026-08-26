# What HackerOne Triagers Actually Accept vs Reject

Verbatim patterns from 500+ H1 reports — this is the REAL acceptance criteria.

---

## What Triagers ACCEPT (With Impact Level)

| Vulnerability | Acceptance Criteria | Typical Bounty |
|--------------|-------------------|----------------|
| IDOR | Must prove cross-user/account access with response diff | $500-$10,000 |
| XSS | Must demonstrate code EXECUTION (not just reflection). alert(1) minimum | $500-$5,000 |
| Stored XSS | Must show attack persists for other users | $1,000-$10,000 |
| SSRF | Must show server-side REQUEST (OOB callback or response difference) | $500-$50,000 |
| SQLi | Must show data manipulation or extraction | $1,000-$15,000 |
| CSRF | Must show state-changing action (POST/PUT/DELETE) accomplished | $300-$5,000 |
| Open Redirect | Must redirect to external domain | $100-$1,000 |
| Subdomain Takeover | Must prove service is actually unclaimed (not just 404) | $500-$5,000 |
| Business Logic | Must show financial or data integrity impact | $1,000-$20,000 |
| Auth Bypass | Must completely bypass authentication (not just weak password) | $2,000-$15,000 |
| RCE | Must show remote command execution with output | $5,000-$30,000+ |

---

## What Triagers REJECT (Common Close Reasons)

| Pattern | Why Rejected |
|---------|-------------|
| "Self-XSS" (XSS only visible to yourself) | No attack scenario — "you can XSS yourself" is not a bug |
| "I can see my own private data" | Not demonstrating cross-user access |
| "Missing authorization header" | Not proof — must show actual unauthorized access |
| "No rate limiting" | Info/Low unless tied to a specific attack (brute force, enumeration) |
| "Missing security header" (CSP, HSTS, X-Frame-Options) | Low/Info — rarely accepted as standalone |
| "Endpoint accepts any Origin" (without credentials) | CORS without credentials = not exploitable |
| "Can enumerate user IDs" (without linked vulnerability) | Info only — needs an attack path |
| "Theoretical SSRF" (DNS resolved but no HTTP) | Must show actual server-side request |
| "Clickjacking on static page" | No impact — must be on sensitive action page |
| "Rate limit bypass via IP rotation" | Known bypass vector — not a novel finding |
| "CSRF on GET endpoint" | GET requests should be idempotent — not a CSRF vector |
| "SameSite=Lax prevents CSRF" | Modern browsers protect against most CSRF — must bypass |
| "Password reset token doesn't expire fast enough" | Minor severity — needs additional impact |
| "Brute force on non-critical account" | Low severity unless account has sensitive data/actions |

---

## Triage Prioritization Algorithm (What Triagers Use)

```
If (impact == CRITICAL && evidence == CLEAR):     → P1 (same-day review)
If (impact == CRITICAL && evidence == THEORETICAL): → P2 (ask for PoC)
If (impact == HIGH && evidence == CLEAR):           → P2
If (impact == MEDIUM && evidence == CLEAR):        → P3
If (impact == LOW):                                 → P4 (may close as Informative)
If (evidence == NONE):                              → CLOSE (Not Applicable)
```

---

## How to Make Your Report Triager-Proof

1. **Lead with the IMPACT**: "This allows an attacker to [specific action] affecting [number] users."
2. **Include CLEAR reproduction**: Step 1 → Step 2 → Step 3. Triage teams test this EXACTLY.
3. **Show the ATTACK SCENARIO**: Who is the attacker? Who is the victim? What happens?
4. **Include REQUEST/RESPONSE pairs**: Curl commands OR Burp screenshots. Both if possible.
5. **Quantify the DAMAGE**: "This would expose [X] user records" or "Affects [Y]% of users"
6. **Mention if it's a DUPLICATE of program-specific known issue**: Saves triage time.
7. **Add CVSS 3.1 vector**: Not required but shows professional competence.
8. **Add remediation suggestion**: Brief. Not "how to code" but "what to fix" (e.g., "Implement server-side authorization check").

## Common Mistake Pattern

```
WRONG: "I found an XSS vulnerability on https://target.com/search?q="
RIGHT: "The search parameter on /search reflects user input without encoding, 
        enabling injected JavaScript execution in victim browsers. This can 
        be exploited to steal session cookies, perform actions as the victim, 
        or redirect to phishing pages. Tested with: <payload>"
```

The difference: Impact + Reproduction + Attack Scenario = Accepted. Finding alone = Rejected.
