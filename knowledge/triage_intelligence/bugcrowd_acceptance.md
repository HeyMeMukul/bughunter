# Bugcrowd Acceptance Patterns

## What Bugcrowd Triagers Value

Bugcrowd triagers tend to prioritize differently from H1:

1. **Clear business impact required** — Bugcrowd is stricter on impact demonstration
2. **Reproduction steps must be exact** — One missing step and they close as "Cannot Reproduce"
3. **CVSS scores matter** — Bugcrowd uses CVSS for bounty calculation more strictly
4. **Proof of concept video preferred** — Video PoC > screenshots > text description

## Bounty Ranges (Typical VRT)

| Technical Severity | VRT Priority | Typical Bounty |
|-------------------|-------------|----------------|
| P1 — Critical | Account takeover, RCE, mass data breach | $2,000-$15,000 |
| P2 — High | IDOR, SQLi, SSRF | $1,000-$5,000 |
| P3 — Medium | Stored XSS, CSRF, LFI | $500-$2,000 |
| P4 — Low | Reflected XSS, Open Redirect | $100-$500 |

## Common Rejection Reasons

- "Not reproducible" — Missing step, stale session, expired token
- "Informative" — No demonstrated impact
- "Duplicate" — Someone reported it first (check the program's known issues)
- "Out of scope" — Always check scope FIRST

## Bugcrowd-Specific Tips

1. Use Bugcrowd's VRT to classify severity — it determines your bounty
2. Include a `curl` command PoC — triagers test these immediately
3. Video PoCs on Bugcrowd increase acceptance rate significantly
4. Bugcrowd programs often have stricter rate limits — enforce them
