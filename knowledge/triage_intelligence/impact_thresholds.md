# Impact Thresholds — What Gets What Bounty

## Critical ($5,000 - $50,000+)
- **Full Account Takeover** — Resetting passwords, stealing sessions, bypassing MFA
- **RCE on production** — Remote code execution with demonstrated shell access
- **Mass data extraction** — >10,000 user records, PII, financial data
- **SSRF → Cloud Credentials** — Metadata access leading to AWS/GCP/Azure account access
- **Payment manipulation** — Modifying prices, stealing funds, unlimited discounts

## High ($1,000 - $5,000)
- **IDOR on sensitive data** — Accessing other users' PII, financial, health data
- **SQLi with data extraction** — Dumping database tables
- **Stored XSS affecting other users** — Persistent cross-site scripting
- **SSRF to internal services** — Without cloud credential access (yet)
- **Auth bypass** — Bypassing authentication without full ATO
- **Race condition on financial operations** — Coupon stacking, double-spending

## Medium ($500 - $2,000)
- **CSRF on critical actions** — Changing email, password, adding SSH keys
- **IDOR on non-sensitive data** — Public profile fields, settings
- **Reflected XSS** — Demonstrated with session theft PoC
- **Open redirect** — Chained with OAuth or other vulnerability
- **Subdomain takeover** — Verified unclaimed service
- **Business logic bypass** — Workflow manipulation

## Low ($100 - $500)
- **Reflected XSS** — Basic alert(1), no chaining
- **Open redirect** — Standalone, no chain
- **Clickjacking** — On a critical action page
- **Information disclosure** — Non-sensitive info (server version, stack traces)
- **Missing security headers** — CSP, HSTS, X-Frame-Options (standalone)

## Informative ($0)
- Self-XSS
- Missing rate limiting (without attack scenario)
- Missing security headers (on low-sensitivity pages)
- Theoretical vulnerabilities without PoC
- Previously reported known issues (duplicate)
