# Real-World Chain Examples with Bounty Amounts

Extracted from disclosed reports — these are the chains that earned elite hunters $10K-$110K+.

---

## Chain 1: Open Redirect → SSRF → AWS Metadata → $50,000 (Shopify)

**Vulnerabilities:** Open Redirect (Low), SSRF (Medium)
**Chain:** Open redirect on partner portal → bypassed SSRF whitelist → IMDS access → IAM credentials
**Lesson:** Never dismiss open redirects — they're bypass primitives for every URL restriction.

---

## Chain 2: CSRF → Account Takeover → Self-XSS → Full Control ($15,000)

**Vulnerabilities:** CSRF on email change, self-XSS in profile
**Chain:** CSRF to change victim's email → password reset → login as victim → self-XSS in profile → stored XSS visible to admin → admin takeover
**Lesson:** CSRF + self-XSS = full chain. Self-XSS alone would be rejected.

---

## Chain 3: IDOR → Mass Data Extraction → $110,000 (Meta/Facebook)

**Vulnerabilities:** IDOR on GraphQL, Batch request abuse
**Chain:** Found internal GraphQL query → batch request with multiple user IDs → returned PII for ALL users → mass data extraction
**Lesson:** Batch operations multiply IDOR impact. One endpoint → thousands of records.

---

## Chain 4: Race Condition → Unlimited Coupon → $25,000

**Vulnerabilities:** Race condition on coupon application
**Chain:** Apply coupon → race 100 parallel requests → all accepted before coupon marked as used → unlimited discount stacking
**Lesson:** Race conditions on financial operations are gold.

---

## Chain 5: Subdomain Takeover → CSP Bypass → XSS → $8,000

**Vulnerabilities:** Subdomain takeover, CSP whitelist inclusion
**Chain:** Take over forgotten staging subdomain → subdomain is in CSP whitelist → host XSS payload → bypass CSP on main domain
**Lesson:** Subdomain takeover isn't just phishing — it's a CSP bypass primitive.

---

## Chain 6: OAuth CSRF → Account Linking → Account Takeover ($20,000)

**Vulnerabilities:** CSRF on OAuth consent, account linking feature
**Chain:** CSRF to force victim into OAuth consent → link victim's account to attacker's OAuth → login via OAuth → full victim account access
**Lesson:** OAuth + CSRF = ATO. Every OAuth implementation needs CSRF on consent screen.

---

## Chain 7: Info Disclosure → IDOR → Critical ($5,000 - $10,000)

**Vulnerabilities:** API leaks user IDs, IDOR on user endpoint
**Chain:** Info disclosure endpoint returns all user IDs → use leaked UUID in IDOR-vulnerable endpoint → access any user's data
**Lesson:** Info disclosure that leaks IDs is a multiplier. Always check what IDs are exposed.

---

## Chain 8: HTTP Smuggling → Cache Poison → XSS × All Users ($15,000)

**Vulnerabilities:** HTTP request smuggling, cache poisoning, reflected XSS
**Chain:** Smuggle request with XSS payload → poison cache → all users get XSS → mass session theft
**Lesson:** Smuggling + caching = multi-user impact from single-user vulnerability.

---

## Chain 9: XXE → SSRF → Internal API → SQLi → Data Dump ($18,000)

**Vulnerabilities:** XXE, SSRF, SQL injection
**Chain:** XXE to read internal config → discover internal API → SSRF to internal API → API has SQLi → dump customer database
**Lesson:** Server-side bugs chain. XXE is a gateway to internal exploration.

---

## Chain 10: Host Header → Password Reset Poison → ATO ($5,000 - $12,000)

**Vulnerabilities:** Host header injection, password reset poisoning
**Chain:** Inject `Host: evil.com` → reset link generated with `evil.com` → victim clicks link → token sent to attacker → reset password → ATO
**Lesson:** Password reset functions are the #1 target for host header attacks.

---

## The "Chain Multiplier" Rule

| Starting Bug | Alone (Bounty) | Chained (Bounty) | Multiplier |
|-------------|----------------|------------------|------------|
| Info Disclosure | $0-$500 | $2,000-$10,000 | 5-20x |
| Open Redirect | $0-$500 | $5,000-$50,000 | 10-100x |
| CSRF | $500-$1,500 | $5,000-$20,000 | 3-15x |
| Self-XSS | $0 | $5,000-$15,000 | ∞ |
| Blind SSRF | $500-$2,000 | $5,000-$50,000 | 3-25x |
| Subdomain Takeover | $500-$2,000 | $5,000-$15,000 | 3-10x |

## Elite Hunter Rule

> **"Every Low finding is a Critical finding waiting for its chain partner."**
> 
> Spend 15 minutes thinking about chains before submitting ANY Medium or Low finding.
> The difference between $500 and $50,000 is usually ONE additional vulnerability in the chain.
