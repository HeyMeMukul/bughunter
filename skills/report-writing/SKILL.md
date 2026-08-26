---
name: report-writing
description: Professional vulnerability report generation for bug bounty submissions and penetration test deliverables. Use after any vulnerability is confirmed in exploitation phase. Generates structured markdown reports with asset details, CVSS scoring, proof-of-concept steps, impact analysis, and remediation recommendations. Produces reports that maximize acceptance rates and bounty awards.
---

# Professional Vulnerability Report Writing

A well-written report is the difference between a bounty and a "Not Applicable." Reports must be clear enough for a developer to reproduce the issue, precise enough for a security team to assess risk, and structured enough for program managers to triage efficiently.

## Reference Files

- [cvss_calculator.md](./cvss_calculator.md) — CVSS 3.1 metric selection guide
- [report_template.md](./report_template.md) — Copy-paste report template

## When to Write a Report

Write a report when:
- Phase 3 (Exploitation) of any skill reaches confirmed impact
- A vulnerability is demonstrated with proof (not theoretical)
- The finding is within program scope
- The impact meets the program's minimum severity threshold

---

## Report Structure

Every report must contain these sections in this order:

### 1. Title
Format: `[Vulnerability Type] on [Asset] — [Impact Summary]`

**Good titles:**
```
IDOR on /api/v2/users/{id}/profile — Unauthorized Access to Any User's PII
Blind SQL Injection on search parameter — Full Database Extraction
Stored XSS in Comment Field — Account Takeover via Session Theft
SSRF via PDF Generator — AWS Credential Extraction from Metadata
Missing Rate Limit on OTP Endpoint — Account Takeover via Brute Force
```

**Bad titles:**
```
Bug found                          (no information)
XSS                                (too vague)
SQL injection vulnerability        (which endpoint? what impact?)
Multiple vulnerabilities           (one report per vulnerability)
```

### 2. Severity & CVSS Score
```
Severity: Critical / High / Medium / Low
CVSS 3.1 Score: X.X
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
```
See [cvss_calculator.md](./cvss_calculator.md) for metric selection.

### 3. Asset Information
```
Asset: https://target.com/api/v2/users
Asset Type: API Endpoint
Program: [Program Name]
Platform: [HackerOne/Bugcrowd/Intigriti]
```

### 4. Vulnerability Description
Write 2-3 paragraphs explaining:
- What the vulnerability is (technical description)
- Where it exists (specific endpoint, parameter, function)
- Why it exists (root cause — missing validation, broken access control, etc.)
- What makes it exploitable (the specific condition)

### 5. Steps to Reproduce (PoC)

This is the MOST IMPORTANT section. If the triage team cannot reproduce, the report is rejected.

**Format: Numbered steps, each with a specific action and expected result.**

```markdown
## Steps to Reproduce

**Prerequisites:**
- Two accounts: Account A (attacker) and Account B (victim)
- Account A: attacker@example.com (user role)
- Account B: victim@example.com (user role)

**Steps:**

1. Log in as Account A (attacker@example.com)

2. Navigate to your profile: `GET /api/v2/users/123/profile`
   - Response shows Account A's profile data (Status: 200)

3. Modify the request to use Account B's ID:
   ```
   GET /api/v2/users/456/profile
   Authorization: Bearer <Account_A_Token>
   ```

4. Observe that Account B's full profile is returned:
   ```json
   {
     "id": 456,
     "email": "victim@example.com",
     "phone": "+1-555-0123",
     "address": "123 Victim St",
     "ssn_last4": "1234"
   }
   ```

5. This confirms that Account A can access ANY user's profile by iterating the ID parameter.
```

**PoC Rules:**
- Include the EXACT HTTP request (method, URL, headers, body)
- Include the EXACT response (status, relevant body)
- Redact actual PII but show the structure
- Each step should be independently verifiable
- Include screenshots or video if the platform supports it
- Include cURL commands for API-based vulnerabilities

### 6. Impact Analysis

Describe the real-world impact in business terms:

```markdown
## Impact

**Confidentiality:** An attacker can access the personal data (email, phone,
address, partial SSN) of ALL users on the platform. With sequential IDs
ranging from 1 to approximately 50,000, the entire user database is
extractable via scripted requests.

**Integrity:** Not directly affected — this is a read-only IDOR.

**Availability:** Not directly affected.

**Business Impact:**
- GDPR/CCPA violation — exposure of personal data
- Regulatory fines — up to 4% of annual revenue under GDPR
- Reputational damage if exploited at scale
- User notification requirements under breach disclosure laws
```

### 7. Affected Endpoints
```markdown
## Affected Endpoints

| Endpoint | Method | Parameter | Vulnerable |
|----------|--------|-----------|------------|
| /api/v2/users/{id}/profile | GET | id (path) | Yes |
| /api/v2/users/{id}/orders | GET | id (path) | Yes |
| /api/v2/users/{id}/settings | GET | id (path) | Not tested |
| /api/v2/users/{id}/settings | PUT | id (path) | Yes (write IDOR) |
```

### 8. Remediation

```markdown
## Remediation

**Immediate Fix:**
Implement server-side authorization checks on all endpoints that accept
user identifiers. Before returning data, verify that the authenticated
user's session owns the requested resource:

```pseudocode
if request.user.id != requested_user_id:
    return 403 Forbidden
```

**Long-term Fix:**
- Implement a centralized authorization middleware that enforces
  object-level access control on all resource endpoints
- Replace sequential integer IDs with UUIDs to reduce enumeration risk
  (defense in depth — NOT a replacement for authorization checks)
- Add automated IDOR testing to the CI/CD pipeline
- Implement rate limiting on user-specific API endpoints
```

### 9. References (Optional)
```markdown
## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## CVSS 3.1 Quick Scoring Guide

### Common Vulnerability CVSS Scores

| Vulnerability | Typical CVSS | Typical Severity |
|--------------|-------------|-----------------|
| RCE (unauthenticated) | 9.8 | Critical |
| SQL Injection (data extraction) | 8.6 | High |
| SSRF to cloud credentials | 9.1 | Critical |
| Full account takeover | 8.8 | High |
| IDOR (PII access) | 6.5 | Medium |
| Stored XSS (other users) | 6.1 | Medium |
| IDOR (write) | 7.5 | High |
| Reflected XSS | 6.1 | Medium |
| CORS (sensitive data) | 7.5 | High |
| CSRF (state-changing) | 4.3 - 8.0 | Medium - High |
| Open redirect | 4.7 | Medium |
| Info disclosure | 5.3 | Medium |
| Missing rate limit | 5.3 | Medium |

See [cvss_calculator.md](./cvss_calculator.md) for precise metric selection.

---

## Report Quality Checklist

Before submitting, verify:

- [ ] Title is specific and descriptive
- [ ] CVSS score is calculated with the correct vector
- [ ] Steps to reproduce are numbered and include exact requests/responses
- [ ] Impact is described in business terms, not just technical terms
- [ ] Remediation is actionable (not just "fix it")
- [ ] No actual PII or sensitive data in the report (redacted)
- [ ] Finding is within program scope
- [ ] Only ONE vulnerability per report (don't combine)
- [ ] cURL commands included for API vulnerabilities
- [ ] Screenshots/video included if applicable

---

## Things to Do

- Write the report immediately after confirming exploitation — details are fresh
- Include the minimum reproduction steps — fewer steps = easier to triage
- Describe impact from the BUSINESS perspective, not just technical
- Provide remediation that a developer can actually implement
- Use the program's preferred severity rating (some use their own, not CVSS)
- If the vulnerability chains multiple bugs, explain each link in the chain

## Things Not to Do

- Do not submit theoretical vulnerabilities — only confirmed, reproducible findings
- Do not include multiple vulnerabilities in one report
- Do not use vague impact descriptions ("this could be bad")
- Do not submit without testing your own PoC steps end-to-end
- Do not include actual user data — redact everything
- Do not demand a specific bounty amount in the report
- Do not argue severity in the initial report — let the triage team assess first
