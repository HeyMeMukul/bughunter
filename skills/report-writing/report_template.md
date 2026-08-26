# Vulnerability Report Template

Copy and fill in this template for each finding.

---

```markdown
# [Vulnerability Type] on [Asset] — [Impact Summary]

## Summary

| Field | Value |
|-------|-------|
| **Severity** | Critical / High / Medium / Low |
| **CVSS 3.1 Score** | X.X |
| **CVSS Vector** | CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_ |
| **Asset** | https://target.com/endpoint |
| **Vulnerability Type** | (e.g., IDOR, SQLi, XSS, SSRF) |
| **CWE** | CWE-XXX: Description |

## Description

[2-3 paragraphs: What is the vulnerability, where does it exist, why does it exist, and what makes it exploitable.]

## Steps to Reproduce

**Prerequisites:**
- [Account requirements, tools needed, setup]

**Steps:**

1. [First action]
   ```
   [HTTP request or command]
   ```
   **Expected result:** [What should happen]

2. [Second action]
   ```
   [HTTP request or command]
   ```
   **Observed result:** [What actually happens — the vulnerability]

3. [Additional steps as needed]

**cURL Proof of Concept:**
```bash
curl -X [METHOD] 'https://target.com/endpoint' \
  -H 'Authorization: Bearer [TOKEN]' \
  -H 'Content-Type: application/json' \
  -d '{"key": "value"}'
```

## Impact

**Confidentiality:** [What data is exposed]
**Integrity:** [What data can be modified]
**Availability:** [Any availability impact]

**Business Impact:**
- [Real-world consequence 1]
- [Real-world consequence 2]
- [Regulatory/compliance implications]

**Affected Users/Scope:** [How many users/resources are affected]

## Affected Endpoints

| Endpoint | Method | Parameter | Status |
|----------|--------|-----------|--------|
| /api/endpoint1 | GET | param_name | Vulnerable |
| /api/endpoint2 | POST | body_field | Vulnerable |

## Remediation

**Immediate Fix:**
[Specific technical fix — what code change is needed]

**Long-term Recommendations:**
- [Architectural improvement 1]
- [Architectural improvement 2]
- [Testing/monitoring recommendation]

## Supporting Evidence

- [Screenshot 1 description] (attached)
- [Screenshot 2 description] (attached)
- [Video PoC] (attached, if applicable)

## References

- [OWASP reference]
- [CWE reference]
- [Relevant blog posts or research]

---

**Reporter:** [Your handle]
**Date:** [YYYY-MM-DD]
**Program:** [Program name]
```

---

## Section Writing Tips

### Description Section
- Lead with what the vulnerability IS, not how you found it
- Mention the root cause (missing validation, broken access control, etc.)
- Keep it under 150 words — triage teams skim

### Steps to Reproduce
- Assume the reader has NEVER seen your application
- Number every step
- Include the FULL HTTP request for each critical step
- Show the EXACT response that demonstrates the vulnerability
- Include a copy-pasteable cURL command

### Impact Section
- Translate technical impact to business impact
- Mention compliance implications (GDPR, PCI-DSS, HIPAA)
- Estimate the scope (how many users affected)
- Don't overstate — exaggeration hurts credibility

### Remediation Section
- Be specific enough for a developer to implement
- Include pseudocode if it helps
- Mention both quick fix and long-term improvement
- Don't lecture — be constructive
