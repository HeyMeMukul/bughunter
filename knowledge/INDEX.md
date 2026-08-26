# Knowledge Base — Attack Patterns from Disclosed Reports

This is the **hunter's mental model library**. It contains manually curated patterns plus a provenance-aware, metadata-only seed corpus derived from public disclosures. Use it to generate and rank hypotheses, not as proof that a target is vulnerable or as permission to test an asset. The ingestion and retrieval rules live in `SCHEMA.md` and `INGESTION_PLAN.md`. The current expanded high-bounty set contains 921 public index records above $1,000 plus 8 curated article/methodology cases; the latter retain source-quality and corroboration status.

---

## Directory Structure

```
knowledge/
├── INDEX.md                          ← This file
├── SCHEMA.md                          ← Provenance, redaction, and retrieval record schema
├── INGESTION_PLAN.md                  ← Public-source ingestion and evaluation protocol
├── corpus_seed/
│   ├── hackerone_paid_gt100.ndjson    ← 2,810 metadata-only public HackerOne index records
│   ├── hackerone_paid_gt1000.ndjson   ← 921 metadata-only records above $1,000
│   ├── curated_high_bounty_methodologies.ndjson ← 8 reviewed/flagged article cases
│   └── expanded_high_bounty_gt1000.ndjson ← Combined 929-record high-bounty corpus
├── disclosed_reports/
│   ├── idor_patterns.md              ← IDOR/BOLA patterns from real reports
│   ├── ssrf_patterns.md              ← SSRF chaining patterns
│   ├── auth_bypass_patterns.md       ← Authentication bypass techniques
│   ├── business_logic_patterns.md    ← Business logic exploitation
│   ├── xss_patterns.md               ← XSS context-specific bypasses
│   ├── chain_patterns.md             ← Multi-vuln chain examples with bounties
│   └── rce_patterns.md               ← RCE exploitation patterns
├── attack_patterns/
│   ├── trust_boundary_violations.md  ← Common trust boundary failures
│   ├── developer_assumptions.md      ← Developer assumptions that lead to bugs
│   └── input_vector_matrix.md        ← Input vectors organized by attack surface
├── triage_intelligence/
│   ├── h1_acceptance_patterns.md     ← What HackerOne triagers actually accept
│   ├── bugcrowd_acceptance.md        ← Bugcrowd-specific acceptance patterns
│   ├── impact_thresholds.md          ← What impact = what bounty tier
│   └── common_duplicate_reasons.md   ← Why reports get closed as duplicates
└── hunter_calendar/
    └── when_to_hunt.md               ← When to hunt specific vuln types
```

## Key Mental Models

### The Trust Boundary Principle
Every critical bug exists at a TRUST BOUNDARY — the point where the application stops verifying and starts trusting. The most profitable boundaries:
1. **Frontend → Backend** — Frontend validates, backend trusts
2. **Backend → Database** — ORM pattern queries can be bypassed
3. **Backend → Internal Services** — Internal APIs often lack auth
4. **CDN → Origin** — Cache poisoning, header smuggling
5. **OAuth Provider → Application** — Token validation gaps
6. **User Input → Template Engine** — SSTI at any reflection point
7. **User Input → Command Execution** — Command injection at OS boundary
8. **User Input → PDF Generator** — SSRF/LFI in server-side rendering
9. **S3 Bucket → Public Internet** — Misconfigured cloud storage
10. **DNS → Cloud Service** — Dangling records → subdomain takeover

### The Impact Maximization Rule
Every finding must answer: "What is the MAXIMUM damage an attacker can do?"
- IDOR Read → Can you escalate to IDOR Write?
- XSS → Can you steal session tokens?
- SSRF → Can you access cloud metadata?
- SQLi → Can you extract user data?
- Open Redirect → Can you chain with OAuth?
- Info Disclosure → What IDs/keys does it leak that enable other attacks?

### The "Would Triagers Accept This?" Test
Triage teams reject reports that:
1. Don't demonstrate IMPACT (finding XSS without showing what it does)
2. Are theoretical (no actual reproduction)
3. Don't show the attack scenario (just a PoC without narrative)
4. Don't quantify impact (how many users affected? what data exposed?)
5. Don't reference the program's scope and rules
