# Memory MCP — Persistent Knowledge Graph

**Phase:** ALL | **MCP:** `@modelcontextprotocol/server-memory`  
**Token Cost:** ~100 per memory recall | **Storage:** Local filesystem (JSON)

---

## What This MCP Gives You

A persistent knowledge graph that survives between sessions and engagements. Remembers:
- Program profiles (what H1/Bugcrowd programs pay for vs reject)
- False positive patterns from previous engagements
- Technology-specific attack vectors that worked
- Chain patterns that were successful
- Tool availability and which bypass techniques worked against specific WAFs

---

## Memory Structure

### Program Profiles
```json
{
  "entity_type": "program",
  "program_name": "Shopify Bug Bounty",
  "platform": "hackerone",
  "pays_for": ["idor", "ssrf", "business_logic", "auth_bypass"],
  "rejects": ["xss_reflected_low", "clickjacking_static"],
  "known_duplicate_areas": ["/api/graphql introspection"],
  "tech_stack": ["rails", "react", "graphql", "mysql"],
  "last_engagement": "2026-08-01",
  "avg_bounty": "$5000"
}
```

### FP Patterns
```json
{
  "entity_type": "false_positive_pattern",
  "vuln_type": "sqli",
  "pattern": "MySQL error message without actual injection",
  "false_positive_count": 12,
  "confidence_adjustment": -0.3,
  "lesson": "Error-based detection alone is NOT confirmation"
}
```

### Successful Chains
```json
{
  "entity_type": "successful_chain",
  "chain": ["open_redirect", "ssrf_bypass", "metadata_access"],
  "bounty": "$50,000",
  "target_type": "e-commerce",
  "key_primitive": "Open redirect on partner subdomain"
}
```

### WAF Bypass Intel
```json
{
  "entity_type": "waf_intelligence",
  "waf_name": "cloudflare",
  "bypass_techniques_working": ["case_variation", "unicode_normalize", "newline_injection"],
  "bypass_techniques_blocked": ["null_byte", "double_encode"],
  "last_tested": "2026-07-15"
}
```

---

## Phase-Locked Usage

### Phase 0 — Load Program Profile
```
Recall all memories for entity_type=program where program_name matches target
```
This tells the Lead what to PRIORITIZE testing. If Shopify pays $50K for SSRF chains, bias testing toward SSRF vectors.

### Phase 3 — Check FP Patterns Before Testing
```
Recall memories for vuln_type matching current hypothesis
Check: Has this pattern been a FP before? If yes → deprioritize or skip
```

### Phase 5 — Store Successful Findings
```
Store memory: entity_type=finding, vuln_type=, bounty=, chain=, key_technique=
This builds institutional knowledge for future engagements.
```

### End of Engagement — Update Program Profile
```
Update program memory with: new_tech_stack, new_payout_categories, new_known_duplicate_areas
The next engagement against this program is SMARTER.
```

---

## Key Memory Queries

```bash
# Before starting new engagement
Recall all program profiles → Load the one matching current target

# Before dispatching testing phase
Recall false_positive_patterns for each hypothesis vuln_type

# During chain synthesis
Recall successful_chains → Match gadget types to known successful patterns

# After confirming a finding
Store memory for this finding with vuln_type + chain + bounty

# Before writing report  
Recall program_payout_categories → Frame impact to match what they pay for
```

---

## What You DO
- Store program profiles after each engagement
- Record every false positive with pattern + reason
- Save successful chain patterns for cross-engagement learning
- Update WAF bypass intelligence as you discover working techniques
- Query memory BEFORE generating hypotheses (FP check)
- Query memory BEFORE writing reports (program-specific framing)

## What You DO NOT Do
- Store actual secrets or PII in memory (use [REDACTED])
- Store raw HTTP responses (summarize patterns only)
- Overwrite without confirmation (memory conflicts should surface)
- Assume memory is the ONLY truth — always verify current state
