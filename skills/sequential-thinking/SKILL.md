# Sequential Thinking MCP — Multi-Step Reasoning Engine

**Phase:** 2/3 (Chain & Hypothesis) | **MCP:** `@anthropic/mcp-server-sequential-thinking`  
**Token Cost:** ~1000-3000 per reasoning session | **Model:** Pro (strategic)

---

## What This MCP Gives You

Structured multi-step reasoning that chains through complex problems systematically. Instead of one-shot analysis, the agent thinks through 5-15 sequential steps, revising hypotheses as new information emerges.

---

## When To Use Sequential Thinking

### Use It When:
- You have 5+ gadgets and need to find chains between them (M9 chain synthesis)
- You're analyzing a complex authorization flow with multiple trust boundaries
- You're trying to pivot from a confirmed finding (how does this get me to Critical?)
- You're analyzing deep business logic flows (multi-step financial transactions)
- You need to work through "what if" scenarios systematically
- Response behavior is subtle and needs multi-step differential analysis

### Do NOT Use It When:
- Running tools (that's Flash/Worker) — this is STRATEGIC reasoning
- Simple one-parameter hypotheses (single IDOR, single XSS) — overkill
- Tasks that need real-time HTTP interaction (Burp MCP handles that)
- Initial Phase 0 recon (discovery, not analysis)

---

## Chain Synthesis Workflow (M9 Enhanced)

Instead of Lead manually reading all profiles, Sequential Thinking MCP enables automated chain reasoning:

```
Step 1: "I have gadget G-001 (info_disclosure leaking user IDs) at EP-012"
Step 2: "I have gadget G-005 (idor_read on /api/users/{id}) at EP-003"  
Step 3: "Can I chain these? Info disclosure → IDOR?"
Step 4: "Yes — leaked UUIDs from EP-012 are accepted by EP-003"
Step 5: "What's the impact? Mass user data extraction"
Step 6: "Confidence: HIGH (both gadgets confirmed)"
Step 7: "Priority score: 8 × 5 = 40 → Critical chain candidate"
Step 8: "Test sequence: 1) Query EP-012 for user list, 2) For each UUID, query EP-003"
Step 9: "Success criteria: Response from EP-003 returns non-own-user data"
Step 10: "Final verdict: Dispatch testing on this chain immediately"
```

---

## Pivot Reasoning

When a finding seems LOW impact, Sequential Thinking helps find escalation paths:

```
Step 1: "Confirmed finding: Open redirect on /logout?redirect=evil.com"
Step 2: "Impact alone: Low ($100-500). Need chain."
Step 3: "What requires a redirect? → OAuth flows, SSO, password reset"
Step 4: "Check: Does target use OAuth? YES (Google + GitHub login)"
Step 5: "Check: Does OAuth login accept redirect_uri? YES"
Step 6: "Check: Can redirect_uri be modified to use /logout?redirect=https://evil.com?"
Step 7: "Hypothesis: OAuth CSRF → redirect to attacker's server → token theft → ATO"
Step 8: "Confidence: MEDIUM (need to verify redirect_uri validation)"
Step 9: "Priority: HIGH (potential ATO from Low finding)"
Step 10: "Next action: Test OAuth redirect_uri manipulation"
```

---

## Business Logic Analysis

For complex multi-step flows (checkout, money transfer, subscription changes):

```
Step 1: Map the complete flow: Add to cart → Apply coupon → Checkout → Payment → Confirmation
Step 2: Identify trust boundaries: Cart (client-side) vs Coupon validation (server-side) vs Payment (third-party)
Step 3: Where does the developer trust client input? Cart total? Coupon code? Quantity?
Step 4: Test order: What if I modify cart total AFTER coupon is validated? 
Step 5: Test order: What if I submit checkout with negative quantity?
Step 6: Race condition: What if I complete payment AND cancel order simultaneously?
Step 7: Each step either confirms or denies a hypothesis → adjust next step
```

---

## Integration with the Framework

```bash
# In Lead prompt — when chain synthesis is needed:
/think "Analyze all EP-XXX.profile.yaml gadgets and find viable chains with priority >12"

# In Worker prompt — when complex analysis is needed:
/think "This endpoint has 7 parameters with different reflection contexts. 
         Analyze each for XSS potential in sequence."

# For pivot decisions:
/think "I have confirmed XSS on one page. What adjacent endpoints could this escalate to ATO?"
```

---

## What You DO
- Use for M9 chain synthesis (replaces manual Lead analysis)
- Use for complex pivot decisions (how to escalate impact)
- Use for business logic multi-step analysis
- Use when you need structured "what if" reasoning
- Output structured: numbered steps with confidence at each step

## What You DO NOT Do
- Use for simple decisions (one endpoint, one parameter)
- Use during Phase 1 (tool-driven phase) — save tokens
- Use when you can decide in one step
- Run in Worker subagent for tactical tasks (reserve for strategic Lead context)
