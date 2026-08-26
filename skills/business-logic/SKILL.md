---
name: testing-business-logic
description: Business logic flaw testing — the vulnerability class that automated scanners CANNOT find. Use when testing multi-step workflows, financial operations, state machines, approval chains, subscription management, limit-enforced operations, or ANY process where the developer made assumptions about user behavior. This skill teaches you to think like the developer, identify their assumptions, and systematically break them. Covers step skipping, parameter manipulation, state abuse, negative value attacks, race conditions on limits, cross-user flow interference, and constraint violation.
---

# Business Logic Testing

Business logic vulnerabilities are not bugs in code — they are bugs in THINKING. The developer assumed users would follow a specific path, and the application doesn't enforce that assumption server-side. Automated scanners can't find these because there's no malicious payload — every request looks legitimate. The vulnerability is in the SEQUENCE, the VALUES, or the OMISSIONS.

## Reference Files

- [patterns.md](./patterns.md) — Common business logic flaw patterns by industry and feature type

## Mental Model

Every business logic flaw follows this reasoning chain:

1. **"What did the developer assume?"**
   - Users complete steps in order
   - Prices/quantities are positive
   - One coupon per customer
   - The user who started a flow finishes it
   - Payment happens before delivery
   - Verification precedes access

2. **"Is that assumption enforced server-side?"**
   - Frontend validation ≠ server-side enforcement
   - If you can send the request directly (bypassing the UI), is the constraint still enforced?

3. **"What happens when the assumption is violated?"**
   - The application may fail open (grant access, complete transaction, skip verification)
   - Or it may fail closed (error, abort, rollback)
   - Or it may enter an undefined state (the developer never considered this case)

**The key question is always:** *"What constraint is the developer relying on that isn't technically enforced?"*

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (map workflow)    (break assumptions) (declare secure)   (demonstrate impact)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Map the Business Process

### Step 1.1: Workflow Tracing

Trace the COMPLETE multi-step process by performing it normally while proxying all requests:

**For each step, document:**
```
Step N: [Action description]
  Endpoint: [URL + method]
  Request: [key parameters and values]
  Response: [status + key fields]
  State change: [what changed in the system]
  Prerequisite: [what must have happened before this step]
  Carries forward: [what data/token connects to the next step]
```

### Step 1.2: Constraint Mapping

For each step in the workflow, identify EVERY assumption:

**Sequential constraints:** "Step 3 requires Step 2 to complete first"
- How is this enforced? Server-side state? Token? Session flag?
- Can you call Step 3's endpoint directly without completing Step 2?

**Value constraints:** "Prices are always positive, quantities are ≥ 1"
- What happens with 0? -1? -99999? 0.001? 999999999?
- What happens with wrong data types? String where number expected? Array where string expected?

**Identity constraints:** "The user who initiates also completes"
- Can you start as User A and complete as User B?
- Can you use User A's state/token in User B's session?

**Temporal constraints:** "Offer expires after first use or after date X"
- Can you reuse an expired token/code?
- Can you manipulate client-side timestamps?

**Quantity/limit constraints:** "One per customer, max 10 per order"
- Race condition? (test with [[race-condition]])
- What's the enforcement mechanism? Database constraint? Application logic? Frontend only?

**Authorization constraints:** "Only the owner can modify, only admin can approve"
- Is this enforced per-endpoint or globally?
- Does modifying the user ID in the request bypass it? (→ [[idor]])

### Step 1.3: Developer Intent Analysis

Think about WHY each endpoint exists:
- What PROBLEM does this feature solve for the user?
- What EDGE CASES did the developer probably not test?
- What THIRD-PARTY INTEGRATIONS does this feature touch? (Payment gateways, email services, external APIs)
- What RACE CONDITIONS are possible? (Two requests hitting the same resource simultaneously)

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[WORKFLOW] {name and description}
[STEPS] {numbered step sequence with endpoints}
[CONSTRAINTS] {every assumption identified}
[STATE-CARRIERS] {tokens, IDs, session flags connecting steps}
[HIGHEST-VALUE-CONSTRAINTS] {which assumptions, if broken, cause the most impact}
[DECISION] Proceed — test highest-value constraints first
```

---

## Phase 2: Confirmation — Break the Assumptions

### Confidence Definitions

| Level | For Business Logic |
|-------|--------------------|
| HIGH | Violating a constraint produces an outcome the developer clearly did not intend, with measurable business impact |
| MEDIUM | Constraint can be violated but the outcome has no clear business impact, or the impact is theoretical |
| LOW | All constraints are properly enforced server-side |

### Technique 1: Step Skipping

**What:** Go directly to a later step without completing prerequisites.

**How:** Send the request for Step N without completing Steps 1 through N-1.

**Common targets:**
- Skip payment in checkout → complete order without paying
- Skip email verification → create unverified but active account
- Skip CAPTCHA → automated action
- Skip MFA → access without second factor
- Skip approval → self-approve a request
- Skip terms acceptance → create account without agreeing to terms

**Key reasoning:** The server must track which steps are completed. If it doesn't → step skipping works. Common implementations that ARE vulnerable: relying on frontend flow, relying on Referer header, no server-side state tracking.

### Technique 2: Parameter Manipulation

**What:** Modify values the developer assumes are controlled.

**Numeric manipulation:**
```
Price: 100.00 → 0, -1, 0.01, 0.001, 99999999, NaN, Infinity
Quantity: 1 → 0, -1, -99, 0.5, 99999999
Discount: 10% → 100%, 110%, -10%, 99.99%
Amount: 50.00 → -50.00 (negative amount = credit?)
Duration: 30 days → 36500 days (100 years)
Count: 1 → 0 (zero items but order processes?)
```

**Type manipulation:**
```
Expected string → send array: "value" → ["value1", "value2"]
Expected number → send string: 100 → "hundred"
Expected object → send null: {"key": "value"} → null
Expected boolean → send number: true → 2
```

**Currency/unit manipulation:**
```
Currency: USD → JPY (¥100 ≈ $0.70 — same number, different value)
Unit: kg → g (1 kg vs 1 g — 1000x difference)
Timezone: UTC → UTC+14 (manipulate time-based restrictions)
```

### Technique 3: State Manipulation

**What:** Modify state-carrying tokens/parameters to alter the process flow.

- Reuse a one-time token after it's been "consumed"
- Modify an order ID to reference another user's order
- Change a status field directly: `status: "pending"` → `status: "approved"`
- Modify a step indicator: `step: 3` → `step: 5` (jump ahead)
- Replay a completed transaction token

### Technique 4: Parameter Dropping

**What:** Completely remove a parameter that the developer assumes will always be present.

- Drop the OTP/PIN parameter → does the server default to "valid"?
- Remove the CAPTCHA token → does verification pass automatically?
- Remove a price field → does the server use a default (possibly $0)?
- Remove a required field → does the server use a permissive default?
- Remove the CSRF token → does the server skip validation? (→ [[csrf]])

**Why this works:** Many frameworks use "fail open" defaults. If a validation field is missing, the validation function may return `None` or `undefined`, which evaluates to `false` in some contexts and `true` in others. The developer assumed the field would always be present because the frontend always sends it.

### Technique 5: Cross-User Flow Interference

**What:** Start a workflow as one user, complete it as another.

- Begin checkout as User A, use User A's cart token to checkout as User B
- Start password reset for User A, use the reset link in User B's session
- Share an invite token intended for User A, accept it as User B
- Start an approval flow as User A (requester), approve it as User A (approver) by manipulating the request

### Technique 6: Business Rule Boundary Testing

**What:** Test at the exact boundaries of business rules.

- If discount max is 50%, try 50%, 50.01%, 51%
- If free shipping above $100, try $99.99 then add $0.01 discount
- If trial is 14 days, try on day 14 at 23:59:59
- If max 3 attempts, try on the 3rd, 4th, and simultaneously (race)
- If one per customer, try with different addresses/emails/payment methods

### Technique 7: Negative Value Attacks

**What:** Use negative numbers to reverse the direction of a transaction.

- Transfer amount: -$100 → instead of sending money, you receive it
- Refund amount: -$50 → instead of receiving refund, you're charged (but item is still "returned")
- Quantity: -1 → negative quantity × positive price = credit to your account
- Points redemption: -500 points → adds points instead of deducting

**This is more common than you'd think.** Many financial applications validate that fields are present but don't check the sign.

### Technique 8: Integer Overflow/Underflow

**What:** Use extremely large or small numbers to cause arithmetic errors.

```
Quantity: 2147483647 (max 32-bit int) → overflow to negative
Quantity: 2147483648 → overflow to -2147483648 → negative total price
Amount: 99999999999999 → may exceed database column limits
```

**Max confirmation attempts: 15 across different manipulation types.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {step skip / param manipulation / state manipulation / param drop / cross-user / boundary / negative}
[ASSUMPTION-VIOLATED] {specific constraint broken}
[INPUT] {what you sent}
[OUTCOME] {what happened — unexpected behavior}
[BUSINESS-IMPACT] {financial, access, integrity}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to exploitation / Try different assumption / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Step skipping attempts rejected with proper error handling
- Parameter manipulation detected and rejected server-side
- State tokens are integrity-protected and server-validated
- Cross-user flow mixing properly rejected
- Negative values handled correctly
- At least 5 different constraint types tested

### Structured Log
```
[VULN-NEGATIVE]
[WORKFLOW] {name}
[STEPS-RUN] {techniques attempted with specific details}
[SIGNAL] {all constraints enforced server-side}
[CONCLUSION] {workflow properly enforces business rules}
[ACTION] Workflow cleared for business logic flaws.
```

---

## Phase 3: Exploitation

### Level 1: Demonstrate Impact
Show the concrete business impact with evidence:
- Free purchase completed
- Unauthorized access granted
- Approval bypassed
- Limit circumvented
- Financial loss demonstrated (with test values)

### Level 2: Quantify Scale
- Is it repeatable? Can it be automated?
- What's the financial impact per exploitation?
- How many users could exploit this?

**Stop condition:** At first demonstrated business-impact violation → STOP. Generate report.

---

## Things to Do

- Think about what the developer ASSUMED, then test if those assumptions are enforced
- Test each constraint INDEPENDENTLY — one variable at a time
- Focus on FINANCIAL operations first — they have the highest impact
- Drop parameters completely — "fail open" defaults are everywhere
- Test negative values on every numeric field — developers rarely check the sign
- Understand the complete workflow before breaking it — context matters

## Things Not to Do

- Do not approach business logic as a checklist — every application has unique logic
- Do not modify real financial transactions in production without explicit authorization
- Do not combine multiple manipulations simultaneously — you won't know which worked
- Do not assume frontend validation equals server-side enforcement
- Do not skip parameter dropping — it's the most commonly missed test
- Do not report theoretical issues — demonstrate the actual impact

---

## Cross-Skill Links

- [[race-condition]] — Race conditions are timing-dependent business logic flaws
- [[idor]] — Object reference manipulation is often a business logic issue
- [[mass-assignment]] — Setting unauthorized fields violates business constraints
- [[csrf]] — CSRF on business-critical operations amplifies impact
