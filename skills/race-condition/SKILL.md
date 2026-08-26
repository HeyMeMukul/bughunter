---
name: testing-race-condition
description: Race condition and TOCTOU (Time-of-Check to Time-of-Use) vulnerability testing. Use when testing state-changing operations that enforce limits — coupon redemption, balance transfers, vote/like systems, invitation acceptance, rate-limited operations, file operations, or any action where the server checks a condition then acts on it. Also covers limit bypass, double-spend, state confusion, and the single-packet attack technique for maximum concurrency.
---

# Race Condition Testing

Race conditions exploit the time gap between CHECK and USE. The server checks "does the user have balance?" — yes — then deducts. But if 50 requests arrive simultaneously, all 50 pass the check before any deduction occurs, and all 50 deductions process. The user pays once, gets 50 items.

## Reference Files

- [techniques.md](./techniques.md) — Single-packet attack, HTTP/2 synchronization, and advanced timing techniques

## Mental Model

Every race condition has three components:
1. **The Check:** Server reads current state (balance, coupon usage count, vote status)
2. **The Gap:** Time between reading the state and modifying it
3. **The Use:** Server modifies state based on the check result

If you can fit multiple requests into the Gap, all of them pass the Check before any of them complete the Use.

**Think about it like turnstile gates at a stadium.** The gate checks your ticket (valid? → yes) then lets you through. But if 50 people rush the gate simultaneously, the gate might check all 50 tickets before it realizes it already let 49 people in. The turnstile's "check" and "use" aren't atomic — they have a gap.

**Where race conditions hide:**
- Financial: balance deduction, payment processing, refunds, transfers
- Limits: coupon codes (single-use), invitation accepts, free trial creation
- Voting/rating: like buttons, upvotes, rating submissions
- Inventory: limited stock items, seat reservations, booking slots
- State machines: order status transitions, approval workflows
- File operations: upload processing, file write → file read sequences
- Session: login/logout race, session creation, token refresh

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (identify targets)  (concurrent test)  (declare secure)  (demonstrate bypass)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Identify Race-Prone Operations

Look for endpoints where:
- A numeric limit is enforced (balance, uses, count, stock)
- An action is single-use (coupon, invite, verification link)
- State transitions should be sequential (pending → approved → completed)
- Rate limits are in application logic (not infrastructure)
- Two operations share a resource (read/write race)

### Step 1.2: Single Request Baseline

Execute the action ONCE normally. Record:
- Response (success, fields returned)
- State change (balance before/after, usage count before/after)
- Response time

### Step 1.3: Sequential Repeat Baseline

Execute the action TWICE sequentially. The second should fail:
- Second coupon apply → "Already used"
- Second balance deduction → "Insufficient funds"
- Second vote → "Already voted"

Record the rejection response — this is what proper serialization looks like.

### Step 1.4: Assess the Race Window

**Think about what happens server-side:**
```
Request 1:                   Request 2 (simultaneous):
  1. Read balance: $100        1. Read balance: $100
  2. Check: $100 >= $50? Yes   2. Check: $100 >= $50? Yes
  3. Deduct: $100 - $50 = $50  3. Deduct: $100 - $50 = $50
  4. Return success             4. Return success

Final balance: $50 (should be $0 — double-spend!)
```

The race window is the time between steps 1 and 3. Wider window = easier to exploit. Database transactions, row-level locking, and atomic operations close this window.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL and method}
[ACTION] {what the endpoint does}
[LIMIT-TYPE] {single-use / numeric limit / state transition / rate limit}
[SEQUENTIAL-REJECTION] {how the second request is rejected}
[ESTIMATED-WINDOW] {narrow - DB transaction likely / wide - application logic likely}
[DECISION] {Proceed / No limit-enforced operation — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions

| Level | For Race Conditions |
|-------|-------------------|
| HIGH | Multiple simultaneous requests ALL succeed when only one should — limit/constraint bypassed, verified by actual state change |
| MEDIUM | More requests succeed than expected but results are inconsistent across test runs |
| LOW | Simultaneous requests properly serialized — only expected number succeed |

### Step 2.1: Single-Packet Attack (Most Effective)

The key to race condition testing is MAXIMUM CONCURRENCY. Regular parallel requests arrive with millisecond gaps. The single-packet attack puts all requests in ONE TCP packet:

```
Technique: Last-byte synchronization
1. Open N TCP connections to the server
2. Send all requests EXCEPT the final byte on each connection
3. Send ALL final bytes simultaneously (one flush per connection)
4. All N requests arrive at the server within microseconds
```

**Tools:**
- Burp Suite Turbo Intruder (race condition mode)
- Custom script with socket-level control
- `race-the-web` tool
- Python with `asyncio` and precise timing

### Step 2.2: HTTP/2 Single-Packet

HTTP/2 multiplexes multiple requests over one connection. Send ALL requests as frames in a single TCP packet:

```python
# Conceptual HTTP/2 race
import h2.connection
# Build N requests as HTTP/2 frames
# Send all frames in one TCP write() call
# All requests arrive at the server simultaneously
```

### Step 2.3: Result Analysis

After the concurrent batch:

**Count successes vs. failures:**
- 1 success, N-1 failures → properly serialized, no race
- 2+ successes → race condition exists
- Inconsistent across runs → timing-dependent race (narrow window)

**Verify ACTUAL state change, not just response codes:**
```
Before: balance = $100, coupon_used = false
Send 50 simultaneous "apply coupon $50" requests
After: how many succeeded? What's the actual balance?

If 3 requests succeeded:
  Expected balance: $100 - $50 = $50 (one use)
  Actual balance: $100 - $150 = -$50 (three uses) → RACE CONFIRMED
```

### Step 2.4: Vary Concurrency

If the first attempt shows no race:
- Try MORE concurrent requests (20, 50, 100)
- Try with HTTP/2 instead of HTTP/1.1
- Try at different times (server load affects window size)
- Try the single-packet technique if you used regular parallel requests

**Max test rounds: 5.** If 5 rounds with 50+ concurrent requests using single-packet technique all show proper serialization → negative verdict.

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {parallel / single-packet / HTTP/2}
[CONCURRENT-REQUESTS] {count sent}
[SUCCESSES] {count that succeeded}
[EXPECTED-SUCCESSES] {what should have succeeded}
[STATE-BEFORE] {balance/count/status before test}
[STATE-AFTER] {actual state after test}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Adjust technique / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Multiple concurrent batches (5+) all properly serialized
- Tested with high concurrency (50+ requests)
- Used single-packet or HTTP/2 technique for maximum simultaneity
- Verified by checking actual state (not just response codes)
- Application uses database transactions or row-level locking

### Structured Log
```
[VULN-NEGATIVE]
[ENDPOINT] {URL}
[STEPS-RUN] {concurrent batches × request count, technique used}
[SIGNAL] {proper serialization — only expected number succeed}
[CONCLUSION] {endpoint uses proper atomic operations / locking}
[ACTION] Endpoint cleared for race conditions.
```

---

## Phase 3: Exploitation

### Level 1: Demonstrate Limit Bypass
Show that N requests succeeded when only 1 should have:
- Before state, after state, number of successes
- Calculate the business impact (extra $X, extra N items, etc.)

### Level 2: Quantify Impact
- Financial impact per race exploit
- Is it repeatable reliably?
- What's the maximum achievable multiplier?

**Stop condition:** Demonstrated bypass with state verification → STOP. Generate report.

---

## Things to Do

- Use single-packet attack for maximum concurrency — regular parallel requests often miss the window
- Always verify ACTUAL state change, not just response codes — the server may return success but roll back
- Test multiple times — race conditions are timing-dependent and may not trigger consistently
- Focus on financial operations — they have the highest impact and often the weakest protections

## Things Not to Do

- Do not test race conditions on irreversible financial transactions without authorization
- Do not send thousands of requests — 50-100 per batch is sufficient
- Do not report race conditions without demonstrating actual state inconsistency
- Do not assume one negative test means no race — try different concurrency levels and techniques

---

## Cross-Skill Links

- [[business-logic]] — Race conditions are a timing-dependent subset of business logic flaws
- [[csrf]] — CSRF + race condition = unauthenticated limit bypass at scale
