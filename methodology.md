# The Hunter's Methodology — How Elite Researchers Actually Find Bugs

This file is not a checklist. It is a collection of THINKING PATTERNS extracted from thousands of successful bug bounty reports and the methodologies of researchers who consistently find critical vulnerabilities. Read it completely before starting any engagement.

---

## Part 1: The Foundational Mindset

### You Are Reverse-Engineering the Developer

Every application was built by a human. That human:
- Had deadlines ("ship by Friday")
- Had incomplete security knowledge ("I think this is enough validation")
- Made assumptions ("nobody would think to do that")
- Took shortcuts ("I'll add auth to this endpoint later")
- Copy-pasted from Stack Overflow ("it works, good enough")
- Didn't test edge cases ("who would send -1 as a quantity?")

Your job is to find THEIR assumptions and THEIR shortcuts. You're not fighting the application — you're finding the gaps in the developer's thinking.

### The Bug Is in the Gap

The most critical vulnerabilities exist in the GAPS:
- Gap between frontend validation and backend validation (frontend checks, backend doesn't)
- Gap between authentication and authorization (knows WHO you are, not IF you're allowed)
- Gap between documentation and implementation (docs say auth required, code doesn't check)
- Gap between proxy and application (proxy sees one request, app processes another)
- Gap between cache and origin (cache stores public version, origin generates private version)
- Gap between developer intent and actual behavior (intended one coupon per user, code allows unlimited)
- Gap between what the API returns and what the UI shows (API over-fetches, sensitive fields in response)

**Every gap is a potential vulnerability.** Your methodology should systematically search for these gaps.

### Think in Workflows, Not Endpoints

Average hunters test endpoints one at a time: "Is this endpoint vulnerable to XSS? No. Next endpoint."

Elite hunters test WORKFLOWS: "How does the password reset flow work? What happens at each step? What assumptions connect the steps? Can I break the chain?"

A workflow perspective reveals vulnerabilities that endpoint testing misses:
- Step skipping (jump from step 1 to step 5)
- Token leakage between steps (Referer header carries reset token to external resources)
- Race conditions at step boundaries (two requests at the "check balance" step before either deducts)
- State confusion (start flow as User A, complete as User B)

### The 5-Layer Analysis

For every interesting endpoint, analyze these five layers:

**Layer 1: What does it DO?** (Read data? Write data? Trigger action? Return file? Send email? Make external request?)

**Layer 2: What INPUTS does it accept?** (URL params? Body fields? Headers? Cookies? File uploads? And which ones affect the response?)

**Layer 3: What CONTEXT does the input reach?** (SQL query? HTML output? Template? Shell command? File path? URL? XML parser?)

**Layer 4: What VALIDATION exists?** (None? Frontend only? WAF? Server-side whitelist? Server-side blacklist? Type checking?)

**Layer 5: What AUTHORIZATION guards it?** (None? Authentication only? Role-based? Object-level? Tenant-level?)

The vulnerability type is determined by Layers 2-4. The severity is determined by Layers 1 and 5.

---

## Part 2: Signal Recognition — What Elite Hunters Notice

### Behavioral Anomalies That Scream "Test Me"

These are the signals that experienced hunters recognize instantly. When you see any of these, STOP and investigate deeply:

**Response differentiation:**
```
Same endpoint, two inputs, different behavior:
  GET /api/user/100 → 200 OK with data        (your ID)
  GET /api/user/101 → 200 OK with OTHER data   (IDOR!)
  GET /api/user/101 → 404 Not Found             (protected — moves on)
  GET /api/user/101 → 403 Forbidden              (exists but forbidden — explore methods)
  GET /api/user/101 → 200 OK with YOUR data     (ignores ID, uses session — no IDOR here, but...)
```

**Error verbosity:**
```
Verbose SQL error → absolutely test for SQLi
Stack trace → reveals framework, file paths, code structure
Template error → test for SSTI
"File not found: /var/www/html/pages/..." → test for path traversal
"Connection refused: 10.0.0.5:3306" → internal infrastructure leak
"Permission denied: /etc/shadow" → close to something — try other files
```

**Timing anomalies:**
```
One endpoint takes 2 seconds when others take 200ms → 
  Is it making a database query? An external request? A file operation?
  Test: Does the time change with your input? If yes → potential blind injection.
Response time varies with input LENGTH → 
  Maybe the server is processing your input character by character (regex, comparison).
Response time increases when you add valid-looking SQL syntax → 
  The query is being executed (even if the result is filtered from the response).
```

**Status code patterns from recon:**
```
/admin → 403 (not 404) → The path EXISTS, just forbidden. Try:
  - Different HTTP methods
  - Path traversal: /images/../admin
  - Header manipulation: X-Original-URL: /admin
  - URL encoding: /adm%69n
  - Case variation: /Admin, /ADMIN
```

**The 3-byte difference:**
```
Response to normal input: 4,823 bytes
Response to test input: 4,826 bytes (+3 bytes)
What are those 3 bytes? Your input reflected? An error message? A database value?
Even tiny differences can be the beginning of a finding.
```

### What Changes in the Response (and What It Means)

| Change | Likely Meaning | Test For |
|--------|---------------|----------|
| Status code changes | Input reaches decision logic | Injection (SQLi, CMDi), authorization bypass |
| Response length changes significantly | Input affects data retrieval | SQLi (UNION), IDOR, LFI |
| Response length changes by exact input length | Input is reflected | XSS, SSTI, header injection |
| Response time increases | Input triggers processing | Blind SQLi, SSRF, command injection |
| New headers appear | Different code path triggered | Authorization bypass, caching issues |
| Error format changes | Different error handler | Input reaching deeper processing |
| Redirect occurs | Input controls flow | Open redirect, auth bypass |
| Nothing changes despite invalid input | Input might be queued/async | Blind injection, stored XSS, async processing |

---

## Part 3: The Testing Cadence — How to Spend Your Time

### The 30-30-30-10 Rule

Adapted from elite hunters' time allocation:

**30% — Recon & Application Understanding**
- Subdomain enumeration, endpoint discovery, JS analysis
- Technology fingerprinting, architecture mapping
- Authentication flow analysis
- Business logic understanding

**30% — Manual Application Exploration**
- Click through every feature as a normal user (with proxy capturing everything)
- Create content, modify settings, interact with other users
- Understand every workflow: registration, profile edit, purchase, sharing, export
- Note every ID, every parameter, every form, every API call

**30% — Targeted Vulnerability Testing**
- Based on what you learned in the first 60%, select the highest-value targets
- Apply the appropriate skill methodology with full rigor
- Test hypotheses systematically
- Chain confirmed findings

**10% — Report Writing & Documentation**
- Write reports immediately after confirmation
- Include complete PoC steps, impact analysis, remediation
- Update session log

### How Long to Test an Endpoint

This is the critical judgment. Here's a framework:

**5 minutes:** Quick check — does the endpoint do anything interesting? Is input reflected? Does it accept unexpected methods? Is there an ID parameter?

**15 minutes:** Focused test — if the 5-minute check shows promise, apply the relevant skill's Phase 1 (baseline) and Phase 2 (confirmation). Test the primary hypothesis.

**1 hour:** Deep investigation — if you have MEDIUM confidence, go deep. Try multiple techniques, check for bypass, test related endpoints. This is where the good bugs live.

**Stop:** If you've spent 1 hour with no signal progression, move on. File as inconclusive if you think there's something but can't confirm.

---

## Part 4: The Reasoning Patterns — How Elite Hunters Make Decisions

### Pattern 1: The "What If" Cascade

When you find ANY endpoint, run through the "what if" cascade:

```
Found: POST /api/orders with body {"item_id": 123, "quantity": 1, "price": 9.99}

What if I change quantity to 0? → Business logic: can I create a free order?
What if I change quantity to -1? → Financial: does negative quantity give me a credit?
What if I change price to 0? → Trust boundary: does the server trust client-sent price?
What if I change price to 0.001? → Rounding: will it round to $0.00?
What if I change item_id to an item from another store? → Authorization: cross-merchant access?
What if I add "discount": 100? → Mass assignment: can I add fields the API doesn't show?
What if I add "admin": true? → Mass assignment: privilege escalation?
What if I send the same request 50 times simultaneously? → Race condition: duplicate orders?
What if I skip the payment step and directly hit the order confirmation endpoint? → Step skipping
What if I change my user in the cookie between adding to cart and checkout? → State confusion
```

Each "what if" is a HYPOTHESIS. Test them. Most will fail. But the one that works could be Critical.

### Pattern 2: The "Who Trusts Whom" Map

Draw (mentally) a trust map of the application:

```
Browser (UNTRUSTED)
  → Cloudflare WAF (FILTERS)
    → Nginx Reverse Proxy (ROUTES)
      → Django Application (PROCESSES)
        → PostgreSQL Database (STORES)
        → Redis Cache (CACHES)
        → S3 Bucket (FILES)
        → Internal Microservice (TRUSTS IMPLICITLY?)
```

Now ask at each boundary: "Does the downstream component validate what it receives from the upstream component, or does it just trust it?"

- Browser → WAF: WAF validates some inputs. Can you craft input the WAF doesn't recognize but the application processes?
- Proxy → Application: Does the proxy add headers the application trusts? (`X-Forwarded-For` for IP-based access control?)
- Application → Database: Parameterized queries? Or string concatenation? (SQLi)
- Application → Internal Service: Does the internal service require auth? Or trust because "it's internal"? (SSRF value)
- Application → S3: Are bucket permissions set correctly? Can you manipulate the path to access other files?

### Pattern 3: The "Developer's Worst Day" Thought Experiment

Imagine the developer's worst day. They're racing to fix a production bug. The CEO is watching. They deploy a hotfix. What do they NOT do?

- They don't update the authorization middleware for the new endpoint
- They don't add CSRF protection to the emergency admin action
- They don't validate the new parameter server-side (the frontend already does it)
- They don't rotate the API key they hardcoded for the quick fix
- They don't add rate limiting to the password reset they just rebuilt
- They don't test what happens when two users trigger the action simultaneously

**Those hotfixes are your bugs.** New features and recently changed code are ALWAYS more likely to be vulnerable. If recon shows an endpoint was recently modified (different code style, different error handling, different framework conventions), test it harder.

### Pattern 4: The "Orthogonal Test"

When you find something interesting but can't confirm it, test from a completely different angle:

```
Found: Input appears to be reflected but XSS doesn't fire (encoded).
Orthogonal test: Is the input also stored? Check profile page, email notifications, admin logs.
  If stored and reflected somewhere WITHOUT encoding → Stored XSS from a different reflection point.

Found: IDOR seems to work but the response is identical to my own data.
Orthogonal test: Make a distinctive change to Account B (unusual name, specific email).
  Then request Account B's resource from Account A. Look for the distinctive change.
  This eliminates "server ignoring the ID parameter" as a false positive.

Found: SQL injection test causes an error, but it might be input validation.
Orthogonal test: Send a valid SQL string (like a number) followed by a comment (--).
  If the comment is stripped by input validation → same error.
  If the comment is processed by the SQL parser → different error → SQLi confirmed.
```

### Pattern 5: The "What Did They Build vs. What Did They Buy"

Custom code has custom bugs. Third-party code has known CVEs.

**Custom code (more likely to have logic/auth bugs):**
- The main application logic
- Authorization middleware
- Business rules engine
- Custom API endpoints
- Internal tools and admin panels

**Third-party code (more likely to have known vuln bugs):**
- WordPress and its plugins
- Open-source libraries (check dependency versions)
- Payment processor integrations
- OAuth libraries
- Template engines
- Serialization libraries

The testing approach differs: for custom code, you REASON about what could be wrong. For third-party code, you IDENTIFY the version and check for known vulnerabilities.

---

## Part 5: Signal vs. Noise — The Definitive Guide

### The Three Baselines (Non-Negotiable)

Before testing any parameter, you MUST record three baselines:

1. **Valid input baseline:** What the application returns for a normal, expected input.
2. **Invalid input baseline:** What the application returns for unexpected but non-malicious input (e.g., a very long string, a number where text is expected).
3. **Variance baseline:** The same valid request sent 3 times — are responses identical? If they vary, by how much?

Every subsequent test result is compared to ALL THREE baselines:
- If your test result matches the valid baseline → your input was treated as valid (possible injection if the input was malicious)
- If your test result matches the invalid baseline → your input was rejected as bad input (input validation, not injection)
- If your test result matches NEITHER → something different happened. THIS IS SIGNAL. Investigate.

### Noise Sources (Things That Look Like Vulnerabilities But Aren't)

1. **WAF blocking:** Returns 403 or custom error page regardless of vulnerability. Verify by sending benign payloads with suspicious keywords.
2. **Rate limiting:** Returns 429 or degraded responses after many requests. Wait and retry.
3. **Session expiry:** Returns 401/302-to-login mid-test. Re-authenticate and re-baseline.
4. **Caching:** Returns the same response regardless of input changes. Try cache-busting (add `?cb=random`).
5. **Load balancer rotation:** Different backend servers have slightly different responses. Multiple identical requests may show variance.
6. **A/B testing:** Application intentionally returns different versions to different users. Compare with a second account.
7. **Geographic routing:** CDN serves different content based on location. Consistent testing from same IP eliminates this.

### The Noise Elimination Protocol

When you see a response change after a test payload:
1. **Re-send the baseline request.** Does it still return the original baseline? If not → your session or the application state changed. That's noise.
2. **Send the same test payload again.** Do you get the same changed response? If not → intermittent behavior. That's noise.
3. **Send a DIFFERENT test payload that SHOULD NOT trigger the same change.** If it does → something systemic changed (WAF, rate limiting). That's noise.
4. **Only after all three checks pass** is the response change attributable to your specific test payload. That's signal.

---

## Part 6: The Chaining Masterclass

### Why Chaining Matters

From analysis of bounty payouts:
- **Individual Low finding:** $100-$300
- **Individual Medium finding:** $500-$1,000
- **Chained Low → Critical:** $5,000-$15,000

The same underlying vulnerabilities, but the chained report demonstrates REAL IMPACT that the individual findings don't.

### The Chaining Framework

**Step 1: Inventory your findings** — including informational ones.
Even "non-findings" can be chain links: endpoints that exist but you can't exploit directly, information disclosure that seems useless alone, rate limiting gaps that aren't impactful standalone.

**Step 2: For each finding, ask "What does this ENABLE?"**
- Open redirect → enables SSRF filter bypass, OAuth token theft
- Information disclosure (internal IDs) → enables IDOR
- XSS (even self-XSS) → enables CSRF bypass, session theft, admin action execution
- SSRF (blind, no response) → enables internal port scan, DNS exfiltration
- Subdomain takeover → enables cookie theft, CORS bypass
- Misconfigured CORS → enables cross-origin data theft (IF endpoint has sensitive data)

**Step 3: Build the chain on paper first, then test each link.**
Don't assume a chain works. Verify each link independently.

### Real-World Chain Examples (From Disclosed Reports)

**Chain 1: Information Leak → IDOR → Account Takeover**
```
1. /api/search?q=john returns {"users": [{"id": "uuid-123", "name": "John"}]}
   → IDs are UUIDs but the search endpoint leaks them
2. GET /api/users/uuid-123/security-settings returns {email, phone, recovery_codes}
   → IDOR: can read any user's security settings using leaked UUID
3. Use recovery codes to bypass 2FA → full account takeover
Impact: Informational + High + Critical = Critical chain
```

**Chain 2: Self-XSS → CSRF → Admin RCE**
```
1. Self-XSS in profile name field (only you see it — normally informational)
2. CSRF on profile update endpoint (change another user's name)
3. Admin views user profile in admin panel → XSS executes in admin context
4. XSS payload accesses admin functionality → creates new admin account
Impact: Informational + Medium + Critical = Critical chain
```

**Chain 3: Open Redirect → SSRF → AWS Credentials**
```
1. Open redirect on /logout?redirect=https://evil.com (Low severity alone)
2. SSRF on /api/fetch-url — has domain whitelist including target.com
3. SSRF with redirect: /api/fetch-url?url=https://target.com/logout?redirect=http://169.254.169.254/latest/meta-data/iam/security-credentials/role
4. AWS credentials returned
Impact: Low + blocked + Critical = Critical chain
```

---

## Part 7: When Something Doesn't Work

### The Pivot Table

When your current approach isn't producing results, don't repeat — pivot:

| Situation | Bad Response | Good Response |
|-----------|-------------|--------------|
| XSS payload encoded | Try more payloads with same encoding | Analyze WHAT is encoded, find the gap in encoding coverage |
| SQLi payload blocked by WAF | Try common bypasses from a list | Identify WHAT the WAF matches, craft minimal evasion |
| IDOR returns 403 | Give up on this endpoint | Try different HTTP methods, path traversal, different ID formats |
| No injection on this parameter | Test next parameter | Ask: does this parameter reach a DIFFERENT context I haven't tested? |
| Auth bypass fails | Move to other vulnerabilities | Check if there's a DIFFERENT auth mechanism (API key? OAuth? Internal?) |
| File upload blocked | Try extension bypass list | Determine the validation type (extension? content-type? magic bytes?) then target specifically |

### The "Fresh Eyes" Technique

If you've been testing for 2+ hours with no progress, do this:
1. Close all your test results
2. Go back to the application as a normal user
3. Click through features you haven't explored
4. Look at the proxy log for requests you didn't notice before
5. Often, you'll find a completely different attack surface you missed

---

## Part 8: Working Across Sessions

### Session Log Discipline

The session log (`notes/session_log.md`) is your most important file. It's your memory between sessions and the foundation for continuity.

**After every significant action, update the log with:**
- What you tested and the result
- Interesting observations (even if you can't exploit them yet)
- Your current theory about the application's architecture
- What you plan to test next and WHY
- Cloudflare/WAF behavior patterns you've noticed
- Rate limit status (any 429s received?)

**On resume, ALWAYS:**
1. Read the session log first
2. Verify scope hasn't changed (programs update rules)
3. Re-verify your session is valid
4. Continue from the "Next Steps" section
5. Never repeat work documented as complete

### The Compound Advantage

Multi-day engagements have a unique advantage: UNDERSTANDING COMPOUNDS.

Day 1: You understand the surface.
Day 2: You understand the architecture.
Day 3: You understand the developer's patterns.
Day 4: You understand the GAPS in the developer's patterns.

The best bugs are found on Day 3+, when you understand the application well enough to see what's MISSING, not just what's present.
