---
name: testing-idor
description: Insecure direct object reference and broken object-level authorization testing. Use when requests contain resource identifiers (numeric IDs, UUIDs, slugs, encoded references) that may allow accessing other users' resources by manipulating the identifier. Covers horizontal and vertical privilege escalation, write IDOR, method-based bypass, identifier prediction, parameter pollution, and chained IDOR discovery across REST and GraphQL APIs.
---

# IDOR / BOLA Testing

IDOR is the most common high-impact vulnerability in modern web applications. The server knows WHO you are (authentication) but fails to verify IF you own the requested resource (authorization). It appears simple — "change the ID" — but finding impactful IDOR requires understanding how the application models ownership, how it references objects, and where developers cut corners on authorization checks.

## Reference Files

- [techniques.md](./techniques.md) — Advanced IDOR techniques: UUID prediction, encoded ID manipulation, GraphQL IDOR, mass endpoint testing

## Mental Model

Every IDOR follows the same pattern:
1. User A is authenticated and requests their own resource: `GET /api/users/123/data`
2. Server checks: "Is this user authenticated?" → Yes → Returns data
3. Server does NOT check: "Does user A own resource 123?" → Missing check = IDOR

The vulnerability is NOT in the identifier itself. UUIDs don't prevent IDOR — they just make enumeration harder. The vulnerability is the missing authorization check.

**Think about it this way:** The application has TWO questions to answer for every request:
- "Who are you?" (authentication)
- "Are you allowed to access this specific resource?" (authorization)

If only the first question is answered, IDOR exists.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (map IDs)     (cross-account)   (declare secure)      (demonstrate impact)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Map the Object Reference Landscape

**Goal:** Identify every place the application uses object references and understand how it models ownership.

### Step 1.1: Identify ALL Object References

Don't just look at URL paths. Check EVERYWHERE:

**URL path segments:** `/api/users/123/profile`, `/orders/456`, `/files/abc-def`
**Query parameters:** `?userId=123`, `?orderId=456`, `?docId=abc`
**Request body (JSON):** `{"accountId": "123", "resourceId": "456"}`
**Request body (form):** `user_id=123&item_id=456`
**Headers:** `X-User-Id: 123`, `X-Account-Id: 456`
**Cookies:** Non-session cookies containing user/account references
**File paths:** `/download?file=user_123/report.pdf`
**Fragments/hashes:** Base64-encoded blobs that decode to IDs

### Step 1.2: Classify Identifier Types and Predictability

| Type | Example | Enumerable? | Strategy |
|------|---------|------------|----------|
| Sequential integer | 1, 2, 3... | Trivially | ±1, ±10, ±100 |
| Short numeric | 10032 | Feasibly | Nearby values |
| UUID v4 (random) | `f47ac10b-58cc-4372-a567-0e02b2c3d479` | No | Need second account or leak |
| UUID v1 (time-based) | `6ba7b810-9dad-11d1-80b4-00c04fd430c8` | Partially | Timestamp-based prediction |
| Base64-encoded | `dXNlcjoxMjM=` | Decode first | Decode → modify → re-encode |
| Hex-encoded | `7b226964223a3132337d` | Decode first | Decode → modify → re-encode |
| Hash (MD5/SHA) | `e10adc3949ba59abbe56e057f20f883e` | No | Need leak or prediction |
| Slug/name | `john-doe`, `my-project` | Guessable | Try common names |
| Composite | `123-456-789` | Depends | Test each segment independently |

### Step 1.3: Understand Ownership Model

**Critical reasoning step.** Before testing, understand HOW the application models ownership:

- **User → Resource:** User 123 owns documents 456, 789. Each document belongs to one user.
- **Organization → User → Resource:** Org A contains Users 1-10. User 1's resources should be invisible to User 11 (different org).
- **Multi-tenancy:** Tenant A's data should be completely isolated from Tenant B.
- **Role-based:** Admin can access everything. Staff can access their department. Users can access only their own.
- **Shared resources:** Some resources may be intentionally shared (public posts, shared documents). Don't report these as IDOR.

### Step 1.4: Establish Baselines

For each identified endpoint + identifier:

**Authorized response (your own resource):**
```
GET /api/users/123/data — 200 OK, returns your data
Record: status, length, fields returned, data structure
```

**Non-existent resource:**
```
GET /api/users/99999999/data — 404 or 403 or empty
Record: how does the application handle non-existent resources?
```

**Why both matter:** IDOR confirmation requires distinguishing THREE states:
1. Your own resource → 200 with your data
2. Another user's resource → If 200 with THEIR data = IDOR. If 404/403 = protected.
3. Non-existent resource → 404

If (2) returns the same as (3), authorization is enforced. If (2) returns data that matches the target ID, IDOR is confirmed.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINTS] {count of endpoints with object references}
[IDENTIFIER-TYPES] {types found and predictability}
[OWNERSHIP-MODEL] {how the app models resource ownership}
[AUTHORIZED-RESPONSE] Status: {code}, Fields: {list}
[NONEXISTENT-RESPONSE] Status: {code}
[DECISION] {Proceed — multiple testable endpoints / Limited — UUID only, need second account}
```

---

## Phase 2: Confirmation — Cross-Account Access Testing

**Goal:** Demonstrate that you can access resources belonging to another user/account/organization.

### Prerequisites

IDOR testing effectiveness depends on your setup:

**Two test accounts (BEST):** You know resource IDs from both accounts. Swap IDs between sessions.
**One account + predictable IDs:** Increment/decrement sequential IDs.
**One account + ID leak:** The application leaks other users' IDs somewhere (API responses, error messages, URL patterns).
**One account + UUID:** Very limited testing. Look for ID leaks first.

### Confidence Definitions

| Level | For IDOR Specifically |
|-------|----------------------|
| HIGH | Response contains ANOTHER user's data (verified by content, not just status code) AND this data is different from your own AND different from the non-existent response |
| MEDIUM | Response differs from non-existent baseline but content cannot be verified as another user's (e.g., partial data, no identifying fields) |
| LOW | Response matches non-existent baseline (404/403), or server ignores the ID and uses session |

### Step 2.1: Horizontal IDOR (Same Role, Different User)

Using Account A's session, request Account B's resource:
```
GET /api/users/456/profile
Authorization: Bearer <Account_A_Token>
```

| Response | Interpretation | Confidence |
|----------|---------------|------------|
| Returns Account B's name, email, data | IDOR confirmed | HIGH |
| Returns Account A's data (ignores ID in URL) | Server uses session, not URL ID | No IDOR (this endpoint) |
| Returns 403 "Forbidden" | Authorization check exists | LOW (but check other endpoints) |
| Returns 404 "Not Found" | Server hides existence of other users' resources | LOW (proper security) |
| Returns 200 but empty/redacted data | Partial protection — still reveals existence | MEDIUM |

### Step 2.2: Vertical IDOR (Cross-Role)

Using a low-privilege account, access high-privilege resources:
```
GET /api/admin/users        — Admin user list
GET /api/admin/config       — Application configuration
GET /api/reports/financial   — Financial reports
PUT /api/users/123/role     — Role modification
```

Even if the endpoint returns 403, try:
- Different HTTP methods (GET blocked? Try POST, PUT, PATCH)
- Different Content-Types
- Adding `X-Original-URL: /api/admin/users` header
- Path traversal: `/api/users/../admin/users`
- Case variation: `/api/Admin/Users`, `/API/admin/users`

### Step 2.3: Cross-Organization IDOR

In multi-tenant applications, the most critical IDOR is cross-tenant access:
```
# Your org's resources
GET /api/org/org-123/data

# Another org's resources (using your auth)
GET /api/org/org-456/data
```

Cross-tenant IDOR is almost always Critical severity.

### Step 2.4: Write IDOR (State-Changing Operations)

Read IDOR exposes data. Write IDOR modifies data — higher impact.

```
# Modify another user's profile
PUT /api/users/456/profile
{"name": "IDOR-Test"}

# Delete another user's resource
DELETE /api/users/456/documents/789

# Perform action on another user's behalf
POST /api/users/456/orders
{"item": "test"}
```

**CRITICAL:** Use reversible actions for write IDOR testing. Change a non-critical field (display name), don't delete data. Verify and revert immediately.

### Step 2.5: Method-Based IDOR

Applications often enforce authorization differently per HTTP method:

```
GET /api/users/456 → 403 (read blocked)
PUT /api/users/456 → 200 (write NOT blocked!)
PATCH /api/users/456 → 200 (also not blocked)
DELETE /api/users/456 → 200 (also not blocked)
```

Test ALL methods on every IDOR endpoint. Authorization middleware sometimes only covers GET.

### Step 2.6: Parameter Pollution IDOR

Sometimes the application checks the first ID but uses the second:
```
GET /api/users/123/data?userId=456    — Checks 123 (your ID), returns data for 456
POST /api/action {"userId": "123", "userId": "456"}  — First passes auth check, second is used
```

Try:
- Duplicate parameters with different values
- ID in URL path + different ID in query parameter
- ID in URL path + different ID in request body
- ID in header + different ID in body

### Step 2.7: Encoded/Hashed ID Manipulation

If IDs are encoded:
```
# Base64
echo "user:123" | base64   → dXNlcjoxMjM=
echo "user:456" | base64   → dXNlcjo0NTY=
# Replace the encoded value in the request

# Hex
echo -n '{"id":123}' | xxd -p   → 7b226964223a3132337d
echo -n '{"id":456}' | xxd -p   → 7b226964223a3435367d

# JWT claims (if ID is in JWT payload — modify claims, test with [[jwt]] skill)
```

### Step 2.8: ID Leakage Discovery

If you can't guess IDs, find where they leak:
- API list endpoints: `GET /api/users` may return all user IDs
- Search results: searching for a user may return their UUID
- Error messages: "User f47ac10b already exists"
- Referer headers: navigating between pages may leak IDs in URLs
- WebSocket messages: real-time features may broadcast user IDs
- Email notifications: "User 456 liked your post" → now you have their ID
- Public profiles: profile URLs contain user IDs
- API response over-fetching: `GET /api/me` returns `{"id": 123, "team_members": [{"id": 456}, {"id": 789}]}`

**Max confirmation attempts: 15 across different endpoints and methods.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[ENDPOINT] {URL pattern}
[TECHNIQUE] {horizontal / vertical / cross-org / write / method / param pollution}
[YOUR-ID] {your identifier value}
[TARGET-ID] {target identifier value}
[RESPONSE] {what was returned — data type, not actual data}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to exploitation / Try different endpoint / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions

A true negative for IDOR means ALL of the following:
- Multiple endpoints tested (at least 5 different resource-accessing endpoints)
- Both read (GET) AND write (PUT/POST/DELETE) operations tested
- Multiple HTTP methods tested per endpoint
- Authorization enforced consistently (403/404 for all unauthorized access)
- Session confirmed valid throughout testing
- Tests performed with proper cross-account setup (not just blind ID manipulation)

### Structured Log
```
[VULN-NEGATIVE]
[PARAMETER] {identifier name}
[ENDPOINTS-TESTED] {list of endpoints and methods}
[TECHNIQUE-COVERAGE] {horizontal, vertical, write, method-based}
[SIGNAL] {all unauthorized requests properly rejected — consistent 403/404}
[CONCLUSION] {object-level authorization is consistently enforced across tested endpoints}
[ACTION] Parameter cleared for IDOR. Do not proceed to exploitation.
```

### True Negative vs. Inconclusive

| Situation | Verdict |
|-----------|---------|
| All endpoints return 403/404 for cross-account access, tested 5+ endpoints | True negative |
| Only GET tested, not write operations | Inconclusive — test PUT/POST/DELETE |
| Only tested with UUID, no second account | Inconclusive — IDs might work if you had valid targets |
| Server uses session-based lookup on tested endpoints, but other endpoints use URL IDs | Inconclusive — test those other endpoints |
| Only 1-2 endpoints tested | Inconclusive — test more endpoints |

---

## Phase 3: Exploitation — Demonstrate Impact

**Entry requirements:** HIGH confidence from Phase 2. No negative verdict.

### Level 1: Data Access Proof
Document WHAT data is accessible:

| Data Type | Severity Multiplier |
|-----------|-------------------|
| Authentication data (passwords, tokens, API keys) | Critical |
| Financial data (transactions, payment methods, balances) | Critical |
| PII (SSN, government ID, medical records) | Critical |
| Personal data (email, phone, address) | High |
| Business data (orders, contracts, internal docs) | High |
| Metadata (user IDs, timestamps, status) | Medium |
| Public data (usernames, profile pictures) | Low |

### Level 2: Scale Assessment

If IDs are sequential:
```
# Find the approximate range
# If your ID is 50,000 and ID 1 also returns data → ~50,000 users affected
# Test: ID 1 (oldest), your ID ±1, max ID (newest)
```

If UUIDs: scale is limited to what you can enumerate, but the vulnerability still affects ALL users.

### Level 3: Write IDOR Impact (if confirmed)

Demonstrate ONE reversible modification:
- Change a non-critical profile field → immediately revert
- Document the request and response
- Calculate what COULD be done (but don't do it): delete accounts, modify permissions, transfer funds

**Stop condition:** At first confirmed unauthorized data access or modification → STOP. Generate report via [[report-writing]].

### Reasoning Checkpoint
```
[PHASE-3] Exploitation
[ENDPOINT] {URL}
[IDOR-TYPE] {read horizontal / read vertical / write / cross-tenant}
[DATA-TYPE] {PII / financial / auth / business / metadata}
[SCALE] {estimated affected users/resources}
[EVIDENCE] {response showing unauthorized access — redact actual data}
[STOP-REASON] {impact demonstrated — generating report}
```

---

## Session Re-verification

- Before each new endpoint test, verify your session is valid
- If 401/403 appears on your OWN resources, session has expired — re-authenticate
- After each write IDOR test, verify the change actually persisted (fetch the modified resource)

---

## Things to Do

- Test with TWO accounts whenever possible — blind IDOR testing misses UUID-based vulnerabilities
- Test both READ and WRITE operations on every endpoint — write IDOR is often unprotected even when read is
- Test ALL HTTP methods, not just the one the UI uses — authorization is often method-specific
- Look for ID leakage if you can't predict IDs — search results, error messages, API over-fetching
- Check parameter pollution — duplicate IDs in different locations sometimes bypass checks
- Test cross-organization access in multi-tenant apps — this is Critical severity
- Decode encoded IDs before modifying — Base64, hex, URL encoding
- Check if the application uses server-side ID vs. client-supplied ID — if it ignores the URL ID and uses the session, that endpoint isn't vulnerable (but others might be)

## Things Not to Do

- Do not report IDOR if the server ignores the ID parameter and uses session-based lookup
- Do not make irreversible write modifications (delete accounts, modify financial data)
- Do not enumerate large numbers of resources — prove the concept with 2-3 examples
- Do not confuse shared/public resources with IDOR — verify the resource should be private
- Do not assume all endpoints have the same authorization — test each independently
- Do not issue negative verdict after testing only GET requests
- Do not test only one endpoint — authorization inconsistency across endpoints is common
- Do not report UUID-based IDOR without demonstrating how you obtained the target UUID

---

## Cross-Skill Links

- [[sqli]] — SQL injection can extract other users' IDs from the database, enabling IDOR on UUID-based systems
- [[mass-assignment]] — If write IDOR exists, mass assignment may allow modifying role/privilege fields
- [[business-logic]] — IDOR + workflow manipulation = higher impact (e.g., IDOR to change order status)
- [[graphql]] — GraphQL queries with ID arguments are IDOR vectors — test each query independently
- [[jwt]] — Forging JWT claims can change the user context, enabling IDOR from a different angle
