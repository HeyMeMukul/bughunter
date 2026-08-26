# IDOR/BOLA Attack Patterns from Disclosed Reports

Patterns extracted from 100+ disclosed HackerOne reports ($500-$110,000 range).

---

## Pattern 1: Sequential ID + API Endpoint

**Most common pattern.** Application uses sequential integers as user IDs, and the API endpoint doesn't verify object ownership.

**Disclosed Examples:**
- Shopify: `GET /api/internal/orders/{id}` — sequential order IDs, no ownership check → access any order ($5,000)
- Twitter: `POST /i/api/1.1/account/remove_ban.json` with manipulated user_id → ban any user ($3,000)
- Airbnb: `GET /api/v2/users/{user_id}` — sequential IDs + sensitive PII → mass user data ($5,000)

**Detection Signal:**
```
Sequential integer ID parameter + PII in response + no ownership verification
```

**What Actually Gets Accepted:**
- You MUST prove cross-user access (not just "I can see my own data")
- Show 2 different user accounts accessing 2 different records
- Include actual response diff showing different users' data

---

## Pattern 2: UUID/GUID IDOR

UUIDs are NOT secure by default. They prevent enumeration but NOT authorization bypass.

**Disclosed Examples:**
- GitLab: `GET /api/v4/projects/{project_id}/issues/{issue_id}` — UUID project IDs, but no membership check ($20,000)
- Uber: UUID-based trip IDs accessible by any authenticated user → view any trip ($5,000)

**Detection Signal:**
```
UUID parameter + returns data for OTHER user's UUID + BOLA (not BFLA)
```

**What Actually Gets Accepted:**
- Must show you accessed data you SHOULDN'T have access to
- UUID must come from an info disclosure or be guessable through other means

---

## Pattern 3: IDOR via Parameter Tampering

Change a numeric ID to a different user's ID and the endpoint returns their data. Common in: profile endpoints, order details, message inbox, document downloads.

**Disclosed Examples:**
- Facebook: Change `profile_id` in GraphQL query → access private posts ($15,000)
- Snapchat: Modify `user_id` in friend request API → add any user as friend ($3,000)

**Detection Signal:**
```
Any endpoint with user/account/order/document/profile ID parameter
```

---

## Pattern 4: Mass Assignment + IDOR

Combine mass assignment with IDOR: send object properties you shouldn't control, targeting another user.

**Disclosed Examples:**
- `PUT /api/users/123` with body `{"role": "admin"}` — change another user's role ($10,000)
- `PATCH /api/organizations/{id}/members` — add yourself to any organization ($7,500)

**Detection Signal:**
```
PUT/PATCH endpoint + user/organization ID + role/permission fields
```

---

## Pattern 5: GraphQL IDOR

GraphQL often has weak authorization — queries don't filter by current user.

**Disclosed Examples:**
- HackerOne: GraphQL query returning all users' private profile data regardless of auth ($12,500)
- GitLab: GraphQL mutation allowing unauthorized project access ($5,000)

**Detection Signal:**
```
GraphQL queries returning user-specific data without auth-filter directives
```

---

## Pattern 6: Batch/Mass Endpoint IDOR

Endpoints that accept arrays of IDs and process them all without per-ID auth check.

**Disclosed Examples:**
- `POST /api/bulk/delete` with `{"user_ids": [1,2,3,4,5]}` — delete any user ($3,000)

**Detection Signal:**
```
Batch/bulk/mass endpoints accepting arrays of IDs
```

---

## Key Hunter Lessons

1. **READ vs WRITE IDOR:** Write IDOR (PUT/PATCH/DELETE) is 2-3x more valuable than Read IDOR (GET)
2. **PII type matters:** Financial data > Personal identifiers > Email > Public info
3. **Chains multiply:** Info disclosure (UUID leak) + IDOR = Critical from Low start
4. **Scope definition:** IDOR on `admin` endpoints is Critical. IDOR on `public profile` is Low.
5. **Response diff is king:** Always show baseline (your data) vs target (other user's data)

## What Triagers REJECT as IDOR

- "I can see my own data" — NOT a bug
- "I changed my own ID to my own ID" — NOT a bug
- "The endpoint returns 200" — NOT proof of IDOR without showing data exposure
- "Sequential IDs exist" — NOT a bug without proving authorization failure
- "Authorization header is missing" — NOT proof if other mechanisms exist
