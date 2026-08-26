---
name: testing-graphql
description: GraphQL-specific vulnerability testing. Use when the target exposes a GraphQL endpoint — identified by /graphql, /gql, /api/graphql paths, or POST requests with query/mutation syntax. GraphQL creates unique attack surfaces beyond REST — the flexible query language means every resolver is a separate authorization boundary, every argument is an injection point, and schema exposure reveals the entire API surface. Covers introspection, field-level authorization testing, batching abuse, alias-based enumeration, nested query DoS, mutation authorization bypass, and injection through GraphQL arguments.
---

# GraphQL Testing

GraphQL's flexibility is its vulnerability. Unlike REST where each endpoint is a discrete unit with its own authorization, GraphQL exposes a single endpoint where the CLIENT decides what data to request. This pushes authorization complexity to individual resolvers — and developers frequently get this wrong. A single GraphQL endpoint can contain hundreds of authorization decisions, any one of which might be flawed.

## Reference Files

- [techniques.md](./techniques.md) — Introspection analysis, alias enumeration, batching attacks, nested DoS, injection through arguments

## Mental Model

In REST: `GET /api/admin/users → 403` — the ENDPOINT is protected.
In GraphQL: `query { adminUsers { email } }` → The RESOLVER decides. The endpoint is always accessible.

This means:
1. You can query for ANY type/field the schema defines — authorization is per-resolver, not per-endpoint
2. Different fields on the same type may have different authorization — `user.name` might be public while `user.email` is private
3. Mutations (write operations) often have DIFFERENT authorization than queries (read operations) on the same data
4. Nested queries traverse relationships — authorization might check the parent but not the child

**The key question:** For every field and mutation in the schema, does the resolver check authorization? Not "does the endpoint require auth" — every individual resolver.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (discover schema)  (test authz)     (declare secure)     (demonstrate access)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Schema Discovery

### Step 1.1: Find the Endpoint
Common paths: `/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`, `/api/gql`

Confirm: `POST {"query":"{ __typename }"}` → should return `{"data":{"__typename":"Query"}}`

### Step 1.2: Full Introspection

Send the complete introspection query:
```json
{"query":"{ __schema { queryType { name } mutationType { name } types { name kind description fields { name type { name kind ofType { name kind } } args { name type { name kind } } } enumValues { name } inputFields { name type { name kind } } } } }"}
```

**If introspection is enabled → you have the complete API blueprint.** This reveals:
- Every query (read operation) and its arguments
- Every mutation (write operation) and its arguments
- Every type with all its fields
- Relationships between types (nested queries possible)
- Enum values (valid options for arguments)

### Step 1.3: If Introspection is Disabled

**Field suggestion attack:** Many GraphQL implementations suggest valid field names when you misspell:
```json
{"query":"{ usrs { id } }"}
```
Response: `"Did you mean 'users'?"` → reconstructs schema one field at a time.

**Brute-force with common field names:** Query known GraphQL patterns:
```graphql
{ users { id email } }
{ user(id: "1") { id email role } }
{ me { id email admin } }
{ allUsers { edges { node { id } } } }
{ search(query: "test") { results { id } } }
```

### Step 1.4: Classify Attack Surface

From the schema, identify:
- **Queries with ID arguments** → IDOR candidates: `user(id:)`, `order(id:)`, `document(id:)`
- **Admin/privileged queries** → Vertical escalation: `adminUsers`, `systemConfig`, `auditLog`
- **Mutations** → All write operations: `updateUser`, `deleteUser`, `createAdmin`
- **Sensitive fields** → Data exposure: `password`, `ssn`, `creditCard`, `internalNotes`, `apiKey`
- **Nested relationships** → Deep traversal: `user → posts → comments → author → posts → ...`
- **Search/filter arguments** → Injection: `query`, `filter`, `where`, `search`

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL}
[INTROSPECTION] {enabled — full schema / disabled — using suggestions}
[QUERIES] {count with notable ones}
[MUTATIONS] {count with notable ones}
[SENSITIVE-TYPES] {types containing sensitive data}
[IDOR-CANDIDATES] {queries accepting ID arguments}
[DECISION] Proceed — attack surface mapped
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For GraphQL |
|-------|------------|
| HIGH | Unauthorized data access or unauthorized mutation confirmed — data belongs to another user or operation should require higher privilege |
| MEDIUM | Query/mutation executes but authorization not conclusively tested (one account only) |
| LOW | All queries/mutations properly enforce authorization |

### Step 2.1: Query Authorization Testing

Test each query that accepts an ID argument:
```graphql
# As regular user — request another user's data
query { user(id: "OTHER_USER_ID") { email phone address ssn } }

# Request admin-only data
query { allUsers { id email role lastLogin } }
query { systemConfig { databaseUrl secretKey } }

# Request data you shouldn't see
query { me { internalNotes adminFlag } }
```

### Step 2.2: Field-Level Authorization

This is where most GraphQL IDOR hides. The TYPE may be accessible, but individual FIELDS should be restricted:
```graphql
# query { user(id: "OTHER_ID") { name } }        → 200 (name is public)
# query { user(id: "OTHER_ID") { email } }        → should be 403 (email is private)
# query { user(id: "OTHER_ID") { creditCard } }   → should be 403
```
Test EACH field independently. Authorization is per-field, not per-type.

### Step 2.3: Mutation Authorization

Test write operations:
```graphql
mutation { updateUser(id: "OTHER_ID", input: { role: "admin" }) { id role } }
mutation { deleteUser(id: "OTHER_ID") { success } }
mutation { createInvite(orgId: "OTHER_ORG") { token } }
```

### Step 2.4: Alias-Based Enumeration

GraphQL aliases let you send multiple queries in one request:
```graphql
query {
  a: user(id: "1") { email }
  b: user(id: "2") { email }
  c: user(id: "3") { email }
  d: user(id: "4") { email }
  e: user(id: "5") { email }
}
```
If this returns multiple users' data → mass IDOR via single request.

### Step 2.5: Batching Attack

Send multiple operations in one request:
```json
[
  {"query": "mutation { login(email: \"user@test.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"user@test.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"user@test.com\", password: \"pass3\") { token } }"}
]
```
If batching is supported → bypasses per-request rate limiting. One HTTP request, N operations.

### Step 2.6: Injection Through Arguments

GraphQL arguments may flow into database queries or other sinks:
```graphql
# SQLi through search
query { users(filter: "' OR 1=1--") { id email } }
query { search(query: "test' UNION SELECT password FROM users--") { results } }

# NoSQL injection  
query { users(where: { email: { $ne: "" } }) { id email } }

# SSRF through URL arguments
mutation { importData(url: "http://169.254.169.254/latest/meta-data/") { result } }
```

### Step 2.7: Nested Query Resource Exhaustion

Test if query depth/complexity limits exist:
```graphql
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments { text }
                }
              }
            }
          }
        }
      }
    }
  }
}
```
If response time increases exponentially with depth → resource exhaustion vulnerability. Start with depth 3, increase to 5, then 7. If each level doubles response time, the server has no depth limiting.

**Do NOT crash the server.** Test incrementally and stop when the pattern is clear.

**Max confirmation attempts: 12 across different techniques.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {query authz / field authz / mutation authz / batching / injection / nesting}
[SPECIFIC-QUERY] {the exact query tested}
[RESULT] {unauthorized data / unauthorized action / rate bypass / DoS pattern / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different queries / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Introspection disabled AND field suggestions don't leak schema
- All queries enforce proper authorization (tested 5+ queries with ID arguments)
- All mutations enforce proper authorization
- Field-level authorization tested (not just type-level)
- Batching disabled or rate-limited per operation
- Query depth/complexity limits enforced

### Structured Log
```
[VULN-NEGATIVE]
[ENDPOINT] {URL}
[STEPS-RUN] {introspection, query authz, mutation authz, field authz, batching, injection, nesting}
[SIGNAL] {all operations properly secured}
[CONCLUSION] {GraphQL implementation enforces authorization and limits}
[ACTION] Endpoint cleared for GraphQL vulnerabilities.
```

---

## Phase 3: Exploitation

### Level 1: Data Exfiltration
Use confirmed unauthorized queries to extract sensitive data. Document one example with the query and response structure (redact actual data).

### Level 2: Unauthorized Mutation
Execute a confirmed unauthorized mutation. Use a reversible action.

### Level 3: Mass Enumeration via Aliases
If alias-based IDOR confirmed, demonstrate mass data extraction with a single request.

**Stop condition:** At first confirmed unauthorized access → STOP. Generate report.

---

## Things to Do

- Always attempt introspection first — it reveals the entire attack surface instantly
- Test authorization on EACH query/mutation independently — they often have inconsistent enforcement
- Test individual FIELDS within types — field-level authz is where the bugs are
- Check batching for rate limit bypass — especially on login/OTP endpoints
- Test injection in arguments — GraphQL arguments flow into resolvers which may use them unsafely

## Things Not to Do

- Do not send deeply nested queries that could crash production — test incrementally
- Do not assume introspection disabled means secure — reconstruct schema via field suggestions
- Do not test only one query/mutation — authorization inconsistency is the norm
- Do not batch hundreds of operations — 5-10 demonstrates the capability

---

## Cross-Skill Links

- [[idor]] — GraphQL queries with ID arguments are IDOR vectors
- [[sqli]] — GraphQL arguments may flow into SQL queries
- [[ssrf]] — URL arguments in mutations may trigger SSRF
- [[mass-assignment]] — Mutation arguments may accept unauthorized fields
- [[race-condition]] — Batched mutations may create race conditions
