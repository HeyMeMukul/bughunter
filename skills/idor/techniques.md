# Advanced IDOR Techniques

## When to Use

Consult when basic IDOR testing (swap IDs) fails or when dealing with non-standard identifier formats.

---

## UUID v1 Prediction

UUID v1 encodes the timestamp and MAC address of the generating machine:
```
6ba7b810-9dad-11d1-80b4-00c04fd430c8
│        │    │    │    │
│        │    │    │    └── MAC address (node)
│        │    │    └── Clock sequence (variant)
│        │    └── Version (1 = time-based)
│        └── Time mid
└── Time low
```

**Attack:** If you know when another user registered and the server uses UUID v1:
1. Extract your UUID → derive the MAC address and clock sequence
2. Estimate the target's registration timestamp
3. Generate UUIDs for that time window with the same MAC/clock
4. One of them will match the target user's UUID

**Tool:** `uuid_tool`, or manual calculation with the UUID spec.

---

## Wrapped/Encrypted ID Manipulation

Some applications encrypt or sign IDs. Analyze the format:

### Padding Oracle on Encrypted IDs
If the encrypted ID uses CBC mode with padding:
1. Modify ciphertext bytes
2. If you get different errors for valid vs. invalid padding → padding oracle
3. Use the oracle to decrypt and re-encrypt with a different ID

### HMAC-Signed IDs
```
ID format: base64(data).base64(hmac)
```
If the HMAC key is weak or reused → crack it → forge IDs.
If the signature validation has timing leaks → byte-by-byte extraction.

### JWT-Wrapped IDs
If the ID is embedded in a JWT → apply [[jwt]] skill to forge the token with a different ID.

---

## GraphQL IDOR

GraphQL makes IDOR testing systematic because the schema tells you what's queryable:

```graphql
# Direct ID query
query { user(id: "456") { email, phone, ssn } }

# Nested queries — access through relationships
query { 
  post(id: "789") { 
    author { 
      email 
      privateNotes 
    } 
  } 
}

# Mutation IDOR
mutation { 
  updateUser(id: "456", input: { role: "admin" }) { 
    id, role 
  } 
}

# Batch queries — test multiple IDs at once
query {
  a: user(id: "1") { email }
  b: user(id: "2") { email }
  c: user(id: "3") { email }
}
```

**Key insight:** GraphQL often has different authorization on different fields within the same type. `user(id: "456") { name }` might work while `user(id: "456") { email }` might not. Test each field independently.

---

## API Endpoint Pattern Testing

Don't test one endpoint — test the PATTERN across the entire API:

```
Base pattern: /api/v1/{resource}/{id}

Test on ALL resources:
/api/v1/users/{id}
/api/v1/users/{id}/profile
/api/v1/users/{id}/settings
/api/v1/users/{id}/orders
/api/v1/users/{id}/documents
/api/v1/users/{id}/payments
/api/v1/users/{id}/notifications
/api/v1/organizations/{id}
/api/v1/organizations/{id}/members
/api/v1/organizations/{id}/settings
/api/v1/orders/{id}
/api/v1/documents/{id}
/api/v1/invoices/{id}
```

**Authorization inconsistency is the norm.** One endpoint being protected does NOT mean others are. Developers often add authorization case-by-case, and they miss some.

---

## IDOR via State Manipulation

Sometimes IDOR is achievable through state transitions, not direct ID access:

### Invite/Share Flow
1. User A shares resource with User B via invite link
2. User B accepts → now has access
3. User B modifies the invite to include resource IDs they shouldn't access
4. Application grants access based on the invite, not proper authorization

### Workflow Transfer
1. Order created by User A (order ID 100)
2. User B creates order (order ID 101)
3. User B modifies their order to reference User A's payment method or shipping address

### Nested Resource Access
```
GET /api/users/123/documents/456
```
What if the server checks that you are user 123 but doesn't verify that document 456 belongs to user 123? You can access ANY document through YOUR user path.

---

## Response Filtering vs. Authorization

Some applications fetch all data then filter the response based on the user:

```
Backend: SELECT * FROM users WHERE id = ?  (no WHERE user_id = current_user)
Filter:  if user.org != current_user.org: remove_sensitive_fields()
```

This creates two problems:
1. The query is still executed (timing/error side-channel)
2. The filter might miss some fields
3. The filter might not apply to all response formats (JSON vs. XML)

Test: Does changing the `Accept` header reveal more data? Does adding `?format=xml` or `?fields=all` bypass the filter?

---

## Automated IDOR Testing Workflow

```bash
# 1. Capture all requests as Account A
# Use Burp proxy → export requests with IDs

# 2. Replace Account A's session with Account B's session
# Keep all IDs the same

# 3. Replay every request
# Compare responses: same data as A → IDOR
#                    different data → using session (no IDOR)
#                    403/404 → protected

# Tools: Autorize (Burp extension), AuthMatrix, Match and Replace rules
```

The Autorize Burp extension does this automatically — it replays every request with a different user's session and flags authorization issues.
