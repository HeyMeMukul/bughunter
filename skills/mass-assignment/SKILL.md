---
name: testing-mass-assignment
description: Mass assignment / auto-binding vulnerability testing. Use when POST/PUT/PATCH endpoints accept JSON or form data that binds to server-side models — identified by user registration, profile/settings updates, resource creation, or any endpoint where submitted fields map to object properties. Covers field discovery, privilege escalation through role fields, cross-tenant manipulation, verification status bypass, and framework-specific binding vulnerabilities (Ruby on Rails, Spring, Laravel, NestJS).
---

# Mass Assignment Testing

Mass assignment occurs when frameworks automatically map request parameters to internal object fields without restricting which fields can be set. The framework does convenience work for the developer — "here's a user object, just bind all the request fields" — but without explicit allowlisting, attackers can set ANY field the model supports, including role, admin flag, account balance, internal IDs, and verification status.

## Reference Files

- [techniques.md](./techniques.md) — Field discovery methodologies, framework-specific attack patterns, and nested object manipulation

## Mental Model

The developer defines a User model:
```
class User {
  id, email, name, password, role, is_verified, is_admin, created_at, org_id
}
```

The framework offers: `User.update(request.body)` — automatically binds all fields in the request body to the User object.

The developer writes the frontend to only submit `name` and `email`. The backend uses `User.update(request.body)` thinking only those fields will ever come in.

You send: `{"name": "attacker", "email": "a@b.com", "role": "admin", "is_admin": true}`. The framework dutifully sets all fields. You're now an admin.

**Key reasoning:** The vulnerability is NEVER the framework — it's the developer trusting that only frontend-defined fields will be submitted. Your job is to discover all fields the model supports and test which ones are unprotected.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (discover fields)  (inject fields)   (declare secure)   (demonstrate escalation)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Field Discovery

### Step 1.1: Visible Fields (UI-Submitted)
What fields does the frontend submit? Intercept the normal request.

### Step 1.2: Hidden Field Discovery — 5 Sources

**Source 1: GET Response Analysis**
```
GET /api/user/me
Response: {"id": 1, "name": "John", "email": "j@b.com", "role": "user", "is_verified": true, "internal_notes": "...", "org_id": "..."}
```
Fields present in GET but absent from PUT = candidates for mass assignment.

**Source 2: API Documentation**
Swagger/OpenAPI specs, API docs, GraphQL schemas — may reveal the complete model.

**Source 3: Source Code**
GitHub for the organization. Model definitions often expose every field:
```
class User(Model):
    email = StringField()
    role = StringField(default="user")
    is_admin = BooleanField(default=False)
    subscription_tier = StringField(default="free")
```

**Source 4: Error Messages**
Send invalid data. Error messages may reveal field names:
```
{"email": 123}
Response: "Validation error: 'email' must be a string, 'name' is required, 'role' has invalid value"
```

**Source 5: Related Endpoints**
If `/api/admin/users` returns user objects with more fields than `/api/users`, those extra fields exist on the model.

### Step 1.3: Baseline Submission
Submit a normal update with expected fields. Record response and which fields actually changed.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL and method}
[VISIBLE-FIELDS] {fields the UI sends}
[HIDDEN-FIELDS] {fields discovered via GET/docs/source/errors}
[HIGHEST-PRIORITY-FIELDS] {role, is_admin, verified, org_id, balance, subscription_tier}
[DECISION] Proceed to confirmation
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Mass Assignment |
|-------|-------------------|
| HIGH | Injected field accepted AND changed object state (verified by GET response) |
| MEDIUM | Server accepts extra fields without error but state change not confirmed |
| LOW | Server strips unknown fields or uses allowlist |

### Step 2.1: Priority Field Injection

Add high-priority fields to the update request:
```json
{
  "name": "expected field",
  "email": "expected field",
  "role": "admin",
  "is_admin": true,
  "isAdmin": true,
  "admin": 1,
  "is_verified": true,
  "email_verified": true,
  "is_active": true,
  "subscription_tier": "enterprise",
  "balance": 99999,
  "org_id": "target-org-uuid",
  "tenant_id": "target-tenant",
  "user_type": "admin",
  "permissions": ["all"],
  "roles": ["admin"],
  "groups": ["administrators"]
}
```

### Step 2.2: Verify State Change

After submission, fetch the object via GET. Check EACH injected field:
- `role` changed to "admin" → Critical. Admin privilege escalation.
- `is_verified` changed to true → Bypass email verification.
- `balance` changed → Financial manipulation.
- `org_id` changed → Cross-tenant access.

**Critical:** Don't trust the response of the UPDATE request. Servers often accept fields for validation but don't persist them. ALWAYS verify via a subsequent GET.

### Step 2.3: Nested Object Manipulation

If the model has nested objects:
```json
{
  "name": "test",
  "address": {
    "street": "123 main",
    "is_admin_address": true,
    "role": "admin"
  },
  "settings": {
    "theme": "dark",
    "override_permissions": true
  }
}
```
Nested objects may have less strict filtering than top-level fields.

### Step 2.4: Registration Endpoint Testing

Registration is often less protected than update:
```json
POST /api/register
{
  "email": "attacker@test.com",
  "password": "password",
  "role": "admin",
  "is_admin": true,
  "email_verified": true
}
```

If the created account has elevated privileges → mass assignment on registration = instant admin account creation.

### Step 2.5: Array and Type Confusion

```json
{"role": ["admin", "user"]}          // Array instead of string
{"role": {"name": "admin"}}          // Object instead of string
{"is_admin": "true"}                 // String instead of boolean
{"is_admin": 1}                      // Number instead of boolean
{"is_admin": "1"}                    // String number
{"is_admin": [true]}                 // Array
```

Type coercion bugs may allow bypassing validators that check the wrong type.

**Max confirmation attempts: 10 field combinations across 3+ endpoints.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[ENDPOINT] {URL}
[FIELDS-INJECTED] {which fields}
[ACCEPTED] {yes — state changed / accepted but no effect / rejected}
[IMPACT] {what privilege/access was gained}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different fields / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Server uses allowlist-based field binding (only explicit fields accepted)
- Extra fields silently ignored (no state change in GET)
- Tested across multiple endpoints (update + registration + creation endpoints)
- Tested nested object manipulation
- Tested type variations

---

## Phase 3: Exploitation

### Level 1: Privilege Escalation
If role/admin field accepted → demonstrate access to admin-only functionality.

### Level 2: Cross-Tenant Access
If org_id/tenant_id accepted → demonstrate access to another tenant's resources.

### Level 3: Financial/State Manipulation
If balance/credits/subscription fields accepted → demonstrate unauthorized modification.

**Stop condition:** Privilege escalation or data manipulation confirmed → STOP.

---

## Things to Do
- Compare GET responses with PUT payloads — the gap reveals candidates
- Test REGISTRATION endpoints separately — they often have weaker protection
- Always verify state change via subsequent GET — don't trust update response
- Test nested objects — they often have less strict filtering
- Check source code if available — model definitions reveal all fields

## Things Not to Do
- Do not guess random field names — discover them from responses, docs, or code
- Do not modify other users' accounts during testing
- Do not inject dozens of random fields — be targeted based on discovered model

## Cross-Skill Links
- [[idor]] — Mass assignment + IDOR = modify any user's role
- [[business-logic]] — Setting unauthorized fields violates business constraints
