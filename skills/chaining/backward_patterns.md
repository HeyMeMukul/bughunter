# Backward Chain Patterns

> "I want impact Y. What primitives do I need to assemble?"

Indexed by **target impact**. For each impact category programs pay for, every documented primitive set that produces it. Use this during **Phase 2 Step 3.2 (Backward Synthesis)**.

This is the senior skill. Forward synthesis finds chains you already half-have. Backward synthesis tells you what to go looking for. Walk this file when the program is paying for specific impacts and you want to know if those impacts are reachable in this target.

---

## Impact: Account Takeover (Any User, No Interaction)

The Holy Grail — every program's top payout. Multiple paths, all viable in different applications.

### Path A — Authentication Token Cross-Origin Read
**Required primitives:**
1. An endpoint that returns the access token in the response body (`/api/auth/session`, `/api/me`, `/api/token`, `/whoami`)
2. CORS misconfiguration on that endpoint reflecting `Origin` with `Credentials: true`

**Construction:** Attacker hosts evil.com. Victim visits evil.com while logged in. JavaScript on evil.com makes credentialed fetch to `/api/auth/session`. CORS allows read. Token captured.

### Path B — Subdomain Takeover + Wide Cookie Scope
**Required primitives:**
1. A subdomain pointing to an unclaimed cloud resource (AWS S3 bucket, Heroku app, GitHub Pages, Azure)
2. Session cookie set with `Domain=.target.com`

**Construction:** Claim the subdomain. Read `document.cookie` from JavaScript on the claimed subdomain. Cookie includes session due to wide scope.

### Path C — Notification Stream Hijack
**Required primitives:**
1. Real-time notification stream (WebSocket, SSE, PubNub, Pusher, Firebase) accessible without per-user auth
2. Predictable channel name pattern (e.g., `notifs-{user_id}`, `inbox-{email_hash}`)
3. Password reset flow that delivers codes via that channel (or sensitive notifications that leak ATO material)

**Construction:** Subscribe to victim's predictable channel. Trigger password reset for victim. Intercept reset code. Reset password.

This is the FIND-306 Cleartax pattern. The scope framing matters: report this as "ClearTax misuse of the third-party notification service" not "PubNub product flaw" — the bug is in how the application uses the service.

### Path D — OAuth Token Theft via redirect_uri Bypass
**Required primitives:**
1. OAuth authorization flow on the target
2. `redirect_uri` validation that uses domain-prefix, substring, or starts-with matching (not exact match)
3. Open redirect on the target's domain that the prefix matching accepts

**Construction:** Attacker crafts `target.com/oauth/authorize?...&redirect_uri=target.com/openredirect?next=evil.com`. Target validates `redirect_uri` starts with `target.com` → passes. OAuth grant happens. Redirect chain leads to evil.com with `?code=` or `#access_token=`.

### Path E — CSRF on Email-Change + Email-Only Password Reset
**Required primitives:**
1. CSRF vulnerability on the email-change endpoint (missing token, weak Origin/Referer check, or vulnerable SameSite setting)
2. Password reset flow that sends reset link to current email (vs. requiring old-email confirmation)

**Construction:** Victim visits attacker page. CSRF changes victim's email to attacker's. Attacker triggers password reset on victim's account. Reset link arrives at attacker's email.

### Path F — Self-XSS + Login CSRF + Context Switch
**Required primitives:**
1. Self-XSS (any flavor — stored, reflected, DOM)
2. Login CSRF: login form lacks CSRF token, accepts cross-origin POST, no `SameSite=Strict`
3. An "account switcher" or single-sign-out endpoint that returns the victim to their own session after the XSS fires

**Construction:** See Vitor Falcao's writeup (canonical_examples.md). Three gadgets, one critical.

### Path G — JWT Forgery
**Required primitives:**
1. JWT-based authentication
2. One of: `alg: none` accepted; `HS256` accepting public RSA key as secret; `kid` parameter SQLi/LFI; weak HMAC secret (brute-forceable); `jku`/`x5u` accepting attacker URL

**Construction:** Forge a JWT with target user's claims. Send authenticated requests as that user.

### Path H — Session Fixation
**Required primitives:**
1. Server accepts attacker-supplied session ID (cookie or URL parameter)
2. Login does not invalidate and reissue the session

**Construction:** Attacker sets victim's session cookie via tab-nabbing, subdomain XSS, or social engineering. Victim logs in. Attacker now shares the session.

### Path I — Predictable Password Reset Token
**Required primitives:**
1. Password reset token generation that is predictable (timestamp-based, sequential, weak randomness)
2. Reset URL that does not include user-binding (e.g., `/reset?token=XYZ` not `/reset?token=XYZ&user=victim`)

**Construction:** Trigger reset for victim. Predict the token (or enumerate a narrow range). Use token before victim does.

### Path J — Email Verification Bypass + Email Takeover
**Required primitives:**
1. Mass assignment on signup or profile update accepting `email_verified: true` or `is_verified: true`
2. Login-by-email or password-reset-by-email as the recovery mechanism

**Construction:** Sign up or change email to the victim's email with `email_verified: true`. Now the application treats attacker as the verified owner of victim's email → password reset → ATO.

---

## Impact: Account Takeover (1-Click on Victim)

Less severe than zero-interaction but still typically Critical or High. The chains are similar but require some victim action.

### Path K — Stored XSS in Common Surface + Auth-in-localStorage
**Required primitives:**
1. Stored XSS reaching another user's session (comment, message, profile rendered for viewers)
2. App stores auth token in `localStorage` instead of `HttpOnly` cookie

**Construction:** Plant XSS. Victim views attacker's profile/comment/message. XSS reads `localStorage.token` and exfils to attacker.

### Path L — Open Redirect + OAuth (1-Click Variant)
**Required primitives:** same as Path D above; the difference is `redirect_uri` is enforced and the chain requires victim to click an attacker-crafted authorization URL.

### Path M — Reflected XSS + Auth Token in URL/Hash
**Required primitives:**
1. Reflected XSS on any page on the target's primary domain
2. Magic-link auth, OAuth implicit flow, or SSO that puts tokens in URL fragments/hashes

**Construction:** Attacker URL combines reflected XSS payload with a malicious script that exfils the magic-link token or watches for OAuth fragment.

---

## Impact: Privilege Escalation (User → Admin)

### Path N — Mass Assignment of Role Field
**Required primitives:**
1. Profile or user update endpoint accepting a role/privilege field not exposed in UI
2. The role field is server-trusted (not re-checked on action)

**Construction:** Send `PATCH /api/user/me` with body containing `{"is_admin": true}` or `{"role": "admin"}`. Hope for the best — works surprisingly often, especially in startup APIs that share the user model between admin and user endpoints.

### Path O — IDOR + Mass Assignment Combined
**Required primitives:**
1. Write IDOR on a user-management endpoint
2. Mass assignment on that same endpoint includes a role field

**Construction:** `PATCH /api/users/<admin_id>` with `{"role": "user"}` — demote admin. Or `PATCH /api/users/<my_id>` with `{"role": "admin"}` — promote self.

### Path P — JWT Claim Manipulation
**Required primitives:**
1. JWT with role/privilege in claims
2. Weak signature (see Path G primitives)

**Construction:** Forge JWT with elevated role claim.

### Path Q — Forced Admin Endpoint Access via SSRF
**Required primitives:**
1. SSRF reaching internal admin paths
2. Admin paths trust the originating IP (no per-request auth)

**Construction:** SSRF to `http://internal-admin.target.local/users/promote?id=...`.

### Path R — Cross-Tenant via IDOR on Multi-Tenant SaaS
**Required primitives:**
1. IDOR that crosses tenant boundary (often missing tenant check, only user check)
2. Target tenant has admin role configured

**Construction:** From a tenant-A user, access tenant-B resources. If the IDOR includes admin endpoints, you have tenant-B admin.

---

## Impact: Mass PII / Customer Data Exposure

### Path S — SSRF → Cloud Storage Access
**Required primitives:**
1. SSRF
2. Cloud instance with IAM role granting S3/blob storage read

**Construction:** SSRF → IMDS → IAM creds → enumerate buckets → exfil. Capital One 2019 pattern.

### Path T — Proxy Traversal (Sam Curry's Pattern)
**Required primitives:**
1. BFF/proxy/gateway endpoint that routes requests internally
2. Path traversal characters (`..`) accepted within the proxy path
3. Internal API behind the proxy returns aggregated data

**Construction:** `GET /bff/proxy/orchestra/get-user` works. `GET /bff/proxy/orchestra/../users/all` reaches a different internal endpoint. This is how Sam Curry got 100M Starbucks records.

### Path U — SQL Injection
**Required primitives:**
1. SQLi (any flavor — UNION, blind, error, time-based)
2. Database contains the target data

**Construction:** Standard SQLi exploitation. Often a single primitive but counts here because the impact path matters: extracting 1M user records to demonstrate scale is the chain to PII exposure.

### Path V — IDOR on Aggregation Endpoint
**Required primitives:**
1. IDOR on an endpoint that returns multiple records given a single ID parameter
2. IDs sequentially enumerable OR leaked elsewhere

**Construction:** `GET /api/reports/<id>` returns aggregated data spanning many users. Enumerate. Exfil.

### Path W — Backup / Export File Disclosure
**Required primitives:**
1. Predictable backup or export filename (`/exports/users-2024-12.csv`, `/backups/db-{date}.sql`)
2. Files served without auth or with weak auth (path-based)

**Construction:** Enumerate filenames. Download.

### Path X — GraphQL Over-Fetching
**Required primitives:**
1. GraphQL endpoint
2. Schema includes fields/relations that REST surface hides
3. No per-field authorization

**Construction:** Introspection query → identify hidden fields (PII, financial, internal) → query at scale.

---

## Impact: Remote Code Execution

### Path Y — Deserialization
**Required primitives:**
1. App deserializes attacker-controlled data (cookie, body, request param)
2. Application stack has known gadget chain (Java: CommonsCollections, ysoserial; PHP: pop chain; .NET: ObjectDataProvider; Python: pickle)

**Construction:** Craft serialized gadget chain. Submit. Win.

### Path Z — File Upload + Execution
**Required primitives:**
1. File upload accepting executable types (.php/.jsp/.aspx) OR extension confusion (.php.jpg with double-extension parsing) OR polyglot (image with embedded code in metadata where parser executes)
2. Uploaded file in web-served path

**Construction:** Upload web shell. Access via URL. Execute commands.

### Path AA — Path Traversal Write + Execution Path
**Required primitives:**
1. Write traversal capability
2. A path in the web-served or auto-loaded directory tree

**Construction:** Write web shell to `/var/www/.../shell.php`. Access. Or write `.htaccess` to enable PHP in upload dir.

### Path BB — DLL Hijacking (Windows targets)
**Required primitives:**
1. Path traversal write to Windows host
2. Application loading DLLs from a search path that includes the writable location

**Construction:** This is Meta Messenger $111,750 — write malicious DLL to a location in `LoadLibrary` search order.

### Path CC — Headless Browser SSRF
**Required primitives:**
1. Feature using headless Chromium (PDF export, screenshot, link preview)
2. `--no-sandbox` flag (common Docker misconfig) OR known Chromium CVE

**Construction:** Trigger feature with attacker HTML. Headless Chromium fetches and renders. Sandbox-less context escapes to host shell.

### Path DD — SSRF + Internal Service RCE
**Required primitives:**
1. SSRF allowing protocol switching (gopher://, file://) OR pure HTTP SSRF + internal service with RCE bug
2. Internal service like Redis (MODULE LOAD), Memcached, MongoDB, ElasticSearch (CVE backlog)

**Construction:** SSRF to `gopher://localhost:6379/_<redis commands>` → MODULE LOAD malicious .so → RCE.

### Path EE — Server-Side Template Injection
**Required primitives:**
1. User input reaches a template engine parser
2. The template engine has a documented RCE technique (Jinja2 `{{ ''.__class__.mro()[1].__subclasses__() }}`, Twig `{{_self.env.registerUndefinedFilterCallback...}}`, etc.)

**Construction:** Confirm SSTI primitive. Apply engine-specific payload.

### Path FF — Prototype Pollution to RCE (Node.js)
**Required primitives:**
1. Prototype pollution vulnerability
2. A sink that reads polluted property and uses it in `child_process.spawn`, `eval`, template render with executable, or option object for spawn

**Construction:** Pollute `Object.prototype.shell = true` (or similar). Trigger sink. RCE.

---

## Impact: Financial Loss / Business Logic Abuse

### Path GG — Race Condition on Limit-Enforced Operation
**Required primitives:**
1. Operation with a usage limit (coupon, free trial, withdrawal)
2. Limit check and consumption not atomic

**Construction:** Send N parallel single-packet requests. Some succeed past the limit.

### Path HH — Workflow Step Skipping
**Required primitives:**
1. Multi-step workflow with state machine
2. Server validates only current-step input, not state transition validity

**Construction:** Submit step 5's payload directly without completing 1-4. State updates without prerequisites.

### Path II — Negative Quantity / Underflow
**Required primitives:**
1. Quantity field on purchase, transfer, or refund
2. No min-value or sign check

**Construction:** Submit `quantity: -10` on refund → adds to attacker balance.

### Path JJ — Currency / Decimal Confusion
**Required primitives:**
1. Multi-currency or decimal-precision pricing
2. Race between price lookup and charge

**Construction:** Pay in low-value currency for high-value-currency item. Or submit `price: 0.001` where server truncates.

### Path KK — Coupon / Discount Stacking
**Required primitives:**
1. Coupon application endpoint that does not check coupon-already-applied
2. Multiple coupons with stackable percentages

**Construction:** Apply same coupon N times (race or direct) → 100%+ discount.

### Path LL — Tax / Shipping / Promo Confusion
**Required primitives:**
1. Order summary that calculates tax/shipping/promo on client side or stale data
2. Submit endpoint trusts client-supplied price components

**Construction:** Tamper with the summary, submit, server charges the tampered amount.

---

## Impact: Mass / Persistent XSS

### Path MM — Reflected XSS + Cache Poisoning
**Required primitives:**
1. Reflected XSS on a cacheable page
2. The reflected input is unkeyed (header, parameter the cache ignores)

**Construction:** Poison cache with XSS payload. Every subsequent visitor served the poisoned response.

### Path NN — Stored XSS in Common-Render Surface
**Required primitives:**
1. Stored XSS in a field rendered to many users (display name, comment, message, support ticket title)
2. No sanitization on render OR sanitization bypassed by mutation XSS

**Construction:** Store the payload. Wait for victims to render it.

### Path OO — XSS via Cache Deception (Kettle)
**Required primitives:**
1. Path-truncation cache behavior (`/profile.css` caches `/profile`)
2. XSS-injectable content in the cached response

**Construction:** Inject XSS into your own profile. Request `/profile.css?cb=1` to cache the XSS response as a public asset. Trick victims into requesting the same.

---

## Impact: Authentication Bypass (Pre-Auth)

### Path PP — Default / Weak Credentials
**Required primitives:**
1. Admin or service account with default credentials
2. Account reachable from internet

Often found via shodan-style enumeration or by inspecting login error messages for username enumeration.

### Path QQ — SQL Injection in Login
**Required primitives:**
1. SQLi in username or password field
2. Login query uses concatenation or weak parameterization

**Construction:** Classic `' OR 1=1--` family payloads.

### Path RR — Authentication Token Confusion
**Required primitives:**
1. Two authentication mechanisms (cookie + bearer token, primary + impersonation header)
2. Backend uses only one, frontend validates only the other

**Construction:** Send request with weak/forged token in the channel the backend trusts.

### Path SS — HTTP Smuggling Auth Bypass
**Required primitives:**
1. HTTP request smuggling (CL.TE, TE.CL, H2 downgrade)
2. Backend trusts header that frontend strips (`X-User`, `X-Auth`)

**Construction:** Smuggle a request that includes the stripped header. Backend trusts it.

### Path TT — SAML Signature Wrapping / Exclusion
**Required primitives:**
1. SAML-based SSO
2. Vulnerable XML parser allowing signature scope confusion OR optional signature validation

**Construction:** Craft SAML assertion with attacker-controlled NameID, wrap or exclude the signature.

---

## Impact: Persistent Presence

### Path UU — Stored XSS in Admin View
**Required primitives:**
1. Stored XSS where the payload reaches an admin's browser
2. Admin has elevated privileges in-session

**Construction:** Plant XSS via a support ticket, user-submitted form, or any field rendered in admin UI.

### Path VV — Subdomain Takeover
**Required primitives:**
1. Unclaimed subdomain pointing to claimable cloud resource

Persistence comes for free — the attacker owns the subdomain until the program reclaims it.

### Path WW — File Upload Web Shell
**Required primitives:** see Path Z

### Path XX — Persistent Session via Long-Lived Refresh Token
**Required primitives:**
1. Refresh token with long expiry (months/years)
2. Refresh tokens not invalidated on password change
3. ATO via any of the above paths

Once you have a refresh token, you keep the access — even after the victim resets the password.

---

## Using This File

The mechanical procedure for **Phase 2 Step 3.2**:

1. List the program's payout tiers (Critical, High, Medium with bounty amounts).
2. For each Critical/High impact category, walk this file's section.
3. For each Path, list its required primitives.
4. Cross-reference with `CHAIN-INVENTORY.md` (Step 1.2).
5. Where ALL required primitives are present → chain hypothesis (write to `CHAINS-NNN.hypothesis.md`).
6. Where SOME required primitives are present → primitive gap → send mapping task to probe for the missing primitive.
7. Where NO primitives are present → impact is unreachable from current inventory; record and move on.

This is mechanical, not creative. The creative part was building the inventory. The backward walk is bookkeeping that finds chains forward synthesis misses.
