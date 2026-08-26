# Forward Chain Patterns

> "I have primitive X. What amplifiers turn it into impact?"

Indexed by primitive. For each primitive, every documented amplifier pattern, the prerequisites the amplifier requires, and the resulting impact. Use this during **Phase 2 Step 2.1 (Forward Synthesis)**.

When a primitive is in inventory, walk this file's section for that primitive. Each amplifier line is a candidate chain.

---

## Open Redirect

The most versatile chain primitive in modern web apps. Almost never reportable alone above informational, almost always amplifies something else.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| OAuth redirect_uri domain-only validation | OAuth flow with permissive redirect_uri check (domain prefix or "starts with" match instead of exact match) | OAuth code/token theft → ATO |
| OAuth redirect_uri allows subdomain | redirect_uri whitelist includes a subdomain that has open redirect | Token theft → ATO |
| `javascript:` scheme accepted in redirect target | Server returns `Location: javascript:...` OR client-side `window.location = userInput` without scheme filter | Reflected XSS |
| CSP allows redirected-to domain via `script-src 'self'` | Open redirect on same-origin endpoint that serves user-controlled content from elsewhere | CSP bypass → XSS |
| CSPT (client-side path traversal) | Front-end JS fetches `api/profile/<userInput>` and `userInput` allows `../` | Profile injection / response confusion → DOM-XSS or data exfil |
| SSRF filter that allows-list trusted domains | SSRF endpoint allowlists `target.com` but follows redirects | Filter bypass → cloud metadata, internal services |
| OAuth state parameter weak/missing | OAuth flow without `state` or with predictable `state` | CSRF on OAuth flow → forced login to attacker session |
| Cookie scope `Domain=.target.com` + redirect to vulnerable subdomain | Wide cookie + any XSS or content injection on a subdomain | Cookie theft → ATO |
| URL-based session token | Auth token in URL fragment or query (e.g., post-OAuth, magic links) + redirect to attacker | Token leak via Referer or redirect chain |
| Trusted-domain phishing | Email recipients trust target.com domain | Phishing-with-trusted-domain → credential theft (often P3 alone, P2 if combined with auth-flow trickery) |
| Tabnabbing | `target="_blank"` without `rel="noopener"` on the redirect link | window.opener manipulation → phishing |
| HTTP-to-HTTPS scheme downgrade | Open redirect accepts HTTP scheme on an HTTPS-only login path | MITM-amplified — credential interception on shared networks |

**Hardest cases:** when the open redirect requires `javascript:` and that scheme is filtered, try `data:`, `vbscript:` (legacy IE), or URL-encoded variants. When the open redirect requires same-origin to bypass CSP, look for the redirect itself returning a 3xx with `Location:` controlled by the parameter — the browser follows the 3xx and ends up at the attacker site while CSP's same-origin check was satisfied for the initial response.

---

## Self-XSS

XSS that only fires in the attacker's own account. Useless alone. Becomes critical with the right amplifier.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Login CSRF | Login form lacks CSRF token, accepts cross-origin POST, no SameSite=Strict on session cookie | Force victim into attacker session → self-XSS becomes "victim XSS in attacker context" |
| Login CSRF + post-XSS account switch | Above + endpoint exists to switch back to victim session (single sign-out, account-switcher) | Full ATO via stolen cookie or in-session API actions |
| Auth-token in URL | Login URL like `target.com/auto-login?token=...` | Phishing victim into clicking attacker's auto-login link → self-XSS now hosts victim's auth context |
| Subdomain takeover | Attacker controls a subdomain that the main app trusts (CORS, postMessage origin, cookie scope) | Self-XSS on attacker-controlled subdomain → reads main-app data |
| Trusted-domain CORS reflection | Main app has CORS that trusts attacker-controllable origin | Self-XSS uses fetch with credentials to read victim data from main app |
| postMessage handler without origin check | Main app listens to `window.message` from any origin | Self-XSS in iframe → postMessage to parent main-app → executes privileged action |

**The Vitor Falcao pattern:** CSPT gadget → self-XSS → login CSRF → context switch → ATO. Documented at https://vitorfalcao.com/posts/hacking-high-profile-targets/. The CSPT made the self-XSS reachable, the login CSRF moved the victim into the attacker's session, the context-switch endpoint completed the takeover. Four gadgets, one critical.

---

## CORS Misconfiguration (Origin Reflection)

CORS reflection without sensitive data exposure is the canonical "no impact" rejection. The fix is not reporting harder — it is finding the sensitive endpoint that the CORS policy applies to.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Auth token endpoint | `/api/auth/session`, `/api/me`, `/api/whoami`, `/api/token` returns access token or session info with the misconfigured CORS | Cross-origin token read → ATO |
| CSRF token endpoint | Form generation endpoint returns CSRF token with reflective CORS | CORS leak of CSRF token → CSRF on protected action (often email change → password reset → ATO) |
| PII endpoint | `/api/user/profile`, `/api/account` returns PII with reflective CORS | Mass PII exposure if victim visits attacker site |
| Internal admin endpoint exposed via CORS | Admin endpoint reachable from logged-in admin session, CORS reflects | Admin compromise via 1-click on attacker site |
| Subdomain takeover | CORS whitelist includes specific subdomains rather than reflecting | Take over the subdomain → ATO via trusted origin |
| Wildcard CORS without credentials, but app uses auth tokens in body | `ACAO: *` + endpoint accepts/returns auth tokens in JSON body (not cookies) | Cross-origin token theft despite `Credentials:false` |
| Null origin reflection | `Origin: null` is reflected with credentials | Sandboxed iframe attack (data: URIs produce null origin) |
| Pre-flight bypass via simple request | App relies on preflight for auth but endpoint accepts simple-request methods (GET, POST with application/x-www-form-urlencoded) | Cross-origin write via simple request, bypassing CORS preflight |

**Why CORS findings get rejected:** The pattern documented at https://bugbounty.info/Attack-Surface/Web/Client-Side/CORS is brutal: "CORS bugs are everywhere and consistently underreported because hunters see the misconfiguration and immediately report it without demonstrating actual impact. That's why programs mark them informational. The misconfiguration only matters if it lets an attacker read sensitive data cross-origin."

The rule: never report a CORS finding without naming the specific sensitive endpoint that becomes cross-origin-readable.

---

## Subdomain Takeover

Often discovered during recon, almost always low-impact alone (defacement at best), critical when amplified.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Cookie `Domain=.target.com` | Main app sets cookies on the parent domain | Read session cookie from attacker subdomain → ATO |
| CORS whitelist includes the taken subdomain | Main app CORS `Access-Control-Allow-Origin` includes the subdomain | Cross-origin auth-credential read → ATO |
| postMessage handler trusts subdomain origin | `event.origin === 'https://taken-subdomain.target.com'` check | Cross-frame command execution → in-session API calls |
| OAuth redirect_uri whitelist | OAuth `redirect_uri` allows the taken subdomain | Token theft → ATO |
| SAML assertion consumer URL whitelist | SAML AssertionConsumerServiceURL points to taken subdomain | SAML assertion interception → ATO |
| Mixed-content trust | Main app embeds scripts from `subdomain.target.com` | Stored attack via attacker-controlled script → ATO for all visitors |
| Email DKIM/SPF includes taken subdomain | `v=spf1 include:newsletter.target.com` and newsletter.target.com is taken | Phishing FROM target.com (cryptographically signed) → mass credential theft |

**Recon trigger:** if spider.sh enumerates subdomains and any of them have CNAMEs pointing to unclaimed cloud resources (AWS, Azure, GitHub Pages, Heroku, Fastly, etc.), they are takeover candidates. The Hacktivity database has hundreds of these. Most pay P3-P2 alone; with the right amplifier they reach P1.

---

## Server-Side Request Forgery (SSRF)

The premier "primitive" — even a basic Collaborator callback is reportable, but the impact ladder is steep.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| AWS IMDSv1 | EC2 instance with default IMDS configuration, IAM role attached | IAM credentials theft → S3/RDS/cloud-wide access |
| GCP / Azure metadata | Different paths, different headers (`Metadata-Flavor: Google`) | Service account token theft → cloud access |
| Kubernetes pod metadata | `https://kubernetes.default.svc` reachable | Service account token, pod metadata |
| Internal admin panel without auth | Internal admin paths (`/admin`, `/internal`, `:8080/admin`) trust source IP | Admin actions via internal-only API |
| Internal Redis/Memcached/MongoDB | Gopher protocol allowed OR HTTP libraries accepting bare TCP | RCE via Redis MODULE LOAD or LUA, data dump |
| Webhook → internal service | SSRF via webhook URL field, internal service responds with sensitive data | Information leak, lateral movement |
| Headless browser SSRF | Feature uses headless Chrome (PDF export, screenshot, link preview, OG-tag) with `--no-sandbox` | Direct RCE on the renderer host |
| Server-side rendering of attacker content | Headless browser fetches attacker page, executes JS in trusted context | Read local files via `file://`, fetch internal endpoints with cookies |
| SSRF + open redirect on internal allow-list | Server validates URL against allowlist, follows redirects | Redirect chain → IMDS or internal service |
| DNS rebinding | Server resolves hostname once, then again later; attacker controls DNS for short-lived A records | Bypass IP allowlist post-resolution |
| SMB/CIFS auth via UNC paths (Windows targets) | SSRF accepts file:// or UNC | NTLM hash leak via SMB callback → offline cracking |
| SSL termination unaware of `https://[IP]` | Frontend allowlists by hostname, attacker uses IP literal | Allowlist bypass → internal service access |

**Capital One pattern (2019):** SSRF in a WAF on EC2 → IMDSv1 → IAM credentials → S3 access → 100M customer records. The vulnerability was not exotic. It was the canonical SSRF→IMDSv1 chain.

**The "PDF export" tell:** features that fetch external content for rendering — PDF reports, screenshots, link previews, profile-picture imports — are almost always SSRF surfaces. The renderer is often a headless browser. If the renderer is Chromium with `--no-sandbox` inside a Docker container (a common misconfig), the SSRF is a direct path to RCE on the host.

---

## Mass Assignment

Almost always low-impact alone unless the over-binding field is sensitive (`is_admin`, `role`, `is_verified`).

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Hidden privilege field | Form accepts a non-UI-exposed field like `is_admin`, `role`, `verified`, `email_verified` | Direct privilege escalation |
| IDOR on the same endpoint | Update endpoint accepts arbitrary `user_id` AND arbitrary `role` | Cross-user role escalation |
| Workflow state field | Order/transaction/document update accepts a state field like `status: 'paid'` | State machine bypass — financial impact |
| Two-step verification email | Email-change endpoint accepts `email_verified: true` alongside new email | Bypass email verification → ATO |
| Foreign key over-binding | Comment endpoint accepts arbitrary `author_id`, post endpoint accepts arbitrary `owner_id` | Identity spoofing — comment/post as another user |
| JSON merge endpoints | API accepts `PATCH` with arbitrary JSON merge — deep object override | Prototype-pollution-style override of nested config |

**Mass assignment alone is informational unless the field has security meaning.** The skill is identifying which fields the application uses for privilege, ownership, or state, then guessing field names from source maps, error responses, or model conventions.

---

## IDOR (Individually Low-Impact)

IDOR on resources containing public data, or IDOR with sequential IDs on a tiny user base, often gets rejected. But IDOR enables many chains:

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Predictable user enumeration | IDOR on `/api/users/<id>/email` returns user email | Mass email harvest → password-reset attack list |
| Mass assignment on same endpoint | Write IDOR + accepts privileged fields | Cross-user privilege escalation |
| Password reset on enumerated user | IDOR identifies admin user IDs → password reset flow | Targeted ATO of admin |
| Notification stream subscription | IDOR-style channel subscription with predictable names | Real-time notification interception → password reset code theft → ATO |
| Cross-tenant IDOR | IDOR crosses tenant boundary in multi-tenant SaaS | Tenant-wide data exposure — usually Critical |
| Resource creation with arbitrary owner | Write IDOR on creation endpoint accepts `owner_id` | Identity spoofing |
| File access via predictable path | IDOR on `/exports/report-{id}.csv` | Mass document exfiltration |
| Aggregation endpoint | IDOR on `/api/reports/aggregate?user_ids=...` accepts multiple IDs | Bulk extraction with single request |

---

## Cache Poisoning

Inherently a chain primitive — poisons the cache to serve attacker content to other users.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Reflected XSS | Reflected payload + cacheable response + unkeyed input that influences the reflection | Persistent XSS for all cache-miss-then-poisoned-cache victims |
| Open redirect | Response with `Location` controlled by unkeyed header | Persistent open redirect (every visitor gets redirected) |
| Authentication confusion | Cache key omits auth → poisoned cache serves attacker-authenticated content to anonymous users (or vice versa) | Mass session leakage or privilege confusion |
| Web cache deception (Kettle's pattern) | `/profile.css` returns the same data as `/profile` due to path-truncation; cache stores it as static | Sensitive data cached as public asset |
| Hop-by-hop header smuggling | Cache key omits hop-by-hop headers an attacker can inject | Header injection persists in cache |

**Always validate cache poisoning with a clean second browser** — it is easy to confuse a personal poisoned cache for a global one. The PortSwigger labs cover this exhaustively.

---

## HTTP Request Smuggling

Almost never reportable alone — programs increasingly require demonstrated impact. The chain is the whole point.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Auth bypass on backend | Frontend strips `X-Original-URL` or similar headers, smuggling re-introduces them | Reach admin endpoints from unauthenticated context |
| Queue another user's request | Smuggle a partial request, capture the next victim's request body | Steal session cookies, credentials, CSRF tokens |
| Cache poisoning | Smuggle a request that produces a cacheable malicious response | Persistent XSS or redirect for all users |
| WebSocket hijack | Smuggle an Upgrade request, frontend treats it as normal | Read victim WebSocket messages |
| Session puzzling | Smuggle a privileged request that the backend associates with the victim's session | Operate in victim's session |

**The albinowax Portswigger research at https://portswigger.net/research is the canonical reference.** Smuggling is rarely a single-shot impact — always plan the chain target before reporting.

---

## Prototype Pollution

JavaScript-only. Library-specific. Useless without a sink.

| Amplifier (Sink) | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Client-side template render | Library reads `Object.prototype.<attr>` and inserts into DOM | DOM-XSS |
| Server-side template render (Node.js) | Backend reads polluted attribute during template render | Server-side XSS, sometimes SSTI-style RCE |
| Express middleware option pollution | Middleware (e.g., body-parser, qs) reads polluted attributes for parsing options | Path or input handling confusion |
| Configuration object pollution | App reads `config.shell` or `config.command` which becomes RCE if attacker-controlled | RCE on Node.js backend |
| `child_process.spawn` argv pollution | Polluted `options.shell: true` makes spawn execute via shell | RCE |
| CSP nonce pollution | Polluted CSP nonce becomes predictable | CSP bypass amplifier |

**Detection pattern:** test for prototype pollution first by checking if `Object.prototype.foo = "bar"` survives across requests/refreshes. Then look for sinks — every framework has different ones.

---

## Path Traversal

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Sensitive config file readable | `/etc/passwd`, `.env`, `config.yml`, `id_rsa`, `secrets.json` in known paths | Direct credential exposure |
| Database credentials in config | DB conn string in .env or config | DB takeover → mass PII |
| Source code disclosure | App code readable via traversal | Secondary vulnerability discovery — JWT secrets, API keys |
| Writable path traversal + execution | Traversal allows file writes + a writable location is in execution path | RCE via web shell upload |
| Path traversal write + scheduled task | Windows: write to `Startup` folder or scheduled task XML; Linux: cron, systemd unit | RCE on next service restart |
| DLL hijacking | Windows app: place malicious DLL in load-search path | RCE — **this is the Meta Messenger $111,750 chain** |
| Log poisoning + LFI | Write attacker-controlled string to logs, include logs via LFI | RCE via injected PHP/JSP in log file |
| Session file inclusion (PHP) | Include PHPSESSID file via LFI, prior request stored PHP code in session | RCE via session content |

---

## File Upload

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Server executes uploaded code | Upload to web-served path + .php/.jsp/.aspx accepted or extension confusion | RCE |
| Path traversal in filename | Server accepts `../` in upload name | Overwrite arbitrary file → RCE via overwriting executable |
| MIME confusion | Server checks MIME but executes by extension | Bypass via dual-purpose file (polyglot) |
| ImageMagick / ghostscript / ffmpeg processing | Upload triggers server-side image processing with known CVE | RCE via processor exploit |
| SVG + XSS | SVG with `<script>` served with content-type `image/svg+xml` | Stored XSS via uploaded "image" |
| Docx XXE | Upload to system that parses .docx | XXE via embedded `[Content_Types].xml` |
| HTML upload + permissive Content-Type | Upload becomes content-type text/html on same origin | Stored XSS |
| Zip bomb | Decompression-without-limits | DoS amplifier |
| Symlink upload | Tar/zip extraction follows symlinks | Read/write arbitrary files |

---

## Race Condition

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Limit on N-uses of resource | Coupon usage, free trial signup, redeem limit | Exceed limit — financial impact |
| Account creation race | Simultaneous registration with same email | Account takeover via duplicate creation |
| Withdrawal/transfer race | Balance check + debit not atomic | Negative balance, duplicate withdrawal |
| Approval workflow race | Approve + execute race | Bypass approval |
| File deletion + use race | Delete file but reference persists | TOCTOU file access |
| Email verification race | Send verification + create account race | Skip verification |

Race conditions usually need the "single-packet" technique (Kettle's research) to work reliably. Document the packet count required in your hypothesis.

---

## XSS (Reflected) — Escalation Patterns

Reflected XSS alone is typically P3. Chains escalate it.

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| Cache poisoning | Reflected response is cacheable + reflection is in unkeyed input | Persistent XSS — P2/P1 |
| Same-domain auth-token storage (localStorage) | App stores access tokens in localStorage instead of HttpOnly cookies | ATO via single-click on reflected XSS link |
| CSRF token leak via XSS | XSS can fetch the CSRF token from the protected endpoint | Perform any privileged action |
| Email confirmation XSS | Stored XSS in email rendering → admin opens email | Admin XSS → admin ATO |
| Self-XSS → login CSRF | See Self-XSS section above | ATO |

---

## JWT Algorithm Confusion / Forgery

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| `alg: none` accepted | Server doesn't enforce algorithm allowlist | Forge any user's JWT → ATO |
| `alg: HS256` with public key as secret | Server uses asymmetric public key in HMAC verification | Forge JWT with known public key |
| `kid` SQL injection | `kid` claim used in SQL query for key lookup | SQLi via JWT header |
| `kid` path traversal | `kid` claim used as file path | Local file inclusion → secret theft |
| `jku` / `x5u` URL trust | Server fetches keys from URL in JWT header | Attacker-controlled signing key |
| Weak HMAC secret | HS256 with brute-forceable secret | Offline crack → forge any user |

---

## Open Webhook / Server URL Fetcher

| Amplifier | Prerequisite | Resulting Impact |
|-----------|--------------|------------------|
| SSRF if server-side fetch | See SSRF section | Cloud metadata → IAM, internal services |
| Blind XXE if fetch parses XML | Webhook delivery payload parses XML | OOB exfiltration |
| Open redirect on webhook destination | Webhook delivery follows redirects with auth headers | Auth header theft via redirect to attacker |
| Webhook signature bypass | Signature uses HMAC with predictable secret OR signature header not validated | Forge webhook events → trigger internal handlers |

---

## Information Disclosure (Stack Traces, Debug Pages)

Almost always P4-P5 alone. Becomes part of chains by revealing:

| What Leaks | What It Enables |
|-----------|------------------|
| Source paths | Path traversal target identification |
| Framework versions | CVE lookup for known RCE/SQLi/etc. |
| Database type | Tailored SQLi payloads |
| AWS account ID | Cross-account confusion attacks |
| Internal hostnames | SSRF targets |
| Email addresses (employees) | Password spray, OSINT for social engineering (out of scope for most programs but useful for impact narrative) |
| Cookie names / session structure | Session prediction, fixation candidates |
| CSRF token format | Predictable token generation flaws |
| API endpoint enumeration | Hidden admin endpoints |

---

## When a Forward Search Returns Nothing

If you walked the forward table for every gadget in inventory and found no amplifier present, the inventory is incomplete. Common gaps:

- You did not re-spider after the initial pass. New gadgets appear when authentication state changes (admin role, beta features, hidden flows).
- You did not enumerate JS files exhaustively. Source maps and lazy-loaded chunks contain endpoints the entry bundle hides.
- You did not test alternative content-types. Same endpoint, different `Content-Type`, different behavior.
- You did not test alternative HTTP methods. PUT/PATCH/DELETE often have weaker auth than GET/POST.
- You did not consider cross-domain trust. If the target federates auth, the trust boundary may have gadgets.

When forward search is empty, run **backward synthesis** (see [backward_patterns.md](./backward_patterns.md)) — start from the impact and identify what primitive you would need, then probe for it.
