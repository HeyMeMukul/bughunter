---
name: testing-chaining
description: Vulnerability chaining and impact escalation — turning low-severity gadgets into high-impact findings. Use during Phase 2 (Mapping) after per-endpoint analysis is complete, before dispatching Phase 3 (Testing) hypotheses. Covers gadget inventory, forward chain synthesis (primitive → amplifier → impact), backward chain synthesis (target impact → required primitives), business-impact translation, and chain hypothesis scoring. This is how a CORS reflection becomes an ATO, how an open redirect becomes RCE, how a path traversal becomes a 100M-record breach. The single most important skill for converting "vulnerability with no impact" findings into paid findings.
---

# Vulnerability Chaining

Most bug bounty rejections do not say "this is not a bug." They say "this has no impact." A CORS reflection on a static endpoint, an open redirect on a logout URL, a stored XSS in your own private profile, a sequential ID on an enumeration that returns only public data — each is technically a vulnerability and economically worthless. Programs do not pay for behavior that violates a specification; they pay for damage to users, data, or trust.

Chaining is how solo gadgets become damage. It is the skill of seeing the application as an interconnected system of trust, identifying small flaws that individually do nothing, and constructing a sequence in which the output of one flaw feeds the input of the next until the chain reaches something the program actually cares about — account takeover, mass data exposure, financial theft, remote code execution, privilege escalation.

This skill is **mandatory** during Phase 2. Run it after single-endpoint mapping completes and before any Phase 3 testing dispatch. It is the difference between weeks of work that produce a Hall of Fame entry and weeks of work that produce a paid critical.

## Reference Files

- [forward_patterns.md](./forward_patterns.md) — "I have primitive X, what amplifies it?" — indexed by gadget type
- [backward_patterns.md](./backward_patterns.md) — "I want impact Y, what primitives do I need to assemble?" — indexed by target impact
- [canonical_examples.md](./canonical_examples.md) — Real chains from public disclosures with citations and dollar amounts
- [business_impact_mapping.md](./business_impact_mapping.md) — Translating technical findings into business-impact statements triagers accept

---

## Mental Model

### The Gadget Concept

A **gadget** is a small misconfiguration or minor bug that on its own does not justify a report, but when combined with other gadgets enables a critical attack. Open redirects, self-XSS, CORS reflections without sensitive data exposure, mass assignment on non-sensitive fields, CSRF on non-state-changing endpoints, IDOR on public resources — these are all gadgets.

> "Think of them as LEGO pieces of an exploit chain — one piece alone doesn't do much, but put a few together and you can build something huge." — Bugcrowd's gadget article

Hardened targets rarely have straight-shot critical vulnerabilities like unauthenticated SQLi or RCE. They have gadgets. The skill is patient gadget collection followed by chain synthesis — not reporting each gadget the moment it is found.

### The Chain Structure

Every chain has the same anatomy:

```
PRIMITIVE  →  AMPLIFIER(S)  →  IMPACT
(the bug)    (the gadgets that  (the thing
             carry the bug      the program
             into damage)       cares about)
```

- **Primitive**: the initial flaw that gives the attacker some capability — code execution in browser context, ability to send authenticated requests cross-origin, ability to fetch arbitrary URLs server-side, ability to override an object property.
- **Amplifier**: a separate bug or design choice that converts the primitive's narrow capability into a broader one. An open redirect amplifies an OAuth flow into token theft. A subdomain takeover amplifies a permissive CORS policy into ATO. IMDSv1 amplifies an SSRF into IAM credential theft.
- **Impact**: the damage category the program pays for. ATO, mass PII exposure, financial loss, RCE, privilege escalation, persistent presence.

### The Two-Axis Search

There are exactly two ways to construct chains. Both are required.

**Forward synthesis** — start from a gadget you have, enumerate amplifiers reachable in this application, and trace forward to impact:
> "I have an open redirect on `/logout?next=`. What can this become? Looking at amplifiers present in this app: there is an OAuth flow with `redirect_uri` validated by domain only. The redirect chain bypasses domain validation. Therefore: open redirect → OAuth `redirect_uri` bypass → access token theft → ATO."

**Backward synthesis** — start from an impact the program pays for, enumerate the primitives required to achieve it, and search the inventory:
> "I want ATO without password reset. The required primitive set is one of: (a) session fixation, (b) CSRF on email-change, (c) XSS with cookie scope, (d) auth-token leak via CORS, (e) self-XSS + login CSRF + post-XSS context switch. Searching inventory: I have a CORS reflection on `/api/auth/session` which returns the access token. Path (d) is viable."

Forward synthesis is what most hunters do naturally and badly — they see a bug and stop. Backward synthesis is the senior skill — work the impact map first, then go shopping for primitives.

### The Triage Lens

Triagers do not score what you found; they score what an attacker could realistically do. Every chain hypothesis must answer four questions before testing:

1. **Realism**: does the chain require user interaction? Cross-browser limitations? An attacker on the same network? Each constraint lowers severity.
2. **Reach**: how many users does this affect? One specific victim? Anyone who clicks a link? Every user of the application?
3. **Reversal**: can the victim detect and reverse the damage? An attacker who silently exfiltrates data scores higher than one whose attack leaves obvious traces.
4. **Compounding**: does the impact persist or compound? Stored XSS that fires for every visitor beats reflected XSS that requires a clicked link.

Write the impact statement before testing. If you cannot articulate the impact in two sentences that a non-technical product manager would understand, the chain is not yet ready to test.

---

## Workflow

```
1. INVENTORY → 2. FORWARD → 3. BACKWARD → 4. CONSTRUCT → 5. IMPACT MODEL
   (catalog       (gadget →    (impact →     (cross-      (write impact
   gadgets)       impact)      gadgets)      reference)    before test)

   Stop conditions checked at every step ↓
   Output: engagement/mapping/CHAINS-NNN.hypothesis.md
```

This skill runs as **M9 (Cross-Endpoint Chain Synthesis)** in the mapping phase, after M1-M8 produce per-endpoint profiles. It is the final mapping step before testing begins.

---

## Phase 1: Gadget Inventory

**Goal:** Build a structured catalog of every gadget the application contains, regardless of whether each gadget alone seems worth reporting.

### Step 1.1: Sweep the EP-XXX profiles for gadgets

For every `engagement/mapping/EP-*.profile.yaml`, extract gadgets matching this catalog. Do not skip a profile because its single-endpoint hypotheses look low-impact — most gadgets ARE low-impact in isolation. That is what makes them gadgets.

| Gadget Class | Detection Signal in Profile | Why It Matters |
|--------------|------------------------------|-----------------|
| Open redirect | `redirect=`, `next=`, `return=`, `callback=`, `url=` parameter; 3xx response with user-controlled `Location` | Trusted-domain phishing, CSP/CORS bypass, OAuth `redirect_uri` bypass, SSRF amplification |
| Reflected input | Parameter value appears verbatim in response body or headers | XSS, HTML injection, header injection precursor |
| CORS reflection | `Access-Control-Allow-Origin` reflects arbitrary `Origin` + `Access-Control-Allow-Credentials: true` | Cross-origin read of authenticated data — only matters with a sensitive endpoint |
| Permissive CORS subdomain trust | ACAO whitelists `*.target.com` or specific subdomains | Combined with subdomain takeover → ATO |
| Self-XSS | XSS that only fires in attacker's own account | Becomes stored XSS for victim via login CSRF |
| Login CSRF | Login form lacks CSRF token, accepts cross-origin POST | Forces victim into attacker session — amplifier for self-XSS, IDOR-as-attacker |
| Session not invalidated on password change | Old session cookies still valid after reset | Persists ATO after victim "fixes" the breach |
| IDOR on non-sensitive resource | Sequential ID, no auth check, but resource returns public data | Becomes user enumeration → password reset target list |
| Mass assignment | POST/PUT accepts fields beyond UI | Combined with IDOR → role escalation; combined with workflow → state confusion |
| Insecure direct file access | `/uploads/`, `/exports/`, `/static/user_*` without auth | Information leak; combined with predictable names → mass exfil |
| URL-fetching server feature | Webhook, link preview, PDF export, profile picture from URL, RSS importer, OAuth callback | SSRF surface — even if filtered, candidate for filter bypass chain |
| HTTP→HTTPS open redirect on auth endpoint | Login page accepts HTTP, redirects to HTTPS | Network attacker can MITM the HTTP hop — combined with auth flow → credential interception |
| postMessage handler | `window.addEventListener('message', ...)` without origin check | Cross-origin script communication abuse |
| `window.opener` not nullified | `target="_blank"` links without `rel="noopener"` | Tabnabbing — amplifier for phishing |
| Local/session storage holds auth | `localStorage.token`, `sessionStorage.jwt` | XSS becomes ATO instead of session theft (HttpOnly bypassed) |
| Subresource without SRI | External script loaded without integrity hash | Supply-chain amplifier if external host has any flaw |
| `target="_blank"` with referrer | Outbound links leak `Referer` containing session info | Token-in-URL theft |
| Wildcard postMessage | `window.parent.postMessage(data, '*')` | Cross-frame data leak to malicious iframe parent |
| Unauthenticated debug/info endpoint | `/debug`, `/health`, `/env`, `/actuator`, `/api-docs`, `/swagger.json` | Internal reconnaissance amplifier |
| BFF/proxy/gateway endpoint | `/bff/proxy/`, `/api/v1/proxy/`, `/gateway/` | Sam Curry's secondary-context attack — proxy-traversal candidate |
| Predictable resource names | Files named `report-USER_ID.pdf`, channels named `notifs-USER_ID` | Combined with weak auth → mass exfil |
| Unauthenticated WebSocket/SSE/PubSub | Real-time stream accessible without auth or with predictable channel | Notification interception → password reset code interception → ATO |
| Cookie scope wider than necessary | `Domain=.target.com` on a high-privilege cookie | Subdomain-takeover-to-ATO amplifier |
| Email/SMS template injection | Username, display name reflected in outbound email | Phishing-from-trusted-domain amplifier |

### Step 1.2: Write the inventory file

Create `engagement/mapping/CHAIN-INVENTORY.md` with the following structure. Keep it tight — one line per gadget.

```markdown
# Gadget Inventory

## Open Redirects
- G-001: GET /logout?next= — no validation, redirects to any URL (EP-014)
- G-002: POST /api/oauth/callback?redirect_uri= — domain-suffix validation only (EP-091)

## CORS
- G-003: ACAO reflects arbitrary Origin + Credentials:true on /api/auth/session (EP-007) ← LEAKS ACCESS TOKEN
- G-004: ACAO whitelists *.target.com on /api/user/profile (EP-022)

## XSS / Reflection
- G-005: Self-XSS in display_name on /profile (EP-031)
- G-006: Reflected param `q` echoed in <script> on /search (EP-042) — quotes escaped, but no encoding inside template literal

## Auth/Session
- G-007: Old sessions survive password change (EP-007)
- G-008: localStorage.access_token used by SPA (observed in spider js_analysis)

## SSRF Surface
- G-009: /api/preview accepts `url=` for OG-tag fetching (EP-088) — filters localhost but follows redirects
- G-010: PDF export uses headless Chrome with --no-sandbox flag (observed in error response leak EP-101)

## Information Disclosure
- G-011: /actuator/env exposed unauthenticated (EP-003)
- G-012: Predictable export filename: /exports/report-{USER_ID}.csv

## Privilege/Trust
- G-013: Mass assignment accepts `is_admin:true` on POST /api/users/create (EP-055) — UI doesn't expose this field
- G-014: Cookie Domain=.target.com on session JWT
```

Every gadget gets an ID (G-XXX) so chains can reference them. Do not delete gadgets that look low-impact alone — the entire point of this step is that low-impact gadgets become critical when chained.

### Step 1.3: Cross-reference with spider intelligence

The spider phase output (`engagement/spider/auth/sitemap.json`) contains intelligence that should add gadgets the per-endpoint profiles missed:

- `framework_detected`: framework-specific gadgets (Angular template injection, React prototype pollution sinks, Vue server-side rendering issues)
- `tech_headers`: `Server: nginx` + `X-Powered-By: PHP` → consider PHP-specific gadgets (type juggling, deserialization)
- `secrets_detected_types`: any `internal_hostname`, `aws_arn`, `api_key_pattern` → SSRF amplifier targets
- `sourcemaps_found > 0` → review reconstructed source for hidden endpoints, debug flags, role names
- `interesting_paths`: `/admin`, `/internal`, `/_next/data` — backward-chain candidates

Add to inventory anything found here that isn't in any individual EP profile.

---

## Phase 2: Forward Synthesis

**Goal:** For each gadget in inventory, enumerate the amplifiers it could combine with that also exist in this application, and trace toward concrete impact.

### Step 2.1: Walk the gadget catalog

For each G-XXX, consult [forward_patterns.md](./forward_patterns.md) to find every known amplifier pattern. Then check the inventory: is the required amplifier ALSO present?

Worked example, from a real engagement pattern:

```
G-001: Open redirect on /logout?next=

Known amplifiers (from forward_patterns.md):
  A. OAuth redirect_uri validation by domain → token theft
  B. CSP `script-src self` + open redirect on JSONP-like endpoint → XSS
  C. CORS subdomain trust + redirect to vulnerable subdomain → cross-origin read
  D. Reflection-XSS via javascript: scheme in redirect
  E. CSPT amplifier — redirect carries client-side path to attacker JSON

Inventory check:
  A. Is there an OAuth flow? Spider says: yes, /oauth/authorize. Domain-only redirect_uri check? Need to test in Phase 3.
  B. CSP `script-src self`? Spider header capture says: yes.
  C. CORS subdomain trust? G-004 says: yes on /api/user/profile.
  D. javascript: scheme accepted? Probe in mapping showed: filtered.
  E. CSPT? No CSPT gadget in inventory.

CANDIDATE CHAINS:
  CC-001: G-001 + OAuth domain bypass → access token theft → ATO   (CRITICAL if confirmed)
  CC-002: G-001 + CSP-self-bypass via redirect → reflected XSS     (HIGH if confirmed)
  CC-003: G-001 + G-004 → cross-origin read of /api/user/profile   (HIGH — but G-004 is already CORS, so this is redundant)
```

Notice CC-003 was eliminated because the amplifier and primitive were redundant. This is normal — most candidate chains will be filtered out. The point of forward synthesis is to enumerate exhaustively then prune.

### Step 2.2: Capture chains as hypotheses

Each surviving candidate becomes a chain hypothesis. Write each to `engagement/mapping/CHAINS-NNN.hypothesis.md`:

```markdown
# Chain Hypothesis CHAIN-001

## Components
- G-001: Open redirect on /logout?next= (EP-014)
- Required: OAuth redirect_uri with domain-only validation (probe needed)

## Forward Trace
1. Attacker hosts evil.com/oauth-relay
2. Attacker crafts: target.com/oauth/authorize?client_id=...&redirect_uri=target.com/logout?next=evil.com/oauth-relay
3. Victim clicks attacker link, target.com sees redirect_uri starts with target.com → passes domain check
4. After OAuth grant, browser follows redirect to /logout?next= → redirected to evil.com with `?code=` or `#access_token=`
5. evil.com extracts code/token, performs auth as victim → ATO

## Impact Statement
An attacker can take over any victim's account with a single click. The victim sees only target.com domains in the URL bar during the OAuth grant; the final redirect to attacker.com occurs after the OAuth code is appended.

## Prerequisites To Verify in Phase 3
- [ ] OAuth flow uses redirect_uri with domain-prefix validation (not exact-match)
- [ ] Authorization code or token included in redirect (vs. body POST)
- [ ] No additional state/PKCE protection blocking the attack

## Severity Estimate
- Confidence: MEDIUM (primitive confirmed; amplifier needs verification)
- Impact: CRITICAL if confirmed (full ATO, 1-click, no special victim profile)
- Realism: HIGH (works on any logged-in victim who clicks)

## Skills to Load in Phase 3
- [[open-redirect]] for primitive verification
- [[oauth]] for amplifier verification
```

### Step 2.3: Score and prioritize

Apply Lead's hypothesis scoring formula:

```
Priority = Confidence × Impact × Realism × (1 / Required_User_Interaction)

Confidence:  HIGH=3, MEDIUM=2, LOW=1
Impact:      Critical=4, High=3, Medium=2, Low=1
Realism:     HIGH=3 (1-click), MEDIUM=2 (specific UA/browser), LOW=1 (network position)
Interaction: NONE=1, CLICK=2, MULTI-STEP=3
```

Chains scoring under ~12 are usually not worth Phase 3 effort. Use this to prune.

---

## Phase 3: Backward Synthesis

**Goal:** For each impact category the program pays for, enumerate the primitives required to achieve it, then search the inventory for those primitives.

### Step 3.1: Identify the program's impact ladder

Read the program brief and rules. Build the impact ladder:

```
TIER 1 — Critical (program pays maximum):
  - Account takeover (any user)
  - Mass PII / customer data exposure
  - Remote code execution
  - Authentication bypass
  - Financial: unauthorized funds transfer

TIER 2 — High:
  - Account takeover (specific user, with interaction)
  - Privilege escalation (user → admin)
  - Partial data exposure (per-user)
  - Stored XSS affecting many users
  - SSRF reaching internal services

TIER 3 — Medium:
  - Reflected XSS
  - CSRF on sensitive action
  - IDOR exposing per-user data
  - Information disclosure with security implications

TIER 4 — Low / Info:
  - Self-XSS, login CSRF
  - Open redirect
  - CORS misconfig without sensitive exposure
  - Information disclosure (versions, paths)
```

The program may have its own taxonomy (VRT for Bugcrowd, severity guidelines for HackerOne, Com Olho's P1-P5). Use that.

### Step 3.2: Walk the impact ladder top-down

For each Tier 1 impact, consult [backward_patterns.md](./backward_patterns.md) for the primitive sets that achieve it. Then search inventory.

Worked example:

```
TARGET IMPACT: Account Takeover (any user, no user interaction or 1-click max)

Known primitive sets (from backward_patterns.md):
  P1. Auth token leak via CORS: requires (CORS reflection + endpoint returning token)
  P2. Password reset interception: requires (notification stream hijack OR email injection OR predictable reset token)
  P3. Session fixation: requires (server accepts attacker-supplied session ID + login form)
  P4. OAuth code/token theft: requires (OAuth flow + open redirect OR redirect_uri bypass)
  P5. Email-change CSRF: requires (CSRF on email change + email-only password reset)
  P6. Self-XSS + Login CSRF + context switch: requires (self-XSS + login CSRF + cookie scope)
  P7. JWT forgery: requires (JWT signature flaw — none alg, kid injection, weak secret)
  P8. Subdomain takeover + cookie scope: requires (vulnerable subdomain + Domain=.target.com cookie)

Inventory search:
  P1. CORS reflection (G-003) + endpoint returning token (G-003 IS /api/auth/session)  → MATCH
  P2. Predictable channel names (need to verify) + WebSocket auth gap  → CANDIDATE (need probe)
  P3. No session fixation gadget in inventory
  P4. Open redirect (G-001) + OAuth flow (spider says yes) — already CHAIN-001
  P5. No CSRF amplifier paired with email-change in inventory yet
  P6. G-005 (self-XSS) + ??? (no login CSRF gadget) → INCOMPLETE
  P7. JWT in use (spider auth recon) → load [[jwt]] for verification
  P8. G-014 (cookie scope) + subdomain takeover (need recon sweep) → CANDIDATE
```

This produces additional chain hypotheses that forward synthesis alone would have missed. The CORS + /api/auth/session = ATO chain (P1) is a direct, devastating finding hiding in plain sight if you only walk forward from gadgets.

### Step 3.3: Identify primitive gaps

Some primitive sets will be partially satisfied. These tell you what to look for in extended mapping:

> "Path P6 (self-XSS + login CSRF + context switch) needs a login CSRF amplifier. None in current inventory. Action: probe the login form for CSRF token validation, SameSite cookie enforcement, and Origin/Referer checks. If login CSRF exists, P6 becomes viable."

These gap-driven probes go back to the Worker as new mapping tasks. This is where Phase 2 iterates with itself before transitioning to Phase 3.

---

## Phase 4: Chain Hypothesis Construction

**Goal:** Convert candidate chains into testable hypotheses with verifiable prerequisites and clear impact statements.

### Step 4.1: Write the chain hypothesis file

Every viable chain (forward or backward) gets its own file: `engagement/mapping/CHAINS-NNN.hypothesis.md`. Use the template above (Step 2.2). Critical fields:

- **Components**: every G-XXX referenced with the EP-XXX it came from
- **Forward Trace**: numbered steps from attacker action to impact, no hand-waving
- **Impact Statement**: 2-3 sentences written for a non-technical reader
- **Prerequisites To Verify**: checkboxes listing what Phase 3 must confirm
- **Severity Estimate**: with the scoring formula
- **Skills to Load**: which vulnerability skills Phase 3 needs

### Step 4.2: De-duplicate

Multiple paths to the same impact are not multiple findings. If CHAIN-001 (forward, via open redirect + OAuth) and CHAIN-007 (backward, via OAuth token theft via redirect_uri bypass) describe the same attack, merge them. Keep the one with stronger evidence.

But: chains that share components but reach different impacts ARE separate findings. CHAIN-002 (open redirect → reflected XSS → cookie theft → session takeover) and CHAIN-005 (open redirect → OAuth code theft → ATO) both use G-001 but produce different impacts. Both are findings.

### Step 4.3: Order for Phase 3 dispatch

Sort the chain hypotheses by priority score (highest first). The smart-overlap rule from v3 stays: as soon as a chain hypothesis is confirmed in Phase 3, Phase 4 (Validation) and Phase 5 (Reporting) can start for it without waiting for other chains to finish testing.

---

## Phase 5: Impact Modeling

**Goal:** Write the business-impact statement BEFORE testing, in language a non-technical product manager would understand. If you cannot do this, the chain is not yet a finding — it is a curiosity.

### Step 5.1: Apply the impact translation framework

See [business_impact_mapping.md](./business_impact_mapping.md) for the full table. Every chain's impact statement must answer:

1. **Who is affected?** "Any logged-in user", "users who click a link", "the entire customer base", "users in tenant X"
2. **What does the attacker get?** Money, data, control, identity, persistence
3. **What can the victim do about it?** Often nothing — the attack is silent. State this explicitly.
4. **What's the realistic blast radius?** One account, all accounts in a tenant, the entire user base, a specific subset (e.g., admins).

### Step 5.2: Stop conditions

Stop testing a chain hypothesis and write the report when ALL of these are true:

- Every gadget in the chain has been verified to exist
- The chain has been end-to-end executed in a controlled environment (attacker controls only their own account and a server)
- The impact statement has been demonstrated, not just described (screenshot, video, captured data with PII redacted)
- The chain is reproducible from a clean state

Do not continue exploiting. Do not enumerate further victims. Do not extract more data than needed to demonstrate the impact category. This is also the Cleartax rule for stored XSS — use harmless payloads like `<svg onload=document.title='poc'>`, never `alert(document.cookie)` against another user's session.

### Step 5.3: Verdict templates

```
[CHAIN-VERDICT] {confirmed / partial / negative}
[CHAIN-ID] CHAIN-NNN
[COMPONENTS] G-XXX, G-YYY, G-ZZZ (all verified / X verified / none verified)
[IMPACT-DEMONSTRATED] {ATO / mass exfil / RCE / privilege escalation / financial}
[BLAST-RADIUS] {one user / all users / one tenant / admins only}
[INTERACTION-REQUIRED] {none / single click / multi-step}
[STOP-REASON] {impact demonstrated — generating report / amplifier not present / blocked by [defense]}
```

---

## Things to Do

- Inventory FIRST. Do not start chaining until every per-endpoint profile has been scanned for gadgets.
- Walk BOTH axes — forward from gadgets, backward from impacts. Most chains are discovered backward.
- Score and prune. A long list of unprioritized chain hypotheses creates Phase 3 thrash. Pick the top 3-5 by priority and dispatch those first.
- Write the impact statement BEFORE testing. If you cannot write it clearly, the chain is not ready.
- Re-inventory after every Phase 3 finding. New findings often reveal new gadgets that enable new chains.
- Keep low-impact gadgets in inventory even after individual probes return negative on them. The chain may resurrect them.
- Probe identified gaps — when backward synthesis identifies a missing primitive, send a mapping task back to Worker to probe for it.
- Consider third-party trust boundaries. CORS that whitelists a subdomain is only safe if that subdomain is also safe. Subdomain takeover is the canonical example.
- Treat Spider-recovered source code as a chain accelerator. Source maps and JS chunks expose internal endpoints and role names that the surface API hides.
- Translate every technical finding to a business-impact statement, especially for "no-impact" technical bugs like CORS reflection. Often the chain is one hop away.

## Things Not to Do

- Do not report individual gadgets unless your inventory analysis confirms there is no viable chain. Open redirects, self-XSS, CORS-without-sensitive-endpoint, and login CSRF reports almost always get rejected as "no impact."
- Do not skip backward synthesis because forward synthesis gave you a chain. The chain you found may not be the best chain.
- Do not chain across out-of-scope domains. A chain that requires the attacker to compromise an out-of-scope subdomain is not a valid finding in most programs.
- Do not chain primitives owned by different programs. Cross-program chains create scope ambiguity and usually get rejected by both.
- Do not assume amplifiers without verifying them. "There is probably an OAuth flow" is not a chain — test for it explicitly.
- Do not over-exploit. Once the chain demonstrates the impact category (e.g., one victim ATO), stop. Continuing risks the program rejecting on ethical grounds.
- Do not chain into RCE without explicit program permission. Some programs ban active RCE testing even when the chain is provable from read-only primitives.
- Do not use real users' data in chain demonstrations. Use second-account self-victim setups. Two-account testing via Chrome 9222/9223 is set up for exactly this.
- Do not abandon a chain hypothesis because one component returns negative on first probe. The component may be present under different conditions (different HTTP method, different content-type, different user agent).
- Do not report a chain as if the components are separate findings. Triagers will close as duplicates and pay for one, often the lowest-severity one. Always submit as a single chained report.

---

## Cross-Skill Links

Chains are by definition cross-skill. The following links are the most common chain edges; consult them when their gadgets appear in your inventory:

- [[open-redirect]] — Primitive for OAuth token theft (with [[oauth]]), CSP bypass (with [[xss]]), CORS context manipulation (with [[cors]]), SSRF amplification (with [[ssrf]]), tabnabbing
- [[cors]] — Amplifier for any endpoint returning auth tokens or sensitive data; combined with subdomain takeover for ATO
- [[oauth]] — Often the impact path for open redirects; redirect_uri validation is the typical weak point
- [[xss]] — Self-XSS becomes stored XSS via [[csrf]] login chain; reflected XSS becomes persistent via [[cache-poisoning]]
- [[csrf]] — Amplifier for mass assignment, IDOR-as-attacker, login CSRF for context switching
- [[idor]] — Combined with [[mass-assignment]] for role escalation; combined with predictable IDs for mass exfil
- [[mass-assignment]] — Combined with IDOR or workflow steps for privilege escalation
- [[ssrf]] — Primitive for cloud metadata theft (with [[cloud-misconfig]]); for internal admin panel access; for blind exfil via Collaborator
- [[cloud-misconfig]] — Amplifier for SSRF (IMDS), for path traversal (writable S3), for subdomain takeover
- [[jwt]] — Algorithm confusion + IDOR-style claim manipulation for ATO
- [[graphql]] — Introspection reveals chain candidates that REST surface hid
- [[cache-poisoning]] — Amplifier for reflected XSS (persistent for all users), for response-splitting chains
- [[business-logic]] — Chains often terminate in a business-logic abuse step (financial, workflow, state)
- [[http-smuggling]] — Auth-bypass amplifier; combined with admin endpoints for privilege escalation
- [[prototype-pollution]] — Library-specific gadget that becomes XSS or RCE when a sink is reachable
- [[path-traversal]] — Read primitive for config leak (DB creds); write primitive for DLL hijacking / scheduled task abuse
- [[deserialization]] — Sometimes reachable via chained input — JSON merge → prototype pollution → deserialization sink
- [[report-writing]] — Chain reports require a different structure than single-finding reports. See chain-specific template.
