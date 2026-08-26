# Business Impact Mapping

> Translating technical findings into business-impact statements that triagers accept and that justify the severity rating you want.

This is the file that converts "vulnerability with no impact" findings into paid findings. Use during **Phase 2 Step 5.1 (Impact Modeling)** and again during **Phase 5 (Reporting)**.

A finding has two values: the technical truth (what's broken) and the business truth (what it costs the target if abused). Triagers care about the business truth. Hunters who only describe the technical truth get rejected for "no impact" even when the bug is real.

This file teaches the translation.

---

## The Translation Framework

Every impact statement must answer four questions, in order:

### 1. Who is affected?

Specificity matters. The categories that pay:

- **Every user** (e.g., persistent XSS, cache poisoning) — Critical territory
- **Any specific targeted user** (e.g., 1-click ATO, IDOR with predictable IDs) — High to Critical
- **Users matching a specific profile** (e.g., admins, paying customers, users in a specific tenant) — High
- **The target's own admin/internal users** (e.g., support ticket XSS reaching admin) — Critical
- **A specific named user** (e.g., the bug only works on user `victim_account_123`) — Low to Medium

Avoid "an attacker could" without scoping. Avoid "potentially". Say "any logged-in user", "any user who clicks a crafted link", "all customers of tenant X".

### 2. What does the attacker get?

The damage categories programs explicitly enumerate in their severity tables:

- **Account control** — read victim's account, perform actions as victim, change victim's email/password/MFA
- **Data exposure** — read victim's PII, financial records, internal documents, customer lists, employee data
- **Financial impact** — direct theft of money, fraudulent transactions, bypass of paid features
- **Identity** — impersonate the victim externally (post as them, send messages as them)
- **System control** — RCE, file write, privilege escalation, persistence
- **Operational disruption** — DoS, data corruption, workflow break

Use the target program's exact severity terminology when possible. Bugcrowd uses VRT terms (P1-P5). HackerOne uses Critical/High/Medium/Low. Com Olho uses P1-P5 with explicit price brackets. Match the program's language.

### 3. What can the victim do about it?

Most chains are silent. State this explicitly. If the victim cannot detect, alert, or reverse the damage, that increases severity. If the victim sees an obvious warning (browser cert error, suspicious URL, unusual login notification), severity drops.

Specific framings that increase severity:
- "No user-visible indicator of compromise"
- "No detection in standard browser security UI"
- "Persistent — survives victim's password change" (if true)
- "Cross-device — affects victim regardless of which device they use"

### 4. What is the realistic blast radius?

Quantify when possible:

- "Affects all ~10M registered users" — read it off the program's public stats
- "Affects all customers of tenant X" — quantify per-tenant
- "Affects every user who views a public profile" — describe the trigger condition

Avoid hedging ("potentially affects users"). State the realistic case. Triagers downgrade hedged language.

---

## Translation Templates by Vulnerability Class

### CORS Misconfiguration

**Bad (rejected/informative):**
> "The endpoint `/api/auth/session` reflects the Origin header with Access-Control-Allow-Credentials: true, indicating a CORS misconfiguration."

**Good (paid):**
> "Any user who visits an attacker-controlled webpage while logged into target.com has their session access token stolen. The token is returned by `/api/auth/session`, which the CORS misconfiguration allows attacker.com to read via credentialed XHR. Once the attacker has the access token, they have full account control: they can read all of the victim's data, modify the account, change the email and password, and access any API endpoint as the victim. The victim has no indication that this occurred — the attacker's webpage can be styled as anything, including a search result, advertisement, or article. This affects every logged-in user of the application."

What changed:
- Named the specific damage (token theft, then full account control)
- Quantified scope (every logged-in user)
- Stated victim has no visibility
- Described the realistic delivery (styled as any webpage)

### Open Redirect (Alone)

**Bad (rejected as informative):**
> "The /logout?next= parameter accepts any URL and redirects to it without validation, allowing open redirect."

**Good (P3 alone, basis for chain):**
> "An attacker can craft phishing links that appear to come from target.com (the URL bar shows target.com domain) and redirect victims to attacker-controlled credential-harvesting pages. Phishing campaigns leveraging trusted-domain links have substantially higher click-through and credential-capture rates than generic phishing. This is also a chain primitive — when combined with the OAuth flow at /oauth/authorize (which uses domain-prefix redirect_uri validation), this enables one-click full account takeover. See companion chain hypothesis CHAIN-XYZ."

What changed:
- Named the realistic threat (phishing with trusted-domain trust)
- Pointed to the chain (signal to triager that this is part of a higher-severity report)
- Gave the security-research framing (phishing CTR claim is publicly documented)

### Self-XSS

**Bad (rejected/closed informational):**
> "Display name field on /profile is vulnerable to XSS — entering `<img src=x onerror=alert(1)>` triggers an alert."

**Good (when chain present):**
> "This is a component of CHAIN-XYZ (see full chain hypothesis). In isolation, this XSS only fires in the attacker's account. When combined with the login CSRF gadget on /auth/login (no SameSite=Strict, no CSRF token, accepts cross-origin POST), an attacker can force any victim into the attacker's session, triggering the XSS in the victim's browser. The XSS then uses the [session-switch endpoint at /account/switch] to return the victim to their own authenticated session — at which point the XSS executes with the victim's credentials and accomplishes full account takeover. Reproducible end-to-end in the attached video PoC."

**Good (when chain not yet found, just submitting):**
> "While this XSS fires only in the attacker's own profile context, modern web applications frequently allow account switching, OAuth flows, and email-based auto-login. Any such mechanism converts this self-XSS into a victim-targeting attack. I am flagging this as a chain primitive and will follow up if additional chain components are discovered. Note that programs including [reference HackerOne/Bugcrowd disclosed self-XSS chain reports] have paid for similar gadgets when chained."

### IDOR (Per-User Data)

**Bad (rejected as not impactful):**
> "The endpoint /api/users/{id}/profile returns the profile of any user, not just the authenticated user."

**Good (P2-P3):**
> "Any authenticated user can read any other user's full profile, including name, email address, phone number, and account creation date, by changing the {id} parameter. User IDs are sequential integers starting from 1, so enumeration is trivial — all ~3.2M users of target.com can be exfiltrated by a single authenticated attacker in under 24 hours at modest request rates. This constitutes mass PII exposure. The attack is undetectable to victims and does not require any special privileges (a free account suffices). The exposed PII (specifically email + phone + name) is sufficient for downstream phishing, SIM-swap targeting, and credential-stuffing attacks against the victims on other services."

What changed:
- Quantified scale (3.2M users, 24 hours)
- Named the downstream impact (phishing, SIM-swap, credential stuffing)
- Stated detection: undetectable
- Stated barrier to entry: free account

### IDOR (Sensitive Data + Cross-Tenant)

**Good (P1):**
> "Any user in any tenant can read all customer records from any other tenant on the platform. The endpoint /api/v1/customers/{customer_id} returns full customer records (PII + financial transaction history) when the {customer_id} parameter is changed to a customer belonging to a different tenant. The endpoint validates that the requester is an authenticated user, but not that the requester belongs to the customer's tenant. This breaks the fundamental multi-tenant isolation that the platform sells as its primary security guarantee. Tenant A could enumerate Tenant B's customers, including business plan details, PII, and transaction history. Severity is maximum: tenants pay for isolation, this finding nullifies that purchase."

What changed:
- Named the security guarantee that is broken (multi-tenant isolation)
- Named the business consequence (customers pay for the broken guarantee)
- Avoided "potentially" — stated definitively

### Mass Assignment (Privilege Field)

**Bad (rejected as not impactful):**
> "POST /api/users/create accepts the field `is_admin: true` which is not in the UI form. New users can be created with admin privileges."

**Good (P2-P1):**
> "Any user can promote themselves to admin by adding `is_admin: true` to the registration request. The application accepts the field server-side without role-based authorization, despite the UI not exposing it. Once admin, the attacker has full access to all application resources: all tenant data, all user data, all financial records, all configuration. This is exploited by free-tier users with no special access (just signup → toggle the field → admin). Combined with the IDOR at GET /api/users (which lists existing admins), an attacker can also demote existing admins to lock them out before exfiltrating."

What changed:
- Named the path to abuse (registration → admin)
- Named the resulting access (everything)
- Pointed to chain amplification (the IDOR)
- Named the barrier: free signup

### SSRF (Initial Bug)

**Bad (rejected as Low):**
> "The /api/preview endpoint accepts a URL parameter and fetches it server-side. Pointing it to a Collaborator URL confirms it makes outbound requests."

**Good (P2-P1):**
> "The application's preview feature makes server-side requests with no URL allowlist, allowing arbitrary internal request forgery. The server is hosted on AWS EC2 with IMDSv1 enabled (verified via metadata fetch). I confirmed reading the IAM role credentials at /latest/meta-data/iam/security-credentials/. The IAM role has been confirmed to grant S3 read access to the production data bucket (verified via aws s3 ls with the stolen credentials). This is the canonical SSRF → IMDSv1 → IAM → S3 chain that produced the Capital One 2019 breach affecting 100M records. The chain can be triggered by any authenticated user with one HTTP request. Recommended immediate remediation: enforce IMDSv2 (`http-tokens required`), restrict IAM role to least privilege, allowlist URL targets in the preview feature."

What changed:
- Walked the full chain to demonstrated impact
- Cited the canonical real-world breach
- Named the specific data at risk
- Specific remediation (signals expertise, accelerates fix)

### File Upload XSS via SVG

**Bad:**
> "The application accepts SVG file uploads and serves them as image/svg+xml from the same origin, allowing stored XSS."

**Good (P2):**
> "Any user can upload an SVG file containing JavaScript, which is then served from a same-origin URL and rendered with script execution when any other user views it. The upload UI is presented as 'profile picture upload', so the attack surface is every user who views the attacker's profile — a common interaction in any social or messaging feature. The XSS runs with the victim's session, allowing the attacker to perform any action as the victim (read messages, send messages impersonating them, change account settings). Impact compounds across users: a single attacker uploading the malicious SVG can compromise every visitor to their profile, and the visitors are typically users with active relationships to the attacker (followers, contacts) — making the attack effective for targeted compromise of specific demographic groups."

What changed:
- Named the realistic delivery vector (profile picture)
- Described compound impact
- Named the social-graph amplification

---

## Translation Templates by Affected Asset Type

### When the Finding Touches Authentication / Sessions

Emphasize:
- Persistence: does the compromise survive password change? (If yes — Critical.)
- Cross-device: does the compromise affect victim on other devices? (Tokens stored in localStorage usually do not survive logout from one device; cookie-based sessions usually do.)
- MFA bypass: does the chain bypass MFA? (Often yes for token-leak chains — Critical.)

### When the Finding Touches PII

Emphasize:
- Categories of PII exposed (name, email, phone, government ID, financial data, health data, location)
- Regulatory implications (GDPR, CCPA, HIPAA, PCI-DSS where applicable). Programs in regulated industries pay more for findings that map to compliance violations.
- Downstream attack enablement (e.g., emails enable phishing, phones enable SIM-swap, addresses enable physical attacks)

### When the Finding Touches Financial Functions

Emphasize:
- Direct theft: can the attacker move money/credit/tokens to themselves?
- Indirect theft: can the attacker get goods/services they didn't pay for?
- Fraud: can the attacker make the victim's account look like it performed actions it didn't?
- Reconciliation difficulty: is the damage hard for the target to detect and reverse?

### When the Finding Touches Admin / Internal Functions

Emphasize:
- Lateral movement: from compromised admin, what else can the attacker reach?
- Insider-data exposure: what employee data is now visible?
- Code/configuration access: can the attacker modify the application itself? (Approaches RCE severity.)

---

## Anti-Patterns in Impact Statements

### "Could potentially"

Hedging signals to the triager that you are not sure of the impact. Replace with definitive statements: "this allows", "an attacker can", "any user is able to".

### "Severe security vulnerability"

Adjectives don't increase severity scores. Specifics do. Replace with the specific damage: "leak of session tokens enabling account takeover".

### "Theoretical impact"

Triagers do not pay for theoretical impact. If the chain only works "in theory", you have not demonstrated the chain. Test it end-to-end before writing the impact statement.

### "If the attacker had X"

If the attacker needs network position, victim's specific browser version, a stale cookie, or any other special precondition, **say so explicitly and quantify how realistic each precondition is**. Don't hide preconditions — triagers will find them anyway, and hiding them damages credibility.

### Padding the impact

Listing every theoretical thing an attacker "could do" weakens the impact statement. Pick the strongest specific consequence and lead with it. The triager skim-reads the first sentence.

### Confusing technical impact with business impact

"This violates the same-origin policy" is technical. "An attacker can steal session tokens of any logged-in user" is business. Programs pay for business.

---

## Cleartax-Specific Translations (Reference for Vaibhav's Current Engagement)

### FIND-301 (CORS_Misconfiguration on /api/kramer/v0/in-app-notification/action/authenticate)

**Current framing (likely producing low triage score):**
> "CORS misconfiguration on /api/kramer/v0/in-app-notification/action/authenticate allows cross-origin requests with credentials."

**Required for High/Critical:**
First — verify what the endpoint returns. If it returns auth tokens, session info, CSRF tokens, or PII, frame as:
> "The /api/kramer/v0/in-app-notification/action/authenticate endpoint returns [SPECIFIC SENSITIVE DATA] in the response body. The CORS configuration reflects the requester's Origin header with credentials enabled, allowing any attacker-controlled webpage to read this data from the browser of any logged-in Cleartax user. Specifically, an attacker hosting a malicious page can: (1) wait for any Cleartax user to visit, (2) issue a credentialed XHR to the endpoint, (3) read [SPECIFIC DATA], (4) use it to [SPECIFIC IMPACT — ATO via session token, CSRF via leaked token, etc.]. This affects every authenticated Cleartax user. The attacker's page can be styled as anything; victims do not see any indication of the data theft."

If the endpoint does NOT return sensitive data, the finding likely belongs at P4-P5 (Hall of Fame, not paid). In that case, search the inventory for OTHER endpoints under the same CORS misconfig that DO return sensitive data, and re-frame the report on that endpoint.

### FIND-306 (Notification_Stream_Hijack on PubNub stream — Critical)

**The scope-ambiguity risk:** ClearTax program rules exclude "third-party services used by Clear" — PubNub is a third party.

**Wrong framing (rejected for scope):**
> "PubNub allows arbitrary clients to subscribe to channels without authentication."

**Right framing (scope-safe):**
> "Cleartax's integration with the PubNub notification service uses predictable channel names ({CLEARTAX-PATTERN}) and does not enforce per-channel authentication when subscribing. This is a flaw in Cleartax's use of PubNub, not a flaw in PubNub itself — PubNub provides authentication primitives that Cleartax chose not to use. An attacker who can predict a Cleartax user's channel name (which is derived from publicly observable user identifiers) can subscribe to that user's notification stream and intercept real-time notifications including password reset codes, 2FA codes, and private messages. This enables full account takeover by triggering a password reset, intercepting the code via the hijacked stream, and resetting the password before the legitimate user receives the email. Recommended remediation: enable PubNub Access Manager with per-channel, per-user grants — a PubNub-supported feature Cleartax is not currently using."

What changed:
- Framed as Cleartax's configuration choice, not PubNub's flaw
- Pointed to the specific Cleartax-controllable fix (PubNub Access Manager)
- Walked the full ATO chain
- Cited PubNub's own features to demonstrate the issue is fixable in-place

### FIND-503 (Unauthenticated_Telemetry_Poisoning on /api/funnel/funnelmetrics/mtsg)

**Reality check:** telemetry poisoning is usually P4-P5 unless the telemetry drives operational decisions or contains exploitable parsing flaws.

**Honest framing:**
> "The /api/funnel/funnelmetrics/mtsg endpoint accepts arbitrary metric values without authentication. An unauthenticated attacker can inject false metrics affecting internal analytics dashboards. While this does not directly compromise user data or accounts, the impact depends on what Cleartax does with these metrics:
> - If metrics drive automated decision systems (auto-scaling triggers, fraud-detection thresholds, A/B test outcomes): impact escalates to operational disruption or fraud-detection evasion (estimated P3).
> - If metrics are display-only on internal dashboards: impact remains P5 (informational).
> - If the metric ingestion endpoint has parsing flaws (e.g., the metric payload influences subsequent serialization), this becomes a chain primitive for [...]."

If this finding is currently positioned for full bounty, **do not submit it as-is**. ClearTax's payment rule pays only Critical (P1) and High (P2) in cash. Submitting a P3-P5 telemetry poisoning report nets Hall of Fame only. Either find the chain amplifier (parsing flaw, operational-impact connection) or accept it as HoF and submit the bigger chains instead.

---

## Using This File During Reporting (Phase 5)

After the chain is confirmed in Phase 4:

1. Open the validated finding file (`engagement/findings/FIND-NNN.validated.md`)
2. Open this file
3. Use the appropriate template by vulnerability class
4. Customize with the specific data from your finding
5. Run the four-question checklist (Who, What, Detection, Blast Radius) explicitly before writing the report's Impact section
6. If you cannot answer any of the four questions specifically, the chain is incomplete — return to Phase 3 testing

The impact statement is the most important paragraph in the report. Reports get triaged on the impact statement first, the PoC second, the technical detail third. A report with a strong impact statement and minimal technical detail will be paid faster than a report with extensive technical detail and a weak impact statement.

This applies double for chained findings — triagers do not have the time to construct the impact themselves. You must construct it for them.
