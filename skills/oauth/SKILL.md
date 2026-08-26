---
name: testing-oauth
description: OAuth 2.0 and OpenID Connect flow exploitation. Use when the application uses OAuth for authentication or authorization delegation — identified by redirect_uri parameters, authorization endpoints, token exchange flows, or social login buttons. Covers redirect_uri manipulation, state parameter abuse, token leakage, and account takeover via OAuth misconfiguration.
---

# OAuth / OpenID Connect Testing

OAuth vulnerabilities arise from misconfigured authorization flows, insufficient redirect URI validation, missing state parameters, and token leakage. Impact ranges from account takeover to unauthorized API access to full SSO bypass.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (map flow)     (test flaws)     (declare secure)      (demonstrate ATO)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Flow Identification

Identify the OAuth grant type in use:

| Grant Type | Indicators | Security Profile |
|-----------|-----------|-----------------|
| Authorization Code | `response_type=code`, code exchanged at token endpoint | Most secure if properly implemented |
| Implicit | `response_type=token`, token returned in URL fragment | Inherently less secure — token exposed in URL |
| Authorization Code + PKCE | `code_challenge` parameter present | Strongest — mitigates code interception |
| Client Credentials | Server-to-server, no user interaction | Different attack surface |

### Step 1.2: Parameter Mapping

Record all parameters in the authorization request:
- `client_id` — application identifier
- `redirect_uri` — where the auth response is sent (primary attack surface)
- `response_type` — code, token, id_token
- `scope` — requested permissions
- `state` — CSRF protection parameter
- `nonce` — replay protection (OIDC)
- `code_challenge` / `code_challenge_method` — PKCE parameters

### Step 1.3: Baseline Authorization Flow

Complete a normal authorization flow. Record:
- The exact `redirect_uri` used
- Whether `state` is present and validated on return
- Where the authorization code/token appears (URL fragment, query parameter, POST body)
- How the code/token is exchanged for a session

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[GRANT-TYPE] {code / implicit / PKCE}
[REDIRECT-URI] {value}
[STATE-PRESENT] {yes / no}
[PKCE-PRESENT] {yes / no}
[TOKEN-LOCATION] {fragment / query / POST body}
[DECISION] {Proceed — attack vectors identified}
```

---

## Phase 2: Confirmation

### Confidence Definitions

| Level | For OAuth Specifically |
|-------|----------------------|
| HIGH | redirect_uri accepts attacker-controlled destination AND code/token is delivered there, OR state parameter missing/not validated enabling CSRF |
| MEDIUM | redirect_uri partially manipulable (subdirectory, subdomain) but exploitation not yet confirmed |
| LOW | redirect_uri strictly validated, state enforced, PKCE present |

### Step 2.1: Redirect URI Manipulation

Test increasingly aggressive modifications to `redirect_uri`:

**Exact match bypass attempts (in order):**
1. Subdirectory: `https://legitimate.com/callback/../attacker-path`
2. Parameter append: `https://legitimate.com/callback?next=attacker.com`
3. Fragment: `https://legitimate.com/callback#@attacker.com`
4. Subdomain: `https://attacker.legitimate.com/callback`
5. Sibling path: `https://legitimate.com/attacker-controlled-page`
6. URL encoding: `https://legitimate.com%2f%2fattacker.com`
7. Different scheme: `http://` instead of `https://`
8. Full replacement: `https://attacker.com` — tests if any validation exists

For each: does the authorization server accept the redirect? Does the code/token reach the modified URI?

### Step 2.2: State Parameter Testing

- Remove `state` entirely — does the flow complete? If yes → CSRF possible
- Reuse old `state` values — does the server validate freshness?
- Use a static/predictable `state` — is it actually random?

If `state` is absent or not validated, an attacker can initiate an OAuth flow and trick a victim into completing it, linking the attacker's external account to the victim's application account.

### Step 2.3: Token Leakage

Check if the authorization code or access token leaks via:
- `Referer` header when the callback page loads external resources
- URL fragment in browser history (implicit flow)
- Server logs (if code is in query parameter of logged URLs)
- Open redirect on the callback page that forwards the token

### Step 2.4: Scope Escalation

Request higher-privilege scopes than the application normally requests:
- Add `scope=admin` or `scope=openid profile email` if only `openid` is used
- Does the authorization server grant the expanded scope?

### Step 2.5: Code/Token Replay

- Can the same authorization code be used twice? (Should be single-use)
- Can the access token be used after the code is exchanged? (Should be invalidated)
- Is the code bound to the client? (Exchange with a different client_id)

**Max confirmation attempts: 12 distinct techniques.**

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[TECHNIQUE] {redirect_uri / state / leakage / scope / replay}
[RESULT] {what happened}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try next technique / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions

- `redirect_uri` strictly validated against exact match whitelist
- `state` parameter present, validated, and unpredictable
- PKCE enforced (for authorization code flow)
- Authorization code is single-use and client-bound
- No token leakage via Referer or URL logging

### Structured Log

```
[VULN-NEGATIVE]
[PARAMETER] OAuth flow
[STEPS-RUN] {techniques attempted}
[SIGNAL] {all manipulations rejected}
[CONCLUSION] {OAuth implementation properly validates all parameters}
[ACTION] OAuth flow cleared. Do not proceed to exploitation.
```

---

## Phase 3: Exploitation

### Level 1: Code/Token Theft via Redirect
If redirect_uri is manipulable, construct a URL that redirects the authorization code to your server `[EXTERNAL INFRA REQUIRED]`. Exchange the stolen code for an access token.

### Level 2: Account Takeover via CSRF
If state is missing, craft a URL that initiates OAuth with your external account and trick the victim into completing it — linking your social account to their application account.

### Level 3: Full ATO Demonstration
Using the stolen token or linked account, demonstrate access to the victim's resources.

**Stop condition:** At first demonstrated unauthorized access, STOP.

### Reasoning Checkpoint

```
[PHASE-3] Exploitation
[TECHNIQUE] {redirect theft / CSRF linking / token replay}
[IMPACT] {ATO / unauthorized access / scope escalation}
[EVIDENCE] {specific access demonstrated}
[STOP-REASON] {impact threshold reached}
```

---

## Session Re-verification

OAuth flows involve multiple redirects. Re-verify by completing a fresh normal OAuth flow before each exploitation attempt to ensure the authorization server is responding normally.

---

## Things to Do

- Map the complete OAuth flow before testing individual parameters
- Test redirect_uri manipulation progressively from subtle to aggressive
- Check for token leakage via Referer header on callback pages
- Verify state parameter validation, not just presence

## Things Not to Do

- Do not assume PKCE presence means the flow is secure — PKCE can be optional
- Do not confuse the authorization server's behavior with the application's behavior
- Do not manipulate redirect_uri without verifying where the code actually lands
- Do not test OAuth CSRF without understanding the account linking implications

---

## Cross-Skill Links

- [[jwt]] — OAuth access tokens are often JWTs
- [[open-redirect]] — Open redirects on the callback domain enable redirect_uri bypass
- [[csrf]] — OAuth state parameter serves as CSRF protection
- [[session-management]] — OAuth session establishment may have independent flaws
