# OAuth Attack Techniques

## When to Use

Consult when OAuth flow is mapped in Phase 1. Contains specific attack implementations for each OAuth vulnerability.

---

## Redirect URI Manipulation (Detailed)

### Understanding Validation Types

| Validation Type | How to Identify | Bypass Difficulty |
|----------------|----------------|------------------|
| No validation | Any redirect_uri accepted | Trivial |
| Exact match | Only the registered URI works | Hard — need open redirect on same origin |
| Prefix match | Any path under the registered origin works | Medium — find controllable path |
| Domain match | Any subdomain of registered domain works | Medium — find/claim subdomain |
| Regex match | Pattern-based validation | Medium — find regex edge cases |

### Bypass Techniques (Progressive)

**1. Path Traversal:**
```
Registered: https://app.com/callback
Try:        https://app.com/callback/../attacker-page
Try:        https://app.com/callback/../../attacker-controlled
Try:        https://app.com/callback/..%2f..%2fattacker
```

**2. Parameter Append:**
```
https://app.com/callback?next=https://attacker.com
https://app.com/callback?redirect=https://attacker.com
https://app.com/callback#@attacker.com
```
The auth code is appended as a query parameter. If the callback page has an open redirect, the code leaks via the Referer header or is forwarded.

**3. Subdomain/Sibling:**
```
https://evil.app.com/callback          (subdomain you control)
https://app.com/user-content/callback  (user-controlled content path)
```

**4. URL Parsing Confusion:**
```
https://app.com@attacker.com/callback
https://attacker.com\@app.com/callback
https://app.com%40attacker.com/callback
https://app.com:password@attacker.com/
```

**5. Fragment/Hash:**
```
https://app.com/callback#.attacker.com
```
In implicit flow, tokens are in the fragment. If redirect validation doesn't check fragments, the token travels with the redirect.

**6. Localhost/Internal:**
```
https://app.com/callback@127.0.0.1
http://localhost/callback (if HTTP allowed)
```

---

## State Parameter Attacks

### Missing State — OAuth CSRF
**Attack flow:**
1. Attacker starts OAuth flow, gets authorization code
2. Attacker constructs callback URL: `https://app.com/callback?code=ATTACKERS_CODE`
3. Victim clicks the link (or attacker embeds as img src)
4. Victim's account gets linked to attacker's social account
5. Attacker logs in via social login → accesses victim's account

### State Fixation
If state is predictable or reusable:
1. Capture a valid state value
2. Use it in crafted authorization URL
3. Wait for victim to complete the flow
4. The known state allows the attacker to correlate the response

---

## Token Leakage Vectors

### Via Referer Header
1. User completes OAuth → redirected to `https://app.com/callback?code=SECRET`
2. Callback page loads external resources (images, scripts, analytics)
3. `Referer: https://app.com/callback?code=SECRET` sent to those external servers

**Check:** View the callback page source. Any external resources loaded?

### Via Browser History
Implicit flow returns tokens in URL fragment. Although fragments aren't sent to servers, they're stored in browser history.

### Via Server Logs
Authorization codes in query parameters are logged by:
- Web server access logs
- CDN/proxy logs
- Analytics platforms
- Error tracking (Sentry, etc.)

---

## Code Exchange Attacks

### Code Reuse
```
1. Get auth code from callback
2. Exchange code for token → success
3. Exchange SAME code again → should fail
```
If the second exchange succeeds → code replay vulnerability.

### Code Injection (PKCE Bypass)
If PKCE is optional:
```
1. Attacker starts flow WITHOUT code_challenge
2. Steals victim's code via redirect_uri manipulation
3. Exchanges stolen code (no code_verifier needed)
```

### Client Confusion
```
1. Get auth code from App A's flow
2. Exchange it at App B's token endpoint
3. If the auth server doesn't bind codes to clients → cross-client access
```

---

## Scope Manipulation

### Scope Upgrade
```
Normal:  scope=openid email
Attack:  scope=openid email admin write:all
```
Some auth servers grant whatever scope is requested without checking the client's allowed scopes.

### Scope Downgrade (Interesting)
```
Attack:  scope=openid
```
Requesting minimal scope may bypass consent screens, enabling silent authorization.

---

## Account Takeover Chains

### Via Missing State + Social Login
1. Link your attacker social account to victim's app account (via CSRF/missing state)
2. Log in via social login → you're now the victim

### Via Code Theft + No PKCE
1. Steal authorization code via redirect_uri manipulation
2. Exchange code for access token
3. Use access token to access victim's resources

### Via Token Leakage + Implicit Flow
1. Craft authorization URL with implicit flow
2. Victim clicks → token in URL fragment
3. Token leaks via Referer or controlled page
4. Use token to access victim's resources
