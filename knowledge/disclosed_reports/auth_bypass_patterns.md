# Authentication Bypass Techniques from Disclosed Reports

## Pattern 1: JWT Algorithm Confusion (alg: none)

**Most common JWT bypass.** Change the algorithm from RS256 to "none" — the server skips signature verification.

**Real Example:** Multiple H1 reports ($500-$5,000 range)

```json
// Original: {"alg": "RS256", "typ": "JWT"}
// Attack:   {"alg": "none", "typ": "JWT"}
// Then: Remove signature, keep header + payload as-is
```

---

## Pattern 2: JWT Secret Key Brute-Force

**When:** Weak HMAC secret (password-like, dictionary word)

**Tools:** jwt-cracker, hashcat, john

```bash
# crack JWT HS256 with wordlist
hashcat -m 16500 jwt.txt rockyou.txt
```

---

## Pattern 3: Password Reset Token Reuse

**The bug:** Password reset tokens don't expire after use. Reset password → use old token → reset again.

---

## Pattern 4: Cookie Manipulation / Session Forging

**Common in:** PHP (deserialized), Node.js (JSON), Rails (Marshal)

```bash
# PHP sessions often look like: user|s:5:"admin"
# Change guest → admin if deserialized without HMAC
```

---

## Pattern 5: OAuth Redirect_uri Validation Bypass

**Bypass techniques:**
- `https://target.com.evil.com/callback` (subdomain match)
- `https://target.com@evil.com/callback` (attacker as auth)
- `https://target.com#@evil.com/` (fragment confusion)
- `https://target.com%2F@evil.com/` (URL-encoded)

---

## Pattern 6: Direct Object Reference to Auth Tokens

**The bug:** API returns auth tokens/API keys in responses accessible by any user.

Example: Profile endpoint returns `api_key`, `access_token`, `refresh_token` — reuse them to authenticate as that user.

---

## What Triagers Accept

- JWT alg:none with working PoC = $1,000-$5,000
- OAuth redirect_uri bypass = $2,000-$10,000
- Password reset token reuse = $500-$3,000
- Cookie forging = $1,000-$5,000
