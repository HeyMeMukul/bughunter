# CSRF Token Bypass Techniques

## CRITICAL: How to Use This File

**This file provides methodology for bypassing CSRF token protections.**
**Phase context:** This is a sub-file of Phase 2 (Confirmation) in SKILL.md.

**Before using this file:**
1. Confirm a CSRF token is present in requests (Phase 1 of SKILL.md)
2. Understand how the token is transmitted (form field, header, cookie)
3. Test one bypass at a time

**Stop Conditions:**
- After 3 failed attempts per technique → Move to next technique
- If token regenerates per-request AND is validated → Likely secure
- If all techniques fail → Return to SKILL.md Phase 3 (Negative Verdict)

---

## Understanding CSRF Tokens

### How They Should Work

```
1. Server generates unique, unpredictable token
2. Token tied to user's session
3. Token included in state-changing requests
4. Server validates token matches session
5. Token regenerates appropriately
```

### Common Implementation Flaws

| Flaw | Description |
|------|-------------|
| Not validated | Server doesn't check the token |
| Not tied to session | Any valid token works for any user |
| Predictable | Token can be guessed or calculated |
| Reusable | Same token works indefinitely |
| Validation conditional | Checked only when present |

---

## Bypass Techniques

### 1. Remove Token Entirely

**Theory:** Some applications validate tokens only when present.

**Test:**
1. Capture request with CSRF token
2. Remove the token parameter completely
3. Send request

**Indicators:**
- Request succeeds → Vulnerable
- Different error (not CSRF-related) → Check other issues
- CSRF error → Try next technique

---

### 2. Empty Token Value

**Theory:** Validation may check presence but not value.

**Test:**
1. Set token parameter to empty string: `csrf_token=`
2. Send request

---

### 3. Arbitrary Token Value

**Theory:** Server may not validate against stored token.

**Test:**
1. Replace token with random string of same length
2. Replace with completely different value
3. Send request

---

### 4. Different User's Token

**Theory:** Token may not be tied to session.

**Test:**
1. Log in as User A, capture their CSRF token
2. Log in as User B in different browser
3. Use User A's token in User B's request

**If successful:** Token not tied to session → CRITICAL flaw

---

### 5. Reuse Old Token

**Theory:** Tokens may not expire or regenerate.

**Test:**
1. Capture CSRF token
2. Use it in multiple requests
3. Log out and log back in
4. Try old token again

**Check:**
- Does token change per request?
- Does token change per session?
- Does token expire?

---

### 6. Token in URL (GET Parameter)

**Theory:** Token exposed in URL can leak via Referer.

**Identify:**
- Is token passed as GET parameter?
- `https://target.com/action?csrf_token=xxx`

**Exploit:**
1. Get victim to click link to attacker site FROM the protected page
2. Token leaks in Referer header
3. Attacker uses stolen token

**PoC requires:**
- Link on page with CSRF token in URL
- User clicks to external site
- Attacker captures Referer

---

### 7. Method Switch

**Theory:** Token validation may be method-specific.

**Test:**
1. If action is POST, convert to GET with parameters in URL
2. If action is GET, convert to POST with parameters in body
3. Check if token validation applies to both

---

### 8. Token in Cookie Only (Double-Submit Flaw)

**Theory:** If token is only verified by comparing cookie to request value, attacker can set both.

**Identify:**
- Token appears in cookie AND request body/header
- Server compares these two values

**Exploit (if cookie-setting vulnerability exists):**
1. Find way to set cookie (CRLF injection, subdomain)
2. Set cookie with attacker-chosen token
3. Include same token in malicious request

---

### 9. Token Predictability

**Theory:** Weak token generation can be predicted.

**Test:**
1. Collect multiple tokens
2. Analyze for patterns (timestamps, sequential, weak random)
3. Attempt to predict next token

**Indicators of weakness:**
- Sequential numbers
- Timestamp-based
- Short length (< 16 chars)
- Visible patterns in hex

---

### 10. Token via XSS

**Theory:** XSS bypasses all CSRF protection.

**If XSS exists:**
1. Read token from DOM
2. Include in forged request
3. Complete bypass

**This is why XSS + CSRF = Critical chain**

---

## Testing Checklist

```
Token Bypass Testing:
- [ ] Remove token parameter
- [ ] Empty token value
- [ ] Random token value
- [ ] Other user's token
- [ ] Reuse old token
- [ ] Token in URL exposure
- [ ] Method switch (POST↔GET)
- [ ] Double-submit cookie flaw
- [ ] Token predictability
- [ ] XSS to steal token
```

---

## Return to Main Workflow

After completing token bypass testing:
1. If bypass found → Return to SKILL.md Phase 4 (Exploitation) for PoC generation
2. If no bypass found → Check other protections (SameSite, Referer), or return to SKILL.md Phase 3 (Negative Verdict)
