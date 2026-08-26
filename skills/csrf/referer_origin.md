# Referer and Origin Validation Bypass

## CRITICAL: How to Use This File

**This file provides methodology for bypassing Referer/Origin header validation.**
**Phase context:** This is a sub-file of Phase 2 (Confirmation) in SKILL.md.

**Before using this file:**
1. Confirm application validates Referer or Origin header
2. Test by removing/modifying these headers
3. Identify validation logic (whitelist, regex, etc.)

**Stop Conditions:**
- Strict whitelist with exact match → Limited bypass potential
- All techniques fail → Return to SKILL.md Phase 3 (Negative Verdict)
- Max 3 attempts per technique

---

## Understanding Header Validation

### How It Should Work

**Referer header:**
- Contains URL of the page that initiated the request
- Can be missing (privacy settings, HTTPS→HTTP)

**Origin header:**
- Contains origin (scheme + host + port) of the request
- Sent with cross-origin requests

**Proper validation:**
- Whitelist of allowed origins
- Exact match, not substring/regex
- Handle missing headers correctly

---

## Bypass Techniques

### 1. Missing Header

**Theory:** Application may allow requests without Referer/Origin.

**Test:**
1. Remove Referer header entirely
2. Remove Origin header entirely
3. Check if request succeeds

**Force missing Referer:**
```html
<meta name="referrer" content="no-referrer">
<form action="TARGET" method="POST">...</form>
```

Or use `rel="noreferrer"`:
```html
<a href="TARGET" rel="noreferrer">Click</a>
```

---

### 2. Subdomain Matching

**Theory:** Validation may use substring match.

**If target is:** `https://example.com`

**Try:**
- `https://example.com.attacker.com` (attacker-controlled)
- `https://attackerexample.com`
- `https://example.com.evil.com`

---

### 3. Regex Bypass

**Theory:** Regex validation may be flawed.

**Common regex flaws:**

| Pattern | Bypass |
|---------|--------|
| `example\.com` | `example.com.attacker.com` |
| `^https://example\.com` | May miss path injection |
| `example.com$` | `attacker.com/example.com` |
| Missing anchors | `attacker.com?example.com` |

**Test variations:**
- `https://attacker.com/https://example.com`
- `https://attacker.com?ref=https://example.com`
- `https://example.com@attacker.com`
- `https://example.com#@attacker.com`

---

### 4. Path Inclusion

**Theory:** May only check domain, not path.

**If Referer must contain `example.com`:**
```
Referer: https://attacker.com/example.com/page
```

---

### 5. Data URI / Null Origin

**Theory:** Sandboxed iframes send `null` origin.

**Test:**
```html
<iframe sandbox="allow-forms allow-scripts" src="data:text/html,
<form action='TARGET' method='POST'>
<input name='param' value='value'>
</form>
<script>document.forms[0].submit();</script>
">
</iframe>
```

**Origin sent:** `null`

If application allows `null` origin → Bypass!

---

### 6. Same-Site != Same-Origin

**Theory:** Different subdomains have different origins.

**Scenario:**
- Validation allows `*.example.com`
- Attacker controls `evil.example.com` (subdomain takeover)
- CSRF from subdomain has allowed origin

---

### 7. Protocol Downgrade

**Theory:** HTTP Referer from HTTPS context may work.

**Test if app at `https://example.com`:**
- Try Referer: `http://example.com`
- Some validations ignore protocol

---

## Specific Header Behaviors

### Referer Header

**When NOT sent:**
- User privacy settings
- HTTPS to HTTP navigation
- `<meta name="referrer" content="no-referrer">`
- Links with `rel="noreferrer"`
- Navigations from `data:` URIs
- Bookmarklets

**Stripping to origin only:**
```html
<meta name="referrer" content="origin">
```
Sends only origin, not full URL.

### Origin Header

**When sent:**
- Cross-origin POST requests
- Cross-origin requests with custom headers
- Fetch/XMLHttpRequest cross-origin

**When NOT sent:**
- Same-origin requests
- GET navigations (sometimes)
- Old browsers

---

## Testing Checklist

```
Referer/Origin Bypass Testing:
- [ ] Remove Referer header
- [ ] Remove Origin header  
- [ ] Subdomain matching bypass
- [ ] Regex validation bypass
- [ ] Path inclusion bypass
- [ ] Null origin (sandboxed iframe)
- [ ] Subdomain origin (if controlled)
- [ ] Protocol variation
```

---

## Return to Main Workflow

After completing Referer/Origin bypass testing:
1. If bypass found → Return to SKILL.md Phase 4 (Exploitation) for PoC generation
2. If all tests failed → Return to SKILL.md Phase 3 (Negative Verdict)
3. Consider combining with other techniques
