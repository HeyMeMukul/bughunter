# SameSite Cookie Bypass Techniques

## CRITICAL: How to Use This File

**This file provides methodology for bypassing SameSite cookie protections.**
**Phase context:** This is a sub-file of Phase 2 (Confirmation) in SKILL.md.

**Before using this file:**
1. Confirm SameSite attribute is set (check Set-Cookie header)
2. Identify the SameSite value (Strict, Lax, None)
3. Understand the target action's HTTP method

**Stop Conditions:**
- SameSite=Strict with no gadgets → Likely secure
- All bypass techniques fail → Return to SKILL.md Phase 3 (Negative Verdict)
- Max 5 attempts per technique

---

## Understanding SameSite

### How It Works

SameSite controls when cookies are sent with cross-site requests:

| Value | Behavior |
|-------|----------|
| `Strict` | Cookie NEVER sent with cross-site requests |
| `Lax` | Cookie sent with top-level GET navigations only |
| `None` | Cookie sent with ALL cross-site requests (requires Secure) |
| Missing | Defaults to Lax in modern browsers |

### Key Concepts

**Same-site vs Cross-site:**
- Same-site: same registrable domain (eTLD+1)
- `app.example.com` and `blog.example.com` are SAME-SITE
- `example.com` and `attacker.com` are CROSS-SITE

**Top-level navigation:**
- User clicks link → Top-level
- JavaScript redirect → Top-level
- `<form>` submit → Top-level (Lax allows GET only)
- `<iframe>` request → NOT top-level

---

## SameSite=Lax Bypasses

### 1. GET-Based Actions

**Theory:** Lax allows cookies on GET navigations.

**Identify:**
- Can the action be performed via GET?
- Does server accept GET for state-changing actions?

**Test:**
1. Convert POST action to GET with parameters in URL
2. Create link: `<a href="TARGET?action=delete">`
3. User clicks → Cookie sent → Action performed

**PoC:**
```html
<a href="https://target.com/delete?id=123">Click here</a>

<!-- Or auto-redirect -->
<script>location = 'https://target.com/delete?id=123';</script>
```

---

### 2. Method Override

**Theory:** Frameworks may honor method override parameters.

**Test:**
1. Send GET request with method override:
   - `?_method=POST`
   - `?method=POST`
   - Header: `X-HTTP-Method-Override: POST`
2. Check if server treats it as POST

**PoC (if override works):**
```html
<a href="https://target.com/action?_method=POST&param=value">Click</a>
```

---

### 3. Two-Minute Window

**Theory:** Chrome has 2-minute leniency for new cookies.

**Scenario:**
- User just logged in (cookie freshly set)
- Within 2 minutes, Lax cookies sent with POST too

**Exploitation:**
- Difficult to time in practice
- Best combined with other techniques

---

## SameSite=Strict Bypasses

### 4. Client-Side Redirect Gadget

**Theory:** If same-site page has open redirect, use it to make same-site request.

**Identify:**
1. Find client-side redirect on target (JavaScript `location = param`)
2. Redirect destination must be controllable

**Attack flow:**
```
1. Attacker page → Opens target's redirect page
2. Target page → Redirects to sensitive action
3. Cookie sent (same-site context)
```

**PoC:**
```html
<script>
  // Target has: if(url_param) location = url_param
  location = 'https://target.com/redirect?url=/delete?id=123';
</script>
```

---

### 5. Sibling Subdomain Attack

**Theory:** Subdomains are same-site.

**Identify:**
- Vulnerable subdomain (XSS, subdomain takeover)
- `vuln.example.com` can attack `app.example.com`

**Attack:**
1. Get XSS or control on sibling subdomain
2. From that context, CSRF against main domain
3. Cookies sent (same-site)

---

### 6. Popup Window Technique

**Theory:** Window.open from same-site context.

**Flow:**
1. User clicks on attacker's link to same-site page
2. That page (or gadget) opens popup
3. Popup loads CSRF action
4. Cookies sent in popup context

---

## SameSite=None

### 7. Direct CSRF

**Theory:** No protection from SameSite.

**If SameSite=None:**
- Standard CSRF applies
- Check for other protections (tokens, headers)

**Common with:**
- Cross-site embedding requirements
- Third-party widgets
- APIs meant for cross-origin use

---

## Browser-Specific Considerations

| Browser | Default SameSite |
|---------|------------------|
| Chrome | Lax |
| Firefox | Lax |
| Safari | Strict (partially) |
| Edge | Lax |

### Testing Notes

- Test in multiple browsers
- Older browsers may not enforce SameSite
- Private/incognito may behave differently

---

## Testing Checklist

```
SameSite Bypass Testing:
- [ ] Identify SameSite value
- [ ] Check if GET actions exist (Lax bypass)
- [ ] Test method override parameters
- [ ] Search for client-side redirects
- [ ] Check for vulnerable sibling subdomains
- [ ] Test popup/window.open scenarios
- [ ] Verify with multiple browsers
```

---

## Return to Main Workflow

After completing SameSite bypass testing:
1. If bypass found → Return to SKILL.md Phase 4 (Exploitation) for PoC generation
2. If not → Check for other protection flaws, or return to SKILL.md Phase 3 (Negative Verdict)
