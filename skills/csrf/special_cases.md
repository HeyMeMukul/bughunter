# CSRF Special Cases

## CRITICAL: How to Use This File

**This file covers special CSRF scenarios that don't fit standard testing.**
**Phase context:** This is a sub-file of Phase 2 (Confirmation) in SKILL.md.

**Scenarios covered:**
- Multi-step workflow CSRF
- Login CSRF
- Logout CSRF
- Double-submit cookie flaws
- State-changing GET requests

**Stop Conditions:**
- Per-technique limits apply
- If test causes account lockout → Stop, document

---

## Multi-Step Workflow CSRF

### What It Is

Actions that require multiple steps (wizard, confirmation flows).

### Why It Matters

Developers may assume multi-step = CSRF protection.

### Testing Methodology

**Step 1: Identify all steps**
```
Step 1: Initiate action → Get token/state
Step 2: Confirm action → Execute
```

**Step 2: Check if steps are predictable**
- Are intermediate tokens predictable?
- Can steps be skipped?
- Is final step protected independently?

**Step 3: Test bypass scenarios**

| Scenario | Test |
|----------|------|
| Skip intermediate steps | Submit final step directly |
| Predict intermediate values | Analyze token patterns |
| Race condition | Submit multiple final steps |

### PoC Approach

If steps can be automated:
```html
<form id="f1" action="STEP1" method="POST" target="frame1">
  <input name="action" value="initiate">
</form>
<form id="f2" action="STEP2" method="POST">
  <input name="action" value="confirm">
</form>
<script>
  document.getElementById('f1').submit();
  setTimeout(() => document.getElementById('f2').submit(), 1000);
</script>
```

---

## Login CSRF

### What It Is

Forcing victim to log into attacker-controlled account.

### Impact

- Victim uses app as attacker
- Actions recorded under attacker account
- Victim may enter sensitive data

### Testing

**Step 1: Verify login doesn't require current session**
- Usually doesn't (user not logged in)

**Step 2: Create PoC**
```html
<form action="https://target.com/login" method="POST">
  <input name="username" value="attacker">
  <input name="password" value="attackerpass">
</form>
<script>document.forms[0].submit();</script>
```

### Severity

**Low-Medium** unless:
- App stores sensitive data (payment info) → Higher
- Used in phishing chain → Higher

---

## Logout CSRF

### What It Is

Forcing victim to log out of their session.

### Impact

- Denial of service (nuisance)
- May interrupt important workflows
- Can be used to force re-auth (combine with phishing)

### Testing

**Step 1: Find logout endpoint**
- Usually GET: `/logout`, `/signout`, `/session/destroy`

**Step 2: Trigger via image or redirect**
```html
<img src="https://target.com/logout">
```

### Severity

**Low** — Typically accepted as minimal risk.

---

## Double-Submit Cookie Flaws

### What It Is

CSRF protection where token is in cookie AND request parameter.
Server verifies they match.

### How It Should Work

```
Cookie: csrf_token=abc123
POST body: csrf_token=abc123
Server: Do they match? OK!
```

### The Flaw

If attacker can SET cookies, they control both values.

### Attack Conditions

Need one of:
- CRLF injection (set arbitrary headers)
- XSS on any subdomain (can set cookies for parent domain)
- Subdomain takeover (same-site cookie setting)

### Attack Flow

1. Attacker sets cookie: `csrf_token=attacker_value`
2. Attacker sends request with body: `csrf_token=attacker_value`
3. Server sees match → Accepts request

### Testing

**Step 1: Identify double-submit pattern**
- Same token in cookie and request

**Step 2: Check for cookie-setting vulnerabilities**
- CRLF injection
- XSS on subdomains
- Subdomain takeover

**Step 3: If cookie-setting exists, chain**

---

## State-Changing GET Requests

### What It Is

Using GET method for actions that change state.

### Why It's Bad

- GET requests easily triggered (images, links)
- GET requests cached, logged, bookmarked
- Easier to exploit than POST

### Impact

Any accessible GET that changes state = trivial CSRF.

### Testing

**Step 1: Identify GET actions**
- Delete: `GET /delete?id=123`
- Toggle: `GET /toggle-setting?pref=email`
- Update: `GET /update?status=active`

**Step 2: Create simple PoC**
```html
<img src="https://target.com/delete?id=123">
```

### Severity

Depends on action — can be CRITICAL for destructive actions.

---

## CSRF Token Exposed via XSS

### What It Is

Not a CSRF flaw itself, but XSS enables complete CSRF bypass.

### How It Works

1. XSS reads CSRF token from DOM
2. XSS includes token in forged request
3. Complete bypass of CSRF protection

### Testing

**If XSS exists:**
```javascript
// Read token from page
var token = document.querySelector('input[name="csrf_token"]').value;

// Make forged request with valid token
fetch('/sensitive-action', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'csrf_token=' + token + '&action=delete&id=123'
});
```

### Severity

XSS + CSRF bypass = CRITICAL chain.

---

## Testing Checklist

```
Special Cases Testing:
- [ ] Map multi-step workflows
- [ ] Test step-skipping
- [ ] Check login endpoint for CSRF
- [ ] Check logout endpoint for CSRF
- [ ] Identify double-submit cookie pattern
- [ ] Find state-changing GET requests
- [ ] If XSS exists, test CSRF token extraction
```

---

## Return to Main Workflow

After completing special case testing:
1. If bypass/vulnerability found → Return to SKILL.md Phase 4 (Exploitation) for PoC generation
2. If all tests failed → Return to SKILL.md Phase 3 (Negative Verdict)
3. Consider chaining opportunities
