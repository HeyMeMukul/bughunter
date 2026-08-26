# XSS Attack Patterns from Disclosed Reports

## Pattern 1: Stored XSS via Profile Fields

**The bug:** User profile fields (name, bio, about) accept HTML/JS and display unsanitized to other users.

**Real Example:** Airbnb — stored XSS in host profile description → viewed by thousands ($5,000)

---

## Pattern 2: DOM XSS via URL Hash/Fragment

**The bug:** `location.hash` used in `innerHTML` or `eval()` without sanitization.

**Detection:** Search JS for: `location.hash`, `$().html()`, `element.innerHTML =`

---

## Pattern 3: Blind XSS in Admin Panels

**The bug:** XSS payload submitted via user-facing form → displayed to support staff/admins in internal dashboard.

**Key:** Use OOB callbacks (interactsh) to confirm blind XSS execution.
```html
<img src="http://your-oob-url/xss-admin">
```

---

## Pattern 4: CSP Bypass → XSS

- `script-src 'unsafe-inline'` → standard XSS works
- `script-src 'self'` → find JSONP endpoint on same domain
- `script-src https://cdnjs.cloudflare.com` → Angular/CSP bypass gadgets
- Missing `object-src` → `<object data="data:text/html;base64,...">`

---

## Pattern 5: SVG Upload → Stored XSS

**Payload:**
```svg
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(document.domain)</script>
</svg>
```

---

## Pattern 6: Markdown/Markup → XSS

HTML allowed in markdown renderers → `<img src=x onerror=alert(1)>` passes through.
