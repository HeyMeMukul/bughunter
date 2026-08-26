---
name: testing-http-smuggling
description: HTTP request smuggling via Content-Length / Transfer-Encoding desync between front-end proxy and back-end server. Use when a reverse proxy (Nginx, HAProxy, AWS ALB, Cloudflare) sits in front of the backend — identified by server headers, response behavior, or known infrastructure. Covers CL.TE, TE.CL, and TE.TE desync detection.
---

# HTTP Request Smuggling Testing

Request smuggling exploits disagreements between a front-end server and back-end server about where one HTTP request ends and the next begins. This allows an attacker to prepend malicious content to another user's request. Impact includes cache poisoning, credential theft, request hijacking, and bypassing security controls.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (proxy detect)   (desync test)    (declare not vuln)    (demonstrate impact)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Identify Proxy Architecture
Look for indicators of a front-end proxy:
- `Via`, `X-Forwarded-For`, `X-Forwarded-Proto` headers in responses
- Different `Server` header than expected
- CDN indicators (Cloudflare, Akamai, Fastly, AWS CloudFront)
- Load balancer behavior (different responses on repeated requests)

If no proxy is detected, request smuggling is not applicable — STOP.

### Step 1.2: HTTP Version Check
Request smuggling primarily affects HTTP/1.1. If the front-end downgrades HTTP/2 to HTTP/1.1 for the backend, smuggling may still be possible.

### Step 1.3: Normal Request Behavior
Send normal requests with standard `Content-Length` headers. Record response timing, status codes, content.

### Step 1.4: Transfer-Encoding Support
Send a request with `Transfer-Encoding: chunked`. Does the server process it correctly?

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[PROXY-DETECTED] {yes — type / no}
[HTTP-VERSION] {1.1 / 2 with downgrade / 2 end-to-end}
[TE-SUPPORT] {accepted / rejected / ignored}
[DECISION] {Proceed / No proxy — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Smuggling |
|-------|--------------|
| HIGH | Timing-based or response-based desync confirmed — smuggled prefix affects subsequent request |
| MEDIUM | Unusual behavior with conflicting CL/TE headers but desync not conclusively demonstrated |
| LOW | Both servers agree on request boundaries |

### Step 2.1: CL.TE Detection
Front-end uses Content-Length, back-end uses Transfer-Encoding:
```
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If the back-end processes `0\r\n\r\n` as chunk terminator and treats `X` as the start of the next request, a follow-up normal request will be affected (timeout, different response, or error).

**Detection method:** Send the probe, then immediately send a normal request. If the normal request is delayed or returns an unexpected response, desync occurred.

### Step 2.2: TE.CL Detection
Front-end uses Transfer-Encoding, back-end uses Content-Length:
```
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
If the back-end reads only 3 bytes (per CL) and leaves the rest for the next request, the follow-up request will be poisoned.

### Step 2.3: TE.TE Detection
Both servers support TE, but one can be confused with obfuscation:
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked` (space before colon)
- `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity`
- `Transfer-encoding: chunked` (lowercase)

### Step 2.4: Time-Based Confirmation
Smuggling probes that cause the back-end to wait for more data will produce measurable delays. A 5-10 second delay on what should be a fast request is strong signal.

**Critical:** Smuggling tests can affect OTHER USERS' requests. Test carefully and with minimal impact. Use timing-based detection first, not content-based poisoning.

**Max confirmation attempts: 8.** Smuggling tests are high-risk for collateral impact.

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {CL.TE / TE.CL / TE.TE}
[RESULT] {timing delay / response poisoning / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different variant / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- No proxy detected, or both endpoints handle CL/TE consistently
- All CL.TE, TE.CL, and TE.TE probes produce no timing or response anomalies
- Application uses HTTP/2 end-to-end without downgrading

### Structured Log
```
[VULN-NEGATIVE]
[ENDPOINT] {target}
[STEPS-RUN] {CL.TE, TE.CL, TE.TE probes}
[SIGNAL] {no desync detected}
[CONCLUSION] {front-end and back-end agree on request boundaries}
[ACTION] Endpoint cleared for smuggling.
```

---

## Phase 3: Exploitation

### Level 1: Self-Poisoning
Demonstrate that you can poison your OWN next request — smuggled prefix appears in your follow-up response. This confirms the desync without affecting other users.

### Level 2: Security Bypass
Smuggle a request that bypasses front-end access controls (e.g., access an admin path that the proxy blocks but the backend serves).

**Stop condition:** At first demonstrated bypass or request poisoning, STOP. Do not poison other users' requests.

### Reasoning Checkpoint
```
[PHASE-3] Exploitation
[TECHNIQUE] {self-poisoning / security bypass}
[IMPACT] {request hijacking / access control bypass}
[EVIDENCE] {specific response showing smuggled content}
[STOP-REASON] {impact demonstrated without affecting other users}
```

---

## Session Re-verification
After any smuggling test, verify your session is clean by sending several normal requests and confirming normal responses.

## Things to Do
- Detect the proxy type before crafting smuggling probes
- Use timing-based detection first to minimize collateral impact
- Test CL.TE, TE.CL, and TE.TE variants — each targets different desync scenarios

## Things Not to Do
- Do NOT deliberately poison other users' requests in production — use self-poisoning for PoC
- Do not test smuggling without confirming a proxy exists
- Do not send large numbers of smuggling probes — they can destabilize the target

## Cross-Skill Links
- [[cache-poisoning]] — Smuggling can poison cached responses
- [[cors]] — Smuggled requests may bypass CORS enforcement at the proxy level
