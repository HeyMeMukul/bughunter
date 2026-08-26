---
name: testing-cache-poisoning
description: Web cache poisoning and deception testing. Use when responses pass through caching layers — identified by cache headers (X-Cache, Age, CF-Cache-Status, X-Varnish), CDN indicators (Cloudflare, Akamai, Fastly, CloudFront), or Cache-Control directives. Covers unkeyed header injection, unkeyed query parameter exploitation, cache key normalization attacks, cache deception via path confusion, and stored XSS via cache poisoning.
---

# Web Cache Poisoning & Deception

Cache poisoning stores a malicious response in the cache, served to all subsequent users. Cache deception tricks the cache into storing private data under a URL the attacker controls. Both exploit the disagreement between what the CACHE uses as a key and what the APPLICATION processes as input.

## Reference Files

- [techniques.md](./techniques.md) — Advanced techniques: cache deception, parameter cloaking, HTTP header injection via cache

## Mental Model

A cache exists to avoid regenerating identical responses. It identifies "identical" requests using a CACHE KEY — typically: HTTP method + Host + Path + sometimes query string.

**The vulnerability:** If the application behavior depends on inputs NOT included in the cache key (UNKEYED inputs), those inputs affect the response but not which cache entry is used. An attacker can manipulate unkeyed inputs to inject malicious content into the response, which gets cached, then served to normal users who don't send the unkeyed input.

**Common unkeyed inputs:**
- `X-Forwarded-Host` header — frequently used by apps for URL generation but cached based on URL only
- `X-Forwarded-Scheme` / `X-Forwarded-Proto`
- `X-Original-URL` / `X-Rewrite-URL`
- `X-Host`, `X-Forwarded-Server`
- Cookies (usually unkeyed)
- UTM parameters (often stripped from cache key)

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (cache behavior)  (unkeyed input)  (declare not vuln)  (poison + impact)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: Cache Detection
```
Request the same URL twice. On the second request, look for:
  X-Cache: HIT (or HIT, MISS, DYNAMIC)
  Age: <number>
  CF-Cache-Status: HIT (Cloudflare)
  X-Varnish: <id>
  X-Served-By: <id>
  Cache-Control: public, max-age=<n>
```
Cache HIT on the second request confirms caching.

### Step 1.2: Cache Key Identification
Test what's part of the cache key:
- Different query parameter → separate cache entry? (query is KEYED)
- Different `?cachebuster=random` → separate entry? (query is keyed)
- Different cookie → same cached response? (cookies UNKEYED)
- Different header → same cached response? (most headers UNKEYED)

### Step 1.3: Cacheability Assessment
Which endpoints cache? Typically: static content, public marketing pages, anonymous-accessible pages. API endpoints with `Cache-Control: no-store` or `private` are NOT cached.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[CACHE] {type: Cloudflare / Varnish / CloudFront / etc.}
[CACHE-KEY] {what's included — path, query, etc.}
[CACHEABLE-ENDPOINTS] {list of endpoints returning cache HITs}
[DECISION] {Proceed / No cache detected — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Cache Poisoning |
|-------|-------------------|
| HIGH | Unkeyed input reflected in cached response, verified by cache HIT serving poisoned content to clean request |
| MEDIUM | Unkeyed input reflected but cache behavior not confirmed |
| LOW | No unkeyed inputs found or no reflection |

### Step 2.1: Unkeyed Header Discovery

Test these headers systematically — send each with a unique canary value:

```
X-Forwarded-Host: canary123.com
X-Forwarded-Scheme: canary-scheme
X-Forwarded-Proto: canary-proto
X-Forwarded-Port: 9999
X-Forwarded-Server: canary-server
X-Original-URL: /canary
X-Rewrite-URL: /canary
X-Host: canary-host.com
X-Original-Host: canary.com
X-Real-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
X-Forwarded-For: 1.2.3.4
Forwarded: for=1.2.3.4;host=canary.com
Referer: https://canary.com/
X-Wap-Profile: https://canary.com/profile
X-Country-Code: XX
```

For each header:
1. Does the value appear anywhere in the response?
2. If yes, where? URL in page? Meta tag? HTML attribute? Script source?
3. Is the response cached after?

### Step 2.2: Verify Cache Poisoning

Once you find an unkeyed reflected header:
```
Step 1: Request with unique cache buster AND unkeyed header injection:
  GET /page?cb=unique123 HTTP/1.1
  X-Forwarded-Host: evil.com

Step 2: Response should show X-Cache: MISS (first request, cache stored)

Step 3: Request SAME URL (same cache buster) WITHOUT the header:
  GET /page?cb=unique123 HTTP/1.1

Step 4: Response should show X-Cache: HIT
        Response body should STILL contain evil.com (the cached poisoned content)
```

If step 4 returns the poisoned content → cache poisoning confirmed.

### Step 2.3: Cache Key Normalization Attacks

Test if the cache normalizes URLs differently than the app processes them:
```
/page              vs  /page/           (trailing slash)
/page              vs  /page?            (empty query)
/page              vs  /PAGE            (case sensitivity)
/page              vs  /page%20          (trailing space)
/page              vs  /./page           (dot)
/page              vs  /a/../page        (traversal)
/page              vs  /%70age           (URL encoding)
```

If cache normalizes `/page/` to `/page` but app serves different content → cache key confusion.

### Step 2.4: Cache Deception (Read Private Data)

Some caches cache based on file extension. `/api/user.css` might be cached as static content even though it contains dynamic user data:
```
GET /profile/sensitive-data            → user's private data, not cached
GET /profile/sensitive-data.css        → same data, cached as "CSS"
GET /profile/sensitive-data.js
GET /profile/sensitive-data/picture.png
```
If the cache stores the authenticated response under the deceptive URL → attacker can later fetch it as anonymous user.

**Max confirmation attempts: 10 headers and variations.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[UNKEYED-INPUT] {header or parameter name}
[REFLECTION-LOCATION] {where in response}
[CACHE-POISONED] {yes — clean request returns poisoned content / no}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different headers / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- No unkeyed inputs reflected in cacheable responses
- Cache key properly includes all reflected inputs
- Tested 10+ headers and key variations
- No cache deception via extension/path tricks

---

## Phase 3: Exploitation

### Level 1: Benign Poisoning Proof (with cache buster)
Poison with identifiable but harmless content. Use a unique cache buster so real users are NOT affected. Verify clean request gets poisoned response.

### Level 2: Stored XSS via Cache
If the reflected unkeyed input is in an HTML context without encoding:
```
X-Forwarded-Host: evil.com/<script>alert(1)</script>
```
If this gets cached → XSS served to all users. This is Stored XSS at scale.

**Use cache-busted URL for PoC** — do NOT poison production cache.

### Level 3: Web Cache Deception for Account Takeover
If cache deception works:
```
Attacker sends victim: https://target.com/api/session?.css
Victim clicks → their session token is cached at that URL
Attacker fetches the same URL → gets victim's session token
```

**Stop condition:** Demonstrated that cache serves poisoned content to clean request → STOP.

---

## Things to Do
- Always use cache busters during testing — don't affect real production traffic
- Test X-Forwarded-Host first — it's the most commonly vulnerable
- Check if reflected content is in an executable context (script src, URL attribute, meta refresh) for maximum impact
- Verify cache poisoning via clean request — reflection alone doesn't confirm cache storage

## Things Not to Do
- Do NOT poison production cache entries without cache-busted isolation
- Do not assume CDN presence means vulnerability — modern CDNs key on more headers
- Do not confuse unkeyed parameters with unkeyed headers — different cache key behavior

## Cross-Skill Links
- [[http-smuggling]] — Smuggling amplifies cache poisoning impact
- [[xss]] — Cache poisoning with XSS payload = stored XSS at scale
- [[open-redirect]] — Open redirect + cache poisoning = mass phishing
