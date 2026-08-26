# SSRF Attack Patterns from Disclosed Reports

Patterns extracted from 50+ disclosed SSRF reports ($500-$50,000 range).

---

## Pattern 1: Cloud Metadata Access

**Highest impact, most common SSRF.** Server-side URL fetch → access cloud metadata endpoints → steal credentials.

**Disclosed Examples:**
- Capital One: SSRF via misconfigured WAF → AWS IMDS → IAM credentials → 100M+ records ($250M fine)
- Shopify: Open redirect → SSRF to IMDS → AWS credentials → internal network access ($50,000)

**Attack Path:**
```
URL input → Server fetches http://169.254.169.254/latest/meta-data/iam/security-credentials/ → 
AWS credentials → Internal network access
```

**Metadata URLs to test:**
```
AWS:     http://169.254.169.254/latest/meta-data/
GCP:     http://metadata.google.internal/computeMetadata/v1/
Azure:   http://169.254.169.254/metadata/instance?api-version=2021-02-01
DO:      http://169.254.169.254/metadata/v1.json
Alibaba: http://100.100.100.200/latest/meta-data/
Oracle:  http://169.254.169.254/opc/v1/instance/
```

---

## Pattern 2: Open Redirect → SSRF Bypass

Server validates the domain but there's an open redirect ON that domain → bypass the whitelist.

**Disclosed Examples:**
- Shopify: Open redirect on partners.shopify.com → SSRF to internal → AWS credentials ($50,000)

**Attack Path:**
```
SSRF checker: "Must be partners.shopify.com"
Hacker: https://partners.shopify.com/redirect?url=http://169.254.169.254/
Result: Bypasses domain check, server fetches metadata
```

---

## Pattern 3: SSRF via PDF/Image Generation

Server generates PDFs or images from user-submitted URLs → SSRF.

**Disclosed Examples:**
- Multiple: wkhtmltopdf SSRF → LFI → /etc/passwd
- Multiple: ImageMagick SSRF → internal port scanning

**Attack Path:**
```
File upload/URL input → Server-side rendering engine fetches URL → SSRF
```

---

## Pattern 4: SSRF via XXE

Out-of-band XXE → SSRF via external entity.

**Attack Path:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

---

## Pattern 5: SSRF via SSI (Server-Side Includes)

Web server with SSI enabled → `<!--#include virtual="http://internal/"-->`

---

## Pattern 6: Blind SSRF → Internal Port Scan

Server makes request but doesn't return content → time-based port scanning.

**Attack Path:**
```
SSRF to internal host:port → measure response time
Fast response = port open, Slow/timeout = port closed
```

---

## Pattern 7: SSRF via Request Smuggling

HTTP request smuggling → inject requests to internal services.

---

## Key Hunter Lessons

1. **OOB is KING:** Blind SSRF with OOB callback = confirmed. Without OOB = questionable.
2. **Chain always:** Open redirect + SSRF = bypass. SSRF + metadata = credentials.
3. **Internal services:** Don't just check metadata. Check internal APIs, databases, admin panels.
4. **DNS rebinding:** Bypass hostname checks with DNS rebinding (TTL=0, different IPs).
5. **Protocol diversity:** HTTP, HTTPS, gopher, dict, file, ftp — try ALL.

## What Triagers REJECT as SSRF

- "URL resolved to internal IP" — must prove actual request was made
- "DNS lookup succeeded" — not SSRF without HTTP request
- Time difference alone (without consistent OOB or response difference)
