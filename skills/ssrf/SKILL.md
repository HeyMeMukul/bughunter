---
name: testing-ssrf
description: Server-side request forgery testing methodology. Use when parameters control URLs, hostnames, IP addresses, or any value the server uses to make outbound requests — including webhook URLs, PDF generators, image fetchers, file importers, URL previews, and proxy endpoints. Covers filter bypass reasoning, internal service discovery, cloud metadata extraction, and impact escalation.
---

# Server-Side Request Forgery (SSRF) Testing

SSRF occurs when an attacker can make the server issue requests to arbitrary destinations. The server becomes a proxy, enabling access to internal services, cloud metadata, and resources behind firewalls. Impact ranges from internal port scanning to credential theft via cloud metadata to full RCE via internal service exploitation.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (behavior)    (confirm fetch)   (declare not vuln)    (escalate access)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Normal Request Behavior

Submit the expected URL/value for the parameter. Record:
- HTTP status code, response length, response time
- Whether the response contains content fetched from the URL (full response, preview, image, metadata)
- Error messages for invalid URLs (reveals URL parsing library behavior)

### Step 1.2: Invalid URL Behavior

Submit clearly invalid values: `notaurl`, `http://`, empty string. Record how each is handled.

### Step 1.3: External URL Test

Submit a URL pointing to a public server you control or a known benign external URL. Does the server fetch it?

| Behavior | Interpretation |
|----------|---------------|
| Server fetches URL, returns/displays content | URL is fetched server-side — SSRF surface confirmed |
| Server returns error about unreachable host | Server attempted the request but couldn't reach it — still SSRF surface |
| Server returns input validation error without fetching | URL is validated before fetching — need to understand the filter |
| Parameter has no effect on server behavior | Not an SSRF surface — stop |

### Step 1.4: Identify Filtering

If external URLs are fetched, test what restrictions exist:
- Does it allow arbitrary domains? Or whitelist-only?
- Does it allow IP addresses? (try `http://1.2.3.4`)
- Does it allow non-HTTP schemes? (`file://`, `gopher://`, `dict://`)
- Does it follow redirects? (critical for filter bypass)

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[PARAMETER] {name}
[FETCH-BEHAVIOR] {fetches URLs / validates without fetching / no effect}
[FILTERING] {none / domain whitelist / scheme restriction / IP block}
[REDIRECT-FOLLOW] {yes / no / untested}
[DECISION] {Proceed / Not an SSRF surface — STOP}
```

---

## Phase 2: Confirmation

**Goal:** Confirm the server makes requests to attacker-influenced destinations, bypassing any filters if present.

### Confidence Definitions

| Level | For SSRF Specifically |
|-------|----------------------|
| HIGH | Server demonstrably fetches content from attacker-controlled or internal destination, confirmed by response content or OOB callback |
| MEDIUM | Server behavior changes with URL manipulation but content from target destination not confirmed |
| LOW | No evidence the server makes requests based on input |

### Step 2.1: Out-of-Band Confirmation `[EXTERNAL INFRA REQUIRED]`

Submit a URL pointing to your controlled server (Burp Collaborator, interactsh, or custom listener):
- DNS callback confirms the server resolved your domain
- HTTP callback confirms the server fetched the URL
- Callback metadata (source IP, User-Agent, headers) reveals the server's identity

### Step 2.2: Localhost / Loopback Test

Test whether the server can reach itself:
- `http://127.0.0.1`
- `http://localhost`
- `http://[::1]` (IPv6 loopback)
- `http://0.0.0.0`
- `http://127.0.0.1:PORT` (with common internal ports: 80, 443, 8080, 8443, 9090, 3000)

If ANY of these return content different from the external URL baseline, the server is fetching internal resources.

### Step 2.3: Filter Bypass (if filters detected in Phase 1)

Reason about the filter type and apply appropriate bypass:

**Domain whitelist bypass:**
- Open redirect on whitelisted domain → chain [[open-redirect]]
- DNS rebinding: attacker domain that resolves to internal IP
- Subdomain: `attacker.whitelisted-domain.com` if wildcard matching
- URL parsing confusion: `http://whitelisted.com@attacker.com`

**IP address filtering bypass:**
- Decimal IP: `http://2130706433` (= 127.0.0.1)
- Hex IP: `http://0x7f000001`
- Octal: `http://0177.0000.0000.0001`
- IPv6 mapping: `http://[::ffff:127.0.0.1]`
- URL encoding of dots: `http://127%2e0%2e0%2e1`
- Short form: `http://127.1`

**Scheme restriction bypass:**
- If only `http://` allowed but redirects are followed: redirect from HTTP to `file://` or `gopher://`
- URL fragments: `http://attacker.com#@internal`

**DNS rebinding:** `[EXTERNAL INFRA REQUIRED]`
- Register a domain with short TTL that alternates between external IP (passes validation) and internal IP (fetched after validation)

### Step 2.4: Blind SSRF Detection

If the response doesn't reflect fetched content:
- Use time-based detection: URL pointing to a slow server vs. a fast server → response time difference indicates fetch
- Use OOB: even if response is not reflected, a DNS/HTTP callback proves the request was made `[EXTERNAL INFRA REQUIRED]`

**Max confirmation attempts: 15 distinct techniques.** After 15, evaluate negative verdict.

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[PARAMETER] {name}
[TECHNIQUE] {direct / OOB / filter bypass / blind timing}
[FILTER-BYPASS] {technique used, if any}
[RESULT] {content from target / callback received / timing difference / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to exploitation / Try different bypass / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions

- Server does not make outbound requests based on this parameter (no OOB callbacks, no timing difference, no content change)
- OR: Server makes requests but strict whitelist + no redirect following + no bypass worked after testing all applicable bypass categories
- Session confirmed valid throughout testing
- At least OOB and direct methods were both attempted

### Structured Log

```
[VULN-NEGATIVE]
[PARAMETER] {name}
[STEPS-RUN] {techniques attempted including bypass categories}
[SIGNAL] {what was observed}
[CONCLUSION] {why this is true negative}
[ACTION] Parameter cleared for SSRF. Do not proceed to exploitation.
```

---

## Phase 3: Exploitation

**Entry requirements:** HIGH confidence. No negative verdict.

### Level 1: Internal Port Scan
Scan common internal ports via SSRF to map internal services:
- HTTP services: 80, 443, 8080, 8443, 3000, 5000, 9090
- Databases: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis)
- Caches: 11211 (Memcached)
- Message queues: 5672 (RabbitMQ), 9092 (Kafka)

Differentiate open ports (content returned or distinct error) from closed ports (connection refused or timeout).

### Level 2: Cloud Metadata Extraction
If the target is cloud-hosted:

**AWS:** `http://169.254.169.254/latest/meta-data/`, then `/latest/meta-data/iam/security-credentials/`
**GCP:** `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header — test if the SSRF can set headers)
**Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)

**Stop condition:** If you extract IAM credentials or service account tokens, this is critical severity. Document and STOP.

### Level 3: Internal Service Exploitation
If internal services are discovered (Redis, Elasticsearch, Kubernetes API):
- Redis: `gopher://` or `dict://` protocol to send commands `[EXTERNAL INFRA REQUIRED for gopher]`
- Kubernetes: `/api/v1/` for pod listing, secrets access
- Internal APIs: Authentication often not required for East-West traffic

**Stop condition:** At first confirmed access to sensitive internal data or service control, STOP.

### Reasoning Checkpoint

```
[PHASE-3] Exploitation
[PARAMETER] {name}
[SSRF-TYPE] {full response / blind / semi-blind}
[LEVEL-REACHED] {port scan / metadata / internal service}
[EVIDENCE] {specific data or access demonstrated}
[STOP-REASON] {impact threshold reached}
```

---

## Session Re-verification

### When to Re-verify
- Server starts returning different errors than baseline
- Sudden response time changes
- Before entering each new phase

### How to Re-verify
Re-send the original valid URL from Phase 1. Compare response to baseline. If different, re-establish session.

### On Failure
Stop. Do not attribute session failures to SSRF behavior.

---

## Things to Do

- Always test OOB callback even if direct SSRF seems to work — confirms the server is making the request, not just reflecting your URL
- Identify the URL parsing library (behavior with edge cases reveals Java URL, Python urllib, PHP curl, etc.)
- Test all applicable filter bypass categories before declaring negative
- Check if the server follows redirects — this is the most common filter bypass vector
- Test cloud metadata endpoints early — highest impact with minimal effort

## Things Not to Do

- Do not declare SSRF without OOB or content confirmation — a changed error message alone is not SSRF
- Do not brute-force internal IPs without first confirming SSRF works against localhost
- Do not scan large internal ranges — this is noisy and may violate program rules
- Do not continue exploitation after extracting cloud credentials — document and stop
- Do not assume all SSRF is the same — response-reflecting SSRF is far more useful than blind SSRF

---

## Cross-Skill Links

- [[open-redirect]] — Open redirects on whitelisted domains bypass SSRF domain filters
- [[cloud-misconfig]] — SSRF to cloud metadata enables IAM credential theft
- [[xxe]] — XXE can achieve SSRF-like behavior via external entity resolution
