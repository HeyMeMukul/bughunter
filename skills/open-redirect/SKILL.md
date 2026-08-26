---
name: testing-open-redirect
description: "Tests redirect parameters for open redirect vulnerabilities — baseline, confirmation, bypass, and XSS escalation via redirect sinks."
---

# Open Redirect Testing

## Mental Model

The app takes a user-supplied value and redirects to it. If that destination isn't locked to the app's own domain, the attacker controls where the user goes. Client-side redirects (JS-based) can also be escalated to XSS via `javascript:` or `data:` schemes.

---

## Phase 1 — Baseline

**Goal:** Build a behavioral profile of the redirect mechanism before testing anything adversarial.

1. **Send the legitimate redirect value unchanged.** Record:
   - HTTP status code (301/302/303/307/308 → server-side; 200 → client-side)
   - `Location` header value (for server-side)
   - Response body content (for client-side — look for JS sink or meta refresh)

2. **Determine redirect type:**
   - **Server-side** → 3xx status + `Location` header
   - **Client-side** → 200 status + JS sink (`window.location`, `document.location`, `meta refresh`) in body

3. **Send a valid but different same-domain path** (e.g., `/dashboard` → `/profile`). Does the app redirect to it, or enforce a fixed destination?

4. **Send the parameter empty or missing.** Does the app default-redirect, error, or behave differently?

### What you know now:
- Whether the redirect is server-side or client-side
- Whether the app transforms, encodes, or truncates the value

> ```
> [PHASE-1-COMPLETE]
> [PARAMETER] {name}
> [REDIRECT-TYPE] {server-side 3xx | client-side JS | client-side meta}
> [NEXT] {Phase 2 | stop — not a redirect parameter}
> ```

---

## Phase 2 — Confirmation

**Goal:** Confirm with HIGH confidence that the parameter accepts attacker-controlled external destinations.

### Confidence Definitions

| Level | Meaning | Evidence Required |
|-------|---------|-------------------|
| **HIGH** | External redirect confirmed | ≥2 distinct techniques redirect to an external domain, AND responses differ from invalid-input baseline |
| **MEDIUM** | Partial signal | One technique redirects externally, but could be app quirk or caching |
| **LOW** | No signal | All techniques produce responses matching the invalid-input baseline |

### Flow

1. **Send a plain external domain** (e.g., `https://example.com`). Record the response.

**Worked?**
- Send one more distinct external domain. Both work → HIGH confidence → exit.

**Blocked?**
- Validation exists. → Refer to [bypasses.md](bypasses.md) to fingerprint and bypass.
- **Hard cap: 15 requests.** If no HIGH confidence in 15 requests → negative verdict

### Interpreting Responses

**For server-side redirects:** Definitive signal is a 3xx status + `Location` header pointing to your external domain. Check the actual header — some apps return `302` with `Location: /error` when they block.

**For client-side redirects:** Your external domain must appear in a redirect sink (`window.location`, `meta refresh`). Reflection in HTML that isn't in a sink is not confirmation — that may be XSS.

**Noise vs. signal:**
- Generic error page ≠ confirmation (app is rejecting you)
- Redirect to homepage/login ≠ confirmation (it's a fallback)
- Your domain in a query parameter of an internal URL ≠ confirmation (parameter echo)
- 200 with your domain reflected in body ≠ redirect confirmation (may be XSS)

### Exit

Open redirect confirmed at HIGH confidence. Document the working technique.

- **Server-side** redirect → finding is **Open Redirect** (Low-Medium severity). Done.
- **Client-side** redirect → proceed to [exploitation.md](exploitation.md) for XSS escalation.

> ```
> [PHASE-2-COMPLETE]
> [PARAMETER] {name}
> [CONFIDENCE] {HIGH | MEDIUM | LOW}
> [TECHNIQUES-TESTED] {list each technique and result}
> [REQUESTS-USED] {n}/15
> [REDIRECT-TYPE] {server-side | client-side}
> [NEXT] {done — server-side | exploitation.md — client-side | negative verdict}
> ```

---

## Negative Verdict

**Mandatory gate.** Before closing any parameter — even if the result seems obviously negative — issue an explicit verdict.

### True Negative Conditions
- Multiple bypass families tested (not just variations of one) — at minimum: protocol-relative, domain-as-subdomain, `@` symbol, encoding
- All responses matched valid-input baseline or invalid-input error baseline
- No `Location` header or client-side sink ever contained an external domain
- Session verified valid throughout testing
- At least 8 distinct test cases with consistent negative results

### Format
```
[VULN-NEGATIVE]
[PARAMETER] {name}
[TECHNIQUES-TESTED] {list}
[SIGNAL] {what was observed, or "nothing — all match baseline"}
[CONCLUSION] {true negative | inconclusive — {reason}}
[ACTION] Parameter cleared. Do not proceed to exploitation.
```

**STOP:** If negative verdict issued, do not proceed to exploitation under any reinterpretation.

---

## Session Re-verification

### When to Re-verify

Pause and re-verify session validity when any of these occur:
- Receive a 401, 403, or login redirect where you previously received 2xx/3xx
- Three consecutive requests return identical responses that differ from all previous responses (possible block page)
- Phase transition (always re-verify at the boundary between phases)

---

## Things to Do

These are operating standards, not techniques. Maintain them across all phases.

- **Always compare against baseline.** Never evaluate a response in isolation. A 302 redirect is meaningless without knowing whether the `Location` header differs from what the baseline produced.
- **Log every phase transition** with the reasoning checkpoint format. No silent transitions.
- **Re-verify session validity at every phase boundary** and whenever a trigger condition is met.
- **Fingerprint validation before attempting bypasses.** Understand what the validator checks before trying to evade it. Two targeted tests beat ten random bypass attempts.
- **Track request count.** Stay within phase caps (15 for confirmation, 5 for XSS escalation).
- **Distinguish between redirect types.** Server-side (3xx + Location) and client-side (JS/meta) require different confirmation methods and different exploitation approaches. Only client-side redirects are candidates for XSS escalation.
- **Stop and document once XSS is confirmed or ruled out.** The goal is demonstrated maximum impact, not exhaustive testing.
- **Issue an explicit negative verdict before closing any parameter**, even if the result seems obviously negative. The structured format forces you to verify the evidence is actually sufficient.
- **Treat MEDIUM confidence as a prompt to try a different approach**, not to proceed with less certainty or to give up.

---

## Things Not to Do

These are specific prohibited behaviors for open redirect testing.

- **Do not interpret any redirect as confirmation without verifying the destination.** A 302 that redirects to `/error` or `/home` is not an open redirect — check the `Location` header value.
- **Do not proceed to exploitation on MEDIUM confidence.** Go back and try a different bypass family.
- **Do not iterate through bypass payloads without a hypothesis.** Each bypass targets a specific validation pattern. If you don't know what the validator is checking, run fingerprinting tests first.
- **Do not conflate reflection with redirect.** Your external domain appearing in the response body (reflected in HTML) is not the same as the app redirecting to it. Reflection may indicate XSS, not open redirect.
- **Do not keep testing the same bypass family after 3 consistent failures.** If URL encoding variants aren't working, the validator likely handles them. Switch to a different family (e.g., from encoding to protocol-relative).
- **Do not count blocked or error responses as negative evidence for the vulnerability.** They may indicate WAF or rate limiting, not effective validation.
- **Do not attribute session-related responses to validation.** A 401/403 after several requests is likely session expiry, not redirect validation getting stricter.
- **Do not attempt XSS escalation on server-side redirects.** If the redirect is a 3xx with a Location header, `javascript:` scheme testing is irrelevant — browsers don't execute JS from Location headers.
- **Do not issue a negative verdict when the result is inconclusive.** If WAF interfered, session died, or you only tested one bypass family, the result is inconclusive — say so.
- **Do not run any exploitation steps while session re-verification is pending or has failed.** Results from a dead session are worthless.
- **Do not keep testing XSS escalation after confirming it works.** Document and stop.
