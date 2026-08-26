---
name: testing-insecure-deserialization
description: "Classifies insecure deserialization findings by format, control level, and exploitation path. Routes to correct methodology. Triggers on serialized data in cookies, request bodies, headers, or API fields."
---

# Insecure Deserialization — Classify and Route

## Workflow

```
1. BASELINE → 2. IDENTIFY FORMAT → 3. CONFIRM DESERIALIZATION → 4. ASSESS CONTROL → 5. EXPLOIT
   (record)      (marker table)       (3 methods)                (direct?)         (tier 1-4)
   
   Stop conditions checked at every phase ↓
```

## Reference Files

**When you encounter blocks or need detailed guidance, you MUST consult:**

| When This Happens | You MUST Read |
|-------------------|---------------|
| Payload blocked by WAF | [waf-bypass.md](waf-bypass.md) |
| Need gadget chain construction, Java classpath enumeration, OR PHAR exploitation | [gadget-chains.md](gadget-chains.md) |

**Do NOT skip these files. They contain bypass techniques and chain selection guidance.**

---

## Core Concept

Deserialization is code execution *before* business logic runs. The application reconstructs an object from attacker-controlled bytes, and any side effects triggered during that reconstruction are in scope for exploitation.

Three escalating questions — answer them in order, stop when the impact ceiling justifies your current depth:

1. Can I change a **value** to alter behaviour? 
2. Can I change the **type/class** to trigger unintended logic?
3. Can I **chain methods** (gadget chain) to reach a dangerous sink?

---

## Confidence Definitions


| Level | Format Identification | Confirmation Evidence | Exploitation Readiness |
|-------|----------------------|----------------------|------------------------|
| **HIGH** | Explicit marker found (magic bytes, header, file extension) | **Active confirmation**: Measurable time delay OR controlled error message change | Ready for Tier 3 exploitation |
| **MEDIUM** | Inferred from context (Content-Type, parameter name, app stack) | **Passive confirmation**: Generic deserialization error observed OR behavioral anomaly (crash, different response code) | Requires one more confirmation before Tier 3 |
| **LOW** | Guessed based on technology stack alone | **No confirmation**: No observable difference when payload sent | Stay in Tier 1, gather more data |


**Proceed to exploitation with HIGH confidence only. MEDIUM requires additional confirmation. LOW requires Phase 3 testing before investing further.**

---

## Phase 1 — Baseline

**Goal:** Confirm where serialized data appears and that you can modify it. Record normal behaviour before touching anything.

**Checklist:**
- [ ] Identify every parameter, cookie, header, and upload field in scope
- [ ] Find serialized data — look for format markers (table in Phase 2)
- [ ] Record a normal response for each candidate: status, size, timing, behaviour
- [ ] Confirm you can submit a MODIFIED value and that the request is accepted

```
[PHASE-1] Baseline
[CANDIDATES] {list}
[BASELINE] {status / size / timing}
[MODIFIABLE] Yes / No
```

> **STOP:** If no modifiable serialized data found → document as "not tested" and move on. Serialized data that is only stored and replayed without processing is not exploitable.

> **Note:** You need evidence the app acts on deserialized content before spending time on chain construction.

---

## Phase 2 — Identify Format

**Goal:** Determine which serialization format is in use.

| Format | Marker | Common Location |
|---|---|---|
| PHP native | `O:`, `a:`, `s:`, `i:` prefix | Cookies, hidden form fields |
| Java native | `AC ED 00 05` (hex) / `rO0AB` (base64) | Cookies, POST body, `.ser` uploads |
| Python pickle | `\x80\x0N` opcode byte | Session cookies, API fields |
| Ruby Marshal | `\x04\x08` | Session cookies |
| .NET BinaryFormatter | `AAEAAAD/////` (base64) | ViewState, cookies, POST body |
| .NET JSON.NET | `$type` field in JSON | API request bodies |
| JSON/XML class hints | `@class`, `_type`, `__type` | Any JSON or XML field |
| Node.js node-serialize | `_$$ND_FUNC$$_` | Cookies, API fields |
| PHAR (PHP) | File upload exists + filesystem op reachable | Avatars, attachments |

> **Decoding tip:** If the data looks base64, decode it: `echo "<value>" | base64 -d | xxd | head`. Look at the first 4 bytes: `AC ED 00 05` = Java, `\x80` = Python pickle, `O:` in ASCII = PHP, `\x04\x08` = Ruby Marshal. If it decompresses (gzip magic `1f 8b`), decompress first.

> **JWT note:** Some frameworks embed serialized objects *inside* JWT claims. Also check if the app accepts non-JWT session formats on the same endpoint.

```
[PHASE-2] Format
[FORMAT] {PHP / Java / Python / .NET / Ruby / Node.js / PHAR / Unknown}
[CONFIDENCE] HIGH / MEDIUM / LOW
[LOCATION] {cookie / parameter / header}
```

> **STOP:** If you cannot identify a recognisable format after decoding and inspecting, and there are no error messages suggesting deserialization, document as "suspected but unconfirmed" and move on. Do not invest in exploitation without format confirmation.

---

## Phase 3 — Confirm Deserialization Occurs

**Goal:** Verify the application actually *deserializes* your modified input — not just accepts and stores it.

Phase 1 identifies that serialized data exists and is modifiable. Phase 3 determines whether the application actually processes that data through its deserializer, which is what makes exploitation possible.

**Confirmation methods (use in order):**

1. **Benign value modification** — Change a field that should have a visible effect if deserialized (e.g., `username`, `role`, a boolean flag). If the app behaviour changes, deserialization confirmed.

2. **Type error provocation** — Submit a valid but structurally wrong object (wrong class name, mismatched field type). A deserialization error in the response (`unserialize()` warning, `ClassNotFoundException`, `InvalidClassException`) confirms deserialization fires.

3. **Time delay** — Use a safe time-delay payload appropriate to the format. Confirmed if response latency ≥5s above baseline.

```
[PHASE-3] Confirmation
[METHOD] {value mod / type error / time delay}
[RESULT] {response delta / error / timing}
[CONFIRMED] YES / NO / SUSPECTED
```

> **STOP:** If three confirmation attempts produce no signal and the endpoint shows no error differentiation between valid and malformed serialized data, the app is likely not deserializing your input.

> **NEGATIVE VERDICT** — Phase 3 exhausted
>
> No behaviour change from value modification. No deserialization error from type provocation. No time delay. The application accepts but does not appear to process the serialized data. Document as "deserialization not confirmed" and do not proceed to Phase 4.

---

## Phase 4 — Assess Control

**Goal:** Determine whether you can actually influence the deserialized content.

| Control Level | Situation | Action |
|---|---|---|
| **Direct** | Unencrypted, unsigned | Modify directly |
| **Signature checked AFTER deserialization** | Sig verified post-construction | Exploit fires before check — treat as direct |
| **Signature checked BEFORE deserialization** | MAC/HMAC validated first | Cannot exploit without valid signature |
| **Encrypted** | Strong encryption, no key leakage | Cannot exploit without decryption key |
| **Strong crypto** | Verified no leak paths | **STOP — document as theoretical** |

```
[PHASE-4] Control
[CONTROL] {Direct / Sig-after / Sig-before / Encrypted}
```

> **STOP:** If signature is checked BEFORE deserialization or data is encrypted, document as "theoretical finding — cryptographic control prevents exploitation" and do not proceed.

---

## Phase 5 — Route to Exploitation

**Goal:** Determine the correct exploitation path and achieve documented impact.

| Format | Quick Win | RCE Path | Tool |
|---|---|---|---|
| PHP native | `b:0` → `b:1`, type juggling (`0 == "string"`) | `__destruct`/`__toString` → PHPGGC | `phpggc` |
| Java native | Attribute modification (rare) | `readObject()` → gadget chain | `ysoserial` |
| Python pickle | N/A | `__reduce__()` = direct RCE *(time delay first)* | Manual / `pickletools` |
| Ruby Marshal | Attribute mod (needs key) | `Gem::Requirement` → `Kernel#open` | `ruby-marshal` gem |
| .NET BinaryFormatter | Attribute modification | `ISerializable` → ysoserial.net chains | `ysoserial.net` |
| .NET JSON.NET | Swap `$type` | `ObjectDataProvider` → `Process.Start` | `ysoserial.net` |
| JSON/XML class hints | Swap class to known vulnerable | Depends on deserializer | Manual |
| Node.js node-serialize | IIFE injection = direct RCE | Same — no chain needed | Manual |
| PHAR (PHP) | N/A | Metadata chain + `phar://` trigger | `phpggc -p phar` |

**Escalate in tiers — stop when impact is sufficient:**

```
Tier 1: Value modification → behaviour change (role, price, flag)
  → if meaningful impact: document, stop here

Tier 2: Authentication/authorization bypass via value or type manipulation
  → if goal achieved: document, stop here

Tier 3: File read/write, SSRF
  → if goal achieved: document, stop here

Tier 4: Remote Code Execution
  → only if scope and written authorisation permit
```

> **Java classpath unknown?** Start with a malformed payload to provoke an error. Then enumerate dependencies via error messages, stack traces, `/actuator/info`, `pom.xml`, `MANIFEST.MF`, or `X-Powered-By` headers. Only then select a ysoserial chain. See [gadget-chains.md](gadget-chains.md).

> **PHP fastest path:** Before reaching for PHPGGC, check if value modification alone achieves the goal. Change `admin:b:0` to `admin:b:1`, or swap a `role` field to `administrator`. Many PHP apps have meaningful impact at Tier 1/2 without needing a gadget chain.

```
[PHASE-5] Exploitation
[PATH] {method + tier}
[PAYLOAD] {payload or command — redact RCE}
[IMPACT] {what you observed}
[TIER] 1 / 2 / 3 / 4
```

> **Payload blocked?** → MUST consult [waf-bypass.md](waf-bypass.md)
> **Need chain construction?** → MUST consult [gadget-chains.md](gadget-chains.md)

---

## Safe PoC Order

Always start at #1. Escalate only when the previous method fails or is insufficient for the goal.

| # | Method | Infra Required? | When to Use |
|---|---|---|---|
| 1 | Time delay (`sleep 5` / `Thread.sleep(5000)`) | No | Default first. Zero footprint, works for synchronous endpoints. |
| 2 | Canary file write to `/tmp` only | No | Delay is ambiguous. Track for cleanup. |
| 3 | `id`/`whoami` in-band | No | Scope permits, previous methods succeeded, need execution context. |

---

## Safety Boundaries

**Hard stops:** No data destruction, persistence mechanisms, lateral movement, or data exfiltration.



**Deserialization-specific:** Gadget chains may trigger side effects (emails, billing). Track all PHAR temp files for cleanup.

**Stop immediately if:** 5xx errors after payload, PII/credentials in response

---


## Checklist

**Do:** Baseline before injection | Confirm deserialization before exploiting | Start with time delay PoC | Track PHAR temp files | Get written authorization for Tier 4 | Stop at sufficient impact

**Don't:** Skip Phase 3 confirmation | Use RCE for confirmation | Proceed with LOW confidence | Spray ysoserial without classpath enumeration | Ignore JEP 290 on Java 8u231+


> **Payload tables and error fingerprinting:** See [gadget-chains.md](gadget-chains.md) Quick Reference Tables.

---

## Worked Example

### PHP Cookie → Privilege Escalation (Tier 2)

```
[PHASE-1] Baseline — Cookie: session=<base64 PHP serialized>
[PHASE-2] Format — PHP native (O: prefix), HIGH confidence
[PHASE-3] Confirmation — Changed role field: "user" → "admin", got admin panel redirect
[PHASE-4] Control — Unsigned cookie, direct modification
[PHASE-5] Payload: O:10:"UserState":2:{s:4:"role";s:5:"admin";...}
          Impact: Admin access — Tier 2 achieved without gadget chain
```

---

## Negative Finding Template

Use this when deserialization is present but not exploitable, or when you cannot confirm the app actually processes your input.

```markdown
## Finding: Insecure Deserialization — Not Exploitable — [Format]

**Endpoint:** [URL, parameter, or cookie]
**Format:** [PHP / Java / Python / .NET / Ruby / Node.js / PHAR]
**Reason not exploitable:** [Select one]
  - [ ] Deserialization not confirmed (app accepts but does not process input)
  - [ ] Strong cryptographic control prevents exploitation
  - [ ] Signature checked BEFORE deserialization
  - [ ] No viable gadget chain for identified classpath/dependencies
  - [ ] open_basedir blocks PHAR exploitation (path restriction)

**Evidence:** [What was tested, what responses were observed]

**Recommendation:** Even if not currently exploitable, this should be remediated:
- Replace deserialisation with a data-only format (JSON, protobuf)
- Apply allowlist of permitted classes before deserialization
- Integrity-check input BEFORE deserialization
```

---

## Report Template (Exploitable Finding)

```markdown
## Finding: Insecure Deserialization — [Format] — Tier [1–4]

**Endpoint:** [URL, parameter, or cookie name]
**Format:** [PHP / Java / Python / .NET / Ruby / Node.js / PHAR]
**Control:** [Direct / Signature bypass / Key required — key found via X]
**Impact:** Tier [1–4] — [Description of demonstrated impact]
**CVSS:** [Score and vector]

### Evidence

**Payload:**
[Payload or generation command. For RCE: redact command if sensitive.]

**Response / Confirmation:**
[Status code, response diff, timing delta, or file content]

### Chain

[Format identified → modification/chain used → impact demonstrated]

### Remediation

- [Format-specific: e.g., "Replace PHP unserialize() with JSON decode"]
- [Integrity: "Validate HMAC before deserialization, not after"]
- [Allowlist: "Use class allowlisting / SerialKiller / NotSoSerial"]
- [General: "Deserialize only trusted, integrity-verified data"]
```
