# WAF and Filter Bypass for Deserialization Payloads

## Why Payloads Fail in Production

In labs, payloads hit a bare endpoint. In production, traffic passes through layers that inspect and modify data:

```
Attacker → CDN/Edge (Cloudflare, Akamai, AWS CloudFront)
         → WAF (ModSecurity, AWS WAF, Imperva, F5 ASM)
         → Reverse Proxy (nginx, HAProxy, Apache)
         → Application Firewall / RASP (Contrast, Dynatrace)
         → Application Code (deserialization happens here)
```

Each layer has different inspection capabilities. The strategy: craft payloads that survive all layers while remaining valid for the deserializer.

---

## Decision Tree

```
Payload blocked?
├── Step 1: Identify WHICH layer blocked it
│   ├── 403 with generic body → Edge WAF (Cloudflare, Akamai)
│   ├── 403 with WAF rule ID in body → Inline WAF (ModSecurity)
│   ├── 200 but payload didn't fire → App-level filter or RASP
│   └── Connection reset / timeout → IPS/IDS dropping packets
│
├── Step 2: Identify WAF vendor (informs first-try technique)
│   ├── cf-ray header / challenge pages → Cloudflare
│   ├── AkamaiGHost / reference ID in errors → Akamai
│   ├── x-amzn-RequestId patterns → AWS WAF
│   ├── Rule IDs in error body → ModSecurity
│   └── visid_incap cookies → Imperva
│
├── Step 3: Determine WHAT triggered the block
│   ├── Send payload in parts — which fragment triggers?
│   └── Send benign serialized data (valid object, no exploit)
│       ├── Benign PASSES → FORMAT is allowed, CONTENT is blocked
│       │   → Evasion Path A (content-pattern bypass):
│       │       1. Encoding mutations (Section A) — obfuscate triggering bytes
│       │       2. Payload restructuring (Section C) — obfuscate class names
│       │       3. Language parser tricks (Section D) — format-specific alternatives
│       │       4. Gzip compression (Section A) — hides decoded content from WAF
│       │
│       └── Benign BLOCKED → FORMAT itself is blocked
│           → Document as blocked at format level, escalate to team
│
└── Step 4: Confirm bypass with safe PoC
    ├── Time delay first — never jump straight to RCE through a bypassed WAF
    └── Document the EXACT bypass technique — it is part of the finding's value


```
## Section A: Encoding Mutations

WAFs pattern-match on known signatures. Changing how the payload is encoded breaks those patterns while the application still processes it correctly.

| Technique | How It Works | When to Use |
|---|---|---|
| **Base64 double-encoding** | Encode payload → base64 → base64 again. App decodes twice. WAF only inspects outer layer. | App does its own base64 decode before deserializing |
| **URL encoding (full)** | Encode every byte as `%XX`, not just special characters. `O:4:` → `%4F%3A%34%3A` | WAF inspects URL-decoded content but misses full encoding |
| **Mixed encoding** | Combine URL + Base64 + hex in the same parameter. `%4F:4:%22Test%22` | WAF normalises one encoding but not combinations |
| **Hex encoding** | Java `AC ED 00 05` sent as raw hex vs base64 `rO0AB` | WAF signatures match one form but not the other |
| **Gzip/deflate wrapping** | Compress serialized payload in request body with `Content-Encoding: gzip` | WAF doesn't decompress before inspection (common misconfiguration) |
| **Unicode escapes** | `\u004F:4:` for PHP, `\u0040class` for Jackson JSON | WAF regex doesn't account for Unicode normalization |
| **Overlong UTF-8** | Encode ASCII characters using 2-3 byte UTF-8 sequences (e.g., `/` as `%c0%af`) | Older WAFs that don't normalise UTF-8 |

**Practical workflow:**
1. Send the known-good payload with no encoding → confirm block.
2. Apply base64 → test. If blocked, the WAF decodes base64.
3. Apply double-base64 → test. If blocked, WAF does recursive decode.
4. Apply gzip → test. Many WAFs skip compressed body inspection.
5. Try mixed: URL-encode the base64 of the payload.

---

## Section B: Payload Restructuring

Modify the payload structure to avoid known signatures while remaining valid for the deserializer.

**Whitespace and Comment Injection (JSON deserializers):**
```json
// WAF blocks: {"$type":"System.Diagnostics.Process"}
// Try:
{
  "$type" : "System.Diagnostics.Process"
}
// Or with Unicode:
{"\u0024type":"System.Diagnostics.Process"}
```

**Class Name Obfuscation:**
- **Java:** Use `TC_PROXYCLASSDESC` instead of `TC_CLASSDESC` — same deserialization result, different byte signature. Tool: custom ysoserial forks that output proxy-wrapped classes.
- **PHP:** Insert `+` before class name length — `O:+4:"Test":1:{}` is equivalent to `O:4:"Test":1:{}` but bypasses regex matching `O:\d+:`.
- **.NET:** Use fully-qualified assembly names with version, culture, and public key token. `System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089` — WAF signature may only match short names.

**Nested Serialization:**
Wrap the malicious serialized object inside an outer benign serialized wrapper. The application deserializes the outer object, which triggers deserialization of the inner payload. WAF only sees the outer layer.

**Fragmented Gadget Chains:**
Instead of a single monolithic payload, split the chain across multiple parameters or requests if the application reassembles them server-side (e.g., session-stored partial state + request parameter).

---

## Section D: Language-Specific Parser Tricks

### PHP
- **Property count manipulation:** `unserialize()` skips `__wakeup()` if declared property count > actual count (CVE-2016-7124, PHP < 7.0.10 / < 5.6.25). `O:4:"Test":1:` → `O:4:"Test":2:`.
- **`S:` escaped strings:** Uppercase `S:` allows hex-encoded characters (`\xx`). `S:4:"\4Fest"` = `s:4:"Test"`. Bypasses string-content filters.
- **`C:` custom serializable:** Classes implementing `Serializable` use `C:` prefix. Different parsing path, different WAF signatures.
- **Plus-prefix on length:** `O:+4:"Test":1:{}` — the `+` is ignored by PHP's parser but breaks regex patterns.
- **Null bytes in strings:** PHP strings can contain null bytes. Insert `\x00` in non-critical positions to break WAF string matching.
- **Array key reordering:** If the WAF matches a specific property order pattern, reorder properties — PHP deserializes by key name, not position.

### Java
- **Stream manipulation:** Java serialization allows extra bytes after the stream terminator (`TC_ENDBLOCKDATA`). Append random bytes to change payload hash/signature.
- **Custom `writeObject`/`writeReplace`:** Modify how objects are serialised to produce non-standard but valid byte sequences.
- **Nested `ObjectStreamClass` variation:** Replace standard class descriptors with proxy descriptors or referential handles — functionally identical, pattern-different.

### .NET
- **ViewState encoding variations:** MAC-validated ViewState can be manipulated if the validation key is predictable, defaults are in use, or leaked via `web.config` / directory traversal.
- **JSON.NET `$type` obfuscation:** Use assembly-qualified names with version/culture/publicKeyToken. `"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"` — bypasses short-name matching.
- **Alternative type resolvers:** Custom `SerializationBinder` implementations often have incomplete allowlists. Enumerate accepted types through error messages.
- **XAML-based payloads:** Instead of direct `ObjectDataProvider`, wrap the payload in XAML markup. Different byte pattern, same execution result.

### Node.js
- **Unicode escapes in JSON:** `{"rce":"_\u0024\u0024ND_FUNC\u0024\u0024_function(){...}()"}` — the `_$$ND_FUNC$$_` signature is obfuscated but the JSON parser normalises it.
- **Prototype pollution fallback:** If `node-serialize` payloads are blocked, look for `cryo` or similar libraries vulnerable to `__proto__` manipulation — entirely different payload structure.

### Python
- **Pickle opcode variation:** Multiple valid opcode sequences produce the same unpickled object. Use `pickletools.optimize()` or manually rewrite opcodes to avoid signature matching. For example, `GLOBAL` vs `STACK_GLOBAL` opcodes achieve the same import but have different byte patterns.
- **Protocol version rotation:** Pickle has protocols 0-5. WAFs may only signature-match one version. `pickle.dumps(payload, protocol=0)` (ASCII, readable) vs `protocol=2` (binary) vs `protocol=4` (framing) — try each.
- **Pickle within pickle:** Nest a malicious pickle inside a benign outer pickle object using `REDUCE` opcode. Outer layer passes WAF inspection.
- **Custom `__reduce_ex__`:** Override to produce non-standard but valid reduce tuples that avoid pattern matching.

---

## WAF Vendor-Specific Notes

| WAF | Common Weakness | Recommended First Try |
|---|---|---|
| **Cloudflare** | Gzip body inspection gaps | Gzip-wrapped payload; Unicode escapes |
| **AWS WAF** | Custom rules often incomplete; regex-based | Double encoding |
| **ModSecurity (CRS)** | Rule-ID based blocking | Identify triggered rule → mutate that specific pattern |
| **Akamai** | Strong default rules but custom exceptions common | Gzip compression; class name obfuscation |
| **Imperva** | Advanced but bypassable with encoding tricks | Unicode escapes; nested serialization |
| **F5 ASM** | Deep inspection but performance-limited | Large payload padding |

---

## Documenting WAF Bypass in Reports

When a WAF bypass is part of the exploitation chain, document it as a separate finding:

```markdown
## Additional Finding: WAF Bypass Enabling Deserialization Exploitation

**WAF Product:** [Identified vendor and version if known]
**Bypass Technique:** [Exact method used]
**Why It Worked:** [WAF limitation — e.g., "Does not inspect gzip-compressed request bodies"]

### Remediation
- [WAF-specific fix: e.g., "Enable gzip body inspection in Cloudflare WAF settings"]
- [Defense-in-depth: "Application-level deserialization controls should not rely on WAF alone"]
```

---

## Return Protocol

After successfully bypassing the WAF:

```
[WAF-BYPASS] Completed
[TECHNIQUE] {encoding / payload restructuring / language-specific}
[WAF VENDOR] {Cloudflare / AWS / ModSecurity / etc.}
[RETURN TO] SKILL.md Phase 5
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| All encoding techniques blocked | Try language-specific parser tricks, escalate to team if all fail |
| Benign serialized data blocked | WAF blocks FORMAT, not content → document as blocked at format level |
| Uncertain if bypass worked | Confirm with time delay (5s+) — never jump to RCE |

---

*Return to [SKILL.md](SKILL.md) | See [gadget-chains.md](gadget-chains.md) for exploitation methodology*
