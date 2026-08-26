# CVSS 3.1 Base Score Calculator Guide

## How to Use

For each metric, select the value that matches your finding. Then construct the vector string.

---

## Attack Vector (AV)

| Value | When to Select | Examples |
|-------|---------------|---------|
| **Network (N)** | Exploitable over the internet | Web vuln, API flaw, remote RCE |
| **Adjacent (A)** | Requires same network segment | ARP poisoning, Bluetooth |
| **Local (L)** | Requires local system access | Local file read, privilege escalation |
| **Physical (P)** | Requires physical access | USB attack, hardware tampering |

**Almost all web/API vulnerabilities = Network (N)**

## Attack Complexity (AC)

| Value | When to Select | Examples |
|-------|---------------|---------|
| **Low (L)** | Attack works reliably, no special conditions | Direct IDOR, simple XSS |
| **High (H)** | Requires specific conditions beyond attacker's control | Race condition with narrow window, MITM required |

**Key:** If the attacker can reproduce it consistently = Low. If it depends on timing, victim state, or environmental factors = High.

## Privileges Required (PR)

| Value | When to Select | Examples |
|-------|---------------|---------|
| **None (N)** | No authentication needed | Unauthenticated SQLi, public endpoint |
| **Low (L)** | Requires basic user account | IDOR as regular user, stored XSS as user |
| **High (H)** | Requires admin/privileged access | Admin panel vulnerability |

## User Interaction (UI)

| Value | When to Select | Examples |
|-------|---------------|---------|
| **None (N)** | No victim action required | IDOR, SQLi, SSRF, API flaws |
| **Required (R)** | Victim must click/visit something | Reflected XSS, CSRF, phishing link |

## Scope (S)

| Value | When to Select | Examples |
|-------|---------------|---------|
| **Unchanged (U)** | Impact limited to the vulnerable component | IDOR on API, SQLi on database |
| **Changed (C)** | Impact extends beyond the vulnerable component | XSS (browser scope ≠ server scope), SSRF (web app → internal network) |

**Scope Changed increases the score significantly.**

## Confidentiality Impact (C)

| Value | When to Select |
|-------|---------------|
| **None (N)** | No confidentiality impact |
| **Low (L)** | Limited data exposure (non-sensitive, partial) |
| **High (H)** | Full data access (PII, credentials, full database) |

## Integrity Impact (I)

| Value | When to Select |
|-------|---------------|
| **None (N)** | No data modification possible |
| **Low (L)** | Limited modification (some data, non-critical) |
| **High (H)** | Full modification (any data, critical data, code execution) |

## Availability Impact (A)

| Value | When to Select |
|-------|---------------|
| **None (N)** | No availability impact |
| **Low (L)** | Partial degradation |
| **High (H)** | Full denial of service, system crash |

---

## Common Vector Strings

### Critical (9.0+)
```
Unauth RCE:           CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  = 9.8
Unauth SQLi (full):   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1
SSRF to cloud creds:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N  = 8.6 → 9.1 with integrity
Auth bypass:          CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1
```

### High (7.0-8.9)
```
Auth SQLi (extract):  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  = 8.1
IDOR (write+read):    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  = 8.1
ATO via OAuth:        CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N  = 8.1
Stored XSS → ATO:    CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N  = 8.7
JWT forge:            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1
```

### Medium (4.0-6.9)
```
IDOR (read only):     CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5
Reflected XSS:        CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1
CSRF (low impact):    CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N  = 4.3
CORS miscfg:          CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N  = 6.5
Info disclosure:      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  = 5.3
Open redirect:        CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1
```

### Low (0.1-3.9)
```
Self-XSS:             CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N  = 3.7
Minor info leak:      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  = 5.3 (actually Medium)
Missing headers:      Usually informational, not scored
```

---

## Constructing the Vector String

```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

**Example construction for "Authenticated IDOR reading other users' PII":**
- AV:N (network accessible)
- AC:L (easy to exploit, just change the ID)
- PR:L (need a basic account)
- UI:N (no victim interaction)
- S:U (stays within the API component)
- C:H (full PII access)
- I:N (read-only)
- A:N (no availability impact)

**Result:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 (Medium)**
