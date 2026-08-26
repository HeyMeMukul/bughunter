# Open Redirect — Bypasses

**Entry point:** External domain was blocked in Phase 2. Something is filtering the redirect value.

---

## Step 1: What Is Getting Blocked?

Fingerprint the validator to understand what it rejects. Send these probes and stop as soon as you identify the pattern.

| Probe | Send | If Accepted | If Rejected |
|-------|------|-------------|-------------|
| Protocol check | `//external.com/path` | Validator ignores protocol-relative URLs → **Family A** | Protocol-aware, continue |
| Substring check | `https://external.com/target-domain.com` | Substring match → **Family B** | Continue |
| Prefix check | `https://target-domain.com.external.com` | Prefix match, no registrable domain verification → **Family B** | Continue |
| Encoding gap | `https://external.com%2fpath` | Encoding differential → **Family C** | Try double: `%252f`. If different → **Family C**, else continue |
| Authority trick | `https://target-domain.com@external.com` | Validator doesn't parse URL authority → **Family D** | Validator handles `@` correctly |

If all probes rejected with same pattern → try **Family E** as final check, then consider negative verdict.

---

## Step 2: How to Bypass?

### Family A — No Protocol Handling
Validator checks for `http://` or `https://` but misses protocol-relative URLs.

- `//external.com`
- `///external.com` (triple slash — some browsers resolve differently)
- `////external.com`

### Family B — Domain Check Weaknesses

**Substring check** — validator looks for `target.com` anywhere in the string:
- `https://external.com/target.com`
- `https://external.com?x=target.com`
- `https://target.com.external.com`

**Prefix check** — validator checks URL starts with expected domain:
- `https://target.com.external.com` (target as subdomain of attacker domain)
- `https://target.com%00.external.com` (null byte after trusted domain)

**Suffix check** — validator checks URL ends with expected domain:
- `https://external.com#target.com`
- `https://external.com?redirect=target.com`

### Family C — Encoding Gaps
Validator checks raw string, app decodes before redirecting.

**Single encoding:**
- `/` → `%2f`
- `@` → `%40`
- `.` → `%2e`

**Double encoding:**
- `%2f` → `%252f`
- `%40` → `%2540`

**Base64:** If parameter value looks Base64-encoded, decode it, swap in your external URL, re-encode.

### Family D — Parser Differentials
Validator and browser parse URL structure differently.

- `https://trusted.com@evil.com` — `trusted.com` is userinfo, `evil.com` is actual host
- `https://trusted.com%40evil.com` — encoded `@`
- `https://trusted.com\@evil.com` — backslash before `@`
- `https://trusted.com\.evil.com` — backslash normalization (`\` → `/` in browsers)
- `https://tru%09sted.com` — tab injection in domain

### Family E — Scheme Alternatives (Client-Side Only)
Validator allows non-HTTP schemes through. Only applies to client-side redirects (JS sinks).

- Test `javascript:` scheme — if the value reaches a DOM sink without scheme validation, this executes JS
- Test `data:` scheme — browser renders inline content

→ For specific payloads and testing steps, go to [exploitation.md](exploitation.md). Do not duplicate testing here.

---

## Step 3: Bypass Achieved?

**Yes** → Open redirect confirmed. Return to [SKILL.md](SKILL.md) Phase 2 exit.

**No after 3+ families tested** → Consider negative verdict. The validator is likely robust.

### When to Stop

- Tested at least one technique from 3 different families with no success
- All responses match the blocked/rejected baseline consistently
- 12+ requests used without any partial signal
