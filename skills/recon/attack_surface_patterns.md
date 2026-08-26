# Attack Surface Pattern Recognition

## When to Use

Consult during Phase 10 (Prioritization) of recon. This file teaches you to READ application behavior and map it to vulnerability classes through reasoning, not just keyword matching.

---

## The Reasoning Framework

Don't ask "what vulnerability should I test?" Ask these questions:

### 1. "What does this parameter DO on the server?"

| If the parameter... | Then the server probably... | Test for... |
|---------------------|---------------------------|-------------|
| Returns different data for different IDs | Queries a database | [[sqli]], [[idor]] |
| Changes what page/template renders | Includes a file or renders a template | [[path-traversal]], [[ssti]] |
| Fetches content from a URL | Makes an HTTP request | [[ssrf]] |
| Redirects to a URL | Constructs a Location header | [[open-redirect]] |
| Appears in the HTML response | Renders user input in output | [[xss]] |
| Triggers an action (create, delete, modify) | Writes to database/filesystem | [[csrf]], [[idor]], [[mass-assignment]] |
| Controls sort order, filtering, search | Constructs a query | [[sqli]], [[ldap-injection]] |
| Specifies a filename | Accesses filesystem | [[path-traversal]], [[file-upload]] |
| Is processed as XML/JSON | Parses structured input | [[xxe]], [[prototype-pollution]] |
| Controls a shell operation | Executes a command | [[command-injection]] |

### 2. "What is the developer ASSUMING I won't do?"

| If the developer assumes... | Break it by... |
|----------------------------|---------------|
| Users follow the UI flow sequentially | Skip steps, go directly to later endpoints |
| IDs in the URL belong to the logged-in user | Use another user's ID |
| The frontend enforces input validation | Send requests directly, bypass frontend |
| Only expected fields are submitted | Add extra fields (mass assignment) |
| The price/quantity is what the frontend sent | Modify price to 0, quantity to negative |
| One request per action | Send 50 simultaneous requests |
| The redirect URL is to their own domain | Point it to your domain |
| The file upload is an image | Upload PHP/SVG/polyglot |
| Authentication = authorization | Authenticate as user A, access user B's resources |
| The session is secure because it uses HTTPS | Steal it via XSS (if no HttpOnly) |

### 3. "Where are the trust boundaries?"

Every application has boundaries where it stops validating:

```
Internet → WAF → Load Balancer → Application → Database
                                              → Internal APIs
                                              → Filesystem
                                              → External Services

Trust typically decreases from left to right.
Internal APIs often have NO authentication.
Database queries often have NO parameterization in legacy code.
Filesystem operations often have NO path validation.
```

**The most critical bugs live at trust boundaries** — where the application stops checking and starts trusting.

---

## Behavioral Signals During Recon

### Signals That Scream "Test Me"

**Error message verbosity:**
- Stack traces → reveals framework, language, file paths
- SQL error messages → definitely test for SQLi
- Template engine errors → definitely test for SSTI
- "File not found" with a full path → test for path traversal
- XML parsing errors → test for XXE

**Response time anomalies:**
- One endpoint takes 2x longer than others → might be doing DB queries, external fetches, or file operations
- Response time changes with input length → might be doing regex, query building, or processing

**Status code patterns:**
- 403 instead of 404 on admin paths → the path EXISTS, just forbidden → test authz bypass
- 405 Method Not Allowed → endpoint exists for other methods → test all methods
- 500 on specific inputs → the input reaches backend processing → potential injection point
- 302 to login page → authentication required → but is authorization checked after auth?

**Header anomalies:**
- CORS headers on API → test CORS misconfiguration
- Missing security headers → note for report, test related vulns
- Custom headers (X-Request-ID, X-Trace-ID) → internal infrastructure exposure
- Different Server headers on different endpoints → multiple backends, potential smuggling

### Response Comparison Intelligence

When testing the same endpoint with different inputs, pay attention to:

**What changes:**
- Status code changes → input reaches decision logic
- Response length changes → input affects data retrieval
- Response time changes → input affects processing
- New headers appear → input triggers different code paths
- Error format changes → input reaches different handlers

**What stays the same when it shouldn't:**
- Same response for valid and invalid IDs → might be ignoring the ID (checking session instead)
- Same response for authenticated and unauthenticated → endpoint may not check auth
- Same response regardless of input → parameter might not be processed (or well-parameterized)

---

## Application Architecture Patterns

### Single-Page Applications (React, Angular, Vue)
- All routing is client-side → API endpoints are the real attack surface
- Look for API calls in JavaScript, not server-rendered pages
- The SPA itself is public → all client-side logic is visible
- API endpoints may have weaker authorization than the UI suggests
- Source maps may be available → full source code access

### Microservices
- Multiple services = multiple attack surfaces
- Internal services often trust each other implicitly (East-West trust)
- Different services may have different auth mechanisms
- Gateway/proxy may enforce auth, but internal endpoints may not
- Look for: different base paths, different response formats, different error styles

### Legacy Monoliths
- Single codebase = consistent but old security
- More likely to have: SQLi, LFI, command injection, deserialization
- Error messages often verbose (no structured error handling)
- Admin interfaces often built into the same application
- Session management may be custom (and flawed)

### Serverless / JAMstack
- API endpoints are Lambda/Cloud Functions → different attack surface
- Static frontend + dynamic API → focus all testing on the API
- Cold start times may cause timeout-based false positives
- IAM misconfigurations are common
- Environment variables often contain secrets

---

## What To Do With Each Discovery

| Discovery | Immediate Action | Skill to Load |
|-----------|-----------------|---------------|
| Login page | Map entire auth flow, check for brute-force protection | [[session-management]], [[csrf]] |
| API with Swagger docs | Read entire spec, map all endpoints | [[idor]], [[mass-assignment]] |
| GraphQL endpoint | Run introspection query | [[graphql]] |
| File upload | Check what's accepted, where files are stored | [[file-upload]] |
| Search function | Test reflection, check if input reaches DB | [[xss]], [[sqli]] |
| URL parameter | Check if server fetches it | [[ssrf]], [[open-redirect]] |
| Admin panel (403) | Check all methods, try auth bypass | [[idor]], [[jwt]] |
| Old API version | Compare with current — what's different? | [[idor]], [[sqli]] |
| Source map | Download and analyze original source | Everything relevant |
| Debug endpoint | Check what information it exposes | Immediate finding |
| Exposed .env | Read it — may contain credentials | Immediate finding |
| Open S3 bucket | Check read/write/list permissions | [[cloud-misconfig]] |
