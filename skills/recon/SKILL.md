---
name: recon
description: Phase 1 spidering — attack surface discovery via tools. Use when starting an engagement to enumerate the target's exposed surface (endpoints, JS files, source maps, robots/sitemap, authenticated areas). This skill orchestrates the spider tool plus CDP browser for full coverage. NO probing, NO testing — only mapping what EXISTS through tool-driven extraction. Outputs structured sitemap.json that downstream phases consume.
---

# Recon Skill — Phase 1 Spidering

## What This Skill Is

Phase 1 is **mechanical attack surface discovery**. You orchestrate tools that extract endpoints, JS files, source maps, and structural information. You do NOT probe, you do NOT test, you do NOT reason about vulnerabilities yet.

The goal: produce `engagement/spider/sitemap.json` containing every URL, endpoint, and parameter the application exposes.

## Critical Principle

**Tool-driven, not agent-driven.** The spider tool does the curl crawling. The CDP browser provides authenticated context. You invoke them and verify outputs. You do NOT crawl manually with curl in this phase — that's what the tools are for.

If you find yourself running 20+ curl commands, you're doing it wrong. Run the tool.

---

## The Tools You Use

### 1. `tools/spider/spider.sh` — Master Spider

This bash script does the heavy lifting. It crawls pages, extracts URLs from HTML, parses JS for endpoints, checks for source maps, processes robots.txt and sitemap.xml. Output: `engagement/spider/<auth|unauth>/sitemap.json`.

### 2. `tools/cdp_browser.py` — Chrome DevTools Bridge

This Python script connects to your manually-logged-in Chrome session via CDP. Lets you extract cookies, capture network traffic while you click, run authenticated recon on JS-heavy SPAs.

### 3. `tools/spider/spider_comprehension.sh` — Deep App Comprehension

Companion to spider.sh. Recovers source maps, enumerates webpack chunks, probes /.well-known/, finds API specs, extracts CSP trust map, lists wayback history.

### 4. `tools/path_fuzzer.sh` — Hidden Path Discovery

Discovers endpoints NOT linked from HTML/JS — admin panels, debug endpoints, legacy APIs, backup files, VCS exposure, internal tools. Uses curated wordlists + application-aware mutations based on spider output. Output: `engagement/spider/fuzz/hidden_endpoints.json`.

```bash
./tools/path_fuzzer.sh "https://target.com" \
    --spider-dir engagement/spider/unauth \
    --header "X-HackerOne-Handle: username" \
    --output-dir engagement/spider/fuzz \
    --rate-limit 5
```

This tool is what separates frameworks that find 2 bugs from frameworks that find 20. Most critical endpoints are NOT linked from the main application.

### 5. `tools/waf_detect.sh` — WAF/Security Layer Fingerprinting

Identifies WAF, CDN, rate limiting, and security layers. Tests which characters/payloads are blocked, identifies bypass opportunities. Output: `engagement/spider/waf/waf_fingerprint.json`.

```bash
./tools/waf_detect.sh "https://target.com" \
    --header "X-HackerOne-Handle: username" \
    --output-dir engagement/spider/waf
```

The bypass techniques this tool discovers are used by every Phase 3 testing task. Knowing which WAF bypass works BEFORE sending payloads saves massive time.

### 6. `tools/param_discover.sh` — Hidden Parameter Discovery

Discovers parameters that endpoints accept but don't advertise in HTML/JS. Tests both query parameters and JSON body fields. Output: `engagement/spider/params/`.

```bash
./tools/param_discover.sh "https://target.com" \
    --endpoint "/api/users/profile" \
    --auth-cookie "$(cat engagement/spider/cookies_a.txt)" \
    --header "X-HackerOne-Handle: username" \
    --method POST
```

Run this on the top 10 most interesting endpoints after mapping identifies them. Hidden parameters are the source of mass assignment, privilege escalation, and hidden functionality bugs.

---

## Execution Sequence

### Step 1: Unauthenticated Spider

Always start unauthenticated. This maps the public attack surface.

```bash
./tools/spider/spider.sh "<target>" \
    --header "<required header>" \
    --output-dir engagement/spider/unauth
```

Expected output: `engagement/spider/unauth/sitemap.json`

### Step 2: Extract Auth Session

If credentials are available (manually logged into Chrome at port 9222):

```bash
python3 ./tools/cdp_browser.py extract-cookies \
    --port 9222 --output engagement/spider/cookies_a.txt --format header
```

Verify the cookies work:
```bash
curl -s -i -H "Cookie: $(cat engagement/spider/cookies_a.txt)" \
    -H "<required header>" \
    https://target.com/api/me  # or any authenticated endpoint
# Should return 200, not 401
```

### Step 3: Authenticated Spider

Re-run the spider with the auth cookie. This reveals authenticated-only endpoints.

```bash
COOKIE=$(cat engagement/spider/cookies_a.txt)
./tools/spider/spider.sh "<target>" \
    --auth-cookie "$COOKIE" \
    --header "<required header>" \
    --output-dir engagement/spider/auth
```

Expected output: `engagement/spider/auth/sitemap.json`

### Step 4: CDP-Based Authenticated Recon

For SPAs and complex applications, use CDP to navigate through the app while capturing the real API calls the frontend makes:

```bash
python3 ./tools/cdp_browser.py auth-recon \
    --port 9222 \
    --base-url "https://target.com" \
    --max-pages 30 \
    --output-dir engagement/spider/cdp_recon
```

The CDP recon will:
- Navigate the browser to discover pages
- Capture every network request the application makes
- Extract forms with their exact field structures
- List localStorage/sessionStorage keys (don't expose values)
- Identify JS-rendered links

### Step 5: Sourcemap Deep Analysis (if available)

The spider already checks for `.map` files. If any were found (`sourcemap_available: true` in the sitemap), they expose ORIGINAL source code. This is gold:

```bash
# Check what source maps were found
jq '.javascript_files[] | select(.sourcemap_available == true)' \
    engagement/spider/auth/sitemap.json

# For each one with source files, extract the file paths
for sm in engagement/spider/auth/raw/sm_*.map; do
    [ -s "$sm" ] || continue
    python3 -c "
import json
try:
    d = json.load(open('$sm'))
    print('=== $sm ===')
    for src in d.get('sources', [])[:50]:  # First 50 sources
        print(src)
except: pass
"
done > engagement/spider/auth/sourcemap_sources.txt
```

Look for file paths like:
- `webpack:///src/api/users.ts` — reveals internal module structure
- `webpack:///src/admin/...` — admin endpoints to investigate
- `webpack:///./node_modules/...` — third-party dependencies

These tell you the application architecture, which directly informs hypothesis generation.

### Step 6: Subdomain Enumeration (Open Scope Only)

If the target program has open scope (rewards any owned asset), enumerate subdomains. Otherwise SKIP this — out-of-scope subdomains waste time.

```bash
# Use a passive technique - no scanning
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
    python3 -c "import json, sys; data=json.load(sys.stdin); 
    print('\n'.join(set(d['name_value'] for d in data)))" | \
    sort -u > engagement/spider/subdomains.txt

# Verify which are live
while read sub; do
    [ -z "$sub" ] && continue
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$sub")
    [ "$status" != "000" ] && echo "$status $sub"
done < engagement/spider/subdomains.txt > engagement/spider/subdomains_live.txt
```

For each LIVE subdomain in scope, run spider on it too.

### Step 7: Source Code Discovery

For any GitHub repos in scope, clone them and audit:

```bash
mkdir -p engagement/spider/source/
for repo in <repo-list>; do
    git clone "$repo" "engagement/spider/source/$(basename $repo)"
done

# Search for hardcoded secrets (TYPE patterns, no values)
for dir in engagement/spider/source/*/; do
    grep -rE "(API_KEY|SECRET|TOKEN|PASSWORD).*=.*['\"][A-Za-z0-9]{20,}" "$dir" \
        2>/dev/null | head -50 >> engagement/spider/source/secret_patterns.txt
done
```

### Step 8: Deep Application Comprehension (MANDATORY before Phase 2)

This is the step that converts "we found endpoints" into "we understand the application." Without this step, Phase 2 mapping produces technically-correct findings with no business impact — the failure mode the framework was designed to eliminate.

Run the comprehension companion tool against the authenticated spider output:

```bash
./tools/spider/spider_comprehension.sh engagement/spider/auth \
    --target "https://target.com" \
    --auth-cookie "$(cat engagement/spider/cookies_a.txt)" \
    --header "<required header>"
```

This produces `engagement/spider/auth/understanding/` containing:

| Output | What It Gives the Agent |
|--------|--------------------------|
| `sources/` | Original .ts/.tsx/.js source files reconstructed from .map — read these to understand routes, role names, internal endpoint paths, business logic |
| `webpack_chunks/` | Lazy-loaded chunks not referenced in the entry bundle — often contain admin/internal-only features |
| `well_known/sw*.js` | Service workers, which usually contain the application's full API route table |
| `well_known/openid-configuration` | OAuth metadata: authorization endpoint, token endpoint, supported redirect_uris — direct chain construction input |
| `api_specs/swagger.json`, `openapi.json` | Full endpoint catalog with auth requirements — if found, this is the highest-value recon output |
| `api_specs/graphql_introspection.json` | Full GraphQL schema if introspection enabled — exposes mutations REST surface hides |
| `trust_map/csp_trusted_hosts.txt` | Third-party trust map — every domain in CSP is a potential chain amplifier if taken over |
| `wayback/historical_interesting.txt` | Removed/renamed endpoints from archive.org — often still reachable |
| `understanding.json` | Summary index with agent reading priority |

**Reading the understanding/ folder is NOT optional during Phase 2.** When the mapping worker reads an endpoint's profile, it cross-references with `understanding/sources/` to understand which feature uses the endpoint. When the Lead runs M9 chain synthesis, it consults `trust_map/csp_trusted_hosts.txt` for amplifier candidates and `api_specs/` for hidden mutations.

**Time budget:** comprehension takes 5-15 minutes depending on how much source the .map files expose. This is time that pays back at 10x in Phase 2 — every minute saved here costs an hour of "no impact" rejections later.

### Step 9: Hidden Path Discovery (MANDATORY)

The spider only finds linked content. Most interesting endpoints are NOT linked. Run the path fuzzer to discover hidden admin panels, debug endpoints, VCS exposure, backup files, and legacy APIs.

```bash
# Unauthenticated path fuzzing
./tools/path_fuzzer.sh "<target>" \
    --spider-dir engagement/spider/unauth \
    --header "<required header>" \
    --output-dir engagement/spider/fuzz \
    --rate-limit 5

# Authenticated path fuzzing (finds auth-gated hidden endpoints)
COOKIE=$(cat engagement/spider/cookies_a.txt)
./tools/path_fuzzer.sh "<target>" \
    --spider-dir engagement/spider/auth \
    --auth-cookie "$COOKIE" \
    --header "<required header>" \
    --output-dir engagement/spider/fuzz_auth \
    --rate-limit 5
```

Expected output: `engagement/spider/fuzz/hidden_endpoints.json` with categorized hidden endpoints. Hidden admin panels and debug endpoints are often the highest-value mapping targets.

### Step 10: WAF/Security Layer Fingerprinting (MANDATORY)

Before any Phase 3 testing begins, you MUST know what defense layer protects the target and which bypass techniques work.

```bash
./tools/waf_detect.sh "<target>" \
    --header "<required header>" \
    --output-dir engagement/spider/waf
```

Expected output: `engagement/spider/waf/waf_fingerprint.json` with WAF name, blocked payloads, working bypass techniques, rate limiting info. This information goes into every Phase 3 testing task.

### Step 11: Parameter Discovery (Post-Mapping, Top Endpoints)

Run AFTER Phase 2 mapping identifies the most interesting endpoints. Tests the top 10 high-value endpoints for hidden parameters they accept but don't advertise.

```bash
# Run on each high-value endpoint (POST/PUT endpoints are most interesting)
./tools/param_discover.sh "<target>" \
    --endpoint "/api/account/profile" \
    --auth-cookie "$(cat engagement/spider/cookies_a.txt)" \
    --header "<required header>" \
    --method POST

./tools/param_discover.sh "<target>" \
    --endpoint "/api/admin/users" \
    --auth-cookie "$(cat engagement/spider/cookies_a.txt)" \
    --header "<required header>" \
    --method POST
```

Expected output: `engagement/spider/params/params_<endpoint>.json` with discovered hidden parameters. Reflected parameters and those that change the response are direct testing candidates for mass assignment and privilege escalation.

---

## Output: The Sitemap

After Phase 1, you have:

```
engagement/spider/
├── unauth/
│   ├── sitemap.json          ← unauthenticated attack surface
│   ├── raw/                  ← raw tool outputs (debugging)
│   └── understanding/        ← deep application comprehension (Step 8 output)
│       ├── understanding.json     ← summary index
│       ├── sources/               ← reconstructed source files from .map
│       ├── webpack_chunks/        ← lazy-loaded chunks
│       ├── well_known/            ← /.well-known/* + service workers
│       ├── api_specs/             ← swagger/openapi/graphql introspection
│       ├── trust_map/             ← CSP trusted hosts (third-party amplifiers)
│       └── wayback/               ← archive.org historical endpoints
├── auth/
│   ├── sitemap.json          ← authenticated attack surface (richer)
│   ├── raw/
│   ├── sourcemap_sources.txt ← original source paths from .map files
│   └── understanding/        ← deep application comprehension (Step 8 output)
├── fuzz/
│   └── hidden_endpoints.json ← hidden paths from path_fuzzer.sh (Step 9)
├── fuzz_auth/
│   └── hidden_endpoints.json ← auth-gated hidden paths (Step 9)
├── waf/
│   └── waf_fingerprint.json  ← WAF fingerprint + bypass techniques (Step 10)
├── params/
│   └── params_<endpoint>.json ← hidden parameter discovery (Step 11)
├── cdp_recon/
│   └── auth_recon.json       ← CDP-captured network/forms/storage
├── cookies_a.txt             ← Session A cookies for downstream phases
├── cookies_b.txt             ← Session B cookies for IDOR testing
├── subdomains.txt            ← All discovered subdomains
└── subdomains_live.txt       ← Live subdomains (for additional spidering)
```

The Lead reads these files to prioritize endpoints for Phase 2 mapping. The `understanding/` folder is consumed by both Phase 2 mapping (M2.5 business-context analysis) and M9 chain synthesis.

---

## What the Spider Catches vs. Doesn't

### Catches Well
✅ HTML-linked pages (href, src, action)
✅ JavaScript-embedded API URLs (string patterns)
✅ robots.txt entries
✅ sitemap.xml URLs
✅ Forms with their action endpoints
✅ Source maps with original file paths
✅ Common secret patterns in JS (types only)

### Doesn't Catch (Need CDP for)
❌ Endpoints only triggered by SPA UI interactions
❌ WebSocket connections
❌ Endpoints loaded only after specific user actions
❌ Form payload structures (just the action URL)
❌ Authentication flows that involve multiple redirects
❌ Dynamic API endpoints constructed at runtime

For these, use CDP `auth-recon` which captures the actual network traffic.

### Doesn't Catch (Need Manual Review for)
❌ Endpoints in unminified/unreferenced JS files
❌ Internal hostnames mentioned in comments
❌ Hidden form fields revealing API structure
❌ GraphQL schema (need introspection separately)

For these, the agent (Lead) reviews the sitemap and decides if specific files warrant deeper inspection.

---

## Critical Rules

### Things You DO
- Run the spider tool with proper arguments
- Extract cookies from CDP for authenticated context
- Re-spider with auth to expand surface
- Use CDP auth-recon for SPAs
- Check for source maps and extract paths
- Enumerate subdomains ONLY in open-scope programs

### Things You DO NOT Do
- ❌ Run probes (no `'`, no `{{7*7}}`, no `../`, no payloads) — except via waf_detect.sh which tests payloads safely
- ❌ Manually curl through pages (use the spider tool)
- ❌ Run external vulnerability scanners (no nikto, no nuclei, no sqlmap)
- ❌ Run external path bruteforce tools (use `path_fuzzer.sh` instead)
- ❌ Analyze findings or generate hypotheses (Phase 2 job)
- ❌ Test cross-account access (Phase 3 job)
- ❌ Spider out-of-scope domains

### Time Discipline

Phase 1 spidering should complete in 30-90 minutes for most targets. If you're spending hours, you're doing the wrong thing.

The spider tool runs in ~5-15 minutes typically. Most of the time is the tool's own work, not your active execution.

---

## Common Issues and Solutions

### Issue: Spider returns very few endpoints

**Cause:** Target is a SPA that hides content behind JS rendering.

**Solution:** Run CDP `auth-recon` to capture actual API calls the frontend makes:
```bash
python3 ./tools/cdp_browser.py auth-recon --port 9222 \
    --base-url "https://target.com" --max-pages 30 \
    --output-dir engagement/spider/cdp_recon
```

### Issue: Auth cookies don't work in curl

**Cause:** Cookie format mismatch or missing required headers.

**Solution:**
1. Check cookie file format: `cat engagement/spider/cookies_a.txt`
2. Should be header format: `name1=value1; name2=value2`
3. Verify the required X-HackerOne-Handle header is included
4. Test with verbose curl:
   ```bash
   curl -v -H "Cookie: $(cat engagement/spider/cookies_a.txt)" \
        -H "X-HackerOne-Handle: username" \
        https://target.com/api/me
   ```

### Issue: WAF blocks spider tool

**Cause:** Cloudflare or similar WAF detecting automated tool patterns.

**Solution:**
- Reduce spider rate (modify the tool's curl args to add `--limit-rate`)
- Spider produces enough results before WAF kicks in for most targets
- Switch to CDP `auth-recon` (uses your browser context, less likely to be blocked)

### Issue: Found a `.git` directory exposed

**Cause:** Misconfigured deployment leaving `.git` accessible.

**Solution:** This is a finding by itself. Note it in the sitemap's `interesting_paths`. Lead decides whether to dispatch a task to extract the git history. Don't extract it yourself in Phase 1.

---

## Hand-off to Phase 2

When Phase 1 completes, write the result file confirming:
- Sitemaps created (path + endpoint count for each)
- Source maps found (count)
- Subdomains discovered (count for open-scope programs)
- Any interesting paths flagged

The Lead will:
1. Read both sitemaps (merge auth + unauth views)
2. Prioritize endpoints by likely value
3. Dispatch Phase 2 mapping tasks in batches of 3-5 endpoints

You don't decide what to map next. You just report what the spider found.
