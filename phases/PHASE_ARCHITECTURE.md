# Phase-Based Architecture — Framework Workflow

This document defines the complete workflow of the bug bounty framework. Every engagement follows this 7-phase sequence with disciplined boundaries between phases.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│  Phase 0: RECON (Tool-driven, infrastructure enumeration)            │
│    └─→ Subdomains, ports, tech stack, cloud, email security          │
│        Output: engagement/recon/recon.json                             │
│                                                                       │
│  Phase 1: SPIDERING (Tool-driven, no agent reasoning)                │
│    └─→ Extracts: URLs, APIs, JS files, source maps, sitemap          │
│        Output: engagement/spider/sitemap.json                         │
│                                                                       │
│  Phase 2: MAPPING (Agent + Skill, surgical probing)                  │
│    └─→ Per-endpoint analysis: baseline, params, auth, signals        │
│        Output: engagement/mapping/<endpoint>.profile.yaml             │
│                                                                       │
│  Phase 3: TESTING (Worker dispatches based on profiles)              │
│    └─→ Hypothesis-driven vulnerability testing                       │
│        Output: engagement/findings/<finding>.confirmed.md             │
│                                                                       │
│  Phase 4: VALIDATING (Re-confirm with clean PoCs)                    │
│    └─→ Reproduce findings, gather report evidence, check chains      │
│        Output: engagement/findings/<finding>.validated.md             │
│                                                                       │
│  Phase 5: REPORTING (Lead-only, no Worker)                           │
│    └─→ Professional reports with full impact analysis                 │
│        Output: engagement/reports/<finding>.report.md                 │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Core Principles

### 1. Phase Discipline With Smart Overlap

Phases run in order BUT testing can dispatch per-endpoint as soon as mapping for THAT endpoint completes. The Lead does NOT wait for ALL endpoints to finish mapping before starting testing on already-mapped ones.

**What this prevents:**
- Spidering tools running probes (token waste, false signals)
- Mapping agent guessing at vulnerabilities (that's testing's job)
- Testing without baseline context (causes false positives)
- Reporting findings that haven't been re-validated

**What this enables:**
- Maximum parallelism within our 2-agent constraint
- Lead can analyze mapping output cross-endpoint to spot chains
- Worker tasks are surgical because mapping provides full context

### 2. Tool-First for Mechanical Work

Anything that's "extract X from Y" should be a TOOL, not an agent task. Tools produce structured JSON output the agent reads. This saves massive tokens because the agent doesn't see raw curl output, raw HTML, or thousands of URLs.

| Mechanical Work | Tool Used |
|----------------|-----------|
| Crawl + extract endpoints | `tools/spider/spider.sh` |
| Deep app comprehension | `tools/spider/spider_comprehension.sh` |
| Hidden path discovery | `tools/path_fuzzer.sh` |
| Parameter discovery | `tools/param_discover.sh` |
| WAF/security fingerprinting | `tools/waf_detect.sh` |
| Authenticated browser recon | `tools/cdp_browser.py` |

The agent reads ONE clean JSON output per phase, not thousands of lines of tool stdout.

### 3. Agent-First for Reasoning Work

Anything that requires JUDGMENT stays with the agent:
- Should I probe this parameter with `'` or `{{7*7}}`? (mapping)
- Is this a real SQL injection or just a different error response? (testing)
- Can this IDOR be chained with the info disclosure for higher impact? (testing/validating)
- What's the business impact of this finding? (reporting)

### 4. File-Based Communication

Lead writes → Worker reads → Worker writes → Lead reads. No sockets, no APIs, no databases. Just files in shared directories. This is what makes two-CLI architecture work.

---

## Phase 0: INFRASTRUCTURE RECONNAISSANCE

### Purpose
Discover the ENTIRE organizational attack surface before touching the web application. Enumerate subdomains, open ports, technology stacks, cloud infrastructure, and email security — the assets the organization owns but may have forgotten about.

60% of critical bugs are on subdomains the spider would never find. Staging/dev environments have weaker security. Cloud buckets exposed by subdomain enumeration are instant bounties.

### Who Does It
- **Worker agent** invokes the recon tools
- Tools do the actual work (subfinder, puredns, naabu, nmap, httpx, cloud_enum)
- Worker produces ONE consolidated `recon.json` output
- **Lead reads only the summary**, not raw tool output

### Inputs
- `target_prompt.md` — scope domain
- `state.json` — engagement context

### Outputs
- `engagement/recon/recon.json` — unified reconnaissance summary
- `engagement/recon/subdomains/` — subdomain enumeration (subdomains.json, alive_hosts.txt, takeover_vulns.txt)
- `engagement/recon/ports/` — port scanning (open_ports.json, services.json, vulnerabilities.json)
- `engagement/recon/tech/` — technology detection (tech_stack.json, cdn_waf.json, api_frameworks.json)
- `engagement/recon/cloud/` — cloud enumeration (cloud_buckets.json, k8s_endpoints.json, cloud_services.json, email_security.json)

### Recon Tool Pipeline (4 tools, sequential)

| # | Tool | Output | What It Finds |
|---|------|--------|---------------|
| 1 | `subdomain_enum.sh` | subdomains.json | Passive + active + permutation subdomain discovery, live host verification, takeover detection |
| 2 | `port_scan.sh` | open_ports.json | Open port discovery (naabu + nmap), service fingerprinting, NSE vulnerability scanning |
| 3 | `tech_detect.sh` | tech_stack.json | Technology fingerprinting (httpx + wappalyzer), CMS detection, CDN/WAF detection, API framework detection |
| 4 | `cloud_enum.sh` | cloud_buckets.json | S3/GCP/Azure bucket enumeration, Kubernetes endpoint discovery, Firebase/Supabase checks, email security (SPF/DMARC/DKIM) |
| 5 | `master_recon.sh` | recon.json | Orchestrator — runs all 4 tools and produces unified recon.json with attack surface insights |

### Recon Rules
- NO active probing of web applications (Phase 1+ does that)
- All enumeration is passive or infrastructure-level
- No cookies, no sessions, no authentication needed
- Tools gracefully degrade if external binaries aren't installed (Python/curl fallbacks)
- Email security is checked passively via DNS records
- Cloud bucket checks perform minimal HTTP requests (rate-limited)

### Recon Completes When
- subdomains.json is written with resolved and live hosts
- open_ports.json and services.json exist (may be empty if no open ports)
- tech_stack.json fingerprints all live hosts
- cloud enumeration completes (buckets, K8s, email)
- recon.json unified summary is generated with attack_surface_insights
- Any CRITICAL recon findings (public S3, takeover candidates, exposed K8s) are flagged for immediate action

---

## Phase 1: SPIDERING

### Purpose
Discover the EXISTING attack surface mechanically. No probing, no reasoning, no exploitation. Just enumeration of what the application exposes.

### Who Does It
- **Worker agent** invokes the spider tools
- Tools do the actual work (curl, gau, JS parsing)
- Worker produces ONE consolidated JSON output

### Inputs
- `target_prompt.md` — scope, credentials, headers
- `state.json` — engagement context

### Outputs
- `engagement/spider/sitemap.json` — consolidated attack surface
- `engagement/spider/<auth|unauth>/understanding/` — deep app comprehension
- `engagement/spider/fuzz/hidden_endpoints.json` — hidden paths from `path_fuzzer.sh`
- `engagement/spider/waf/waf_fingerprint.json` — WAF/security layer fingerprint
- `engagement/spider/params/` — hidden parameter discovery results
- `engagement/spider/raw/` — raw tool outputs (for debugging only)

### Sitemap Structure (Critical Format)

```json
{
  "meta": {
    "target": "target.com",
    "scanned_at": "2026-05-13T10:00:00Z",
    "auth_status": "authenticated|unauthenticated|both"
  },
  "subdomains": [
    {
      "host": "api.target.com",
      "live": true,
      "tech": ["nginx", "node.js"]
    }
  ],
  "endpoints": [
    {
      "id": "EP-001",
      "url": "https://api.target.com/users/{id}",
      "methods_observed": ["GET", "PUT", "DELETE"],
      "params": {
        "path": ["id"],
        "query": ["fields", "expand"],
        "body": [],
        "headers": ["Authorization"]
      },
      "discovered_from": ["main.abc.js:line 42", "robots.txt"],
      "auth_required": "unknown",
      "content_type": "application/json"
    }
  ],
  "javascript_files": [
    {
      "url": "/static/main.abc123.js",
      "size_bytes": 487231,
      "sourcemap_available": true,
      "sourcemap_url": "/static/main.abc123.js.map",
      "endpoints_extracted": 47,
      "internal_routes_found": ["/admin/*", "/api/internal/*"]
    }
  ],
  "secrets_detected_types": ["api_key_pattern", "internal_hostname"],
  "interesting_paths": ["/admin", "/swagger", "/.git"]
}
```

**Note:** Secrets in JS files are reported by TYPE only (e.g., "api_key_pattern"), NEVER the actual values. The Lead reviews types and decides if Worker should fetch specific files for analysis.

### Spidering Rules
- NO active probing (no `'`, no `{{7*7}}`, no `../../`)
- NO external scanners (no nikto, no nuclei, no sqlmap in spidering)
- `spider.sh` discovers linked paths ONLY (links, JS, robots.txt, sitemap.xml)
- `path_fuzzer.sh` discovers HIDDEN paths NOT linked anywhere (admin panels, debug, backups, VCS exposure)
- `waf_detect.sh` fingerprints the security layer so Phase 3 knows what bypasses work
- `param_discover.sh` finds hidden parameters endpoints accept but don't advertise
- Use authenticated sessions if available to expose more surface
- Stop when no new endpoints found for 2 consecutive crawl iterations

### Spidering Completes When
- Sitemap.json is written (spider.sh)
- Comprehension outputs exist (spider_comprehension.sh)
- Hidden endpoints fuzzed (path_fuzzer.sh)
- WAF/security layer fingerprinted (waf_detect.sh)
- Parameter discovery run on high-value endpoints (param_discover.sh)
- All discovered JS files have been analyzed for endpoints
- All source maps have been checked and parsed

---

## Phase 2: MAPPING

### Purpose
For EACH endpoint, build a "profile" containing baseline behavior, parameter classification, authentication requirements, and signal detection. The mapping phase produces the INTELLIGENCE that testing uses.

### Who Does It
- **Worker agent** with `skills/mapping/SKILL.md` loaded
- One mapping task per endpoint (or small endpoint group)
- Lead dispatches mapping tasks based on spider output

### Inputs
- `engagement/spider/sitemap.json` — the attack surface
- `engagement/spider/fuzz/hidden_endpoints.json` — hidden paths from path fuzzer
- `engagement/spider/waf/waf_fingerprint.json` — WAF bypass info
- `engagement/spider/params/` — hidden parameter discovery results
- `engagement/spider/<auth|unauth>/understanding/` — deep app comprehension
- `state.json` — credentials, session info
- Endpoint(s) to map (from Lead's task)

### Outputs
- `engagement/mapping/<endpoint-id>.profile.yaml` — one profile per endpoint
- Updated `state.json` with mapping progress

### Endpoint Profile Structure (Critical Format)

```yaml
endpoint_id: EP-001
url: /api/users/{id}
methods: [GET, PUT, DELETE]

baseline:
  valid_authenticated:
    status: 200
    size_bytes: 1247
    response_summary: "Returns user object with email, name, role"
  valid_unauthenticated:
    status: 401
    size_bytes: 87
    response_summary: "Unauthorized error"
  invalid_id:
    status: 404
    size_bytes: 56
    response_summary: "Not found"

parameters:
  - name: id
    location: path
    type: integer
    pattern: sequential  # sequential | uuid | hash | random
    db_classification: DB_LOOKUP  # DB_LOOKUP | DB_WRITE | DB_AUTH | API_PASSTHROUGH | CLIENT_ONLY | UNKNOWN
    echoes_in_response: false
    
  - name: fields
    location: query
    type: string
    pattern: enum
    db_classification: CLIENT_ONLY
    echoes_in_response: yes_html_body

auth_analysis:
  endpoint_enforces_auth: yes
  auth_mechanism: JSESSIONID_cookie
  unauth_response: 401
  unauth_leaks_data: false

signals_detected:
  - signal: "sequential_integer_id"
    confidence: HIGH
    implies: IDOR_candidate
    evidence: "id=5, id=6 visible in user-facing pages"
    
  - signal: "PII_in_response"
    confidence: HIGH
    implies: impact_multiplier
    evidence: "Response contains email, phone, full_name"

passive_findings:
  - finding: "Cache-Control missing on PII response"
    severity: low
  - finding: "No rate limiting headers observed"
    severity: info

hypotheses_generated:
  - id: HYP-001
    type: IDOR
    target_param: id (path)
    confidence: HIGH
    rationale: "Sequential integer ID + PII response = classic IDOR"
    suggested_skill: skills/idor
    
  - id: HYP-002
    type: SQLi
    target_param: id (path)
    confidence: LOW
    rationale: "DB_LOOKUP with integer param - parameterized queries possible but verify"
    suggested_skill: skills/sqli

cross_endpoint_signals:
  related_endpoints: ["EP-005", "EP-012"]
  potential_chains: ["Info disclosure in EP-012 leaks user_id - chain into IDOR here"]
```

### Mapping Rules
- Use ONLY harmless markers and probes (per `skills/mapping/SKILL.md`)
- NEVER change identifier values to test IDOR (that's testing's job)
- Baseline EVERY endpoint before probing
- Classify EVERY parameter (DB_LOOKUP / DB_WRITE / etc.)
- Generate hypotheses with confidence levels
- Look for cross-endpoint signals (info from one endpoint helping another)

### Mapping Completes When
- Every in-scope endpoint has a profile
- Every parameter has a DB classification
- Every signal has a hypothesis with confidence level
- Cross-endpoint chain opportunities are noted

---

## Phase 3: TESTING

### Purpose
Execute hypothesis-driven vulnerability testing. Each test confirms or denies one specific hypothesis from the mapping profiles.

### Who Does It
- **Worker agent** with one vulnerability skill loaded
- One test task per hypothesis
- Lead dispatches based on mapping profiles, prioritized by confidence

### Inputs
- ONE specific hypothesis from mapping
- The relevant skill file (e.g., `skills/idor/SKILL.md`)
- The endpoint profile from mapping
- Credentials and context

### Outputs
- `engagement/findings/<hypothesis-id>.<status>.md`
  - Status can be: `confirmed` | `negative` | `partial`
- Updated `state.json`

### Testing Dispatch Order (Lead's Strategy)

The Lead dispatches testing in this priority order:

1. **HIGH confidence hypotheses with HIGH impact** (PII, financial, auth bypass)
2. **HIGH confidence hypotheses with MEDIUM impact**
3. **Cross-endpoint chain candidates** (test the leak first, then the consumer)
4. **MEDIUM confidence hypotheses**
5. **LOW confidence hypotheses** (do these last, often negative)

### Testing Rules
- Worker tests ONE hypothesis at a time
- Worker reads ONLY the assigned skill file (not all skills)
- Baseline ALWAYS comes from mapping profile (don't re-baseline)
- If new signals emerge during testing, report them but don't pursue (Lead decides)
- Stop at first confirmed HIGH impact — don't extend exploitation

### Testing Completes When
- All HIGH confidence hypotheses have been tested
- All MEDIUM confidence hypotheses have been tested
- All cross-endpoint chains have been verified
- LOW confidence hypotheses are tested OR explicitly deferred

---

## Phase 4: VALIDATING

### Purpose
Re-confirm findings with clean reproducible PoCs. Gather report-ready evidence. Verify findings haven't been impacted by application state changes. Check final chain potential.

### Who Does It
- **Worker agent** (no skill file needed — works from finding markdown)
- One validation per confirmed finding
- Lead dispatches after testing produces confirmed findings

### Inputs
- A confirmed finding from `engagement/findings/<id>.confirmed.md`
- Fresh credentials/session (verify they still work)

### Outputs
- `engagement/findings/<id>.validated.md` with:
  - Clean reproduction steps (numbered, exact)
  - Exact request/response pairs
  - Evidence redacted of any real user data
  - Impact analysis (what an attacker could actually do)
  - Chain check (does this enable other findings?)
  - CVSS calculation

### Validation Rules
- Use FRESH session (don't reuse the testing session)
- Reproduce from scratch following only the documented steps
- If reproduction fails, mark as `validation_failed` (don't fix the finding)
- Capture exact request/response bytes
- Redact any real user data encountered (replace with `[REDACTED]`)
- Calculate CVSS v3.1 score

### Validation Completes When
- Every confirmed finding is independently reproducible
- All evidence is captured and redacted
- Impact and chains are documented

---

## Phase 5: REPORTING

### Purpose
Generate professional bug bounty reports ready for submission. Triage teams should be able to reproduce findings from the report alone.

### Who Does It
- **Lead agent ONLY** (no Worker)
- Lead has holistic context across all findings
- Lead can spot chains and decide on grouping

### Inputs
- All `engagement/findings/<id>.validated.md` files
- `skills/report-writing/SKILL.md`
- Target program requirements (header format, etc.)

### Outputs
- `engagement/reports/<finding>.report.md` — one report per finding
- Optionally `engagement/reports/chain-<id>.report.md` — for chained findings

### Reporting Rules
- One finding per report (unless chained)
- Follow the target program's report format
- Include CVSS score with vector string
- Include exact reproduction steps
- Include screenshots/PoC files referenced from `engagement/findings/<id>/poc/`
- Maximize demonstrated impact (without exceeding ethical limits)

### Reporting Completes When
- Every validated finding has a report
- Chains are reported as combined findings
- Reports are ready for HackerOne/Bugcrowd submission

---

## How Phases Interact (The Smart Overlap)

The Lead orchestrates these phases with this rule:

> **"Move to the next phase for an item AS SOON AS that item is ready, even if other items are still in earlier phases."**

Example timeline:
```
T+00min  Spider tool runs → sitemap.json with 30 endpoints
T+05min  Lead dispatches mapping task for endpoints 1-5
T+15min  Worker returns profiles for endpoints 1-5
T+15min  Lead dispatches mapping task for endpoints 6-10
T+15min  Lead simultaneously dispatches testing on EP-3 (HIGH confidence IDOR found)
T+25min  Worker returns profiles for 6-10 + Worker returns IDOR confirmed on EP-3
T+25min  Lead dispatches validation on EP-3 confirmed finding
T+25min  Lead dispatches mapping for endpoints 11-15
... and so on
```

**But here's the constraint with 2 agents:** Only ONE worker task at a time. So in practice, you alternate. Lead can have testing tasks queued for one worker session while another worker session is doing mapping.

This is why the Lead is the BRAIN — it maintains the queue, prioritizes, and ensures the worker always has the highest-value task waiting.

---

## State Tracking Across Phases

`state.json` is updated by the Lead after every Worker result:

```json
{
  "engagement": {
    "program": "...",
    "started": "...",
    "current_phase_emphasis": "mapping"
  },
  "spider": {
    "status": "complete",
    "sitemap_path": "engagement/spider/sitemap.json",
    "endpoints_total": 87
  },
  "mapping": {
    "status": "in_progress",
    "endpoints_mapped": 23,
    "endpoints_pending": ["EP-024", "EP-025", "EP-026"],
    "endpoints_total": 87
  },
  "testing": {
    "status": "in_progress",
    "hypotheses_total": 45,
    "hypotheses_tested": 12,
    "hypotheses_confirmed": 3,
    "hypotheses_negative": 9,
    "high_priority_pending": ["HYP-018", "HYP-021"]
  },
  "validating": {
    "status": "in_progress",
    "validated": 1,
    "pending": ["FIND-001", "FIND-002"]
  },
  "reporting": {
    "status": "not_started",
    "reports_written": 0
  },
  "findings": [
    {
      "id": "FIND-001",
      "type": "IDOR",
      "endpoint": "/api/users/{id}",
      "severity": "High",
      "status": "validated",
      "chain_potential": ["info disclosure in EP-012 leaks IDs"]
    }
  ],
  "chains_identified": [
    {
      "chain_id": "CHAIN-001",
      "components": ["FIND-002 (info disclosure)", "FIND-001 (IDOR)"],
      "combined_impact": "Critical",
      "report_as": "single_chained_finding"
    }
  ]
}
```

---

## Why This Architecture Beats the Old One

| Aspect | Old (Single Recon Phase) | New (5-Phase) |
|--------|-------------------------|--------------|
| Token usage in recon | Agent crawls manually (~5K lines) | Tool produces JSON (~200 lines for agent) |
| Mapping quality | Mixed with recon, often skipped | Dedicated phase with per-endpoint profiles |
| Testing precision | Agent decides what to test mid-stream | Lead dispatches surgical tasks based on profiles |
| Chain detection | Often missed | Lead's job during phase 3-4 transition |
| Report quality | Generated from memory | Generated from validated evidence files |
| Resume capability | Hard to know where to pick up | state.json shows exact phase + pending items |

---

## The Operator's Mental Model

When you sit down to hunt:
```
1. You start ONE opencode session
2. Lead (primary agent) reads target_prompt.md, state.json, decides what phase to work on
3. Lead writes a task file and spawns a Worker subagent via /worker
4. Worker executes the task, writes result, returns to Lead
5. Lead reads result, updates state, spawns next Worker
6. Repeat until reporting phase completes
```

You supervise. Lead handles coordination. Worker subagents are spawned automatically. The phases ensure work is done in the right order with the right context.
