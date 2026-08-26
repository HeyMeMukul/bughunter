# Quick Start — Framework v4.0.0 (The GOATED Framework)

## 60-Second Version

1. `./setup.sh "https://target.com" "program-name"` — initializes engagement, launches Chrome
2. Manually log in to both Chrome windows (ports 9222, 9223)
3. Start ONE opencode session (Lead = DeepSeek V4 Pro) — it auto-spawns Worker subagents
4. First message: "Read all prompts. Dispatch Phase 0 Recon. Then Phase 1 Spidering."
5. Lead writes tasks → spawns Worker subagents → reads results → repeats

**Full step-by-step manual:** `OPERATOR_GUIDE.md`
**Agent configuration:** `AGENTS.md`

---

## The 7 Phases

| Phase | What | Driven By | Output |
|-------|------|-----------|--------|
| 0. Recon | Infrastructure enumeration (subdomains, ports, tech, cloud, email) | Worker runs recon tools | `engagement/recon/recon.json` |
| 1. Spidering | Attack surface discovery (5+ tools) | Worker runs spider tools | `sitemap.json` + `hidden_endpoints.json` + `waf_fingerprint.json` |
| 2. Mapping | Per-endpoint analysis with light probing (M1-M8) | Worker + mapping skill | `engagement/mapping/EP-XXX.profile.yaml` |
| 3. Testing | OOB-first hypothesis-driven vulnerability testing | Worker + vuln skill | `engagement/findings/HYP-XXX.<status>.md` |
| 3.5 Exploitation | Automated exploitation for confirmed findings | Worker + sqlmap/nuclei | `engagement/findings/FIND-XXX.exploited.md` |
| 4. Validating | Re-confirm with clean PoC | Worker (no skill) | `engagement/findings/FIND-XXX.validated.md` |
| 5. Reporting | Professional reports with full impact analysis | Lead only | `engagement/reports/<slug>.report.md` |

Phase architecture detail: `phases/PHASE_ARCHITECTURE.md`

---

## Phase 0 Recon Tools (ALL mandatory)

| Tool | What It Finds |
|------|---------------|
| `tools/recon/master_recon.sh` | Orchestrator — runs all 4 recon tools, unified summary |
| `tools/recon/subdomain_enum.sh` | Subdomains, live hosts, takeover candidates, DNS resolution |
| `tools/recon/port_scan.sh` | Open ports, service detection, NSE vulnerability scanning |
| `tools/recon/tech_detect.sh` | Technology stack, CMS, CDN/WAF, API frameworks, favicons |
| `tools/recon/cloud_enum.sh` | S3/Azure/GCP buckets, K8s endpoints, email security |

## Phase 1 Spidering Tools (ALL mandatory)

| Tool | What It Finds |
|------|---------------|
| `tools/spider/spider.sh` | Linked endpoints, JS files, source maps, forms |
| `tools/spider/spider_comprehension.sh` | Reconstructed source, API specs, webpack chunks, CSP trust map |
| `tools/path_fuzzer.sh` | Hidden admin panels, debug endpoints, VCS exposure, backups |
| `tools/waf_detect.sh` | WAF fingerprint, blocked payloads, working bypass techniques |
| `tools/param_discover.sh` | Hidden parameters endpoints accept but don't advertise |
| `tools/cdp_browser.py` | Authenticated SPA navigation, cookie extraction, JS execution |

## New v4.0.0 Tools

| Tool | Purpose |
|------|---------|
| `tools/nuclei_runner.sh` | Nuclei vulnerability scanning with tech-stack-matched templates |
| `tools/interactsh_launcher.sh` | OOB (Out-of-Band) testing harness for blind vulnerabilities |
| `tools/sqlmap_runner.sh` | Safe SQLMap integration for Phase 3.5 exploitation only |
| `tools/secret_scanner.sh` | GitHub secret scanning via trufflehog + dorking |
| `tools/response_diff.py` | Automated 3-way baseline comparison + noise elimination |
| `tools/oob_validator.py` | OOB callback validation + payload correlation |
| `tools/chain_automation.py` | Automated M9 chain synthesis from endpoint profiles |
| `tools/fp_database.py` | False positive pattern database with confidence adjustment |
| `tools/model_router.py` | Pro vs Flash model routing based on task complexity |

## MCP Servers (6 total)

| Server | Purpose | Free? |
|--------|---------|-------|
| Playwright MCP | Browser automation | Yes |
| Burp Suite MCP | HTTP testing + Collaborator OOB | Pro required |
| GitHub MCP | Code/secret search in target repos | Yes (PAT token) |
| Brave Search MCP | Automated web dorking | Yes (2K/mo) |
| Memory MCP | Persistent knowledge graph across sessions | Yes (local) |
| Sequential Thinking | Multi-step chain reasoning | Yes (local) |

## Available Commands

| Command | Phase | Description |
|---------|-------|-------------|
| `/recon` | 0 | Run Phase 0 infrastructure reconnaissance |
| `/dork` | 0/1 | GitHub + Brave Search dorking for secrets and subdomains |
| `/spider` | 1 | Run Phase 1 spidering |
| `/map` | 2 | Run Phase 2 mapping on endpoints |
| `/test` | 3 | Run Phase 3 vulnerability testing |
| `/think` | 2/3/5 | Sequential multi-step reasoning for complex chain analysis |
| `/validate` | 4 | Run Phase 4 validation |
| `/browser` | Any | Browser automation via Playwright MCP |
| `/burp` | Any | HTTP analysis via Burp Suite MCP |
| `/worker` | Any | Execute a general framework task |
| `/status` | Any | Show current engagement status |
| `/resume` | Any | Resume engagement from last session |

## Key Files

| Who Reads | File |
|-----------|------|
| Both agents | `master_prompt.md` (thinking foundation) |
| Lead | `lead_prompt.md` (coordinator role, model routing) |
| Worker | `worker_prompt.md` (executor role, OOB-first testing) |
| Both (reference) | `target_prompt.md` (current engagement) |
| Lead (strategic) | `methodology.md`, `bug_bounty_master_methodology_lean.md` |
| Lead (reference) | `knowledge/` (disclosed report patterns, triage intel) |
| Both | `state.json` (engagement state — schema v3.0.0) |
| Operator | `OPERATOR_GUIDE.md`, `AGENTS.md` |

## Token Budget (Per Engagement)

| Phase | Lead (Pro) | Worker (Flash) | Total |
|-------|-----------|---------------|-------|
| Startup | 6,000 | 1,000 | 7,000 |
| Phase 0 Recon | 500 | 1,000 | 1,500 |
| Phase 1 Spider | 3,000 | 2,000 | 5,000 |
| Phase 2 Mapping (per batch) | 2,000 | 2,500/endpoint | variable |
| Phase 3 Testing (per hypothesis) | 1,500 | 3,000/hyp | variable |
| Phase 3.5 Exploitation | 500 | 2,000/finding | 2,500 |
| Phase 4 Validation | 1,000 | 2,000/finding | 3,000 |
| Phase 5 Reporting | 5,000/report | — | 5,000 |
| M9 Chain Synthesis | Automated | — | 2,000 |

**Context Limit:** 800,000 tokens | **Warn:** 80% | **Block:** 90%

## Critical Rules

1. **Phase 0 FIRST.** Always. Infrastructure recon expands attack surface 5-10x.
2. **OOB-first testing.** Every Phase 3 test starts with interactsh/OOB callbacks.
3. **Pro = Strategy, Flash = Execution.** Pro for chain synthesis/reporting, Flash for tool running/testing.
4. **Phase discipline.** Don't skip. Recon before spider. Spider before mapping. Mapping before testing.
5. **Smart overlap.** Testing dispatches for mapped endpoints while other endpoints are still mapping.
6. **Tool-first for mechanical.** Tools produce JSON, Lead reads JSON — not raw HTTP.
7. **WAF-aware testing.** Every Phase 3 task includes WAF bypass techniques from fingerprinting.
8. **Skill summary cards.** Worker reads ~40-line SUMMARY.md first, loads full SKILL.md only if needed.
9. **state.json is truth.** Lead updates after every Worker result.
10. **Two Chrome sessions.** Port 9222 (attacker) + port 9223 (victim) for cross-account testing.
