# Skill Graph Index (MOC) — Phase-Based Framework v4.0.0

> Entry point for the penetration testing skill graph. 51 skills across 7 phases.
>
> **Phase 0 (Infra Recon):** Worker invokes `tools/recon/master_recon.sh` — see [[recon-infra]] for orchestration.
> **Phase 1 (Spidering):** Worker invokes `tools/spider/spider.sh` — see [[recon]] for web recon.
> **Phase 2 (Mapping):** Worker uses [[mapping]] for per-endpoint deep analysis (M1-M8).
> **Phase 3 (Testing):** Worker uses one vulnerability skill per hypothesis (categories below). OOB-FIRST.
> **Phase 4 (Validating):** Worker reproduces confirmed findings (no skill needed).
> **Phase 5 (Reporting):** Lead uses [[report-writing]] to generate professional reports.
>
> Workers load ONE skill at a time, based on Lead's task assignment. Do NOT browse other skills unless your task references them.

---

## Phase 0: Infrastructure Recon

- [[recon-infra]] — Phase 0: Infrastructure reconnaissance. Subdomain enumeration (passive + active + permutations), port scanning, technology fingerprinting, cloud bucket enumeration, email security (SPF/DMARC/DKIM). Run FIRST — expands attack surface 5-10x.

## Phase 1: Spidering & Web Recon

- [[recon]] — Phase 1: Web application attack surface discovery. spider.sh + cdp_browser.py + spider_comprehension.sh + path_fuzzer.sh + waf_detect.sh + param_discover.sh. Produces `engagement/spider/sitemap.json`.

## Mapping & Chain Synthesis (Phases 2 & M9)

- [[mapping]] — Phase 2: Per-endpoint deep analysis (M1-M8). Baseline capture, parameter classification, light probing (M4.5), signal detection, hypothesis generation with `impact_floor`/`impact_ceiling`. Produces `engagement/mapping/EP-XXX.profile.yaml`.
- [[chaining]] — M9 chain synthesis: gadget inventory, forward synthesis, backward synthesis, business-impact translation. [[chain_automation.py]] automates this. Loaded by mapping at M9.

## MCP Servers (Always-On Tools)

- [[browser-sessions]] — Playwright MCP: browser automation, cookie extraction, two-account workflows, DOM analysis.
- [[burp-mcp]] — Burp Suite Pro MCP: HTTP crafting, Intruder (race conditions), Collaborator (OOB), passive scanning.
- [[github-mcp]] — GitHub MCP: code/secret search, leaked credentials, internal endpoint discovery.
- [[brave-search-mcp]] — Brave Search MCP: automated web dorking, subdomain discovery, exposed panel search.
- [[memory-mcp]] — Memory MCP: persistent knowledge graph, program profiles, FP patterns, WAF intel.
- [[sequential-thinking]] — Sequential Thinking MCP: multi-step reasoning for chain synthesis and pivot analysis.

## Injection Attacks

- [[sqli]] — SQL injection: error-based, boolean blind, time-based blind, UNION-based, out-of-band.
- [[nosqli]] — NoSQL injection: MongoDB $where/$regex/$ne, Redis commands, Firebase query injection.
- [[ssti]] — Server-side template injection: detection, engine identification, sandbox escape, RCE.
- [[command-injection]] — OS command injection via shell metacharacters and blind OOB techniques.
- [[xxe]] — XML external entity injection: file read, SSRF, OOB exfiltration.
- [[ldap-injection]] — LDAP query injection: authentication bypass, blind extraction, filter bypass.
- [[ssi-injection]] — Server-side includes and edge-side includes (ESI) injection.
- [[xpath-injection]] — XPATH query injection: authentication bypass, blind extraction, error-based.
- [[crlf-injection]] — CRLF injection / HTTP response splitting, log forging, header injection.
- [[path-traversal]] — Directory traversal / LFI: path encoding, PHP wrappers, log poisoning.

## Authorization & Access Control

- [[idor]] — Insecure Direct Object Reference / BOLA: ID patterns, UUID-guessing, batch IDOR, GraphQL IDOR.
- [[bfla]] — Broken Function-Level Authorization: admin endpoint access, role escalation, method tampering.
- [[mass-assignment]] — Mass assignment / auto-binding: hidden field injection, privilege through property.

## Authentication

- [[jwt]] — JWT attacks: algorithm confusion (alg:none), key confusion, weak secret brute-force.
- [[oauth]] — OAuth 2.0 exploitation: redirect_uri manipulation, state parameter, token leakage.
- [[oauth-ato]] — OAuth Account Takeover: CSRF→account linking, implicit flow abuse, PKCE bypass.
- [[session-management]] — Session vulnerabilities: fixation, prediction, invalidation, cookie attributes.
- [[csrf]] — Cross-site request forgery: token bypass, SameSite bypass, JSON CSRF, multi-step CSRF.
- [[mfa-bypass]] — MFA/2FA bypass: response manipulation, direct endpoint access, rate limit bypass, OAuth skip.
- [[email-spoofing]] — Email spoofing / SMTP injection: SPF/DMARC analysis, header injection.

## Server-Side Attacks

- [[ssrf]] — Server-side request forgery: cloud metadata, filter bypass, DNS rebinding, protocol smuggling.
- [[pdf-ssrf]] — SSRF via PDF generation: wkhtmltopdf exploitation, server-side rendering, ImageMagick.
- [[host-header-injection]] — Host header attacks: password reset poisoning, cache poisoning, internal routing.
- [[deserialization]] — Insecure deserialization: Java gadgets, Python pickle, PHP unserialize, YAML unsafe_load.
- [[race-condition]] — Race condition / TOCTOU: single-packet attack, Turbo Intruder, multi-endpoint races.
- [[http-smuggling]] — HTTP request smuggling: CL.TE, TE.CL, H2 downgrade, front-end inconsistencies.

## Client-Side Attacks

- [[xss]] — Cross-site scripting: reflected, stored, DOM, blind, CSP bypass, WAF bypass, 10 phases.
- [[cors]] — CORS misconfiguration: null origin, subdomain wildcard, regex bypass, preflight bypass.
- [[postmessage]] — postMessage cross-origin communication: source bypass, sink exploitation, data theft.
- [[open-redirect]] — Open redirect: filter bypass, chaining with OAuth/SSRF, exploitation escalation.
- [[webrtc-leak]] — WebRTC IP leaking: STUN/TURN enumeration, internal IP exposure.

## Infrastructure & Cloud

- [[subdomain-takeover]] — Subdomain takeover: 15+ service fingerprints, CNAME analysis, claim verification.
- [[cloud-misconfig]] — Cloud misconfig: AWS S3/GCP/Azure/K8s, metadata endpoints, bucket policies.
- [[dependency-confusion]] — Dependency confusion / supply chain: private package scanning, registry checks.

## Business Logic & Advanced

- [[business-logic]] — Business logic flaws: workflow bypass, parameter tampering, coupon abuse, type juggling.
- [[graphql]] — GraphQL vulnerabilities: introspection, batching, depth attacks, persisted queries.
- [[websocket]] — WebSocket security: CSWSH, message injection, auth in channel subscriptions.
- [[file-upload]] — File upload: extension bypass, content-type bypass, SVG XSS, ZIP traversal.
- [[cache-poisoning]] — Web cache poisoning & deception: unkeyed queries, header injection, parameter cloaking.
- [[prototype-pollution]] — JavaScript prototype pollution: detection, gadget chains, DOM sinks.

## Reporting

- [[report-writing]] — Phase 5: Professional vulnerability report generation, CVSS 3.1 calculation, impact analysis.
