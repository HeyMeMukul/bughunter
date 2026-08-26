# Recon Infrastructure — Phase 0 Skill

**Role:** Phase 0 Recon Runner  
**Phase:** 0 — Infrastructure Reconnaissance  
**Skill Type:** Tool execution  
**Prerequisite:** None (this is the first phase)

---

## Mental Model

Phase 0 is about EXPANDING the attack surface before touching the web application. Most bug bounty hunters start by hitting the main website. Elite hunters FIRST enumerate everything the organization exposes to the internet: subdomains, cloud storage, email config, open ports, technology stacks.

**Why Phase 0 matters:**
- 60% of critical bugs are on subdomains the spider would never find
- Staging/dev environments have weaker security
- Cloud buckets leaked by subdomain enumeration = instant bounty
- Email spoofability = chaining amplifier for social engineering impact
- Technology fingerprinting = targeted Phase 3 testing

**The Phase 0 mindset:** "What does this organization own that they forgot about?"

---

## Tool Pipeline (4 tools, run in order):

```
1. subdomain_enum.sh  → engagement/recon/subdomains/   (subdomains, live hosts, takeover)
2. port_scan.sh       → engagement/recon/ports/        (open ports, services, vulns)
3. tech_detect.sh     → engagement/recon/tech/         (tech stack, CMS, CDN/WAF, APIs)
4. cloud_enum.sh      → engagement/recon/cloud/        (S3 buckets, K8s, email security)
5. master_recon.sh    → Runs ALL above + unified recon.json
```

---

## Execution Phases

### R1: PRE-FLIGHT CHECKS

Before running any tool, verify:

```
1. Target domain resolves (dig +short TARGET)
2. Output directory exists (mkdir -p engagement/recon/{subdomains,ports,tech,cloud})
3. Check if optional tools are installed:
   - subfinder, assetfinder, puredns, dnsx, gotator  (subdomain enum)
   - naabu, nmap, searchsploit                        (port scan)
   - httpx, cmseek, whatweb                            (tech detect)
   - cloud_enum, s3scanner, nuclei                     (cloud enum)
4. Note: ALL tools gracefully degrade if missing — they use Python/curl fallbacks
```

### R2: RUN MASTER RECON (recommended)

```bash
# This runs all 4 tools sequentially and produces unified recon.json
./tools/recon/master_recon.sh \
    --target "target.com" \
    --output-dir engagement/
```

### R3: RUN INDIVIDUAL TOOLS (optional)

```bash
# 1. Subdomain enumeration
./tools/recon/subdomain_enum.sh \
    --target "target.com" \
    --output-dir engagement/recon/subdomains \
    --recursive

# 2. Port scanning (needs subdomains from step 1)
./tools/recon/port_scan.sh \
    --targets engagement/recon/subdomains/alive_hosts.txt \
    --output-dir engagement/recon/ports \
    --top-ports 1000

# 3. Technology detection
./tools/recon/tech_detect.sh \
    --targets engagement/recon/subdomains/alive_hosts.txt \
    --output-dir engagement/recon/tech

# 4. Cloud enumeration
./tools/recon/cloud_enum.sh \
    --target "target.com" \
    --output-dir engagement/recon/cloud
```

### R4: VALIDATE OUTPUTS

After tool execution, verify:

1. `engagement/recon/recon.json` exists and is valid JSON
2. Check summary counts — if subdomains=0, investigate
3. Read `attack_surface_insights` array — these are Phase 1-3 priorities
4. Check `email_security.risk_assessment` — HIGH risk = reportable finding
5. Check `cloud_buckets.summary` — any public buckets?

### R5: REPORT BACK TO LEAD

Write result to `results/result-NNN-recon.md`:

```markdown
# Result — Task NNN: Phase 0 Recon Complete

## Status: COMPLETE

## Outputs
- engagement/recon/recon.json (unified)
- engagement/recon/subdomains/subdomains.json
- engagement/recon/ports/open_ports.json
- engagement/recon/tech/tech_stack.json
- engagement/recon/cloud/cloud_buckets.json

## Summary
- Subdomains resolved: N
- Live hosts: N
- Hosts with open ports: N
- Technology profiles created: N
- Cloud buckets found: N (N public!)
- Email security risk: HIGH/MEDIUM/LOW
- Subdomain takeover candidates: N

## Critical Findings (Immediate Action)
- [List any CRITICAL recon findings — public buckets, takeover, exposed K8s]

## Attack Surface Insights
- [Copy insights from recon.json]

## Tool Availability
- subfinder: [installed/not installed]
- puredns: [installed/not installed]
- naabu: [installed/not installed]
- httpx: [installed/not installed]
- nuclei: [installed/not installed]
```

---

## What You DO

- Execute tools exactly as specified in the task
- Verify output files exist and contain data
- Count and summarize key metrics
- Flag CRITICAL recon findings immediately (public S3 buckets, takeover-ready subdomains, exposed K8s API)

## What You DO NOT Do

- Test the discovered endpoints (that's Phase 1+)
- Run vulnerability probes against discovered services
- Exceed rate limits — all tools default to safe rates
- Continue if a tool fails irrecoverably — report PARTIAL status instead

---

## Tool Dependency Handling

| Tool | If Missing | Fallback |
|------|-----------|---------|
| subfinder | Python/crt.sh passive | Works but fewer results |
| puredns | dnsx or basic dig loop | Works but slower |
| dnsx | basic dig loop | Very slow, keep thread count low |
| naabu | nmap fast scan | Works but slower |
| httpx | Python urllib + regex | Works but less accurate |
| nuclei | subjack/subzy fallback | Takeover detection limited |
| cloud_enum | Python direct bucket checks | Works but fewer cloud providers |

---

## Session / Auth

Phase 0 does NOT require authentication. All enumeration is passive or unauthenticated. No cookies, no sessions, no browser needed.

---

## Token Budget

| Operation | Token Estimate |
|-----------|---------------|
| Read this skill | ~200 tokens |
| Execute master_recon.sh | ~0 tokens (tool runs locally) |
| Read recon.json summary | ~500 tokens |
| Write result file | ~300 tokens |
| **Total Phase 0 Worker** | **~1,000 tokens** |
| Lead reads recon.json | ~500 tokens (reads summary only) |
