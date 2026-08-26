# Task NNN — PHASE 0: Infrastructure Reconnaissance

## Phase: 0
## Status: PENDING
## Worker Role: Recon Runner

## Objective
Run the 4 infrastructure recon tools against the target to discover subdomains, open ports, technology stacks, and cloud infrastructure BEFORE hitting the web application.

## Commands to Run
```bash
# Option A: Run all at once (recommended)
./tools/recon/master_recon.sh \
    --target "https://target.com" \
    --output-dir engagement/

# Option B: Run individual tools (for targeted recon)
# 1. Subdomain enumeration (most important)
./tools/recon/subdomain_enum.sh \
    --target "target.com" \
    --output-dir engagement/recon/subdomains \
    --recursive

# 2. Port scanning
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

## Skill File
Load: skills/recon-infra/SKILL.md
First read: skills/recon-infra/SUMMARY.md (~40 lines, confirms relevance)

## What to Report
Write result to results/result-NNN-recon.md:
- Subdomains found (total / live / takeover-vulnerable)
- Open ports and services discovered
- Technology stack fingerprint (key technologies found)
- Cloud infrastructure findings (buckets, K8s, email security)
- Attack surface insights (from recon.json)
- Any CRITICAL immediate findings (public S3 buckets, exposed admin panels, email spoofing risk)
- Tool availability report (which tools were installed vs fallback used)
