# Recon Infrastructure — Summary Card

**Phase:** 0 | **Role:** Recon Runner | **Type:** Tool Execution

## Quick Summary
Run 4 tools to enumerate subdomains, ports, technologies, and cloud infrastructure BEFORE hitting the web app. Produces `engagement/recon/recon.json`.

## When To Use
- Start of every new engagement (mandatory Phase 0)
- Before any spidering or mapping
- When target scope changes (new domains added)

## Tool Pipeline
1. `subdomain_enum.sh` → finds subdomains, live hosts, takeover candidates
2. `port_scan.sh` → discovers open ports, services, and vulns
3. `tech_detect.sh` → fingerprints tech stack, CMS, CDN/WAF, APIs
4. `cloud_enum.sh` → finds S3 buckets, K8s endpoints, email config

## Quick Run
```bash
./tools/recon/master_recon.sh --target "target.com" --output-dir engagement/
```

## Output Artifact
`engagement/recon/recon.json` — unified summary with attack surface insights

## Token Cost
~1,000 tokens (Worker) + ~500 tokens (Lead reads summary)
