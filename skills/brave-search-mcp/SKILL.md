# Brave Search MCP — Automated Dorking Engine

**Phase:** 0/1 | **MCP:** `@anthropic/mcp-server-brave-search`  
**Token Cost:** ~300-1000 per dork session  
**API Key:** Brave Search API key (`BRAVE_API_KEY` env, free 2000 queries/month)

---

## What This MCP Gives You

Automate web dorking — find subdomains, exposed admin panels, leaked data, forum mentions, and technology-specific vulnerabilities that Google dorking would take hours to find manually. Zero rate-limit headaches.

### Available Tools
- `brave_web_search` — Web search with programmatic filtering
- `brave_local_search` — Location-based results (useful for physical security)

---

## Phase 0: Infrastructure Discovery Dorks

### Subdomain Discovery
```
site:target.com -www
subdomain finder site:*.target.com
```

### Technology Fingerprinting
```
site:target.com inurl:wp-admin
site:target.com inurl:phpmyadmin
site:target.com "Powered by" OR "Built with"
```

### Exposed Admin Panels
```
intitle:"admin panel" site:target.com
intitle:"dashboard" inurl:admin site:target.com
"dev environment" OR "staging" site:target.com
```

### Exposed Documents
```
site:target.com ext:pdf OR ext:docx OR ext:xlsx
site:target.com "confidential" OR "internal use only"
site:target.com "password" ext:txt OR ext:csv
```

### Developer / DevOps Leaks
```
site:target.com inurl:.env OR inurl:config
site:target.com "api_key" OR "secret_key" OR "private_key"
site:target.com "TODO" OR "FIXME" OR "HACK"
```

### Cloud Infrastructure
```
site:target.com "s3.amazonaws.com"
site:target.com "cloudfront.net"
site:target.com "firebaseio.com"
site:target.com "storage.googleapis.com"
```

### Email / Employee Info
```
"@target.com" email
site:linkedin.com "target.com" developer OR engineer
site:github.com "target.com"
```

### Bug Bounty Intelligence
```
"bug bounty" "target.com" OR "hackerone" "target.com"
target.com "vulnerability" OR "security" report
target.com site:medium.com OR site:blog
```

---

## Phase 1: Spidering Enhancement

### Discover Hidden Pages
```
site:target.com -inurl:www -inurl:blog -inurl:support
site:target.com "test" OR "dev" OR "staging" OR "beta"
site:target.com inurl:api OR inurl:graphql OR inurl:swagger
```

### CVE Context
```
"target.com" CVE-2025 OR CVE-2024 OR CVE-2023
"nginx target.com" vulnerability
"react target.com" OR "vue target.com" security issue
```

---

## API Key Setup

```bash
# Get free API key: https://brave.com/search/api/
export BRAVE_API_KEY="BSA_your_key_here"

# Add to engagement/.creds.sh
echo 'export BRAVE_API_KEY="BSA_your_key"' >> engagement/.creds.sh
```

## Free Tier: 2,000 queries/month — plenty for engagement-level dorking

---

## What You DO
- Run 10-20 dork queries per target domain
- Save discovered URLs to `engagement/recon/search_dorks.json`
- Flag any exposed admin panels or leaked credentials immediately
- Combine with GitHub MCP for cross-platform intelligence

## What You DO NOT Do
- Exceed rate limits (2K/month free)
- Run automated mass scanning via search
- Cache search results that contain PII
