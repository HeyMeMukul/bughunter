# GitHub MCP — Summary Card

**Phase:** 0/1/3 | **Type:** Intelligence | **MCP Tool**

Search GitHub for exposed secrets, leaked configs, internal endpoints, and subdomains.

## Quick Run
```bash
# Search for leaked secrets
search_code "target.com" password OR secret OR api_key

# Find exposed dev configs
search_code "target.com" filename:.env OR filename:config.json

# Discover subdomains from code
search_code "*.target.com" OR "api.target.com"
```

## Key Capability
Programmatic GitHub dorking — find what hunters spend hours searching manually.

## Token Cost
~500-2000 per dork session
