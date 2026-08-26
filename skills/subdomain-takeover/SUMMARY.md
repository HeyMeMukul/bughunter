# Subdomain Takeover — Summary Card

**Phase:** 0/3 | **Type:** Infrastructure | **Impact:** High/Critical

## Quick Summary
Detect subdomains pointing to unclaimed cloud services (AWS S3, GitHub Pages, Heroku, Azure, etc.). When a subdomain's CNAME/DNS points to a service that no longer exists, an attacker can claim it and host content on that subdomain.

## Key Indicators
- CNAME records pointing to cloud services (check subdomain_enum.sh output)
- 404/Not Found on cloud service URLs
- "No such bucket" S3 errors
- "There isn't a GitHub Pages site here" messages
- "NoSuchBucket", "DomainNotFound", "Heroku No such app"

## Quick Test
```bash
# Check CNAME
dig CNAME sub.domain.com
# Try claiming the service
# S3: aws s3 ls s3://bucket-name
# GitHub: try creating repo for github.io domain
```

## Critical Bounty Potential
- $500-$5000+ per takeover
- Can host phishing pages, steal cookies, bypass CSP
- Often found on forgotten subdomains from Phase 0

## Token Cost
~3,000 tokens
