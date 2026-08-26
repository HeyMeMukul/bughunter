# Subdomain Takeover — Vulnerability Skill

**Phase:** 0/3 | **Skill Type:** Infrastructure | **Prerequisite:** Phase 0 recon complete, subdomain list available

---

## Mental Model

Subdomain takeover happens when a subdomain's DNS record (CNAME or A) points to a third-party service that no longer exists or is unclaimed. An attacker can register/claim that service and control the content served on the subdomain.

**The key insight:** Companies decommission cloud services (Heroku apps, S3 buckets, GitHub Pages, Azure sites) but FORGET to remove the DNS records. Your Phase 0 subdomain enumeration finds these orphans.

**Why this matters for bounties:**
- You can host phishing pages on `secure.company.com`
- You can steal cookies/sessions (subdomain cookies are often scoped)
- You can bypass CSP if the subdomain is in the policy
- You can host malicious JavaScript for XSS chaining

---

## Phase 1: OOB-First Detection (MANDATORY)

### 1.1 Check from Phase 0 outputs

Phase 0's `subdomain_enum.sh` already checked takeover candidates. Read:
```bash
cat engagement/recon/subdomains/takeover_vulns.txt
```

### 1.2 Manual CNAME check

```bash
# Check each subdomain's CNAME
dig CNAME subdomain.target.com +short

# Common vulnerable CNAME patterns
dig CNAME *.target.com | grep -E "(amazonaws\.com|herokuapp\.com|github\.io|azurewebsites\.net|cloudapp\.net|firebaseapp\.com|netlify\.app|surge\.sh|bitbucket\.io|readme\.io|cargocollective\.com|fastly\.net|shopify\.com|myshopify\.com|webflow\.io|squarespace\.com|unbounce\.com|helpscoutdocs\.com|zendesk\.com|statuspage\.io|intercom\.io)"
```

---

## Phase 2: Confirmation — Service-Specific Testing

### 2.1 AWS S3 Buckets

```bash
# Check if bucket exists
curl -sI https://subdomain.target.com | grep -i "x-amz"

# Check CNAME
dig CNAME subdomain.target.com +short
# If points to s3.amazonaws.com or bucket-name.s3.amazonaws.com

# Check if bucket is claimable
aws s3 ls s3://bucket-name --no-sign-request
# "NoSuchBucket" = claimable!

# Common S3 error patterns
curl -s https://subdomain.target.com | grep -E "(NoSuchBucket|The specified bucket does not exist)"
```

### 2.2 GitHub Pages

```bash
dig CNAME subdomain.target.com +short
# If ends with github.io → check if repo exists

# Verify
curl -sI https://subdomain.target.com | grep -i "github"
# "There isn't a GitHub Pages site here" = claimable!

# Claim: Create repo matching the org/user from CNAME
# Set GitHub Pages to serve from that repo with the custom domain
```

### 2.3 Heroku

```bash
dig CNAME subdomain.target.com +short
# If ends with herokuapp.com or herokudns.com

# Check
curl -s https://subdomain.target.com
# "No such app" = claimable!

# Claim: heroku create app-name
# heroku domains:add subdomain.target.com
```

### 2.4 Azure

```bash
dig CNAME subdomain.target.com +short
# If ends with azurewebsites.net, cloudapp.net, trafficmanager.net

curl -sI https://subdomain.target.com
# 404 with Azure error = potentially claimable
```

### 2.5 Other Services (Quick Check Table)

| Service | CNAME Pattern | Error Indicator | Claimable? |
|---------|--------------|-----------------|-----------|
| Netlify | netlify.app, netlify.com | "Not Found — site not found" | Yes |
| Vercel | vercel.app, cname.vercel-dns.com | "DEPLOYMENT_NOT_FOUND" | Yes |
| Surge.sh | surge.sh | "project not found" | Yes |
| Shopify | shops.myshopify.com | "Sorry, this shop is currently unavailable" | Yes |
| Bitbucket | bitbucket.io | "Repository not found" | Yes |
| Readme.io | readme.io | "Project not found" | Yes |
| Help Scout | helpscoutdocs.com | "Site not found" | Sometimes |
| Zendesk | zendesk.com | "Oops, this help center no longer exists" | Sometimes |
| Cargo | cargocollective.com | "404 — not found" | Sometimes |
| Fastly | fastly.net | "Fastly error" | Yes |
| Firebase | firebaseapp.com | "Site not found" | Yes |
| WP Engine | wpengine.com | "Site not found" | Sometimes |
| Pantheon | gotpantheon.com | "Site not found" | Sometimes |

---

## Phase 3: Negative Verdict (MANDATORY GATE)

1. Check CNAME/A record for EVERY subdomain from Phase 0
2. For each service match, verify the service is actually unclaimed
3. Check HTTP response body for the service-specific "not found" indicator
4. If NONE of the subdomains have vulnerable CNAME patterns → NEGATIVE
5. Note: A 404 error alone is NOT a takeover — must match the service-specific "unclaimed" patterns

---

## Phase 4: Proof of Concept (Service Claim)

**EXTREME CAUTION:** Only claim the service if the bug bounty program EXPLICITLY allows it. Many programs forbid actual service registration as PoC. Default to fingerprinted evidence + screenshot.

### Safe PoC (No Service Claim):
1. Capture DNS CNAME/A record: `dig CNAME sub.target.com +short > takeover_poc/dns.txt`
2. Capture HTTP response showing service-specific "unclaimed" error
3. Screenshot the error page
4. Document the exact steps to claim the service (but do NOT claim it)
5. Calculate impact: "An attacker could host phishing page, steal cookies, bypass CSP"

### Service-Specific Claim Commands (if program allows):
```bash
# S3: aws s3 mb s3://exact-bucket-name --region us-east-1
# GitHub: gh repo create org/repo-name
# Heroku: heroku create app-name
# Netlify: netlify sites:create
```

---

## What You DO
- Check every subdomain's CNAME/A record
- Match CNAME patterns to known vulnerable services
- Fingerprint HTTP response bodies for service-specific "unclaimed" errors
- Document DNS evidence and response evidence
- Calculate impact (phishing, cookie theft, CSP bypass)

## What You DO NOT Do
- Claim the service unless explicitly allowed by the program
- Simply report 404 pages — must prove the service is UNCLAIMED, not just not found
- Skip DNS verification — the CNAME/A record MUST point to the service
- Report "potential" takeover without solid evidence
