# GitHub MCP — Code & Secret Search

**Phase:** 0/1/3 | **MCP:** `@modelcontextprotocol/server-github`  
**Token Cost:** ~500-2000 per search session  
**API Key:** GitHub Personal Access Token (`GITHUB_PERSONAL_ACCESS_TOKEN` env)

---

## What This MCP Gives You

Search GitHub programmatically — find exposed secrets, internal configs, API endpoints, and leaked credentials that belong to your target organization. This is what elite hunters do manually for hours.

### Available Tools
- `search_code` — Find code containing your target domain/org
- `search_repositories` — Find repos owned by or mentioning your target
- `search_issues` — Find issues/PRs that leak internal URLs or secrets
- `search_commits` — Find commits with exposed credentials
- `search_users` — Find developers who work at target company
- `get_file_contents` — Read discovered files without browser
- `list_commits` — See commit history for discovered repos

---

## Phase 0: Reconnaissance Dorking

### Dork Queries for Infrastructure Discovery

```bash
# When Worker has GitHub MCP enabled, the Lead dispatches via /dork command:

# 1. Find all repos mentioning target domain
search_code: "target.com" type:repository

# 2. Find leaked credentials
search_code: "target.com" password OR secret OR api_key OR token
search_code: "target.com" BEGIN RSA PRIVATE KEY
search_code: "target.com" mongodb:// OR redis:// OR postgres://

# 3. Find internal endpoints
search_code: "target.com" "/api/internal" OR "/admin" OR "/staging"
search_code: "target.com" ".env" OR "config.json" OR "credentials"

# 4. Find developer tools/config leaks
search_code: "target.com" "aws_access_key" OR "AWS_SECRET"
search_code: "target.com" "firebase" OR "supabase" OR "heroku"
search_code: "target.com" filename:Dockerfile

# 5. Find CI/CD leaks
search_code: "target.com" filename:.gitlab-ci.yml
search_code: "target.com" filename:Jenkinsfile
search_code: "target.com" filename:.github/workflows

# 6. Discover subdomains
search_code: "*.target.com" OR "api.target.com" OR "admin.target.com"
```

---

## Phase 1: Spidering Enhancement

### Discover Endpoints from Source Code

```bash
# When a target repo is found, extract endpoints:
search_code: repo:org/repo-name "fetch(" OR "axios." OR "api/"
search_code: repo:org/repo-name "/graphql" OR "/swagger" OR "/api-docs"

# Find JavaScript source maps
search_code: repo:org/repo-name filename:.js.map

# Find GraphQL schemas
search_code: repo:org/repo-name "type Query" OR "type Mutation" language:graphql
```

---

## Phase 3: Vulnerability Validation

### Cross-Reference Findings with Source Code

```bash
# If you found an IDOR on /api/users/{id}, check if the code has auth:
search_code: repo:org/repo-name "/api/users" AND "authorization"
# If NO auth middleware found → confirms the finding

# If you found a SQLi-vulnerable parameter, check if it uses parameterized queries:
search_code: repo:org/repo-name "SELECT.*FROM.*users" AND (parameterized OR prepared)
```

---

## API Key Setup

```bash
# Set your GitHub token (needs repo + code search scopes)
export GITHUB_PERSONAL_ACCESS_TOKEN="ghp_your_token_here"

# Add to engagement/.creds.sh
echo 'export GITHUB_PERSONAL_ACCESS_TOKEN="ghp_your_token"' >> engagement/.creds.sh

# Verify it works:
gh auth status
```

---

## Rate Limits

| Auth Level | Code Search | Rate Limit |
|-----------|-------------|-----------|
| Unauthenticated | 10 req/min | Very limited |
| Authenticated | 30 req/min | 5000 req/hr |
| Enterprise | 30 req/min | 15000 req/hr |

---

## What You DO
- Search for target's org name, domain, and known repo patterns
- Search for secrets (password, token, key, secret, credentials)
- Extract API endpoints, subdomains, and internal URLs from code
- Cross-reference confirmed findings against source code
- NEVER output actual secret values — always mask as `[REDACTED]`
- Save discovered endpoints to `engagement/recon/github_endpoints.json`

## What You DO NOT Do
- Clone repos or exfiltrate large amounts of source code
- Output secret values in results (mask them)
- Search beyond rate limits — respect 429 responses
- Run searches on personal/private repos
