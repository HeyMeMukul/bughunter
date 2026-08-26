# Broken Function-Level Authorization (BFLA) — Summary Card

**Phase:** 3 | **Type:** Access Control | **Impact:** Critical

## Quick Summary
Regular users accessing admin-only functions. Vertical privilege escalation — the UI hides the button but the API behind it still works. Test every privileged endpoint with a low-privilege session.

## Key Indicators
- Admin panel routes (`/admin`, `/api/admin/`, `/internal/`, `/v1/admin/`)
- API endpoints where the method (GET/POST/PUT/DELETE) matters
- Role/permission fields in request bodies
- GraphQL mutations that lack authz checks
- Versioned API paths with weaker controls

## Quick Test
```bash
# Baseline: same request with admin vs regular session
curl -H "Cookie: <ADMIN_SESSION>" https://target.com/api/admin/users -o a.json
curl -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users -o r.json
diff a.json r.json || echo "BFLA CANDIDATE"

# Method tampering + path normalization
curl -X DELETE -H "Cookie: <REGULAR_SESSION>" https://target.com/api/admin/users/1
curl -H "Cookie: <REGULAR_SESSION>" https://target.com/api/%61dmin/users
```

## Critical Bounty Potential
- Admin function access with low-privilege user = critical ($2,000-$10,000+)
- Role escalation → full account/admin panel takeover
- Bulk PII/data exfiltration via admin read endpoints

## Token Cost
~4,000 tokens (Worker reads full SKILL.md)
