# NoSQL Injection — Summary Card

**Phase:** 3 | **Type:** Injection | **Impact:** Critical

## Quick Summary
Test for MongoDB, Redis, Firebase, CouchDB, and other NoSQL injection. Different from SQLi — uses JSON operators ($where, $regex, $gt, $ne), JavaScript injection, and REST API query manipulation.

## Key Indicators
- JSON body parameters or URL query params that look like IDs
- MongoDB-style `$` operators in requests
- `/api/` endpoints with query filtering
- Firebase/Firestore database URLs
- Redis cache interaction points

## Quick Test
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"$where": "sleep(5000) || true"}
{"$regex": ".*"}
```

## Critical Bounty Potential
- Auth bypass via $ne/$gt operators = instant access
- Data extraction via $regex blind enumeration
- NoSQL injection in Firebase = mass data access

## Token Cost
~4,000 tokens (Worker reads full SKILL.md)
