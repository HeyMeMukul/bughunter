# IDOR Skill — Quick Reference Card

> Read this first. Load `SKILL.md` only if you need full technique detail.

## Workflow (3 Phases)
```
Phase 1: Baseline (from profile — usually already done)
Phase 2: Confirmation (cross-user access test with 2 sessions)
Phase 3: Exploitation (one concrete example only)
```

## When to Confirm (Phase 2 Criteria)
- Session A accesses resource owned by Session B → different, non-empty, non-error response
- Response contains target user's PII/data (not just session A's own data)

## Key Payloads
- Numeric IDs: try `victim_id` (from Session B, or +1/-1 from your own)
- UUIDs: get victim UUID from info disclosure endpoint or recon
- Encoded IDs: decode first, modify, re-encode
- Indirect references: names, emails, slugs that map to records

## Stop Signals
- Both users get identical response → NOT IDOR, same data pool
- 403/404 on victim ID → auth enforced, move to next ID pattern
- WAF blocks → try bypass techniques from waf_fingerprint.json

## Result Format
```
Status: confirmed | negative | partial
Evidence: exact request/response pairs (HTTP/1.1 format)
```

> **Full skill:** `cat skills/idor/SKILL.md`
