# SQLi Skill — Quick Reference Card

> Read this first. Load `SKILL.md` only if you need full technique detail.

## Workflow (3 Phases)
```
Phase 1: Error-based detection (structural error signals)
Phase 2: Boolean blind + time-based confirmation
Phase 3: Data extraction (one example — don't dump DB)
```

## Detection Order
1. `'` (single quote) — syntax error indicator
2. `''` (double quote escape) — comparison
3. `1 AND 1=1` vs `1 AND 1=2` — boolean delta
4. `1; WAITFOR DELAY '0:0:5'--` — time-based (last resort)

## WAF Bypass Checklist (before giving up)
- Lowercase: `select` → `SELECT` → `SeLeCt`
- Comment substitution: `UNION/**/SELECT`
- URL encoding: `%27` for `'`
- Double URL encoding: `%2527`
- Unicode: check waf_fingerprint.json bypass_techniques

## Stop Signals
- Every payload returns 400 → WAF blocking (not app error) — try bypass techniques
- No delta between 1=1 and 1=2 → NOT SQLi via boolean, try time-based
- Errors vary but structurally the same → app error, not injection

## Result Format
```
Status: confirmed | negative | partial
Evidence: at minimum a boolean delta (different response sizes/content)
```

> **Full skill:** `cat skills/sqli/SKILL.md`
