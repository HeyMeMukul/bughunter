# Boolean-Based Blind SQLi

## Prerequisites

- HIGH confidence from Phase 2 (injection confirmed)
- TRUE/FALSE conditions produce measurably different responses
- Response difference >20% in length or distinct content pattern

## Core Principle

Infer data by asking true/false questions. Response content (not timing) is the signal.

## Response Differentiation

Identify your TRUE vs FALSE indicators:
```
TRUE response:  [length: ~5000 bytes, contains "Welcome"]
FALSE response: [length: ~2000 bytes, contains "No results"]
```

Use the clearest differentiator—content pattern preferred over length.

## Extraction Workflow

### Step 1: Validate Control

```
Known TRUE:  ' AND 1=1-- -     → TRUE response
Known FALSE: ' AND 1=2-- -     → FALSE response
```

If inconsistent, reassess baseline or injection point.

### Step 2: Extract Length

```
' AND LENGTH(database())=N-- -
```

Binary search starting at 8. TRUE response = correct length.

### Step 3: Extract Characters

```
' AND ASCII(SUBSTRING(database(),1,1))>N-- -
```

Binary search ASCII 32-126. ~7 requests per character.

## Extraction Targets

Apply the same pattern to extract:
1. **Database/schema info:** `database()`, `user()`, `@@version`
2. **Table names:** subquery from `information_schema.tables`
3. **Column names:** subquery from `information_schema.columns`  
4. **Data:** subquery from target table

Use LIMIT offset to iterate through rows.

**Optimization:** For known charsets (hex hashes, numeric IDs), reduce search range accordingly.

## Response Classification

```
Response matches TRUE pattern  → condition is TRUE
Response matches FALSE pattern → condition is FALSE  
Response matches neither       → error or injection failed, retest
```

## Attempt Limits

- Max 10 requests to determine string length
- ~7 requests per character (binary search)
- Max 300 total requests per extraction target
- Max 2 retries on ambiguous responses before flagging

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Same response always | Injection not affecting query | Check syntax, context |
| Random responses | Session state or caching | Add cache-busting param |
| Partial extraction | Hitting LIMIT issues | Adjust LIMIT offset |

## Stop Conditions

- Response pattern shifts unexpectedly → re-baseline
- 5 consecutive ambiguous responses → reassess injection
- Rate limiting detected → back off
