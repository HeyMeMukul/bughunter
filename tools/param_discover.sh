#!/bin/bash
# param_discover.sh — Hidden Parameter Discovery
#
# Discovers parameters that endpoints accept but don't advertise in HTML/JS.
# Uses common parameter name wordlists + application-aware mutations.
# Tests both query parameters and JSON body fields.
#
# Usage: ./param_discover.sh <target-url> --endpoint /api/path [--auth-cookie "..."] [--header "..."] [--output-dir <dir>] [--method GET|POST] [--body-json '{...}'] [--rate-limit <req/s>]

set -e

TARGET=""
ENDPOINT=""
AUTH_COOKIE=""
EXTRA_HEADER=""
OUTPUT_DIR="engagement/spider/params"
METHOD="GET"
BODY_JSON=""
RATE_LIMIT=3
WORDLIST=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
        --header) EXTRA_HEADER="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --method) METHOD="$2"; shift 2 ;;
        --body-json) BODY_JSON="$2"; shift 2 ;;
        --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        --wordlist) WORDLIST="$2"; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ -z "$TARGET" ] || [ -z "$ENDPOINT" ]; then
    echo "Usage: $0 <target-url> --endpoint /api/path [--auth-cookie ...] [--method GET|POST] [--body-json '{...}']"
    exit 1
fi

TARGET="${TARGET%/}"
mkdir -p "$OUTPUT_DIR"

CURL_ARGS=(-s -L --max-time 10 -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
[ -n "$AUTH_COOKIE" ] && CURL_ARGS+=(-b "$AUTH_COOKIE")
[ -n "$EXTRA_HEADER" ] && CURL_ARGS+=(-H "$EXTRA_HEADER")

SAFE_NAME=$(echo "$ENDPOINT" | tr '/' '_' | sed 's/^_//')
RESULTS_FILE="$OUTPUT_DIR/params_${SAFE_NAME}.json"

echo "================================================="
echo "  PARAMETER DISCOVERY"
echo "================================================="
echo "  Target:    $TARGET$ENDPOINT"
echo "  Method:    $METHOD"
echo "  Output:    $RESULTS_FILE"
echo "  Rate:      ${RATE_LIMIT} req/s"
echo "================================================="
echo ""

BASELINE_RESP=$(curl "${CURL_ARGS[@]}" -w "\n%{http_code}|%{size_download}" "$TARGET$ENDPOINT" 2>/dev/null)
BASELINE_BODY=$(echo "$BASELINE_RESP" | sed '$d')
BASELINE_META=$(echo "$BASELINE_RESP" | tail -1)
BASELINE_STATUS=$(echo "$BASELINE_META" | cut -d'|' -f1)
BASELINE_SIZE=$(echo "$BASELINE_META" | cut -d'|' -f2)
echo "  Baseline: status=$BASELINE_STATUS size=${BASELINE_SIZE}B"

DELAY=$(python3 -c "print(1.0 / max(1, $RATE_LIMIT))" 2>/dev/null || echo "0.33")

BUILTIN_PARAMS="$OUTPUT_DIR/_builtin_params.txt"
cat > "$BUILTIN_PARAMS" << 'PEOF'
id
user_id
userId
account_id
accountId
org_id
orgId
tenant_id
tenantId
team_id
teamId
project_id
projectId
company_id
companyId
role
admin
is_admin
isAdmin
is_superuser
superuser
permission
permissions
access_level
accessLevel
level
type
status
state
action
method
format
output
input
callback
redirect
redirect_uri
redirect_url
return
return_url
returnTo
next
next_url
url
uri
path
target
dest
destination
page
file
filename
filepath
folder
dir
directory
name
username
email
password
token
secret
key
api_key
apiKey
api_secret
apiSecret
auth
authorization
session
cookie
debug
test
testing
verbose
trace
log
logging
dry_run
dry-run
preview
draft
published
active
enabled
disabled
visible
hidden
deleted
archived
sort
order
orderby
order_by
sort_by
sortBy
direction
limit
offset
skip
take
count
size
page_size
pageSize
per_page
perPage
fields
include
expand
embed
filter
search
query
q
keyword
term
category
tag
label
group
scope
context
env
environment
lang
language
locale
region
country
currency
timezone
date
start_date
end_date
from
to
since
until
before
after
min
max
price
amount
total
quantity
qty
discount
coupon
code
promo
ref
referral
source
origin
referrer
utm_source
utm_medium
utm_campaign
tracking
track
analytics
event
action_name
PEOF

ALL_PARAMS="$OUTPUT_DIR/_all_params.txt"
{
    cat "$BUILTIN_PARAMS"
    [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ] && cat "$WORDLIST"
} | sort -u > "$ALL_PARAMS"

TOTAL_PARAMS=$(wc -l < "$ALL_PARAMS")
echo ""
echo "[1/3] Testing $TOTAL_PARAMS query parameters..."

FOUND_PARAMS="$OUTPUT_DIR/found_params_${SAFE_NAME}.txt"
> "$FOUND_PARAMS"

TESTED=0
FOUND=0

while IFS= read -r param; do
    [ -z "$param" ] && continue

    TEST_URL="${TARGET}${ENDPOINT}?${param}=PARAMDISCOVER_$(echo $param | md5sum | cut -c1-8)"

    resp=$(curl "${CURL_ARGS[@]}" -w "\n%{http_code}|%{size_download}" "$TEST_URL" 2>/dev/null)
    body=$(echo "$resp" | sed '$d')
    meta=$(echo "$resp" | tail -1)
    status=$(echo "$meta" | cut -d'|' -f1)
    size=$(echo "$meta" | cut -d'|' -f2)

    TESTED=$((TESTED + 1))

    if [ "$status" != "$BASELINE_STATUS" ] || [ "$size" != "$BASELINE_SIZE" ]; then
        marker="PARAMDISCOVER_$(echo $param | md5sum | cut -c1-8)"
        reflected="false"
        if echo "$body" | grep -q "$marker" 2>/dev/null; then
            reflected="true"
        fi

        size_diff=$((size - BASELINE_SIZE))
        echo "$param|$status|$size|$size_diff|$reflected" >> "$FOUND_PARAMS"
        FOUND=$((FOUND + 1))
        echo "   [$FOUND] $param → status=$status size=${size}B diff=${size_diff}B reflected=$reflected"
    fi

    if [ $((TESTED % 30)) -eq 0 ]; then
        echo "   Progress: $TESTED/$TOTAL_PARAMS tested, $FOUND responsive"
    fi

    sleep "$DELAY" 2>/dev/null || true

done < "$ALL_PARAMS"

echo ""
echo "[2/3] Testing JSON body parameter injection..."

BODY_FOUND="$OUTPUT_DIR/found_body_${SAFE_NAME}.txt"
> "$BODY_FOUND"

if [ "$METHOD" = "POST" ] || [ "$METHOD" = "PUT" ] || [ "$METHOD" = "PATCH" ]; then
    BASE_BODY="$BODY_JSON"
    [ -z "$BASE_BODY" ] && BASE_BODY="{}"

    BASE_BODY_RESP=$(curl "${CURL_ARGS[@]}" -X "$METHOD" -H "Content-Type: application/json" \
        -d "$BASE_BODY" -w "\n%{http_code}|%{size_download}" "$TARGET$ENDPOINT" 2>/dev/null)
    BASE_BODY_META=$(echo "$BASE_BODY_RESP" | tail -1)
    BASE_BODY_STATUS=$(echo "$BASE_BODY_META" | cut -d'|' -f1)
    BASE_BODY_SIZE=$(echo "$BASE_BODY_META" | cut -d'|' -f2)
    echo "  Body baseline: status=$BASE_BODY_STATUS size=${BASE_BODY_SIZE}B"

    BODY_PARAMS=(
        "role:admin"
        "isAdmin:true"
        "is_admin:true"
        "superuser:true"
        "permissions:[\"admin\"]"
        "access_level:99"
        "level:admin"
        "price:0.01"
        "amount:-1"
        "quantity:-1"
        "total:0"
        "discount:100"
        "status:approved"
        "approved:true"
        "verified:true"
        "active:true"
        "enabled:true"
        "debug:true"
        "test:true"
        "dry_run:true"
        "preview:true"
        "bypass:true"
        "skip_validation:true"
        "force:true"
        "override:true"
        "internal:true"
        "scope:admin"
        "type:admin"
        "account_type:admin"
    )

    for bp in "${BODY_PARAMS[@]}"; do
        bname=$(echo "$bp" | cut -d: -f1)
        bval=$(echo "$bp" | cut -d: -f2-)

        INJECTED_BODY=$(python3 -c "
import json
try:
    body = json.loads('$BASE_BODY')
except:
    body = {}
body['$bname'] = json.loads('$bval') if '$bval' in ('true','false','null') or '$bval'.startswith('[') else '$bval'
print(json.dumps(body))
" 2>/dev/null || echo "{}")

        resp=$(curl "${CURL_ARGS[@]}" -X "$METHOD" -H "Content-Type: application/json" \
            -d "$INJECTED_BODY" -w "\n%{http_code}|%{size_download}" "$TARGET$ENDPOINT" 2>/dev/null)
        meta=$(echo "$resp" | tail -1)
        status=$(echo "$meta" | cut -d'|' -f1)
        size=$(echo "$meta" | cut -d'|' -f2)

        if [ "$status" != "$BASE_BODY_STATUS" ] || [ "$size" != "$BASE_BODY_SIZE" ]; then
            size_diff=$((size - BASE_BODY_SIZE))
            echo "$bname|$bval|$status|$size|$size_diff" >> "$BODY_FOUND"
            echo "   BODY: $bname=$bval → status=$status size=${size}B diff=${size_diff}B"
        fi
        sleep "$DELAY" 2>/dev/null || true
    done
fi

echo ""
echo "[3/3] Building results JSON..."

python3 << PYEOF
import json
from datetime import datetime, timezone

query_params = []
with open("$FOUND_PARAMS") as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) < 5: continue
        name, status, size, diff, reflected = parts
        query_params.append({
            "name": name,
            "status": int(status),
            "size_bytes": int(size),
            "size_diff": int(diff),
            "reflected": reflected == "true",
            "signal_strength": "HIGH" if abs(int(diff)) > 50 or reflected == "true" else "MEDIUM"
        })

body_params = []
body_file = "$BODY_FOUND"
try:
    with open(body_file) as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) < 5: continue
            name, val, status, size, diff = parts
            body_params.append({
                "name": name,
                "injected_value": val,
                "status": int(status),
                "size_bytes": int(size),
                "size_diff": int(diff),
                "signal_strength": "HIGH" if abs(int(diff)) > 50 else "MEDIUM"
            })
except: pass

high_value = [p for p in query_params if p.get("reflected") or p.get("signal_strength") == "HIGH"]
high_value += [p for p in body_params if p.get("signal_strength") == "HIGH"]

output = {
    "meta": {
        "endpoint": "$ENDPOINT",
        "method": "$METHOD",
        "target": "$TARGET",
        "tested_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "params_tested": $TESTED,
        "query_params_found": len(query_params),
        "body_params_found": len(body_params),
        "high_value_params": len(high_value)
    },
    "baseline": {
        "status": int("$BASELINE_STATUS"),
        "size_bytes": int("$BASELINE_SIZE")
    },
    "query_parameters": query_params,
    "body_parameters": body_params,
    "high_value_params": high_value
}

with open("$RESULTS_FILE", "w") as f:
    json.dump(output, f, indent=2)

print(f"   Query params found:  {len(query_params)}")
print(f"   Body params found:   {len(body_params)}")
print(f"   High-value params:   {len(high_value)}")
print(f"   Output: $RESULTS_FILE")
PYEOF

echo ""
echo "================================================="
echo "  PARAMETER DISCOVERY COMPLETE"
echo "================================================="
echo "  Endpoint:   $ENDPOINT"
echo "  Query found: $FOUND"
echo "  Output: $RESULTS_FILE"
echo "================================================="
