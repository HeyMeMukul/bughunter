#!/bin/bash
# spider.sh - Master Spider Tool
# Discovers attack surface mechanically. NO probing, NO reasoning.
# Output: engagement/spider/sitemap.json (consumed by agent)
#
# Usage: ./spider.sh <target-url> [--auth-cookie "name=value"] [--header "X-HackerOne: user"]

set -e

TARGET=""
AUTH_COOKIE=""
EXTRA_HEADER=""
OUTPUT_DIR="engagement/spider"
RAW_DIR="$OUTPUT_DIR/raw"
SITEMAP="$OUTPUT_DIR/sitemap.json"
MAX_PAGES=200
MAX_JS_FILES=50

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
        --header) EXTRA_HEADER="$2"; shift 2 ;;
        --max-pages) MAX_PAGES="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; RAW_DIR="$OUTPUT_DIR/raw"; SITEMAP="$OUTPUT_DIR/sitemap.json"; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-url> [--auth-cookie 'name=value'] [--header 'X-Header: value']"
    exit 1
fi

# Strip trailing slash, get base
TARGET="${TARGET%/}"
BASE_DOMAIN=$(echo "$TARGET" | sed -E 's|https?://([^/]+).*|\1|')

mkdir -p "$OUTPUT_DIR" "$RAW_DIR"

echo "================================================="
echo "  SPIDER TOOL — Attack Surface Discovery"
echo "================================================="
echo "  Target:     $TARGET"
echo "  Domain:     $BASE_DOMAIN"
echo "  Output:     $SITEMAP"
echo "  Auth:       ${AUTH_COOKIE:+Provided}${AUTH_COOKIE:-Unauthenticated}"
echo "================================================="
echo ""

# Build curl args
CURL_ARGS=(-s -L --max-time 15 -A "Mozilla/5.0 (X11; Linux x86_64) bugbounty-spider")
[ -n "$AUTH_COOKIE" ] && CURL_ARGS+=(-b "$AUTH_COOKIE")
[ -n "$EXTRA_HEADER" ] && CURL_ARGS+=(-H "$EXTRA_HEADER")

# Helper: extract URLs from HTML
extract_urls_from_html() {
    local file="$1"
    {
        # href/src attributes
        grep -oE 'href=["'\'']([^"'\'']*)["'\'']' "$file" 2>/dev/null | sed -E 's/href=["'\'']([^"'\'']*)["'\'']/\1/g'
        grep -oE 'src=["'\'']([^"'\'']*)["'\'']' "$file" 2>/dev/null | sed -E 's/src=["'\'']([^"'\'']*)["'\'']/\1/g'
        grep -oE 'action=["'\'']([^"'\'']*)["'\'']' "$file" 2>/dev/null | sed -E 's/action=["'\'']([^"'\'']*)["'\'']/\1/g'
    } | sort -u | grep -v '^#' | grep -v '^javascript:' | grep -v '^mailto:'
}

# Helper: extract endpoints from JS
extract_endpoints_from_js() {
    local file="$1"
    {
        # API patterns in strings
        grep -oE '["'\'']/api/[^"'\'' ]+["'\'']' "$file" 2>/dev/null
        grep -oE '["'\'']/v[0-9]+/[^"'\'' ]+["'\'']' "$file" 2>/dev/null
        grep -oE '["'\'']/graphql[^"'\'' ]*["'\'']' "$file" 2>/dev/null
        # fetch() calls
        grep -oE 'fetch\(["'\''][^"'\'']+["'\'']' "$file" 2>/dev/null | sed -E 's/fetch\(["'\'']([^"'\'']+)["'\'']/\1/g'
        # axios calls
        grep -oE 'axios\.[a-z]+\(["'\''][^"'\'']+["'\'']' "$file" 2>/dev/null | sed -E 's/axios\.[a-z]+\(["'\'']([^"'\'']+)["'\'']/\1/g'
        # Path-like strings
        grep -oE '["'\'']\/[a-z][a-zA-Z0-9_/\-]+["'\'']' "$file" 2>/dev/null
    } | sed 's/["'\'']//g' | sort -u | grep -E '^/[a-z]' | head -200
}

# Helper: detect secrets in JS (TYPE ONLY, not values)
detect_secret_types() {
    local file="$1"
    local types=""
    
    grep -qE '(api[_-]?key|apikey)["'\'': =]+[A-Za-z0-9_\-]{20,}' "$file" 2>/dev/null && types+="api_key_pattern "
    grep -qE 'bearer[ ]+[A-Za-z0-9_\.\-]{20,}' "$file" 2>/dev/null && types+="bearer_token_pattern "
    grep -qE 'aws[_-]?(access[_-]?key|secret)' "$file" 2>/dev/null && types+="aws_credential_pattern "
    grep -qE '(private[_-]?key|BEGIN.{0,20}PRIVATE.{0,20}KEY)' "$file" 2>/dev/null && types+="private_key_pattern "
    grep -qE 'firebase[_-]?(api[_-]?key|database)' "$file" 2>/dev/null && types+="firebase_pattern "
    grep -qE 'stripe[_-]?(secret|live)' "$file" 2>/dev/null && types+="stripe_pattern "
    grep -qE 'mongodb://[^ ]+' "$file" 2>/dev/null && types+="mongodb_uri_pattern "
    grep -qE 'postgres(ql)?://[^ ]+' "$file" 2>/dev/null && types+="postgres_uri_pattern "
    grep -qE 'redis://[^ ]+' "$file" 2>/dev/null && types+="redis_uri_pattern "
    # Internal hostnames
    grep -qE '(\.local|\.internal|localhost|127\.0\.0\.1|10\.[0-9]+|192\.168|172\.(1[6-9]|2[0-9]|3[01]))' "$file" 2>/dev/null && types+="internal_hostname "
    # Debug indicators
    grep -qE 'debug[ =:]+true' "$file" 2>/dev/null && types+="debug_enabled_pattern "
    
    echo "$types"
}

# ============================================================
# STAGE 1: Fetch root, robots.txt, sitemap.xml
# ============================================================
echo "[1/6] Fetching root and well-known files..."

curl "${CURL_ARGS[@]}" -i "$TARGET/" > "$RAW_DIR/root.txt" 2>/dev/null || echo "Root fetch failed"
curl "${CURL_ARGS[@]}" "$TARGET/robots.txt" > "$RAW_DIR/robots.txt" 2>/dev/null || true
curl "${CURL_ARGS[@]}" "$TARGET/sitemap.xml" > "$RAW_DIR/sitemap.xml" 2>/dev/null || true
curl "${CURL_ARGS[@]}" "$TARGET/.well-known/security.txt" > "$RAW_DIR/security.txt" 2>/dev/null || true

# Extract headers
TECH_HEADERS=$(grep -iE "^(Server|X-Powered-By|X-Generator):" "$RAW_DIR/root.txt" 2>/dev/null | head -5 | tr '\n' '|' | sed 's/|/, /g')

# Detect framework from content
FRAMEWORK="unknown"
if grep -qi "react" "$RAW_DIR/root.txt" 2>/dev/null; then FRAMEWORK="react";
elif grep -qi "angular" "$RAW_DIR/root.txt" 2>/dev/null; then FRAMEWORK="angular";
elif grep -qi "vue" "$RAW_DIR/root.txt" 2>/dev/null; then FRAMEWORK="vue";
elif grep -qi "next.js\|_next/" "$RAW_DIR/root.txt" 2>/dev/null; then FRAMEWORK="nextjs";
fi

echo "   Headers: $TECH_HEADERS"
echo "   Framework: $FRAMEWORK"

# ============================================================
# STAGE 2: Crawl pages (BFS, max-pages limit)
# ============================================================
echo "[2/6] Crawling pages (BFS, max $MAX_PAGES pages)..."

declare -A SEEN_URLS
echo "$TARGET/" > "$RAW_DIR/queue.txt"
PAGES_CRAWLED=0
> "$RAW_DIR/discovered_urls.txt"
> "$RAW_DIR/discovered_forms.txt"
> "$RAW_DIR/discovered_js.txt"

while [ -s "$RAW_DIR/queue.txt" ] && [ $PAGES_CRAWLED -lt $MAX_PAGES ]; do
    URL=$(head -1 "$RAW_DIR/queue.txt")
    sed -i '1d' "$RAW_DIR/queue.txt"
    
    [ -n "${SEEN_URLS[$URL]}" ] && continue
    SEEN_URLS[$URL]=1
    
    # Only crawl same domain
    if ! echo "$URL" | grep -q "$BASE_DOMAIN"; then continue; fi
    
    # Skip binaries
    if echo "$URL" | grep -qE '\.(jpg|jpeg|png|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|mp4)$'; then continue; fi
    
    PAGE_FILE="$RAW_DIR/page_$PAGES_CRAWLED.html"
    # || true: one failed page fetch must not kill the loop under `set -e`
    curl "${CURL_ARGS[@]}" "$URL" > "$PAGE_FILE" 2>/dev/null || true

    if [ ! -s "$PAGE_FILE" ]; then continue; fi
    
    PAGES_CRAWLED=$((PAGES_CRAWLED + 1))
    echo "   [$PAGES_CRAWLED] $URL"
    echo "$URL" >> "$RAW_DIR/discovered_urls.txt"
    
    # Extract forms
    grep -oE '<form[^>]*action=["'\''][^"'\'']*["'\''][^>]*>' "$PAGE_FILE" 2>/dev/null | while read form; do
        ACTION=$(echo "$form" | grep -oE 'action=["'\''][^"'\'']*["'\'']' | sed -E 's/action=["'\'']([^"'\'']*)["'\'']/\1/')
        METHOD=$(echo "$form" | grep -oiE 'method=["'\''][^"'\'']*["'\'']' | sed -E 's/method=["'\'']([^"'\'']*)["'\'']/\1/' | tr 'a-z' 'A-Z')
        [ -z "$METHOD" ] && METHOD="GET"
        echo "${METHOD} ${ACTION}" >> "$RAW_DIR/discovered_forms.txt"
    done
    
    # Extract URLs and enqueue
    extract_urls_from_html "$PAGE_FILE" | while read found_url; do
        # Make absolute
        if [[ "$found_url" =~ ^/ ]]; then found_url="${TARGET%/}$found_url"; fi
        if [[ "$found_url" =~ ^https?:// ]]; then
            # JS file?
            if [[ "$found_url" =~ \.js(\?.*)?$ ]]; then
                echo "$found_url" >> "$RAW_DIR/discovered_js.txt"
            else
                echo "$found_url" >> "$RAW_DIR/queue.txt"
            fi
        fi
    done
done

# Deduplicate JS
sort -u "$RAW_DIR/discovered_js.txt" > "$RAW_DIR/discovered_js.unique.txt"
mv "$RAW_DIR/discovered_js.unique.txt" "$RAW_DIR/discovered_js.txt"

JS_COUNT=$(wc -l < "$RAW_DIR/discovered_js.txt" 2>/dev/null || echo 0)
URL_COUNT=$(wc -l < "$RAW_DIR/discovered_urls.txt" 2>/dev/null || echo 0)
FORM_COUNT=$(wc -l < "$RAW_DIR/discovered_forms.txt" 2>/dev/null || echo 0)

echo "   Crawled: $PAGES_CRAWLED pages"
echo "   URLs:    $URL_COUNT"
echo "   Forms:   $FORM_COUNT"
echo "   JS:      $JS_COUNT files discovered"

# ============================================================
# STAGE 3: Download and analyze JS files
# ============================================================
echo "[3/6] Analyzing JavaScript files (max $MAX_JS_FILES)..."

> "$RAW_DIR/js_endpoints.txt"
> "$RAW_DIR/sourcemap_data.jsonl"
> "$RAW_DIR/secrets_types.jsonl"
JS_ANALYZED=0

# Drop malformed JS URLs before the fetch loop:
#   - require absolute http(s) URL
#   - require hostname with at least one dot AND ending in 2+ alpha chars (real TLD)
# This kills false positives like "http://Node.js" that the HTML extractor produces
# from script-text mentions of "Node.js", "React.js", etc.
JS_LIST_FILTERED="$RAW_DIR/discovered_js.filtered.txt"
grep -E '^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)' "$RAW_DIR/discovered_js.txt" > "$JS_LIST_FILTERED" || true
JS_DROPPED=$(($(wc -l < "$RAW_DIR/discovered_js.txt") - $(wc -l < "$JS_LIST_FILTERED")))
[ "$JS_DROPPED" -gt 0 ] && echo "   (filtered out $JS_DROPPED malformed JS URLs)"

while read js_url && [ $JS_ANALYZED -lt $MAX_JS_FILES ]; do
    [ -z "$js_url" ] && continue

    JS_FILE="$RAW_DIR/js_$JS_ANALYZED.js"
    # || true: a single curl failure (DNS, timeout, TLS) must NOT kill the whole script
    # under `set -e`. Empty-file check below handles the failed-fetch case cleanly.
    curl "${CURL_ARGS[@]}" "$js_url" > "$JS_FILE" 2>/dev/null || true

    if [ ! -s "$JS_FILE" ]; then continue; fi
    JS_ANALYZED=$((JS_ANALYZED + 1))
    
    # Extract endpoints
    extract_endpoints_from_js "$JS_FILE" >> "$RAW_DIR/js_endpoints.txt"
    
    # Check for sourcemap
    SOURCEMAP_URL=""
    if grep -q "sourceMappingURL" "$JS_FILE" 2>/dev/null; then
        SM_HINT=$(grep -oE "sourceMappingURL=[^*]+" "$JS_FILE" | head -1 | sed 's/sourceMappingURL=//')
        if [[ "$SM_HINT" =~ ^https?:// ]]; then
            SOURCEMAP_URL="$SM_HINT"
        elif [[ "$SM_HINT" =~ ^/ ]]; then
            SOURCEMAP_URL="${TARGET%/}$SM_HINT"
        else
            JS_DIR=$(dirname "$js_url")
            SOURCEMAP_URL="$JS_DIR/$SM_HINT"
        fi
    else
        SOURCEMAP_URL="${js_url}.map"
    fi
    
    # Try fetching sourcemap
    SM_FILE="$RAW_DIR/sm_$JS_ANALYZED.map"
    SM_STATUS=$(curl "${CURL_ARGS[@]}" -o "$SM_FILE" -w "%{http_code}" "$SOURCEMAP_URL" 2>/dev/null || echo 000)
    SM_AVAILABLE="false"
    SM_FILES_COUNT=0
    if [ "$SM_STATUS" = "200" ] && [ -s "$SM_FILE" ]; then
        # Verify it's actually a sourcemap (has "sources" key)
        if grep -q '"sources"' "$SM_FILE" 2>/dev/null; then
            SM_AVAILABLE="true"
            SM_FILES_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$SM_FILE'))
    print(len(d.get('sources', [])))
except: print(0)
" 2>/dev/null || echo 0)
        fi
    fi
    
    # Detect secret types (NOT values)
    SECRET_TYPES=$(detect_secret_types "$JS_FILE")
    
    # Record JSONL
    JS_SIZE=$(stat -c%s "$JS_FILE" 2>/dev/null || stat -f%z "$JS_FILE" 2>/dev/null || echo 0)
    EP_FROM_THIS=$(extract_endpoints_from_js "$JS_FILE" | wc -l)
    
    python3 -c "
import json
print(json.dumps({
    'url': '$js_url',
    'size': $JS_SIZE,
    'sourcemap_available': '$SM_AVAILABLE' == 'true',
    'sourcemap_url': '$SOURCEMAP_URL' if '$SM_AVAILABLE' == 'true' else None,
    'sourcemap_sources_count': $SM_FILES_COUNT,
    'endpoints_extracted': $EP_FROM_THIS,
    'secret_types_detected': '$SECRET_TYPES'.strip().split() if '$SECRET_TYPES'.strip() else []
}))
" >> "$RAW_DIR/sourcemap_data.jsonl"
done < "$JS_LIST_FILTERED"

sort -u "$RAW_DIR/js_endpoints.txt" > "$RAW_DIR/js_endpoints.unique.txt"
JS_EP_COUNT=$(wc -l < "$RAW_DIR/js_endpoints.unique.txt")
# Use a safe count that always returns a single integer
if [ -s "$RAW_DIR/sourcemap_data.jsonl" ]; then
    SM_AVAILABLE_COUNT=$(grep -c '"sourcemap_available": true' "$RAW_DIR/sourcemap_data.jsonl" 2>/dev/null || true)
else
    SM_AVAILABLE_COUNT=0
fi
# Trim any whitespace/newlines just in case
SM_AVAILABLE_COUNT=$(echo "$SM_AVAILABLE_COUNT" | tr -d '[:space:]')
[ -z "$SM_AVAILABLE_COUNT" ] && SM_AVAILABLE_COUNT=0

echo "   JS files analyzed:    $JS_ANALYZED"
echo "   Endpoints in JS:      $JS_EP_COUNT"
echo "   Source maps found:    $SM_AVAILABLE_COUNT"

# ============================================================
# STAGE 4: Process robots.txt and sitemap.xml
# ============================================================
echo "[4/6] Processing robots.txt and sitemap.xml..."

> "$RAW_DIR/robots_paths.txt"
> "$RAW_DIR/sitemap_paths.txt"

if [ -s "$RAW_DIR/robots.txt" ]; then
    grep -iE "^(Disallow|Allow):" "$RAW_DIR/robots.txt" 2>/dev/null | awk '{print $2}' | grep -v '^$' >> "$RAW_DIR/robots_paths.txt" || true
fi

if [ -s "$RAW_DIR/sitemap.xml" ]; then
    grep -oE '<loc>[^<]+</loc>' "$RAW_DIR/sitemap.xml" 2>/dev/null | sed 's/<\/\?loc>//g' >> "$RAW_DIR/sitemap_paths.txt" || true
fi

ROBOTS_COUNT=$(wc -l < "$RAW_DIR/robots_paths.txt")
SITEMAP_COUNT=$(wc -l < "$RAW_DIR/sitemap_paths.txt")
echo "   robots.txt paths:  $ROBOTS_COUNT"
echo "   sitemap.xml URLs:  $SITEMAP_COUNT"

# ============================================================
# STAGE 5: Consolidate endpoints with parameters
# ============================================================
echo "[5/6] Consolidating endpoint list with parameters..."

# Combine all sources of URLs/endpoints
{
    cat "$RAW_DIR/discovered_urls.txt"
    awk '{print $2}' "$RAW_DIR/discovered_forms.txt"
    cat "$RAW_DIR/js_endpoints.unique.txt"
    cat "$RAW_DIR/robots_paths.txt"
    sed -E "s|https?://$BASE_DOMAIN||" "$RAW_DIR/sitemap_paths.txt"
} | grep -E '^(/|https?://)' | sort -u > "$RAW_DIR/all_paths.txt"

# Normalize and group by endpoint pattern
python3 << PYEOF
import re, json
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

paths = []
with open("$RAW_DIR/all_paths.txt") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        if line.startswith("http"):
            p = urlparse(line)
            paths.append((p.path, parse_qs(p.query)))
        else:
            if "?" in line:
                path, query = line.split("?", 1)
                paths.append((path, parse_qs(query)))
            else:
                paths.append((line, {}))

# Group by normalized path (replace numeric IDs with {id})
endpoint_map = defaultdict(lambda: {"methods": set(), "params_query": set(), "params_path_pattern": []})

for path, query_params in paths:
    # Normalize: replace numeric segments and UUIDs with placeholders
    normalized = re.sub(r'/\d+(?=/|$)', '/{id}', path)
    normalized = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=/|$)', '/{uuid}', normalized, flags=re.I)
    
    endpoint_map[normalized]["methods"].add("GET")  # default
    for q in query_params:
        endpoint_map[normalized]["params_query"].add(q)
    
    # Detect path params
    path_params = []
    if "{id}" in normalized: path_params.append("id")
    if "{uuid}" in normalized: path_params.append("uuid")
    endpoint_map[normalized]["params_path_pattern"] = path_params

# Add forms with their methods
with open("$RAW_DIR/discovered_forms.txt") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        parts = line.split(maxsplit=1)
        if len(parts) < 2: continue
        method, action = parts
        action_path = action if action.startswith("/") else urlparse(action).path
        normalized = re.sub(r'/\d+(?=/|$)', '/{id}', action_path)
        endpoint_map[normalized]["methods"].add(method)

# Convert to list
endpoints = []
for idx, (path, info) in enumerate(sorted(endpoint_map.items())):
    if not path: continue
    endpoints.append({
        "id": f"EP-{idx+1:03d}",
        "path": path,
        "url": f"$TARGET{path}",
        "methods_observed": sorted(info["methods"]),
        "params": {
            "path": info["params_path_pattern"],
            "query": sorted(info["params_query"]),
            "body": [],
            "headers": []
        },
        "auth_required": "unknown",
        "content_type": "unknown"
    })

with open("$RAW_DIR/endpoints.json", "w") as f:
    json.dump(endpoints, f, indent=2)

print(f"   Consolidated endpoints: {len(endpoints)}")
PYEOF

ENDPOINT_COUNT=$(python3 -c "import json; print(len(json.load(open('$RAW_DIR/endpoints.json'))))" 2>/dev/null || echo 0)

# ============================================================
# STAGE 6: Build final sitemap.json
# ============================================================
echo "[6/6] Building final sitemap.json..."

python3 << PYEOF
import json
from datetime import datetime, timezone

# Load all pieces
with open("$RAW_DIR/endpoints.json") as f:
    endpoints = json.load(f)

js_files = []
all_secret_types = set()
with open("$RAW_DIR/sourcemap_data.jsonl") as f:
    for line in f:
        try:
            d = json.loads(line)
            js_files.append(d)
            for s in d.get("secret_types_detected", []):
                all_secret_types.add(s)
        except: continue

# Read tech headers
tech_headers = """$TECH_HEADERS""".strip().rstrip(',').strip()

# Interesting paths from robots
interesting = []
try:
    with open("$RAW_DIR/robots_paths.txt") as f:
        for line in f:
            line = line.strip()
            if line and any(kw in line.lower() for kw in ['admin', 'api', 'internal', 'private', 'staging', 'dev', '.git', 'backup']):
                interesting.append(line)
except: pass

sitemap = {
    "meta": {
        "target": "$TARGET",
        "scanned_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "auth_status": "authenticated" if "$AUTH_COOKIE" else "unauthenticated",
        "framework_detected": "$FRAMEWORK",
        "tech_headers": tech_headers,
        "pages_crawled": $PAGES_CRAWLED,
        "js_files_analyzed": $JS_ANALYZED,
        "sourcemaps_found": $SM_AVAILABLE_COUNT
    },
    "endpoints": endpoints,
    "javascript_files": js_files,
    "secrets_detected_types": sorted(all_secret_types),
    "interesting_paths": interesting,
    "robots_paths_count": $ROBOTS_COUNT,
    "sitemap_xml_paths_count": $SITEMAP_COUNT
}

with open("$SITEMAP", "w") as f:
    json.dump(sitemap, f, indent=2)

print(f"   Sitemap written: $SITEMAP")
print(f"   Total endpoints: {len(endpoints)}")
print(f"   JS files: {len(js_files)}")
print(f"   Source maps: $SM_AVAILABLE_COUNT")
print(f"   Secret types detected: {len(all_secret_types)}")
PYEOF

echo ""
echo "================================================="
echo "  SPIDER COMPLETE"
echo "================================================="
echo "  Output: $SITEMAP"
echo "  Agent reads ONE file, not thousands of curl outputs"
echo "================================================="
