#!/bin/bash
# spider_comprehension.sh — Deep application comprehension companion to spider.sh
#
# Runs AFTER spider.sh and consumes its output. Performs the deeper recovery
# that converts "we found endpoints" into "we understand the application":
#   - Source map full recovery (reconstructs original source from .js.map)
#   - Webpack chunk enumeration (numbered chunks not referenced by entry bundle)
#   - Service worker analysis (sw.js often contains API route table)
#   - /.well-known/ probing (security.txt, openid-configuration, etc.)
#   - Swagger / OpenAPI / GraphQL introspection discovery
#   - CSP trusted-hosts extraction (third-party trust map for chaining)
#   - Archive.org wayback enumeration (historical endpoints)
#
# Output: engagement/spider/<auth|unauth>/understanding/
#
# Usage: ./spider_comprehension.sh <spider-output-dir> [--target https://target.com] [--auth-cookie "..."] [--header "X-..."]

set -e

SPIDER_DIR=""
TARGET=""
AUTH_COOKIE=""
EXTRA_HEADER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
        --header) EXTRA_HEADER="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        *) SPIDER_DIR="$1"; shift ;;
    esac
done

if [ -z "$SPIDER_DIR" ] || [ ! -d "$SPIDER_DIR" ]; then
    echo "Usage: $0 <spider-output-dir> [--target https://target.com] [--auth-cookie ...] [--header ...]"
    echo "Example: $0 engagement/spider/auth --target https://target.com --auth-cookie \"sess=abc\" --header \"X-Comolho-Client: handle\""
    exit 1
fi

# Infer target from sitemap if not provided
if [ -z "$TARGET" ] && [ -f "$SPIDER_DIR/sitemap.json" ]; then
    TARGET=$(python3 -c "import json; print(json.load(open('$SPIDER_DIR/sitemap.json'))['meta']['target'])" 2>/dev/null || echo "")
fi

if [ -z "$TARGET" ]; then
    echo "ERROR: could not determine target. Pass --target."
    exit 1
fi

BASE_DOMAIN=$(echo "$TARGET" | sed -E 's|https?://([^/]+).*|\1|')
UNDERSTANDING="$SPIDER_DIR/understanding"
RAW_DIR="$SPIDER_DIR/raw"
mkdir -p "$UNDERSTANDING"/{sources,webpack_chunks,well_known,api_specs,wayback,trust_map}

# Build curl args
CURL_ARGS=(-s -L --max-time 15 -A "Mozilla/5.0 (X11; Linux x86_64) bugbounty-comprehension")
[ -n "$AUTH_COOKIE" ] && CURL_ARGS+=(-H "Cookie: $AUTH_COOKIE")
[ -n "$EXTRA_HEADER" ] && CURL_ARGS+=(-H "$EXTRA_HEADER")

echo "================================================="
echo "  SPIDER COMPREHENSION"
echo "  Target: $TARGET"
echo "  Spider dir: $SPIDER_DIR"
echo "  Output: $UNDERSTANDING"
echo "================================================="
echo ""

# ============================================================
# STAGE 1: Source Map Full Recovery
# ============================================================
# spider.sh records that .map files exist. This stage RECOVERS the original
# source files from them so the agent can read the actual application code.
echo "[1/7] Source map full recovery..."

SM_RECOVERED=0
if [ -d "$RAW_DIR" ]; then
    for sm in "$RAW_DIR"/sm_*.map; do
        [ -s "$sm" ] || continue
        sm_name=$(basename "$sm" .map)
        out_dir="$UNDERSTANDING/sources/$sm_name"
        mkdir -p "$out_dir"
        python3 << PYEOF
import json, os, sys

try:
    with open("$sm") as f:
        sm_data = json.load(f)
    sources = sm_data.get("sources", [])
    sources_content = sm_data.get("sourcesContent", [])
    if not sources_content:
        # No embedded source; just write the file list
        with open("$out_dir/_file_list.txt", "w") as f:
            f.write("\n".join(sources))
        sys.exit(0)
    written = 0
    for i, (src_path, src_content) in enumerate(zip(sources, sources_content)):
        if src_content is None:
            continue
        # Sanitize the path
        clean = src_path.replace("webpack:///", "").replace("webpack://", "")
        clean = clean.lstrip("./").replace("..", "_dotdot_")
        # Skip node_modules unless it's a workspace-internal package
        if "node_modules" in clean and not clean.startswith("./packages/"):
            continue
        full_path = os.path.join("$out_dir", clean)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        try:
            with open(full_path, "w") as f:
                f.write(src_content)
            written += 1
        except OSError:
            pass
    print(f"   $sm_name: recovered {written}/{len(sources)} source files")
except Exception as e:
    print(f"   $sm_name: recovery failed ({e})", file=sys.stderr)
PYEOF
        SM_RECOVERED=$((SM_RECOVERED + 1))
    done
fi
echo "   Total source maps processed: $SM_RECOVERED"

# Build a quick index of what was recovered
find "$UNDERSTANDING/sources" -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" -o -name "*.vue" \) 2>/dev/null \
    | head -500 > "$UNDERSTANDING/sources/_index.txt" || true
SOURCE_FILES=$(wc -l < "$UNDERSTANDING/sources/_index.txt" 2>/dev/null || echo 0)
echo "   Total recovered source files: $SOURCE_FILES"

# ============================================================
# STAGE 2: Webpack Chunk Enumeration
# ============================================================
# React/Angular/Vue apps emit numbered chunks (0.js, 1.chunk.js, main.abc123.js).
# The entry bundle references some by name, but lazy-loaded chunks are only
# referenced by chunk ID in webpack's runtime config. Enumerate those.
echo "[2/7] Webpack chunk enumeration..."

WEBPACK_CHUNKS=0
if [ -d "$RAW_DIR" ]; then
    # Extract chunk references from existing JS files
    grep -hoE '"[0-9a-f]+":"[0-9a-f]+"' "$RAW_DIR"/js_*.txt 2>/dev/null \
        | sort -u > "$UNDERSTANDING/webpack_chunks/chunk_map.txt" 2>/dev/null || true

    # Extract chunk path patterns (e.g., "static/js/[id].chunk.js")
    grep -hoE 'static/js/[A-Za-z0-9_./-]+\.chunk\.js' "$RAW_DIR"/js_*.txt 2>/dev/null \
        | sort -u > "$UNDERSTANDING/webpack_chunks/chunk_patterns.txt" 2>/dev/null || true

    # Try to fetch numbered chunks (common range: 0-50)
    chunk_base=$(grep -ohE 'https?://[^"]+/static/js/' "$RAW_DIR"/js_*.txt 2>/dev/null | head -1 | tr -d '"')
    if [ -n "$chunk_base" ]; then
        echo "   Trying chunk enumeration at $chunk_base"
        for i in $(seq 0 50); do
            for ext in ".chunk.js" ".js"; do
                url="${chunk_base}${i}${ext}"
                status=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo 000)
                if [ "$status" = "200" ]; then
                    # || true: download must not kill the loop under `set -e` if the chunk
                    # disappears between the HEAD-equivalent probe and this GET
                    curl "${CURL_ARGS[@]}" -o "$UNDERSTANDING/webpack_chunks/chunk_${i}${ext}" "$url" 2>/dev/null || true
                    WEBPACK_CHUNKS=$((WEBPACK_CHUNKS + 1))
                fi
            done
        done
    fi
fi
echo "   Webpack chunks recovered: $WEBPACK_CHUNKS"

# ============================================================
# STAGE 3: Service Worker Analysis
# ============================================================
# sw.js often contains the application's API route table because the
# service worker needs to know which URLs to cache vs pass through.
echo "[3/7] Service worker analysis..."

SW_FOUND=0
for sw_path in "/sw.js" "/service-worker.js" "/firebase-messaging-sw.js" "/workbox-sw.js"; do
    url="${TARGET}${sw_path}"
    status=$(curl "${CURL_ARGS[@]}" -o "$UNDERSTANDING/well_known/sw_$(echo $sw_path | tr / _).js" -w "%{http_code}" "$url" 2>/dev/null || echo 000)
    if [ "$status" = "200" ]; then
        SW_FOUND=$((SW_FOUND + 1))
        echo "   Found: $sw_path"
    else
        rm -f "$UNDERSTANDING/well_known/sw_$(echo $sw_path | tr / _).js"
    fi
done
echo "   Service workers found: $SW_FOUND"

# ============================================================
# STAGE 4: /.well-known/ Probing
# ============================================================
# Standardized endpoints under /.well-known/ — most are info disclosure but
# openid-configuration is a goldmine for OAuth chain construction.
echo "[4/7] /.well-known/ probing..."

WK_FOUND=0
WK_PATHS=(
    "/.well-known/security.txt"
    "/.well-known/openid-configuration"
    "/.well-known/oauth-authorization-server"
    "/.well-known/jwks.json"
    "/.well-known/apple-app-site-association"
    "/.well-known/assetlinks.json"
    "/.well-known/change-password"
    "/.well-known/host-meta"
    "/.well-known/webfinger"
    "/.well-known/nodeinfo"
    "/.well-known/matrix/server"
    "/.well-known/openid-federation"
)
for path in "${WK_PATHS[@]}"; do
    out_name=$(echo "$path" | tr / _)
    url="${TARGET}${path}"
    status=$(curl "${CURL_ARGS[@]}" -o "$UNDERSTANDING/well_known/${out_name}" -w "%{http_code}" "$url" 2>/dev/null || echo 000)
    if [ "$status" = "200" ]; then
        size=$(stat -c%s "$UNDERSTANDING/well_known/${out_name}" 2>/dev/null || stat -f%z "$UNDERSTANDING/well_known/${out_name}" 2>/dev/null || echo 0)
        if [ "$size" -gt 10 ]; then
            WK_FOUND=$((WK_FOUND + 1))
            echo "   Found: $path ($size bytes)"
        else
            rm -f "$UNDERSTANDING/well_known/${out_name}"
        fi
    else
        rm -f "$UNDERSTANDING/well_known/${out_name}"
    fi
done
echo "   /.well-known endpoints found: $WK_FOUND"

# ============================================================
# STAGE 5: API Spec Discovery
# ============================================================
# Swagger, OpenAPI, GraphQL introspection — discoverable spec files often
# expose every endpoint and its auth requirements. When present, this is
# the single highest-value recon output.
echo "[5/7] API specification discovery..."

API_SPECS=0
SPEC_PATHS=(
    "/swagger.json"
    "/swagger.yaml"
    "/swagger/v1/swagger.json"
    "/api/swagger.json"
    "/v1/swagger.json"
    "/openapi.json"
    "/openapi.yaml"
    "/api/openapi.json"
    "/api-docs"
    "/api-docs.json"
    "/api/api-docs"
    "/swagger-ui.html"
    "/swagger-ui/"
    "/docs"
    "/docs/"
    "/api/docs"
    "/redoc"
    "/graphql"
    "/api/graphql"
    "/v1/graphql"
    "/graphiql"
    "/playground"
    "/altair"
)
for path in "${SPEC_PATHS[@]}"; do
    out_name=$(echo "$path" | tr / _ | tr -d '?&')
    url="${TARGET}${path}"
    status=$(curl "${CURL_ARGS[@]}" -o "$UNDERSTANDING/api_specs/${out_name}" -w "%{http_code}" "$url" 2>/dev/null || echo 000)
    if [ "$status" = "200" ] || [ "$status" = "401" ]; then
        size=$(stat -c%s "$UNDERSTANDING/api_specs/${out_name}" 2>/dev/null || stat -f%z "$UNDERSTANDING/api_specs/${out_name}" 2>/dev/null || echo 0)
        if [ "$size" -gt 50 ]; then
            API_SPECS=$((API_SPECS + 1))
            echo "   Found: $path ($status, $size bytes)"
        else
            rm -f "$UNDERSTANDING/api_specs/${out_name}"
        fi
    else
        rm -f "$UNDERSTANDING/api_specs/${out_name}"
    fi
done

# Try GraphQL introspection if a /graphql endpoint responded
if [ -s "$UNDERSTANDING/api_specs/_graphql" ] || [ -s "$UNDERSTANDING/api_specs/_api_graphql" ]; then
    GQL_URL="${TARGET}/graphql"
    echo "   Probing GraphQL introspection..."
    curl "${CURL_ARGS[@]}" -X POST -H "Content-Type: application/json" \
        -d '{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind}} type{name kind}}}}}"}' \
        "$GQL_URL" -o "$UNDERSTANDING/api_specs/graphql_introspection.json" 2>/dev/null || true
    if [ -s "$UNDERSTANDING/api_specs/graphql_introspection.json" ]; then
        # Validate it's actually a schema, not an error
        if grep -q "__schema" "$UNDERSTANDING/api_specs/graphql_introspection.json" 2>/dev/null; then
            echo "   GraphQL introspection: ENABLED (chain primitive)"
            API_SPECS=$((API_SPECS + 1))
        else
            rm -f "$UNDERSTANDING/api_specs/graphql_introspection.json"
        fi
    fi
fi
echo "   API specs/docs/explorers found: $API_SPECS"

# ============================================================
# STAGE 6: CSP Trusted-Hosts Extraction (Third-Party Trust Map)
# ============================================================
# The CSP header lists every domain the app trusts to load scripts/frames/etc.
# This is the third-party trust map — every hostname here is a potential
# chain amplifier if compromised, taken over, or has its own bugs.
echo "[6/7] CSP trusted-hosts extraction..."

if [ -f "$RAW_DIR/root.txt" ]; then
    python3 << PYEOF > "$UNDERSTANDING/trust_map/csp_trusted_hosts.txt"
import re

with open("$RAW_DIR/root.txt") as f:
    content = f.read()

# Find CSP header (case-insensitive)
csp_match = re.search(r'(?i)content-security-policy(-report-only)?:\s*([^\r\n]+)', content)
if not csp_match:
    print("# No CSP header found")
else:
    csp = csp_match.group(2)
    # Extract host sources
    directives = {}
    for d in csp.split(";"):
        d = d.strip()
        if not d: continue
        parts = d.split(None, 1)
        if len(parts) < 2: continue
        directive, sources = parts
        hosts = re.findall(r'[a-zA-Z0-9*][a-zA-Z0-9.*-]+\.[a-zA-Z]+', sources)
        if hosts:
            directives[directive] = hosts

    print("# CSP Trusted Hosts — Third-Party Trust Map")
    print(f"# Extracted from CSP header on $TARGET")
    print()
    all_hosts = set()
    for directive, hosts in directives.items():
        print(f"## {directive}")
        for h in sorted(set(hosts)):
            print(f"  {h}")
            all_hosts.add(h)
        print()
    
    # Subdomain takeover candidates: hosts on the target's own domain tree
    print("## TARGET SUBDOMAIN CHAIN CANDIDATES")
    target_base = "$BASE_DOMAIN".lstrip("www.")
    for h in sorted(all_hosts):
        if target_base in h and h != target_base:
            print(f"  {h}  ← if takeover possible, becomes CSP bypass amplifier")
    print()
    
    # Third-party amplifiers
    print("## THIRD-PARTY AMPLIFIERS")
    print("# Any of these compromised externally → chain primitive available in $TARGET")
    for h in sorted(all_hosts):
        if "$BASE_DOMAIN" not in h and not h.startswith("*"):
            print(f"  {h}")
PYEOF
    CSP_HOSTS=$(grep -cE "^  [a-z*]" "$UNDERSTANDING/trust_map/csp_trusted_hosts.txt" 2>/dev/null || true)
    CSP_HOSTS=$(echo "$CSP_HOSTS" | tr -d '[:space:]')
    [ -z "$CSP_HOSTS" ] && CSP_HOSTS=0
    echo "   CSP trusted hosts extracted: $CSP_HOSTS"
else
    echo "   No root.txt available — skipping CSP extraction"
    CSP_HOSTS=0
fi

# ============================================================
# STAGE 7: Archive.org Wayback Enumeration
# ============================================================
# Historical endpoints — features removed from the app but still
# reachable, or endpoints whose names changed but old versions still exist.
echo "[7/7] Archive.org wayback enumeration..."

WAYBACK_URL="https://web.archive.org/cdx/search/cdx?url=${BASE_DOMAIN}/*&output=json&fl=original&collapse=urlkey&limit=2000"
curl -s --max-time 30 "$WAYBACK_URL" 2>/dev/null \
    | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    urls = [row[0] for row in data[1:]] if len(data) > 1 else []
    print('\n'.join(sorted(set(urls))))
except Exception as e:
    print('# Wayback enumeration failed:', e, file=sys.stderr)
" 2>/dev/null > "$UNDERSTANDING/wayback/historical_urls.txt" || true

WAYBACK_COUNT=$(wc -l < "$UNDERSTANDING/wayback/historical_urls.txt" 2>/dev/null || echo 0)
echo "   Historical URLs found: $WAYBACK_COUNT"

# Filter to interesting ones (admin, api, internal, etc.)
if [ -f "$UNDERSTANDING/wayback/historical_urls.txt" ]; then
    grep -iE "(admin|api|internal|debug|test|staging|dev|backup|export|download|/v[0-9]+/)" \
        "$UNDERSTANDING/wayback/historical_urls.txt" 2>/dev/null \
        | head -200 > "$UNDERSTANDING/wayback/historical_interesting.txt" || true
    INTERESTING=$(wc -l < "$UNDERSTANDING/wayback/historical_interesting.txt" 2>/dev/null || echo 0)
    echo "   Of which interesting: $INTERESTING"
fi

# ============================================================
# UNDERSTANDING SUMMARY
# ============================================================
echo ""
echo "[*] Building understanding.json summary..."

python3 << PYEOF
import json, os
from datetime import datetime, timezone

summary = {
    "meta": {
        "target": "$TARGET",
        "comprehension_completed_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "spider_dir": "$SPIDER_DIR"
    },
    "source_recovery": {
        "source_maps_processed": $SM_RECOVERED,
        "source_files_recovered": $SOURCE_FILES,
        "index_file": "understanding/sources/_index.txt"
    },
    "webpack_chunks_recovered": $WEBPACK_CHUNKS,
    "service_workers_found": $SW_FOUND,
    "well_known_endpoints_found": $WK_FOUND,
    "api_specs_found": $API_SPECS,
    "csp_trusted_hosts": $CSP_HOSTS,
    "wayback_historical_urls": $WAYBACK_COUNT,
    "agent_reading_priority": [
        "understanding/api_specs/  ← spec files reveal full endpoint catalog with auth",
        "understanding/sources/    ← reconstructed app source code, search for routes/role names/secrets",
        "understanding/trust_map/csp_trusted_hosts.txt  ← third-party amplifiers for chain synthesis",
        "understanding/well_known/openid-configuration  ← OAuth chain construction",
        "understanding/wayback/historical_interesting.txt  ← removed endpoints worth probing",
        "understanding/well_known/sw*.js  ← service workers often contain API route tables"
    ]
}

with open("$UNDERSTANDING/understanding.json", "w") as f:
    json.dump(summary, f, indent=2)
PYEOF

echo ""
echo "================================================="
echo "  COMPREHENSION COMPLETE"
echo "================================================="
echo "  Output: $UNDERSTANDING/"
echo "  Summary: $UNDERSTANDING/understanding.json"
echo ""
echo "  Source files recovered: $SOURCE_FILES"
echo "  Webpack chunks: $WEBPACK_CHUNKS"
echo "  Service workers: $SW_FOUND"
echo "  /.well-known: $WK_FOUND"
echo "  API specs/docs: $API_SPECS"
echo "  CSP trusted hosts: $CSP_HOSTS"
echo "  Wayback historical: $WAYBACK_COUNT"
echo "================================================="
echo ""
echo "Next: Mapping phase (skills/mapping/) consumes both sitemap.json AND understanding/"
