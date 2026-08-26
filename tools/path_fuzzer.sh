#!/bin/bash
# path_fuzzer.sh — Forced Browsing / Hidden Path Discovery
#
# Discovers endpoints NOT linked from HTML/JS — admin panels, debug endpoints,
# legacy APIs, backup files, internal tools. Uses curated wordlists + 
# application-aware mutations based on spider output.
#
# Usage: ./path_fuzzer.sh <target-url> --spider-dir <dir> [--auth-cookie "..."] [--header "..."] [--output-dir <dir>] [--wordlist <file>] [--threads <N>] [--rate-limit <req/s>]

set -e

TARGET=""
SPIDER_DIR=""
AUTH_COOKIE=""
EXTRA_HEADER=""
OUTPUT_DIR=""
WORDLIST=""
THREADS=10
RATE_LIMIT=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --spider-dir) SPIDER_DIR="$2"; shift 2 ;;
        --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
        --header) EXTRA_HEADER="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --wordlist) WORDLIST="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-url> --spider-dir <dir> [--auth-cookie ...] [--header ...] [--output-dir ...] [--threads N] [--rate-limit N]"
    exit 1
fi

TARGET="${TARGET%/}"
BASE_DOMAIN=$(echo "$TARGET" | sed -E 's|https?://([^/]+).*|\1|')
OUTPUT_DIR="${OUTPUT_DIR:-engagement/spider/fuzz}"
mkdir -p "$OUTPUT_DIR"

CURL_ARGS=(-s -o /dev/null -w "%{http_code} %{size_download} %{time_total}" -L --max-time 10 -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
[ -n "$AUTH_COOKIE" ] && CURL_ARGS+=(-b "$AUTH_COOKIE")
[ -n "$EXTRA_HEADER" ] && CURL_ARGS+=(-H "$EXTRA_HEADER")

echo "================================================="
echo "  PATH FUZZER — Hidden Endpoint Discovery"
echo "================================================="
echo "  Target:      $TARGET"
echo "  Spider dir:  $SPIDER_DIR"
echo "  Output:      $OUTPUT_DIR"
echo "  Threads:     $THREADS"
echo "  Rate limit:  ${RATE_LIMIT} req/s"
echo "  Auth:        ${AUTH_COOKIE:+Provided}${AUTH_COOKIE:-Unauthenticated}"
echo "================================================="
echo ""

KNOWN_PATHS_FILE="$OUTPUT_DIR/known_paths.txt"
> "$KNOWN_PATHS_FILE"

if [ -f "$SPIDER_DIR/sitemap.json" ]; then
    python3 -c "
import json
with open('$SPIDER_DIR/sitemap.json') as f:
    sm = json.load(f)
for ep in sm.get('endpoints', []):
    print(ep.get('path', ''))
" | sort -u > "$KNOWN_PATHS_FILE" 2>/dev/null || true
fi

KNOWN_COUNT=$(wc -l < "$KNOWN_PATHS_FILE" 2>/dev/null || echo 0)
echo "  Known paths from spider: $KNOWN_COUNT"

BUILTIN_WORDLIST="$OUTPUT_DIR/_builtin_wordlist.txt"
cat > "$BUILTIN_WORDLIST" << 'WLEOF'
admin
administrator
admin/dashboard
admin/settings
admin/users
admin/logs
admin/config
admin/api
admin/panel
admin/console
admin/login
admin/auth
internal
internal/api
internal/debug
internal/status
internal/health
internal/metrics
internal/config
debug
debug/vars
debug/pprof
debug/requests
debug/events
debug/stats
test
testing
staging
dev
development
backup
backups
bak
old
legacy
archive
tmp
temp
uploads
downloads
exports
imports
files
documents
reports
logs
log
access.log
error.log
audit.log
.env
.env.local
.env.production
.env.staging
.env.backup
.git
.git/HEAD
.git/config
.gitignore
.svn
.svn/entries
.DS_Store
Thumbs.db
WEB-INF/web.xml
META-INF/MANIFEST.MF
server-status
server-info
elmah.axd
trace.axd
actuator
actuator/health
actuator/env
actuator/info
actuator/beans
actuator/configprops
actuator/mappings
actuator/metrics
actuator/threaddump
actuator/heapdump
actuator/loggers
actuator/httptrace
api
api/v1
api/v2
api/v3
api/internal
api/debug
api/admin
api/test
api/health
api/status
api/config
api/swagger.json
api/openapi.json
api/graphql
api/docs
api/schema
graphql
graphql/console
graphql/schema
graphiql
playground
altair
swagger
swagger-ui
swagger-ui.html
swagger-resources
api-docs
docs
redoc
health
healthcheck
health-check
status
status/check
info
metrics
prometheus
ready
live
ping
version
robots.txt
sitemap.xml
humans.txt
security.txt
.well-known/security.txt
.well-known/openid-configuration
.well-known/oauth-authorization-server
.well-known/jwks.json
.well-known/apple-app-site-association
.well-known/assetlinks.json
.well-known/change-password
crossdomain.xml
clientaccesspolicy.xml
phpinfo.php
info.php
test.php
config.php
wp-config.php.bak
wp-login.php
wp-admin
xmlrpc.php
console
manager
jmx-console
web-console
solr
jenkins
hudson
bamboo
gitlab
gitea
gogs
sonarqube
nexus
artifactory
rancher
portainer
grafana
kibana
elasticsearch
kafka
rabbitmq
redis
mongo
phpmyadmin
adminer
setup
install
wizard
onboarding
register
signup
login
auth
oauth
sso
callback
webhook
webhooks
hooks
notify
notifications
events
cron
jobs
queue
worker
scheduler
tasks
batch
bulk
export
import
migrate
migration
seed
WLEOF

API_PREFIXES=()
if [ -f "$SPIDER_DIR/sitemap.json" ]; then
    while IFS= read -r prefix; do
        [ -n "$prefix" ] && API_PREFIXES+=("$prefix")
    done < <(python3 -c "
import json
with open('$SPIDER_DIR/sitemap.json') as f:
    sm = json.load(f)
prefixes = set()
for ep in sm.get('endpoints', []):
    path = ep.get('path', '')
    parts = path.strip('/').split('/')
    if len(parts) >= 2 and parts[0] in ('api', 'v1', 'v2', 'v3', 'internal', 'graphql'):
        prefixes.add('/' + parts[0])
    if len(parts) >= 3:
        prefixes.add('/' + '/'.join(parts[:2]))
for p in sorted(prefixes):
    print(p)
" 2>/dev/null || true)
fi

APP_PATHS_FILE="$OUTPUT_DIR/_app_aware_wordlist.txt"
> "$APP_PATHS_FILE"
for prefix in "${API_PREFIXES[@]}"; do
    for suffix in admin debug test internal config status health metrics logs export import batch bulk users accounts orders payments settings profile search; do
        echo "${prefix}/${suffix}" >> "$APP_PATHS_FILE"
    done
done

ALL_PATHS="$OUTPUT_DIR/_all_paths.txt"
{
    cat "$BUILTIN_WORDLIST"
    [ -f "$APP_PATHS_FILE" ] && cat "$APP_PATHS_FILE"
    [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ] && cat "$WORDLIST"
} | sort -u | grep -v '^$' > "$ALL_PATHS"

TOTAL_PATHS=$(wc -l < "$ALL_PATHS")
echo ""
echo "[1/3] Fuzzing $TOTAL_PATHS paths against $TARGET..."

RESULTS_FILE="$OUTPUT_DIR/fuzz_results.txt"
HIDDEN_FILE="$OUTPUT_DIR/hidden_endpoints.json"
> "$RESULTS_FILE"

DELAY=$(python3 -c "print(1.0 / max(1, $RATE_LIMIT))" 2>/dev/null || echo "0.2")

TESTED=0
FOUND=0

while IFS= read -r path; do
    [ -z "$path" ] && continue
    [ "${path:0:1}" != "/" ] && path="/$path"

    if grep -qFx "$path" "$KNOWN_PATHS_FILE" 2>/dev/null; then
        continue
    fi

    url="${TARGET}${path}"
    result=$(curl "${CURL_ARGS[@]}" "$url" 2>/dev/null || echo "000 0 0")
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')
    time=$(echo "$result" | awk '{print $3}')

    TESTED=$((TESTED + 1))

    if [ "$status" != "000" ] && [ "$status" != "404" ]; then
        echo "$status $size $time $path" >> "$RESULTS_FILE"
        FOUND=$((FOUND + 1))
        echo "   [$FOUND] $status ${size}B $path"
    fi

    if [ $((TESTED % 50)) -eq 0 ]; then
        echo "   Progress: $TESTED/$TOTAL_PATHS tested, $FOUND found"
    fi

    sleep "$DELAY" 2>/dev/null || true

done < "$ALL_PATHS"

echo ""
echo "[2/3] HTTP method probing on discovered endpoints..."

METHODS_FILE="$OUTPUT_DIR/method_results.txt"
> "$METHODS_FILE"

METHODS_TO_TEST=(GET POST PUT PATCH DELETE OPTIONS HEAD)

while IFS=' ' read -r status size time path; do
    [ -z "$path" ] && continue
    url="${TARGET}${path}"
    for method in "${METHODS_TO_TEST[@]}"; do
        [ "$method" = "GET" ] && continue
        m_result=$(curl "${CURL_ARGS[@]}" -X "$method" "$url" 2>/dev/null || echo "000 0 0")
        m_status=$(echo "$m_result" | awk '{print $1}')
        m_size=$(echo "$m_result" | awk '{print $2}')
        if [ "$m_status" != "000" ] && [ "$m_status" != "404" ] && [ "$m_status" != "405" ]; then
            echo "$method $m_status $m_size $path" >> "$METHODS_FILE"
            echo "   $method $m_status ${m_size}B $path"
        fi
        sleep "$DELAY" 2>/dev/null || true
    done
done < "$RESULTS_FILE"

echo ""
echo "[3/3] Building hidden_endpoints.json..."

python3 << PYEOF
import json
from datetime import datetime, timezone

results = []
with open("$RESULTS_FILE") as f:
    for line in f:
        parts = line.strip().split(None, 3)
        if len(parts) < 4: continue
        status, size, time_s, path = parts
        results.append({
            "path": path,
            "url": f"$TARGET{path}",
            "status": int(status),
            "size_bytes": int(size),
            "response_time": float(time_s),
            "methods_found": ["GET"]
        })

with open("$METHODS_FILE") as f:
    for line in f:
        parts = line.strip().split(None, 3)
        if len(parts) < 4: continue
        method, status, size, path = parts
        for r in results:
            if r["path"] == path:
                if method not in r["methods_found"]:
                    r["methods_found"].append(method)
                break

known = set()
try:
    with open("$KNOWN_PATHS_FILE") as f:
        for line in f:
            known.add(line.strip())
except: pass

hidden = [r for r in results if r["path"] not in known]

categories = {
    "admin_panels": [],
    "debug_internal": [],
    "api_endpoints": [],
    "config_exposure": [],
    "backup_files": [],
    "vcs_exposure": [],
    "docs_explorer": [],
    "legacy_old": [],
    "other": []
}

for r in hidden:
    p = r["path"].lower()
    if any(kw in p for kw in ["admin", "panel", "console", "dashboard", "manage"]):
        categories["admin_panels"].append(r)
    elif any(kw in p for kw in ["debug", "internal", "trace", "pprof", "actuator"]):
        categories["debug_internal"].append(r)
    elif any(kw in p for kw in ["/api/", "/v1/", "/v2/", "/v3/", "graphql"]):
        categories["api_endpoints"].append(r)
    elif any(kw in p for kw in [".env", "config", ".bak", "wp-config"]):
        categories["config_exposure"].append(r)
    elif any(kw in p for kw in ["backup", "bak", "old", "archive", "dump"]):
        categories["backup_files"].append(r)
    elif any(kw in p for kw in [".git", ".svn", "HEAD"]):
        categories["vcs_exposure"].append(r)
    elif any(kw in p for kw in ["swagger", "docs", "graphiql", "playground", "redoc", "api-docs"]):
        categories["docs_explorer"].append(r)
    elif any(kw in p for kw in ["legacy", "old", "deprecated"]):
        categories["legacy_old"].append(r)
    else:
        categories["other"].append(r)

output = {
    "meta": {
        "target": "$TARGET",
        "scanned_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "auth_status": "authenticated" if "$AUTH_COOKIE" else "unauthenticated",
        "paths_tested": $TESTED,
        "hidden_found": len(hidden),
        "spider_known_paths": len(known)
    },
    "categories": {k: v for k, v in categories.items() if v},
    "all_hidden": hidden,
    "method_overrides": []
}

with open("$METHODS_FILE") as f:
    for line in f:
        parts = line.strip().split(None, 3)
        if len(parts) < 4: continue
        method, status, size, path = parts
        output["method_overrides"].append({
            "path": path,
            "method": method,
            "status": int(status),
            "size_bytes": int(size)
        })

with open("$HIDDEN_FILE", "w") as f:
    json.dump(output, f, indent=2)

print(f"   Hidden endpoints found: {len(hidden)}")
for cat, items in categories.items():
    if items:
        print(f"     {cat}: {len(items)}")
print(f"   Method overrides: {len(output['method_overrides'])}")
print(f"   Output: $HIDDEN_FILE")
PYEOF

echo ""
echo "================================================="
echo "  PATH FUZZING COMPLETE"
echo "================================================="
echo "  Paths tested:     $TESTED"
echo "  Hidden endpoints:  $FOUND"
echo "  Output: $HIDDEN_FILE"
echo "  Raw results: $RESULTS_FILE"
echo "================================================="
