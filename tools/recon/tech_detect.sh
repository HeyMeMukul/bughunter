#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# tech_detect.sh — Phase 0: Technology Stack Detection
# Fingerprints technologies per subdomain using httpx + wappalyzer + CMS detection.
# =============================================================================

VERSION="1.0.0"
TARGETS_FILE=""
OUTPUT_DIR=""
THREADS=50
TIMEOUT=30

usage() {
    cat <<EOF
Usage: $0 --targets <file> --output-dir <path> [options]

Technology stack detection across all discovered subdomains.

Options:
  --targets <file>       File with live host URLs (one per line) from subdomain_enum.sh
  --output-dir <path>    Output directory (required)
  --threads <N>          Concurrent threads (default: 50)
  --timeout <N>          Timeout per host in seconds (default: 30)
  --help                 Show this help

Output:
  <output-dir>/tech_stack.json    — Technology fingerprint per host
  <output-dir>/tech_summary.txt   — Aggregated technology summary
  <output-dir>/cms_detected.txt   — CMS detections (WordPress, Drupal, etc.)
  <output-dir>/cdn_waf.json       — CDN and WAF detections
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets) TARGETS_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGETS_FILE" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --targets and --output-dir are required"
    usage
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  Phase 0: Technology Stack Detection"
echo "  Targets: $(wc -l < "$TARGETS_FILE") hosts"
echo "============================================"

TMP_DIR=$(mktemp -d -t techdetect-XXXXXXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# =============================================================================
# STAGE 1: httpx Technology Detection
# =============================================================================
echo "[1/5] httpx technology fingerprinting..."

TECH_JSON="$OUTPUT_DIR/tech_stack.json"
CDN_WAF_JSON="$OUTPUT_DIR/cdn_waf.json"

if command -v httpx &>/dev/null; then
    httpx -l "$TARGETS_FILE" -silent \
        -title -tech-detect -status-code -content-length \
        -websocket -ip -cname -cdn -web-server \
        -threads "$THREADS" -timeout "$TIMEOUT" \
        -json -o "$TMP_DIR/httpx_tech.jsonl" 2>/dev/null || true

    if [[ -s "$TMP_DIR/httpx_tech.jsonl" ]]; then
        python3 <<PYEOF > "$TECH_JSON"
import json, sys
from collections import Counter

hosts = {}
all_tech = Counter()
all_servers = Counter()
cdn_hosts = {}

for line in open("${TMP_DIR}/httpx_tech.jsonl"):
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
        url = e.get("url", e.get("input", e.get("host", "unknown")))
        hostname = e.get("host", url)
        tech_list = e.get("tech", [])
        status_code = e.get("status_code", 0)
        title = e.get("title", "")
        content_length = e.get("content_length", 0)
        web_server = e.get("webserver", "")
        cdn = e.get("cdn_name", "")
        ip_addr = e.get("ip", "")

        # Count technologies globally
        for t in tech_list:
            all_tech[t] += 1
        if web_server:
            all_servers[web_server] += 1

        hosts[hostname] = {
            "url": url,
            "ip": ip_addr,
            "status": status_code,
            "title": title,
            "content_length": content_length,
            "technologies": tech_list,
            "web_server": web_server,
            "cdn": cdn,
            "cdn_ips": e.get("cdn_ips", []),
            "websocket": e.get("websocket", False),
            "cnames": e.get("cnames", [])
        }

        if cdn:
            cdn_hosts[hostname] = {
                "cdn": cdn,
                "cdn_ips": e.get("cdn_ips", []),
                "original_ip": ip_addr if ip_addr not in e.get("cdn_ips",[]) else ""
            }
    except (json.JSONDecodeError, KeyError):
        continue

result = {
    "meta": {
        "tool": "tech_detect.sh",
        "version": "${VERSION}",
        "total_hosts": len(hosts)
    },
    "aggregate": {
        "top_technologies": all_tech.most_common(30),
        "top_web_servers": all_servers.most_common(10),
        "cdn_hosts_count": len(cdn_hosts)
    },
    "hosts": hosts
}
json.dump(result, sys.stdout, indent=2)
PYEOF

        # CDN/WAF output
        python3 <<PYEOF > "$CDN_WAF_JSON"
import json

with open("$TECH_JSON") as f:
    data = json.load(f)

cdn_info = {}
for host, info in data.get("hosts", {}).items():
    cdn = info.get("cdn", "")
    if cdn:
        cdn_info[host] = {
            "cdn": cdn,
            "cdn_ips": info.get("cdn_ips", []),
            "waf_hint": "Check headers for WAF (Cloudflare/AWS/Akamai/Imperva)"
        }

waf_indicators = ["cloudflare", "aws", "akamai", "imperva", "sucuri", "fastly", "f5", "barracuda", "fortinet"]
waf_hosts = {}
for host, info in data.get("hosts", {}).items():
    server = info.get("web_server", "").lower()
    for tech in info.get("technologies", []):
        tech_lower = tech.lower()
        for waf in waf_indicators:
            if waf in tech_lower or waf in server:
                waf_hosts[host] = {"detected": waf, "source": tech if waf in tech_lower else server}
                break

result = {
    "cdn_hosts": cdn_info,
    "total_cdn_hosts": len(cdn_info),
    "waf_detected_hosts": waf_hosts,
    "total_waf_hosts": len(waf_hosts)
}
json.dump(result, sys.stdout, indent=2)
PYEOF

        HOST_COUNT=$(python3 -c "import json; d=json.load(open('$TECH_JSON')); print(d.get('meta',{}).get('total_hosts',0))" 2>/dev/null || echo 0)
        echo "  => $HOST_COUNT host technology profiles created"
    else
        echo '{"meta":{"total_hosts":0},"aggregate":{},"hosts":{}}' > "$TECH_JSON"
        echo '{"cdn_hosts":{},"total_cdn_hosts":0,"waf_detected_hosts":{},"total_waf_hosts":0}' > "$CDN_WAF_JSON"
    fi
else
    echo "  [!] httpx not found — using curl fallback..."
    python3 <<PYEOF > "$TECH_JSON"
import json, subprocess, sys

hosts = {}
for line in open("${TARGETS_FILE}"):
    url = line.strip()
    if not url:
        continue
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        headers = dict(resp.headers)
        body = resp.read(20000).decode('utf-8', errors='ignore')
        status = resp.getcode()

        techs = []
        server = headers.get("Server", "")
        if "nginx" in server.lower(): techs.append("nginx")
        if "apache" in server.lower(): techs.append("apache")
        if "cloudflare" in server.lower(): techs.append("cloudflare")
        if "php" in headers.get("X-Powered-By","").lower(): techs.append("php")
        if "wp-content" in body.lower() or "wp-json" in body.lower(): techs.append("wordpress")
        if "react" in body.lower(): techs.append("react")
        if "vue" in body.lower(): techs.append("vue")
        if "django" in body.lower(): techs.append("django")
        if "laravel" in body.lower(): techs.append("laravel")

        hosts[url] = {
            "url": url, "status": status, "technologies": techs,
            "web_server": server, "title": (body.split("<title>")[1].split("</title>")[0] if "<title>" in body else "")
        }
    except Exception as e:
        hosts[url] = {"url": url, "status": 0, "technologies": [], "error": str(e)}

result = {"meta": {"total_hosts": len(hosts)}, "hosts": hosts}
json.dump(result, sys.stdout, indent=2)
PYEOF
    echo '{"cdn_hosts":{},"total_cdn_hosts":0,"waf_detected_hosts":{},"total_waf_hosts":0}' > "$CDN_WAF_JSON"
fi

# =============================================================================
# STAGE 2: CMS Detection
# =============================================================================
echo "[2/5] CMS detection..."

CMS_FILE="$OUTPUT_DIR/cms_detected.txt"
> "$CMS_FILE"

if command -v cmseek &>/dev/null; then
    echo "  [*] CMSeeK scanning..."
    while read -r url; do
        [[ -z "$url" ]] && continue
        cmseek -u "$url" --random-agent --batch 2>/dev/null | tee -a "$CMS_FILE" || true
    done < <(head -20 "$TARGETS_FILE")
elif command -v whatweb &>/dev/null; then
    echo "  [*] WhatWeb scanning..."
    whatweb -i "$TARGETS_FILE" --no-errors -a 3 2>/dev/null > "$CMS_FILE" || true
else
    # Python-based CMS fingerprinting
    python3 <<PYEOF > "$CMS_FILE"
import json, re, urllib.request, ssl

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

cms_patterns = {
    "wordpress": [r"wp-content", r"wp-includes", r"wp-json", r'name="generator" content="WordPress'],
    "drupal": [r"Drupal", r"sites/all", r"sites/default"],
    "joomla": [r"Joomla", r"com_content", r"com_users"],
    "magento": [r"Magento", r"mage/", r"skin/frontend"],
    "shopify": [r"shopify", r"cdn\.shopify\.com"],
    "wix": [r"wix\.com", r"static\.wixstatic\.com"],
    "squarespace": [r"squarespace\.com", r"templateId.*squarespace"],
    "ghost": [r"ghost\.org", r'name="generator" content="Ghost'],
    "django": [r"django", r"csrftoken"],
    "rails": [r"rails", r'name="csrf-param"'],
    "laravel": [r"laravel", r'name="csrf-token"'],
    "express": [r"x-powered-by.*express", r"etag"],
    "nextjs": [r'__NEXT_DATA__', r'/_next/', r'__next'],
    "gatsby": [r'___gatsby', r'gatsby'],
    "flask": [r"flask", r"werkzeug"],
    "spring": [r"spring", r"_csrf"],
    "aspnet": [r"asp\.net", r"__VIEWSTATE", r"__RequestVerificationToken"],
}

print("CMS Detection Results")
print("=" * 60)

for line in open("${TARGETS_FILE}"):
    url = line.strip()
    if not url:
        continue
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=10)
        headers = str(resp.headers)
        body = resp.read(50000).decode('utf-8', errors='ignore').lower()

        detected = []
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                    detected.append(cms)
                    break

        if detected:
            print(f"\n{url}")
            for d in set(detected):
                print(f"  [+] {d}")
    except Exception as e:
        print(f"\n{url}\n  [!] Error: {e}")
        continue
PYEOF
fi

CMS_COUNT=$(grep -c '\[+\]' "$CMS_FILE" 2>/dev/null || echo 0)
echo "  => $CMS_COUNT CMS detections"

# =============================================================================
# STAGE 3: API & Framework Detection
# =============================================================================
echo "[3/5] API & framework detection..."

python3 <<PYEOF > "$OUTPUT_DIR/api_frameworks.json"
import json, re, urllib.request, ssl

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

api_patterns = {
    "graphql": [r"graphql", r"__schema", r'"data":{'],
    "swagger": [r"swagger", r"/swagger-ui", r"swagger\.json", r"swagger\.yml"],
    "openapi": [r"openapi:|\"openapi\"", r"/api-docs", r"/v3/api-docs"],
    "rest": [r"/api/", r"application/json"],
    "soap": [r"soap", r"wsdl", r"text/xml.*soap"],
    "grpc": [r"grpc", r"application/grpc"],
    "firebase": [r"firebaseio\.com", r"firestore", r"firebase\.app"],
    "supabase": [r"supabase\.co", r"supabase"],
    "strapi": [r"strapi", r"/content-manager"],
    "hasura": [r"hasura", r"x-hasura"],
}

results = {}
for line in open("${TARGETS_FILE}"):
    url = line.strip()
    if not url:
        continue
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=10)
        body = resp.read(30000).decode('utf-8', errors='ignore')
        headers = str(resp.headers)

        detected = []
        for api, patterns in api_patterns.items():
            for p in patterns:
                if re.search(p, body, re.IGNORECASE) or re.search(p, headers, re.IGNORECASE):
                    detected.append(api)
                    break

        if detected:
            results[url] = list(set(detected))
    except:
        continue

print(json.dumps({"total_api_frameworks_found": len(results), "hosts": results}, indent=2))
PYEOF

API_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/api_frameworks.json')); print(d.get('total_api_frameworks_found',0))" 2>/dev/null || echo 0)
echo "  => $API_COUNT hosts with API/framework signatures"

# =============================================================================
# STAGE 4: Favicon Hash Recon
# =============================================================================
echo "[4/5] Favicon analysis..."

python3 <<PYEOF > "$OUTPUT_DIR/favicon_hashes.json"
import json, hashlib, urllib.request, ssl, base64

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Known favicon hashes for common technologies
KNOWN_HASHES = {
    "-1589117666": "jira",
    "-1391569864": "atlassian_confluence",
    "708578229": "wordpress",
    "116323821": "spring_boot",
    "-1190075052": "apache_tomcat",
    "-10974981": "jenkins",
    "252728887": "grafana",
    "1278323681": "gitlab",
    "-182423204": "phpmyadmin",
    "2068154487": "drupal",
    "-699916087": "magento",
    "180732987": "apache",
    "81586312": "nginx",
    "-180573259": "bootstrap",
    "699620261": "react",
    "177181369": "vue",
}

results = {}
for line in open("${TARGETS_FILE}"):
    url = line.strip()
    if not url:
        continue
    try:
        favicon_url = url.rstrip("/") + "/favicon.ico"
        req = urllib.request.Request(favicon_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
        data = resp.read()

        # MurmurHash3-like simple hash
        import struct
        h = 0
        for b in data:
            h = ((h << 5) - h + b) & 0xFFFFFFFF
        h = h if h < 0x80000000 else h - 0x100000000

        tech_match = KNOWN_HASHES.get(str(h), "unknown")
        results[url] = {
            "favicon_hash": h,
            "matched_technology": tech_match,
            "favicon_size": len(data)
        }
    except:
        continue

print(json.dumps({"total_favicons_checked": len(results), "hosts": results}, indent=2))
PYEOF

FAVICON_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/favicon_hashes.json')); print(d.get('total_favicons_checked',0))" 2>/dev/null || echo 0)
echo "  => $FAVICON_COUNT favicons analyzed"

# =============================================================================
# STAGE 5: Technology Summary
# =============================================================================
echo "[5/5] Generating technology summary..."

python3 <<PYEOF > "$OUTPUT_DIR/tech_summary.txt"
import json
from collections import Counter

summary = []
summary.append("=" * 70)
summary.append("  TECHNOLOGY STACK SUMMARY")
summary.append("=" * 70)

try:
    with open("$TECH_JSON") as f:
        data = json.load(f)

    agg = data.get("aggregate", {})
    summary.append(f"\nTotal Hosts Analyzed: {data['meta']['total_hosts']}")

    summary.append("\n--- Top Technologies ---")
    for tech, count in agg.get("top_technologies", [])[:15]:
        summary.append(f"  {tech}: {count} hosts")

    summary.append("\n--- Web Servers ---")
    for server, count in agg.get("top_web_servers", [])[:10]:
        summary.append(f"  {server}: {count} hosts")

    summary.append(f"\nCDN-Protected Hosts: {agg.get('cdn_hosts_count', 0)}")

    # Extract unique technology stack for quick reference
    all_tech_set = set()
    for host_info in data.get("hosts", {}).values():
        for tech in host_info.get("technologies", []):
            all_tech_set.add(tech)

    summary.append("\n--- Unique Technologies Detected ---")
    for tech in sorted(all_tech_set):
        summary.append(f"  - {tech}")

    # Identify attack surface
    summary.append("\n--- Attack Surface Insights ---")
    tech_str = " ".join(all_tech_set).lower()
    if "react" in tech_str or "vue" in tech_str or "angular" in tech_str:
        summary.append("  [+] SPA Framework detected — JavaScript-heavy app (check source maps, API calls)")
    if "wordpress" in tech_str:
        summary.append("  [+] WordPress detected — check wp-json, xmlrpc, plugin enumeration")
    if "graphql" in tech_str:
        summary.append("  [+] GraphQL detected — test introspection, batching, depth limits")
    if "firebase" in tech_str:
        summary.append("  [+] Firebase detected — check misconfigured databases, auth rules")
    if "spring" in tech_str:
        summary.append("  [+] Spring Boot detected — check actuator endpoints, SpEL injection")
    if "nginx" in tech_str:
        summary.append("  [+] Nginx detected — check path traversal, alias misconfig, SSI")
    if "aws" in tech_str or "cloudfront" in tech_str:
        summary.append("  [+] AWS detected — check S3 buckets, IMDS access, Cognito misconfig")
    if "laravel" in tech_str:
        summary.append("  [+] Laravel detected — check .env exposure, debug mode, deserialization")

except Exception as e:
    summary.append(f"[!] Error reading tech stack: {e}")

print("\n".join(summary))
PYEOF

echo ""
echo "============================================"
echo "  PHASE 0: TECH DETECTION COMPLETE"
echo "  Tech Stack: $OUTPUT_DIR/tech_stack.json"
echo "  CDN/WAF: $OUTPUT_DIR/cdn_waf.json"
echo "  CMS: $OUTPUT_DIR/cms_detected.txt"
echo "  Summary: $OUTPUT_DIR/tech_summary.txt"
echo "============================================"
