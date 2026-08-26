#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# master_recon.sh — Phase 0 Orchestrator
# Runs all 4 recon tools and produces a unified recon.json summary.
# =============================================================================

VERSION="1.0.0"
TARGET=""
OUTPUT_DIR=""
SKIP_SUBDOMAIN="false"
SKIP_PORTS="false"
SKIP_TECH="false"
SKIP_CLOUD="false"
ALL_TARGETS_FILE=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 --target <domain> --output-dir <path> [options]

Master Phase 0 orchestrator — runs all infrastructure reconnaissance tools.

Options:
  --target <domain>        Target domain (required)
  --output-dir <path>      Base engagement output directory (required)
  --skip-subdomain         Skip subdomain enumeration
  --skip-ports             Skip port scanning
  --skip-tech              Skip technology detection
  --skip-cloud             Skip cloud enumeration
  --help                   Show this help

Phase 0 Pipeline:
  1. subdomain_enum.sh  → engagement/recon/subdomains/
  2. port_scan.sh       → engagement/recon/ports/
  3. tech_detect.sh     → engagement/recon/tech/
  4. cloud_enum.sh      → engagement/recon/cloud/
  5. Recon summary      → engagement/recon/recon.json (unified)

Output: engagement/recon/recon.json — single source of truth for Phase 0
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-subdomain) SKIP_SUBDOMAIN="true"; shift ;;
        --skip-ports) SKIP_PORTS="true"; shift ;;
        --skip-tech) SKIP_TECH="true"; shift ;;
        --skip-cloud) SKIP_CLOUD="true"; shift ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --target and --output-dir are required"
    usage
fi

RECON_DIR="$OUTPUT_DIR/recon"
mkdir -p "$RECON_DIR"/{subdomains,ports,tech,cloud}
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 0: INFRASTRUCTURE RECONNAISSANCE                     ║"
echo "║  Target: $TARGET"
echo "║  Output: $RECON_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

START_TIME=$(date +%s)

# =============================================================================
# STEP 1: Subdomain Enumeration
# =============================================================================
if [[ "$SKIP_SUBDOMAIN" == "false" ]]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP 1/5: Subdomain Enumeration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    bash "$SCRIPT_DIR/subdomain_enum.sh" \
        --target "$TARGET" \
        --output-dir "$RECON_DIR/subdomains" \
        --recursive

    ALIVE_HOSTS="$RECON_DIR/subdomains/alive_hosts.txt"
    ALL_TARGETS_FILE="$ALIVE_HOSTS"
else
    echo "[SKIP] Subdomain enumeration"
fi

# =============================================================================
# STEP 2: Port Scanning
# =============================================================================
if [[ "$SKIP_PORTS" == "false" && -n "$ALL_TARGETS_FILE" && -f "$ALL_TARGETS_FILE" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP 2/5: Port Scanning"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    bash "$SCRIPT_DIR/port_scan.sh" \
        --targets "$ALL_TARGETS_FILE" \
        --output-dir "$RECON_DIR/ports" \
        --top-ports 1000

elif [[ "$SKIP_PORTS" == "false" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP 2/5: Port Scanning (main target only — no subdomains yet)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "$TARGET" > "$TMP_DIR/main_target.txt"
    TMP_DIR=$(mktemp -d -t recon-XXXXXXXXXX)
    bash "$SCRIPT_DIR/port_scan.sh" \
        --targets "$TMP_DIR/main_target.txt" \
        --output-dir "$RECON_DIR/ports" \
        --top-ports 1000
    rm -rf "$TMP_DIR"
else
    echo "[SKIP] Port scanning"
fi

# =============================================================================
# STEP 3: Technology Detection
# =============================================================================
if [[ "$SKIP_TECH" == "false" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP 3/5: Technology Detection"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$RECON_DIR/subdomains/alive_hosts.txt" ]]; then
        TECHS_TARGETS="$RECON_DIR/subdomains/alive_hosts.txt"
    else
        TECHS_TARGETS="$RECON_DIR/subdomains/subdomains.txt"
    fi

    if [[ -f "$TECHS_TARGETS" ]]; then
        bash "$SCRIPT_DIR/tech_detect.sh" \
            --targets "$TECHS_TARGETS" \
            --output-dir "$RECON_DIR/tech"
    else
        # Just scan the main target
        echo "https://$TARGET" > "$TMP_DIR/main_tech.txt"
        TMP_DIR=$(mktemp -d -t recontech-XXXXXXXXXX)
        bash "$SCRIPT_DIR/tech_detect.sh" \
            --targets "$TMP_DIR/main_tech.txt" \
            --output-dir "$RECON_DIR/tech"
        rm -rf "$TMP_DIR"
    fi
else
    echo "[SKIP] Technology detection"
fi

# =============================================================================
# STEP 4: Cloud Enumeration
# =============================================================================
if [[ "$SKIP_CLOUD" == "false" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  STEP 4/5: Cloud Enumeration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    bash "$SCRIPT_DIR/cloud_enum.sh" \
        --target "$TARGET" \
        --output-dir "$RECON_DIR/cloud"
else
    echo "[SKIP] Cloud enumeration"
fi

# =============================================================================
# STEP 5: Generate Unified recon.json
# =============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  STEP 5/5: Generating Unified Recon Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

python3 <<PYEOF > "$RECON_DIR/recon.json"
import json, os, glob

recon_dir = "${RECON_DIR}"
target = "${TARGET}"

def load_json(path):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return None
    return None

def count_file_lines(path):
    if os.path.exists(path):
        with open(path) as f:
            return sum(1 for _ in f)
    return 0

result = {
    "meta": {
        "version": "1.0.0",
        "target": target,
        "phase": 0,
        "generated_by": "master_recon.sh"
    },
    "subdomains": load_json("$RECON_DIR/subdomains/subdomains.json") or {},
    "ports": load_json("$RECON_DIR/ports/open_ports.json") or {},
    "services": load_json("$RECON_DIR/ports/services.json") or {},
    "vulnerabilities": load_json("$RECON_DIR/ports/vulnerabilities.json") or {},
    "tech_stack": load_json("$RECON_DIR/tech/tech_stack.json") or {},
    "cdn_waf": load_json("$RECON_DIR/tech/cdn_waf.json") or {},
    "api_frameworks": load_json("$RECON_DIR/tech/api_frameworks.json") or {},
    "cloud_buckets": load_json("$RECON_DIR/cloud/cloud_buckets.json") or {},
    "k8s_endpoints": load_json("$RECON_DIR/cloud/k8s_endpoints.json") or {},
    "cloud_services": load_json("$RECON_DIR/cloud/cloud_services.json") or {},
    "email_security": load_json("$RECON_DIR/cloud/email_security.json") or {},
    "summary": {
        "total_subdomains": load_json("$RECON_DIR/subdomains/subdomains.json").get("counts", {}).get("total_resolved", 0) if load_json("$RECON_DIR/subdomains/subdomains.json") else 0,
        "live_hosts": load_json("$RECON_DIR/subdomains/subdomains.json").get("counts", {}).get("alive_hosts", 0) if load_json("$RECON_DIR/subdomains/subdomains.json") else 0,
        "takeover_vulnerable": load_json("$RECON_DIR/subdomains/subdomains.json").get("counts", {}).get("takeover_vulnerable", 0) if load_json("$RECON_DIR/subdomains/subdomains.json") else 0,
        "hosts_with_open_ports": load_json("$RECON_DIR/ports/open_ports.json").get("total_hosts_scanned", 0) if load_json("$RECON_DIR/ports/open_ports.json") else 0,
        "tech_hosts_analyzed": load_json("$RECON_DIR/tech/tech_stack.json").get("meta", {}).get("total_hosts", 0) if load_json("$RECON_DIR/tech/tech_stack.json") else 0,
        "api_frameworks_found": load_json("$RECON_DIR/tech/api_frameworks.json").get("total_api_frameworks_found", 0) if load_json("$RECON_DIR/tech/api_frameworks.json") else 0,
        "cloud_buckets_found": load_json("$RECON_DIR/cloud/cloud_buckets.json").get("summary", {}).get("aws_exists", 0) if load_json("$RECON_DIR/cloud/cloud_buckets.json") else 0,
        "email_security_risk": load_json("$RECON_DIR/cloud/email_security.json").get("risk_assessment", {}).get("overall", "UNKNOWN") if load_json("$RECON_DIR/cloud/email_security.json") else "UNKNOWN"
    },
    "attack_surface_insights": []
}

# Generate insights
insights = result["attack_surface_insights"]

s = result["summary"]
if s["total_subdomains"] > 50:
    insights.append(f"LARGE_ATTACK_SURFACE: {s['total_subdomains']} subdomains found")
if s["takeover_vulnerable"] > 0:
    insights.append(f"CRITICAL: {s['takeover_vulnerable']} potential subdomain takeover targets")
if s["hosts_with_open_ports"] > 0:
    insights.append(f"INFRASTRUCTURE_CRITICAL: {s['hosts_with_open_ports']} hosts have open non-standard ports")

tech_data = result.get("tech_stack", {})
if tech_data:
    all_tech = []
    for host_info in tech_data.get("hosts", {}).values():
        all_tech.extend(host_info.get("technologies", []))
    tech_set = set(all_tech)
    if "wordpress" in tech_set:
        insights.append("WORDPRESS_DETECTED: Check wp-json, xmlrpc.php, plugin enumeration")
    if "graphql" in tech_set:
        insights.append("GRAPHQL_DETECTED: Test introspection, batching, depth limits")
    if "react" in tech_set or "vue" in tech_set or "angular" in tech_set:
        insights.append("SPA_DETECTED: Deep JS analysis needed — check source maps")
    if "firebase" in tech_set:
        insights.append("FIREBASE_DETECTED: Check database rules, auth configuration")
    if "spring" in tech_set:
        insights.append("SPRING_BOOT_DETECTED: Check actuator endpoints")
    if "nginx" in tech_set:
        insights.append("NGINX_DETECTED: Check path traversal, SSI injection, alias misconfig")

email = result.get("email_security", {})
if email and email.get("risk_assessment", {}).get("overall") == "HIGH":
    insights.append("EMAIL_SPOOFABLE: No SPF/DMARC — potential for phishing impact")

k8s = result.get("k8s_endpoints", {})
if k8s and k8s.get("kubernetes_found", 0) > 0:
    insights.append("KUBERNETES_EXPOSED: K8s API endpoints reachable")

json.dump(result, sys.stdout, indent=2)
PYEOF

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 0: RECONNAISSANCE COMPLETE                           ║"
echo "║  Duration: ${DURATION}s                                     ║"
echo "║  Summary: $RECON_DIR/recon.json                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Print quick stats
python3 <<PYEOF
import json
with open("$RECON_DIR/recon.json") as f:
    r = json.load(f)
s = r.get("summary", {})
print(f"\n  Subdomains resolved: {s.get('total_subdomains', 0)}")
print(f"  Live hosts:          {s.get('live_hosts', 0)}")
print(f"  Takeover vulns:      {s.get('takeover_vulnerable', 0)}")
print(f"  Tech analyzed:       {s.get('tech_hosts_analyzed', 0)}")
print(f"  Cloud buckets:       {s.get('cloud_buckets_found', 0)}")
print(f"  Email risk:          {s.get('email_security_risk', 'UNKNOWN')}")
print(f"\n  Attack Surface Insights:")
for insight in r.get("attack_surface_insights", []):
    print(f"    → {insight}")
PYEOF

echo ""
echo "→ Next: Run Phase 1 Spidering (spider.sh) on discovered live hosts"
