#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# nuclei_runner.sh — Automated Vulnerability Scanning with Nuclei
# Runs nuclei templates matched to the discovered tech stack and spider output.
# Integrates with the framework's Phase 1 (post-spider) and Phase 3 (validation).
# =============================================================================

VERSION="1.0.0"
TARGETS_FILE=""
OUTPUT_DIR=""
TECH_STACK_JSON=""
TEMPLATES_DIR="${HOME}/nuclei-templates"
SEVERITY="critical,high,medium"
TIMEOUT=30
THREADS=50
CONCURRENCY=25
MODE="tech-stack"
TAGS=""
CUSTOM_TEMPLATES=""

usage() {
    cat <<EOF
Usage: $0 --targets <file> --output-dir <path> [options]

Nuclei vulnerability scanner integration for the framework.

Options:
  --targets <file>         File with target URLs (one per line)
  --output-dir <path>      Output directory (required)
  --tech-stack <json>      Technology stack JSON from tech_detect.sh (for smart template selection)
  --templates-dir <path>   Nuclei templates directory (default: ~/nuclei-templates)
  --severity <list>        Severity filter (default: critical,high,medium)
  --mode <mode>            Scan mode: tech-stack|full|quick|cve-only (default: tech-stack)
  --tags <tags>            Specific nuclei tags (comma-separated)
  --custom-templates <dir> Additional custom template directory
  --threads <N>            Concurrency (default: 50)
  --timeout <N>            Request timeout in seconds (default: 30)
  --help                   Show this help

Modes:
  tech-stack  — Run only templates matching discovered technologies (safest, most accurate)
  full        — Run all templates (comprehensive but slow, higher FP rate)
  quick       — Run only critical + high severity with timeouts (fast overview)
  cve-only    — Run only CVE templates (known vulnerabilities in discovered versions)

Output:
  <output-dir>/nuclei_findings.jsonl   — Raw nuclei output (JSONL)
  <output-dir>/nuclei_summary.json      — Categorized summary with severity breakdown
  <output-dir>/nuclei_critical.txt       — Critical findings only (plain text)
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets) TARGETS_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --tech-stack) TECH_STACK_JSON="$2"; shift 2 ;;
        --templates-dir) TEMPLATES_DIR="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --tags) TAGS="$2"; shift 2 ;;
        --custom-templates) CUSTOM_TEMPLATES="$2"; shift 2 ;;
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
echo "  Nuclei Vulnerability Scanner"
echo "  Targets: $(wc -l < "$TARGETS_FILE") URLs"
echo "  Mode: $MODE"
echo "============================================"

if ! command -v nuclei &>/dev/null; then
    echo "[!] nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "    or: apt install nuclei"
    # Generate empty placeholder
    python3 <<PYEOF > "$OUTPUT_DIR/nuclei_summary.json"
import json
json.dump({"error": "nuclei_not_installed", "findings": 0, "severity_breakdown": {}}, open("$OUTPUT_DIR/nuclei_summary.json","w"), indent=2)
PYEOF
    exit 0
fi

# =============================================================================
# Smart Template Selection Based on Tech Stack
# =============================================================================
TEMPLATE_ARGS=""

if [[ "$MODE" == "tech-stack" && -n "$TECH_STACK_JSON" && -f "$TECH_STACK_JSON" ]]; then
    echo "[*] Building tech-stack-matched template list..."

    SELECTED_TAGS=""
    TEMP_TAGS_FILE=$(mktemp)

    python3 <<PYEOF > "$TEMP_TAGS_FILE"
import json, sys

tech_tags_map = {
    "nginx": "nginx",
    "apache": "apache",
    "iis": "iis",
    "tomcat": "apache,tomcat",
    "wordpress": "wordpress,cms",
    "drupal": "drupal,cms",
    "joomla": "joomla,cms",
    "magento": "magento,ecommerce",
    "shopify": "shopify,ecommerce",
    "django": "django,python",
    "flask": "flask,python",
    "laravel": "laravel,php",
    "symfony": "php,symfony",
    "rails": "rails,ruby",
    "express": "express,nodejs",
    "nextjs": "nextjs,react",
    "react": "react,javascript",
    "angular": "angular,javascript",
    "vue": "vue,javascript",
    "jquery": "jquery,javascript",
    "spring": "spring,java,springboot",
    "struts": "struts,apache,java",
    "graphql": "graphql,api",
    "aws": "aws,cloud",
    "gcp": "gcp,cloud",
    "azure": "azure,cloud",
    "cloudflare": "cloudflare,cdn",
    "fastly": "fastly,cdn",
    "jenkins": "jenkins,ci",
    "gitlab": "gitlab,ci",
    "jira": "jira,atlassian",
    "confluence": "confluence,atlassian",
    "grafana": "grafana,monitoring",
    "kibana": "kibana,elastic",
    "elasticsearch": "elastic,elasticsearch",
    "mongodb": "mongodb,nosql",
    "mysql": "mysql,sql",
    "postgresql": "postgres,sql",
    "redis": "redis,nosql",
    "memcached": "memcached,cache",
    "kubernetes": "kubernetes,k8s",
    "docker": "docker,container",
    "firebase": "firebase,cloud",
    "swagger": "swagger,api",
    "php": "php",
    "node.js": "nodejs,javascript",
    "python": "python",
    "java": "java",
    "ruby": "ruby",
    "go": "go",
    "cpanel": "cpanel,control-panel",
    "webmin": "webmin,control-panel",
    "haproxy": "haproxy,load-balancer",
    "varnish": "varnish,cache",
    "kong": "kong,api-gateway",
    "tyk": "tyk,api-gateway",
    "traefik": "traefik,load-balancer",
}

all_tags = set()
all_tags.add("cve")  # Always include CVE templates
all_tags.add("misconfig")  # Always include misconfig templates

if "${TECH_STACK_JSON}" and __import__('os').path.exists("${TECH_STACK_JSON}"):
    try:
        with open("${TECH_STACK_JSON}") as f:
            tech_data = json.load(f)

        for host_info in tech_data.get("hosts", {}).values():
            for tech in host_info.get("technologies", []):
                tech_lower = tech.lower()
                for key, tags in tech_tags_map.items():
                    if key in tech_lower:
                        for tag in tags.split(","):
                            all_tags.add(tag.strip())
    except:
        pass

print(",".join(sorted(all_tags)))
PYEOF

    SELECTED_TAGS=$(cat "$TEMP_TAGS_FILE")
    rm -f "$TEMP_TAGS_FILE"

    if [[ -n "$SELECTED_TAGS" ]]; then
        echo "  => Selected tags: $SELECTED_TAGS"
        # Run nuclei with each tag group to avoid overwhelming
        IFS=',' read -ra TAG_ARRAY <<< "$SELECTED_TAGS"
        TEMPLATE_ARGS="-tags cve,misconfig"
        for tag in "${TAG_ARRAY[@]}"; do
            [[ "$tag" == "cve" || "$tag" == "misconfig" ]] && continue
            TEMPLATE_ARGS="$TEMPLATE_ARGS,$tag"
        done
    fi
elif [[ "$MODE" == "full" ]]; then
    TEMPLATE_ARGS=""
    echo "  => Full scan mode — all templates"
elif [[ "$MODE" == "quick" ]]; then
    TEMPLATE_ARGS="-severity critical,high"
    echo "  => Quick scan mode — critical + high only"
elif [[ "$MODE" == "cve-only" ]]; then
    TEMPLATE_ARGS="-tags cve"
    echo "  => CVE-only mode"
elif [[ -n "$TAGS" ]]; then
    TEMPLATE_ARGS="-tags $TAGS"
    echo "  => Custom tags: $TAGS"
fi

if [[ -n "$CUSTOM_TEMPLATES" && -d "$CUSTOM_TEMPLATES" ]]; then
    TEMPLATE_ARGS="$TEMPLATE_ARGS -t $CUSTOM_TEMPLATES"
fi

# =============================================================================
# Run Nuclei
# =============================================================================
echo "[*] Running nuclei..."

FINDINGS_FILE="$OUTPUT_DIR/nuclei_findings.jsonl"
SUMMARY_JSON="$OUTPUT_DIR/nuclei_summary.json"
CRITICAL_FILE="$OUTPUT_DIR/nuclei_critical.txt"

# Update templates if dir exists
if [[ -d "$TEMPLATES_DIR" ]]; then
    nuclei -update-templates -silent -ud "$TEMPLATES_DIR" 2>/dev/null || true
    TEMPLATE_ARGS="$TEMPLATE_ARGS -t $TEMPLATES_DIR"
fi

nuclei \
    -list "$TARGETS_FILE" \
    $TEMPLATE_ARGS \
    -severity "$SEVERITY" \
    -timeout "$TIMEOUT" \
    -c "$CONCURRENCY" \
    -bs "$THREADS" \
    -silent \
    -no-color \
    -jsonl \
    -o "$FINDINGS_FILE" \
    -stats \
    -stats-interval 30 \
    -interactions-cache-size 100 \
    -retries 1 \
    2>/dev/null || true

FINDING_COUNT=$(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo 0)
echo "  => $FINDING_COUNT findings from nuclei"

# =============================================================================
# Process Results
# =============================================================================
echo "[*] Processing nuclei results..."

python3 <<PYEOF > "$SUMMARY_JSON"
import json
from collections import Counter, defaultdict

findings = []
severity_count = Counter()
vuln_types = Counter()
affected_hosts = set()
critical_items = []

criticals_txt = []

try:
    with open("$FINDINGS_FILE") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                info = entry.get("info", {})
                severity = info.get("severity", "unknown")
                name = info.get("name", "unnamed")
                template_id = entry.get("template-id", "unknown")
                host = entry.get("host", entry.get("matched-at", "unknown"))
                url = entry.get("matched-at", host)
                description = info.get("description", "")
                tags = info.get("tags", [])

                severity_count[severity] += 1
                vuln_types[template_id] += 1
                affected_hosts.add(host)

                finding = {
                    "name": name,
                    "severity": severity,
                    "template_id": template_id,
                    "host": host,
                    "url": url,
                    "description": description[:300],
                    "tags": tags[:10] if isinstance(tags, list) else []
                }
                findings.append(finding)

                if severity in ("critical", "high"):
                    critical_items.append(finding)
                    criticals_txt.append(f"[{severity.upper()}] {name}")
                    criticals_txt.append(f"  URL: {url}")
                    criticals_txt.append(f"  Template: {template_id}")
                    criticals_txt.append("")
            except (json.JSONDecodeError, KeyError):
                continue
except FileNotFoundError:
    pass

result = {
    "meta": {
        "tool": "nuclei_runner.sh",
        "version": "${VERSION}",
        "mode": "${MODE}"
    },
    "total_findings": len(findings),
    "affected_hosts": len(affected_hosts),
    "severity_breakdown": dict(severity_count),
    "top_vulnerability_types": vuln_types.most_common(20),
    "critical_high_findings": len(critical_items),
    "findings": findings
}

json.dump(result, sys.stdout, indent=2)
PYEOF

# Write critical findings to plain text
python3 <<PYEOF > "$CRITICAL_FILE"
import json
lines = ["NUCLEI CRITICAL FINDINGS", "=" * 60, ""]
try:
    with open("$SUMMARY_JSON") as f:
        data = json.load(f)
    for f in data.get("findings", []):
        if f.get("severity") in ("critical", "high"):
            lines.append(f"[{f['severity'].upper()}] {f['name']}")
            lines.append(f"  URL: {f.get('url', 'N/A')}")
            lines.append(f"  Host: {f.get('host', 'N/A')}")
            lines.append(f"  Template: {f.get('template_id', 'N/A')}")
            lines.append("")
except:
    pass
print("\n".join(lines))
PYEOF

CRIT_COUNT=$(python3 -c "import json; d=json.load(open('$SUMMARY_JSON')); print(d.get('critical_high_findings',0))" 2>/dev/null || echo 0)
echo "  => $CRIT_COUNT critical/high findings"
echo "  => $(python3 -c "import json; d=json.load(open('$SUMMARY_JSON')); print(d.get('affected_hosts',0))" 2>/dev/null || echo 0) hosts affected"

echo ""
echo "============================================"
echo "  NUCLEI SCAN COMPLETE"
echo "  Total findings: $FINDING_COUNT"
echo "  Critical/High: $CRIT_COUNT"
echo "  Summary: $SUMMARY_JSON"
echo "============================================"
