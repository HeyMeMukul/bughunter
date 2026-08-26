#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# cloud_enum.sh — Phase 0: Cloud Infrastructure Enumeration
# Scans for exposed S3 buckets, Azure blobs, GCP storage, and K8s endpoints.
# =============================================================================

VERSION="1.0.0"
TARGET=""
OUTPUT_DIR=""
WORDFILE=""

usage() {
    cat <<EOF
Usage: $0 --target <domain> --output-dir <path> [options]

Cloud infrastructure enumeration and misconfiguration scanning.

Options:
  --target <domain>      Target domain/company name (required)
  --output-dir <path>    Output directory (required)
  --wordfile <path>      Custom wordlist for bucket name generation
  --help                 Show this help

Output:
  <output-dir>/cloud_buckets.json   — Discovered cloud storage buckets
  <output-dir>/k8s_endpoints.json   — Kubernetes API/etcd endpoints
  <output-dir>/cloud_services.json  — All detected cloud services
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --wordfile) WORDFILE="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --target and --output-dir are required"
    usage
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  Phase 0: Cloud Infrastructure Enumeration"
echo "  Target: $TARGET"
echo "============================================"

TMP_DIR=$(mktemp -d -t cloudenum-XXXXXXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

COMPANY_NAME=$(echo "$TARGET" | sed 's/\.[^.]*\.[^.]*$//' | sed 's/\.[^.]*$//')

# =============================================================================
# STAGE 1: S3 Bucket Enumeration
# =============================================================================
echo "[1/4] S3/Cloud bucket enumeration..."

CLOUD_BUCKETS="$OUTPUT_DIR/cloud_buckets.json"

S3_CANDIDATES=(
    "${TARGET}" "${COMPANY_NAME}" "${COMPANY_NAME}-prod" "${COMPANY_NAME}-dev" "${COMPANY_NAME}-staging"
    "${COMPANY_NAME}-backup" "${COMPANY_NAME}-logs" "${COMPANY_NAME}-assets" "${COMPANY_NAME}-static"
    "${COMPANY_NAME}-media" "${COMPANY_NAME}-cdn" "${COMPANY_NAME}-data" "${COMPANY_NAME}-files"
    "${COMPANY_NAME}-uploads" "${COMPANY_NAME}-images" "${COMPANY_NAME}-public" "${COMPANY_NAME}-private"
    "${COMPANY_NAME}-terraform" "${COMPANY_NAME}-config" "${COMPANY_NAME}-secrets"
    "${TARGET}-prod" "${TARGET}-dev" "${TARGET}-staging"
)

if command -v cloud_enum &>/dev/null; then
    echo "  [*] cloud_enum scanning..."
    echo "$TARGET" > "$TMP_DIR/targets.txt"
    cloud_enum -k "$TARGET" -l "$TMP_DIR/targets.txt" \
        -t 10 -f "$TMP_DIR/cloud_enum_output.json" 2>/dev/null || true
elif command -v s3scanner &>/dev/null; then
    echo "  [*] S3Scanner..."
    printf '%s\n' "${S3_CANDIDATES[@]}" > "$TMP_DIR/s3_candidates.txt"
    s3scanner scan --buckets-file "$TMP_DIR/s3_candidates.txt" \
        --threads 10 -o "$TMP_DIR/s3_results.txt" 2>/dev/null || true
fi

# Python-based bucket checker (works without external tools)
python3 <<PYEOF > "$CLOUD_BUCKETS"
import json, urllib.request, ssl, sys

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

target = "${TARGET}"
company = "${COMPANY_NAME}"

# Bucket naming patterns
s3_names = [
    company, target,
    f"{company}-prod", f"{company}-dev", f"{company}-staging",
    f"{company}-backup", f"{company}-logs", f"{company}-assets",
    f"{company}-static", f"{company}-media", f"{company}-cdn",
    f"{company}-data", f"{company}-files", f"{company}-uploads",
    f"{company}-images", f"{company}-public", f"{company}-private",
    f"{company}-terraform", f"{company}-config",
    f"{target}-prod", f"{target}-dev", f"{target}-staging",
]

# Generate permutations
for suffix in ['', '-prod', '-dev', '-staging', '-test', '-backup', '-logs']:
    for part in [company, company.replace('-',''), company.replace('.','')]:
        name = f"{part}{suffix}"
        if name not in s3_names:
            s3_names.append(name)

results = {
    "aws_s3": [],
    "gcp_storage": [],
    "azure_blob": [],
    "digitalocean_spaces": []
}

for bucket in s3_names:
    # AWS S3 check
    for region in ['', '.us-east-1', '.us-west-2', '.eu-west-1', '.ap-southeast-1']:
        url = f"https://{bucket}.s3{region}.amazonaws.com"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
            status = resp.getcode()
            body = resp.read(5000).decode('utf-8', errors='ignore')
            results["aws_s3"].append({
                "bucket": bucket,
                "url": url,
                "status": status,
                "public": status == 200,
                "snippet": body[:500] if status == 200 else ""
            })
            break  # Found, don't check other regions
        except urllib.error.HTTPError as e:
            if e.code == 403:
                results["aws_s3"].append({
                    "bucket": bucket,
                    "url": url,
                    "status": 403,
                    "public": False,
                    "accessible": "Forbidden — exists but not public"
                })
                break
            elif e.code == 404:
                continue
        except:
            continue

    # GCP Storage check
    gcp_url = f"https://storage.googleapis.com/{bucket}"
    try:
        req = urllib.request.Request(gcp_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
        results["gcp_storage"].append({
            "bucket": bucket,
            "url": gcp_url,
            "status": resp.getcode(),
            "public": True
        })
    except:
        pass

print(json.dumps({
    "meta": {
        "tool": "cloud_enum.sh",
        "target": target,
        "buckets_tested": len(s3_names)
    },
    "findings": results,
    "summary": {
        "aws_public": len([b for b in results["aws_s3"] if b.get("public")]),
        "aws_exists": len(results["aws_s3"]),
        "gcp_public": len([b for b in results["gcp_storage"] if b.get("public")]),
        "gcp_exists": len(results["gcp_storage"])
    }
}, indent=2))
PYEOF

BUCKET_COUNT=$(python3 -c "import json; d=json.load(open('$CLOUD_BUCKETS')); s=d.get('summary',{}); print(s.get('aws_exists',0)+s.get('gcp_exists',0))" 2>/dev/null || echo 0)
PUBLIC_COUNT=$(python3 -c "import json; d=json.load(open('$CLOUD_BUCKETS')); s=d.get('summary',{}); print(s.get('aws_public',0)+s.get('gcp_public',0))" 2>/dev/null || echo 0)
echo "  => $BUCKET_COUNT buckets found ($PUBLIC_COUNT public)"

# =============================================================================
# STAGE 2: Kubernetes / Container Scanning
# =============================================================================
echo "[2/4] Kubernetes & container endpoint scanning..."

K8S_JSON="$OUTPUT_DIR/k8s_endpoints.json"

python3 <<PYEOF > "$K8S_JSON"
import json, urllib.request, ssl, urllib.error

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

target = "${TARGET}"
k8s_paths = [
    "/.kube/config", "/kubeconfig",
    "/api/v1/pods", "/api/v1/secrets",
    "/api/v1/namespaces", "/api/v1/nodes",
    "/apis/apps/v1/deployments",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/openapi/v2", "/version",
    "/healthz", "/readyz", "/livez",
    "/metrics",
]

docker_paths = [
    "/v2/_catalog",
    "/v2/<name>/tags/list",
    "/.dockercfg", "/.docker/config.json",
]

results = {"kubernetes": [], "docker_registry": [], "etcd": []}

# Check common ports for K8s
for port in [6443, 8443, 443, 8080, 10250, 10255, 2379, 2380]:
    base = f"https://{target}:{port}"
    try:
        req = urllib.request.Request(f"{base}/version", headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
        body = resp.read(5000).decode('utf-8', errors='ignore')
        if 'major' in body.lower() and ('kubernetes' in body.lower() or 'gitversion' in body.lower()):
            results["kubernetes"].append({"host": f"{target}:{port}", "endpoint": "/version", "exposed": True, "snippet": body[:300]})
    except:
        # Check HTTP as well
        try:
            req = urllib.request.Request(f"http://{target}:{port}/version", headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
            body = resp.read(5000).decode('utf-8', errors='ignore')
            if 'major' in body.lower() and ('kubernetes' in body.lower() or 'gitversion' in body.lower()):
                results["kubernetes"].append({"host": f"{target}:{port}", "endpoint": "/version", "exposed": True, "snippet": body[:300], "protocol": "http"})
        except:
            continue

    # etcd check
    if port in [2379, 2380]:
        try:
            req = urllib.request.Request(f"http://{target}:{port}/version")
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read(3000).decode('utf-8', errors='ignore')
            if 'etcd' in body.lower():
                results["etcd"].append({"host": f"{target}:{port}", "exposed": True, "snippet": body[:300]})
        except:
            continue

# Check K8s paths on main host (could be behind reverse proxy)
for path in k8s_paths[:5]:
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{target}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
            if resp.getcode() == 200:
                results["kubernetes"].append({"host": target, "endpoint": path, "exposed": True, "protocol": scheme})
        except:
            continue

# Docker registry check
for path in docker_paths[:2]:
    for scheme in ['https', 'http']:
        for port in ['', ':5000', ':443']:
            try:
                url = f"{scheme}://{target}{port}{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
                if resp.getcode() == 200:
                    results["docker_registry"].append({"host": f"{target}{port}", "endpoint": path, "exposed": True})
            except:
                continue

print(json.dumps({
    "meta": {"tool": "cloud_enum.sh", "target": target},
    "kubernetes_found": len(results["kubernetes"]),
    "docker_registries_found": len(results["docker_registry"]),
    "etcd_found": len(results["etcd"]),
    "findings": results
}, indent=2))
PYEOF

K8S_COUNT=$(python3 -c "import json; d=json.load(open('$K8S_JSON')); print(d.get('kubernetes_found',0))" 2>/dev/null || echo 0)
echo "  => $K8S_COUNT Kubernetes endpoints found"

# =============================================================================
# STAGE 3: Cloud Service Detection
# =============================================================================
echo "[3/4] Cloud service detection..."

CLOUD_SERVICES="$OUTPUT_DIR/cloud_services.json"

python3 <<PYEOF > "$CLOUD_SERVICES"
import json, urllib.request, ssl, urllib.error

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

target = "${TARGET}"

# Cloud metadata endpoints
metadata_endpoints = {
    "aws": ["http://169.254.169.254/latest/meta-data/", "http://instance-data/latest/meta-data/"],
    "gcp": ["http://metadata.google.internal/computeMetadata/v1/"],
    "azure": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
    "digitalocean": ["http://169.254.169.254/metadata/v1.json"],
    "oracle": ["http://169.254.169.254/opc/v1/instance/"],
    "alibaba": ["http://100.100.100.200/latest/meta-data/"],
}

# These are tested via SSRF vectors, not directly — but flag their existence
results = {"cloud_provider_indicators": [], "exposed_services": []}

# Check CNAME records for cloud service indicators
cloud_cnames = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "elb.amazonaws.com": "AWS ELB",
    "s3.amazonaws.com": "AWS S3",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "googleapis.com": "GCP",
    "appspot.com": "GCP App Engine",
    "firebaseio.com": "Firebase",
    "herokuapp.com": "Heroku",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "workers.dev": "Cloudflare Workers",
    "pages.dev": "Cloudflare Pages",
    "fly.dev": "Fly.io",
    "render.com": "Render",
    "railway.app": "Railway",
    "onrender.com": "Render",
}

results["cloud_provider_indicators"] = {"lookup_required": True, "cname_patterns": cloud_cnames}

# Firebase check
for suffix in ['', '-dev', '-staging', '-test']:
    fb_name = f"{target}{suffix}".replace(".", "-")
    for base in ['https://', '']:
        try:
            url = f"https://{fb_name}.firebaseio.com/.json"
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
            body = resp.read(2000).decode('utf-8', errors='ignore')
            if resp.getcode() == 200 and (body == 'null' or body.startswith('{')):
                results["exposed_services"].append({
                    "type": "firebase",
                    "name": fb_name,
                    "url": url,
                    "exposed": True,
                    "snippet": body[:200]
                })
        except:
            continue

# Check Supabase
try:
    url = f"https://{target}".replace("https://", "").replace("http://", "").split("/")[0]
    supabase_url = f"https://{url}.supabase.co"
    req = urllib.request.Request(supabase_url, headers={"User-Agent": "Mozilla/5.0"})
    resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=5)
    if resp.getcode() in [200, 404]:
        results["exposed_services"].append({"type": "supabase", "url": supabase_url, "exists": True})
except:
    pass

print(json.dumps({
    "meta": {"tool": "cloud_enum.sh", "target": target},
    "metadata_endpoints_to_test_via_ssrf": metadata_endpoints,
    "cloud_cname_patterns": cloud_cnames,
    "exposed_services_found": len(results["exposed_services"]),
    "findings": results
}, indent=2))
PYEOF

EXPOSED_COUNT=$(python3 -c "import json; d=json.load(open('$CLOUD_SERVICES')); print(d.get('exposed_services_found',0))" 2>/dev/null || echo 0)
echo "  => $EXPOSED_COUNT exposed cloud services"

# =============================================================================
# STAGE 4: Spoofcheck / Email Security
# =============================================================================
echo "[4/4] Email security check..."

python3 <<PYEOF > "$OUTPUT_DIR/email_security.json"
import json, subprocess, re

target = "${TARGET}"
result = {"domain": target, "checks": {}}

# SPF check
try:
    import dns.resolver
    spf_records = dns.resolver.resolve(target, 'TXT')
    for rdata in spf_records:
        txt = rdata.to_text().strip('"')
        if 'v=spf1' in txt:
            result["checks"]["spf"] = {
                "exists": True,
                "record": txt,
                "has_all": ' -all' in txt or ' ~all' in txt or ' ?all' in txt,
                "strict": ' -all' in txt,
                "softfail": ' ~all' in txt,
                "neutral": ' ?all' in txt,
                "spoofable": ' +all' in txt or (' ?all' in txt)
            }
        elif 'MS=' in txt:
            result["checks"]["microsoft_365"] = {"verified": True, "record": txt}
except:
    result["checks"]["spf"] = {"exists": False, "note": "No SPF record — domain is spoofable"}

# DMARC check
try:
    dmarc_records = dns.resolver.resolve(f'_dmarc.{target}', 'TXT')
    for rdata in dmarc_records:
        txt = rdata.to_text().strip('"')
        if 'v=DMARC1' in txt:
            p = re.search(r'p=(\w+)', txt)
            pct = re.search(r'pct=(\d+)', txt)
            result["checks"]["dmarc"] = {
                "exists": True,
                "record": txt,
                "policy": p.group(1) if p else "none",
                "enforcement_pct": int(pct.group(1)) if pct else 100,
                "strong": p and p.group(1) == "reject",
                "spoofable": not p or p.group(1) == "none"
            }
except:
    result["checks"]["dmarc"] = {"exists": False, "note": "No DMARC record — email is fully spoofable"}

# DKIM check (common selectors)
dkim_selectors = ['google', 'default', 'dkim', 'selector1', 'selector2', 'mail', 'k1', 's1', 's2']
dkim_found = []
for selector in dkim_selectors:
    try:
        dkim_records = dns.resolver.resolve(f'{selector}._domainkey.{target}', 'TXT')
        for rdata in dkim_records:
            txt = rdata.to_text().strip('"')
            if 'v=DKIM1' in txt:
                dkim_found.append({"selector": selector, "record": txt[:200]})
    except:
        continue
result["checks"]["dkim"] = {"selectors_found": dkim_found, "count": len(dkim_found)}

# Risk assessment
risks = []
if not result["checks"].get("spf", {}).get("exists"):
    risks.append("HIGH: No SPF — any server can send email as @{target}")
elif result["checks"]["spf"].get("spoofable"):
    risks.append("MEDIUM: Weak SPF policy — domain can be spoofed")
if not result["checks"].get("dmarc", {}).get("exists"):
    risks.append("HIGH: No DMARC — email forging possible without detection")
elif result["checks"]["dmarc"].get("spoofable"):
    risks.append("MEDIUM: DMARC policy is 'none' — spoofing not blocked")
if len(dkim_found) == 0:
    risks.append("MEDIUM: No DKIM selectors found")

result["risk_assessment"] = {
    "overall": "HIGH" if any("HIGH" in r for r in risks) else "MEDIUM" if risks else "LOW",
    "findings": risks
}

print(json.dumps(result, indent=2))
PYEOF

RISK=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/email_security.json')); print(d.get('risk_assessment',{}).get('overall','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
echo "  => Email security risk: $RISK"

echo ""
echo "============================================"
echo "  PHASE 0: CLOUD ENUMERATION COMPLETE"
echo "  Buckets: $OUTPUT_DIR/cloud_buckets.json"
echo "  K8s: $OUTPUT_DIR/k8s_endpoints.json"
echo "  Services: $OUTPUT_DIR/cloud_services.json"
echo "  Email: $OUTPUT_DIR/email_security.json"
echo "============================================"
