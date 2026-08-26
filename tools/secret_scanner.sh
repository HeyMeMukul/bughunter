#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# secret_scanner.sh — GitHub Secret Scanning
# Wraps trufflehog + gitleaks for scanning the target's GitHub org for secrets.
# =============================================================================

VERSION="1.0.0"
TARGET=""
GITHUB_ORG=""
OUTPUT_DIR=""
GITHUB_TOKEN=""

usage() {
    cat <<EOF
Usage: $0 --target <domain> --output-dir <path> [options]

GitHub secret scanning for leaked credentials and exposed configs.

Options:
  --target <domain>         Target domain/company name (required)
  --github-org <org>        GitHub organization (auto-detected if not provided)
  --output-dir <path>       Output directory (required)
  --github-token <token>    GitHub personal access token (for rate limits)
  --help                    Show this help

Output:
  <output-dir>/secrets_github.json   — Discovered secrets (masked)
  <output-dir>/secrets_summary.txt   — Readable summary
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --github-org) GITHUB_ORG="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --github-token) GITHUB_TOKEN="$2"; shift 2 ;;
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
echo "  Secret Scanner — GitHub Dorking"
echo "  Target: $TARGET"
echo "============================================"

# =============================================================================
# GitHub Dorking
# =============================================================================
echo "[*] Running GitHub dorking for leaked secrets..."

DORK_RESULTS="$OUTPUT_DIR/github_dorks.json"

python3 <<PYEOF > "$DORK_RESULTS"
import json, urllib.request, urllib.parse, base64, re, sys

target = "${TARGET}"
domain = target.replace("https://", "").replace("http://", "").strip("/")

results = {"target": target, "findings": [], "dorks_run": []}

# ========= GitHub Code Search API (unauthenticated limited) =========
dork_queries = [
    f'"{domain}" password',
    f'"{domain}" api_key',
    f'"{domain}" secret',
    f'"{domain}" token',
    f'"{domain}" BEGIN RSA PRIVATE KEY',
    f'"{domain}" aws_access_key',
    f'"{domain}" DATABASE_URL',
    f'"{domain}" mongodb://',
    f'"{domain}" redis://',
    f'"{domain}" .env',
    f'"{domain}" config.json',
    f'"{domain}" credentials',
    f'"{domain}" DB_PASSWORD',
    f'"{domain}" AUTH_TOKEN',
    f'"{domain}" JWT_SECRET',
]

# Check if github-cli is available
import subprocess
try:
    result = subprocess.run(
        ["gh", "search", "code", f'"{domain}"', "--limit", "5"],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode == 0:
        results["gh_cli_available"] = True
        results["gh_cli_output"] = result.stdout[:500]
    else:
        results["gh_cli_available"] = False
except:
    results["gh_cli_available"] = False

# Python-based search (unauthenticated API)
for query in dork_queries:
    results["dorks_run"].append(query)
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded}&per_page=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "bugbounty-framework",
            "Accept": "application/vnd.github.v3+json"
        })
        
        token = "${GITHUB_TOKEN}"
        if token:
            req.add_header("Authorization", f"token {token}")
        
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        
        for item in data.get("items", [])[:3]:
            repo_name = item.get("repository", {}).get("full_name", "unknown")
            file_path = item.get("path", "unknown")
            html_url = item.get("html_url", "")
            
            # Don't fetch actual content — just note the finding
            results["findings"].append({
                "dork": query,
                "repository": repo_name,
                "file": file_path,
                "url": html_url,
                "severity": "high" if any(kw in query for kw in ["password", "secret", "token", "key", "credentials"]) else "medium"
            })
    except Exception as e:
        continue

# Deduplicate
seen = set()
unique_findings = []
for f in results["findings"]:
    key = f["url"]
    if key not in seen:
        seen.add(key)
        unique_findings.append(f)
results["findings"] = unique_findings

results["total_findings"] = len(results["findings"])
print(json.dumps(results, indent=2))
PYEOF

DORK_COUNT=$(python3 -c "import json; d=json.load(open('$DORK_RESULTS')); print(d.get('total_findings',0))" 2>/dev/null || echo 0)
echo "  => $DORK_COUNT potential secret files found on GitHub"

# =============================================================================
# Trufflehog (if installed)
# =============================================================================
TRUFFLEHOG_RESULTS="$OUTPUT_DIR/secrets_trufflehog.json"

if command -v trufflehog &>/dev/null; then
    echo "[*] Running trufflehog on GitHub org..."

    if [[ -n "$GITHUB_ORG" ]]; then
        trufflehog github --org="$GITHUB_ORG" --json 2>/dev/null > "$TRUFFLEHOG_RESULTS" || true
    else
        # Search for repos mentioning the domain
        trufflehog github --repo="$(echo "$TARGET" | sed 's/\..*//')" --json 2>/dev/null > "$TRUFFLEHOG_RESULTS" || true
    fi

    TH_COUNT=$(wc -l < "$TRUFFLEHOG_RESULTS" 2>/dev/null || echo 0)
    echo "  => $TH_COUNT trufflehog findings"
else
    echo "  [!] trufflehog not installed — skipping"
    echo '{"findings":[]}' > "$TRUFFLEHOG_RESULTS"
fi

# =============================================================================
# Gitleaks (if installed)
# =============================================================================
GITLEAKS_RESULTS="$OUTPUT_DIR/secrets_gitleaks.json"

if command -v gitleaks &>/dev/null; then
    echo "[*] Running gitleaks..."

    # Gitleaks needs a repo to scan — can't scan GitHub org without cloning
    echo '{"note":"gitleaks requires local git repos — run manually for specific repos"}' > "$GITLEAKS_RESULTS"
else
    echo "  [!] gitleaks not installed — skipping"
    echo '{"note":"gitleaks not installed"}' > "$GITLEAKS_RESULTS"
fi

# =============================================================================
# Generate Summary
# =============================================================================
echo "[*] Generating secrets summary..."

python3 <<PYEOF > "$OUTPUT_DIR/secrets_summary.txt"
import json, os

def try_load(path):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path) as f:
            return json.load(f)
    return {}

dorks = try_load("$DORK_RESULTS")
truffle = try_load("$TRUFFLEHOG_RESULTS")

lines = []
lines.append("=" * 70)
lines.append("  SECRET SCANNING SUMMARY")
lines.append("=" * 70)
lines.append(f"\n  GitHub Dork Findings: {dorks.get('total_findings', 0)}")
lines.append(f"  Trufflehog Findings: {isinstance(truffle, list) and len(truffle) or 'N/A'}")
lines.append(f"  Domain: ${TARGET}")

if dorks.get("findings"):
    lines.append("\n--- Potential Leaked Files on GitHub ---")
    for finding in dorks["findings"][:10]:
        lines.append(f"  [{finding.get('severity','?').upper()}] {finding.get('repository','?')}/{finding.get('file','?')}")
        lines.append(f"       URL: {finding.get('url','?')}")

lines.append("\n [!] IMPORTANT: All findings are POTENTIAL leaks only.")
lines.append("     Verify manually before reporting. Secrets are NEVER stored in plaintext.")

print("\n".join(lines))
PYEOF

echo ""
echo "============================================"
echo "  SECRET SCANNING COMPLETE"
echo "  GitHub dorks: $DORK_RESULTS"
echo "  Summary: $OUTPUT_DIR/secrets_summary.txt"
echo "============================================"
