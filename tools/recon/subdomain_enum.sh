#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# subdomain_enum.sh — Phase 0: Subdomain Enumeration
# Combines passive + active + permutation-based subdomain discovery.
# Mirrors reconFTW's subdomain pipeline.
# =============================================================================

VERSION="1.0.0"
TARGET=""
OUTPUT_DIR=""
WORDLIST=""
RECURSIVE="false"
THREADS=50
TIMEOUT=30

usage() {
    cat <<EOF
Usage: $0 --target <domain> --output-dir <path> [options]

Subdomain enumeration combining passive, active, and permutation techniques.

Options:
  --target <domain>       Target domain (required)
  --output-dir <path>     Output directory (required)
  --wordlist <path>       Custom wordlist for DNS bruteforce
  --recursive             Enable recursive subdomain enumeration
  --threads <N>           DNS bruteforce threads (default: 50)
  --timeout <N>           Timeout per resolver in seconds (default: 30)
  --help                  Show this help

Output:
  <output-dir>/subdomains.json    — All discovered subdomains with metadata
  <output-dir>/subdomains.txt     — Plain list for tool chaining
  <output-dir>/alive_hosts.txt    — Verified live hosts
  <output-dir>/takeover_vulns.txt — Potential subdomain takeover targets
EOF
    exit 0
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --wordlist) WORDLIST="$2"; shift 2 ;;
        --recursive) RECURSIVE="true"; shift ;;
        --threads) THREADS="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --target and --output-dir are required"
    usage
fi

mkdir -p "$OUTPUT_DIR"

TMP_DIR=$(mktemp -d -t subenum-XXXXXXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

RESOLVERS="$HOME/Tools/resolvers.txt"
if [[ ! -f "$RESOLVERS" ]]; then
    echo "[*] Downloading trusted resolvers..."
    mkdir -p "$(dirname "$RESOLVERS")"
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS" 2>/dev/null || \
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" -o "$RESOLVERS" 2>/dev/null || \
    cp /etc/resolv.conf "$RESOLVERS"
fi

echo "============================================"
echo "  Phase 0: Subdomain Enumeration"
echo "  Target: $TARGET"
echo "  Output: $OUTPUT_DIR"
echo "============================================"

# =============================================================================
# STAGE 1: Passive Enumeration
# =============================================================================
echo "[1/6] Passive subdomain discovery..."

PASSIVE_FILE="$TMP_DIR/passive_all.txt"
> "$PASSIVE_FILE"

# crt.sh — certificate transparency
echo "  [*] crt.sh certificate transparency..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    for e in data:
        name=e.get('name_value','')
        for n in name.split('\n'):
            n=n.strip().lstrip('*.').lower()
            if n and '.' in n: print(n)
except: pass
" 2>/dev/null >> "$PASSIVE_FILE" || true

# subfinder — if installed
if command -v subfinder &>/dev/null; then
    echo "  [*] subfinder..."
    subfinder -d "$TARGET" -silent -all 2>/dev/null >> "$PASSIVE_FILE" || true
fi

# assetfinder — if installed
if command -v assetfinder &>/dev/null; then
    echo "  [*] assetfinder..."
    assetfinder --subs-only "$TARGET" 2>/dev/null >> "$PASSIVE_FILE" || true
fi

# amass passive — if installed
if command -v amass &>/dev/null; then
    echo "  [*] amass (passive)..."
    amass enum -passive -d "$TARGET" -silent 2>/dev/null >> "$PASSIVE_FILE" || true
fi

# Chaos (ProjectDiscovery) — if installed
if command -v chaos &>/dev/null; then
    echo "  [*] chaos..."
    chaos -d "$TARGET" -silent 2>/dev/null >> "$PASSIVE_FILE" || true
fi

# AbuseIPDB / AlienVault — free passive DNS via curl
echo "  [*] AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" 2>/dev/null | \
    python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    for e in data.get('passive_dns',[]):
        h=e.get('hostname','')
        if h and h.endswith('.$TARGET'.replace('*','')):
            print(h.lower())
except: pass
" 2>/dev/null >> "$PASSIVE_FILE" || true

# Filter and deduplicate passive results
sort -u "$PASSIVE_FILE" | grep -iE "\.${TARGET}$" > "$TMP_DIR/passive_clean.txt" 2>/dev/null || true
PASSIVE_COUNT=$(wc -l < "$TMP_DIR/passive_clean.txt" 2>/dev/null || echo 0)
echo "  => $PASSIVE_COUNT passive subdomains found"

# =============================================================================
# STAGE 2: Active DNS Bruteforce
# =============================================================================
echo "[2/6] DNS bruteforce..."

# Select wordlist
if [[ -z "$WORDLIST" ]]; then
    # Try common wordlist locations
    for wl in \
        "$HOME/Tools/wordlists/subdomains-top1million-5000.txt" \
        "$HOME/wordlists/subdomains-top1million-5000.txt" \
        "/usr/share/wordlists/subdomains-top1million-5000.txt" \
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"; do
        if [[ -f "$wl" ]]; then WORDLIST="$wl"; break; fi
    done
    # Fallback: download a small wordlist
    if [[ -z "$WORDLIST" ]]; then
        WORDLIST="$TMP_DIR/bruteforce_wordlist.txt"
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
            -o "$WORDLIST" 2>/dev/null || \
        curl -sL "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt" \
            -o "$WORDLIST" 2>/dev/null || \
        printf "www\nmail\napi\nadmin\nblog\ndev\nstaging\ntest\napp\nportal\nauth\ncdn\ndocs\nftp\nm\nmobile\nremote\nsecure\nshop\nvpn\n" > "$WORDLIST"
    fi
fi

BRUTE_FILE="$TMP_DIR/bruteforce.txt"
> "$BRUTE_FILE"

# puredns — if installed
if command -v puredns &>/dev/null; then
    echo "  [*] puredns bruteforce..."
    puredns bruteforce "$WORDLIST" "$TARGET" \
        --resolvers "$RESOLVERS" \
        --rate-limit "$THREADS" \
        --write "$BRUTE_FILE" 2>/dev/null || true
else
    echo "  [*] puredns not found — using dnsx fallback..."
    # Fallback: Generate subdomain list and resolve
    while read -r sub; do
        echo "${sub}.${TARGET}"
    done < "$WORDLIST" > "$TMP_DIR/brute_candidates.txt"

    if command -v dnsx &>/dev/null; then
        dnsx -l "$TMP_DIR/brute_candidates.txt" -silent -a -aaaa -cname -resp-only \
            -r "$RESOLVERS" -t "$THREADS" 2>/dev/null >> "$TMP_DIR/dnsx_output.txt" || true
        # Extract only unique names that resolved
        dnsx -l "$TMP_DIR/brute_candidates.txt" -silent -a -resp-only \
            -r "$RESOLVERS" -t "$THREADS" 2>/dev/null | \
            sed 's/.*\[//' | sed 's/\]//' | sort -u > "$BRUTE_FILE" || true
    else
        # Last resort: basic dig loop (limited)
        count=0
        while read -r sub; do
            hostname="${sub}.${TARGET}"
            if host "$hostname" &>/dev/null 2>&1; then
                echo "$hostname" >> "$BRUTE_FILE"
            fi
            ((count++))
            [[ $count -gt 500 ]] && break
        done < "$TMP_DIR/brute_candidates.txt"
    fi
fi

BRUTE_COUNT=$(wc -l < "$BRUTE_FILE" 2>/dev/null || echo 0)
echo "  => $BRUTE_COUNT subdomains from bruteforce"

# =============================================================================
# STAGE 3: DNS Resolution & Validation
# =============================================================================
echo "[3/6] DNS resolution and validation..."

ALL_SUBS="$TMP_DIR/all_subs.txt"
cat "$TMP_DIR/passive_clean.txt" "$BRUTE_FILE" 2>/dev/null | sort -u > "$ALL_SUBS"

ALL_COUNT=$(wc -l < "$ALL_SUBS" 2>/dev/null || echo 0)
echo "  => $ALL_COUNT unique subdomains to resolve"

RESOLVED_FILE="$TMP_DIR/resolved.txt"
> "$RESOLVED_FILE"

if command -v dnsx &>/dev/null; then
    dnsx -l "$ALL_SUBS" -silent -a -aaaa -cname \
        -r "$RESOLVERS" -t "$THREADS" \
        -o "$RESOLVED_FILE" 2>/dev/null || true
else
    # dig fallback
    while read -r hostname; do
        [[ -z "$hostname" ]] && continue
        result=$(dig +short "$hostname" A 2>/dev/null | head -1)
        if [[ -n "$result" ]]; then
            echo "$hostname [$result]" >> "$RESOLVED_FILE"
        fi
    done < "$ALL_SUBS"
fi

RESOLVED_COUNT=$(wc -l < "$RESOLVED_FILE" 2>/dev/null || echo 0)
echo "  => $RESOLVED_COUNT subdomains resolved"

# =============================================================================
# STAGE 4: Permutation Generation
# =============================================================================
echo "[4/6] Permutation-based subdomain discovery..."

PERM_FILE="$TMP_DIR/permutations.txt"
> "$PERM_FILE"

if command -v gotator &>/dev/null; then
    echo "  [*] gotator permutations..."
    gotator -sub "$ALL_SUBS" -perm "$TMP_DIR/perm_wordlist.txt" -silent \
        -depth 1 -numbers 10 -mindup -adv \
        2>/dev/null | sort -u > "$TMP_DIR/perm_candidates.txt" || true

    # Generate a basic perm wordlist
    printf "www\napi\nadmin\ndev\nstaging\ntest\napp\nportal\nm\nmobile\nv1\nv2\napi-v1\napi-v2\nuat\nqa\ninternal\nprod\nbeta\ncorp" \
        > "$TMP_DIR/perm_wordlist.txt"

    gotator -sub "$ALL_SUBS" -perm "$TMP_DIR/perm_wordlist.txt" -silent \
        -depth 1 -numbers 5 -mindup \
        2>/dev/null > "$TMP_DIR/perm_candidates.txt" || true

    if [[ -s "$TMP_DIR/perm_candidates.txt" ]]; then
        if command -v dnsx &>/dev/null; then
            dnsx -l "$TMP_DIR/perm_candidates.txt" -silent -a -resp-only \
                -r "$RESOLVERS" -t "$THREADS" 2>/dev/null \
                > "$PERM_FILE" || true
        fi
    fi
else
    # Basic manual permutations
    while read -r sub; do
        [[ -z "$sub" ]] && continue
        base="${sub%%.*}"
        for prefix in www api dev staging test admin app; do
            candidate="${prefix}.${sub#*.}"
            echo "$candidate" >> "$TMP_DIR/perm_manual.txt"
            candidate="${prefix}-${base}.${TARGET}"
            echo "$candidate" >> "$TMP_DIR/perm_manual.txt"
        done
    done < "$ALL_SUBS"

    sort -u "$TMP_DIR/perm_manual.txt" 2>/dev/null > "$TMP_DIR/perm_candidates.txt" || true
    if command -v dnsx &>/dev/null; then
        dnsx -l "$TMP_DIR/perm_candidates.txt" -silent -a -resp-only \
            -r "$RESOLVERS" -t "$THREADS" 2>/dev/null \
            > "$PERM_FILE" || true
    fi
fi

PERM_COUNT=$(wc -l < "$PERM_FILE" 2>/dev/null || echo 0)
echo "  => $PERM_COUNT new subdomains from permutations"

# =============================================================================
# STAGE 5: Live Host Verification
# =============================================================================
echo "[5/6] Verifying live hosts..."

# Merge all resolved subdomains
FINAL_SUBS="$TMP_DIR/final_subs.txt"
cat "$RESOLVED_FILE" "$PERM_FILE" 2>/dev/null | \
    awk '{print $1}' | sed 's/\[.*\]//' | sort -u > "$FINAL_SUBS"

FINAL_COUNT=$(wc -l < "$FINAL_SUBS" 2>/dev/null || echo 0)
echo "  => $FINAL_COUNT total subdomains to probe"

ALIVE_FILE="$OUTPUT_DIR/alive_hosts.txt"
> "$ALIVE_FILE"

if command -v httpx &>/dev/null; then
    httpx -l "$FINAL_SUBS" -silent -ports 80,443,8080,8443,3000,5000,8000,9000,9443 \
        -title -tech-detect -status-code -content-length \
        -threads "$THREADS" -timeout "$TIMEOUT" \
        -o "$TMP_DIR/httpx_output.txt" 2>/dev/null || true

    if [[ -s "$TMP_DIR/httpx_output.txt" ]]; then
        cp "$TMP_DIR/httpx_output.txt" "$ALIVE_FILE"
    fi
else
    # curl fallback
    while read -r hostname; do
        [[ -z "$hostname" ]] && continue
        for proto in https http; do
            url="${proto}://${hostname}"
            status=$(curl -skL --connect-timeout 5 --max-time 10 \
                -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
            if [[ "$status" != "000" ]]; then
                echo "$url [$status]" >> "$ALIVE_FILE"
                break
            fi
        done
    done < "$FINAL_SUBS"
fi

ALIVE_COUNT=$(wc -l < "$ALIVE_FILE" 2>/dev/null || echo 0)
echo "  => $ALIVE_COUNT live hosts"

# =============================================================================
# STAGE 6: Subdomain Takeover Detection
# =============================================================================
echo "[6/6] Subdomain takeover detection..."

TAKEOVER_FILE="$OUTPUT_DIR/takeover_vulns.txt"
> "$TAKEOVER_FILE"

if command -v nuclei &>/dev/null; then
    nuclei -l "$FINAL_SUBS" -t ~/nuclei-templates/dns/ \
        -silent -timeout "$TIMEOUT" \
        -o "$TAKEOVER_FILE" 2>/dev/null || true
elif command -v subjack &>/dev/null; then
    subjack -w "$FINAL_SUBS" -t "$THREADS" -timeout "$TIMEOUT" \
        -o "$TAKEOVER_FILE" -ssl 2>/dev/null || true
elif command -v subzy &>/dev/null; then
    subzy run --targets "$FINAL_SUBS" --concurrency "$THREADS" \
        --hide_fails --output "$TAKEOVER_FILE" 2>/dev/null || true
else
    echo "  [!] No takeover detection tool found — install nuclei, subjack, or subzy"
fi

TAKEOVER_COUNT=$(wc -l < "$TAKEOVER_FILE" 2>/dev/null || echo 0)
echo "  => $TAKEOVER_COUNT potential takeover targets"

# =============================================================================
# OUTPUT: Structured JSON
# =============================================================================
echo "[*] Writing structured output..."

python3 <<PYEOF > "$OUTPUT_DIR/subdomains.json"
import json, os

target = "${TARGET}"
output_dir = "${OUTPUT_DIR}"

def read_file(path):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    return []

final_subs = read_file("${FINAL_SUBS}")
alive_hosts = read_file("${ALIVE_FILE}")
takeover = read_file("${TAKEOVER_FILE}")

result = {
    "meta": {
        "tool": "subdomain_enum.sh",
        "version": "${VERSION}",
        "target": target,
        "timestamp": "$(date -Iseconds)"
    },
    "counts": {
        "passive": ${PASSIVE_COUNT},
        "bruteforce": ${BRUTE_COUNT},
        "permutations": ${PERM_COUNT},
        "total_resolved": ${FINAL_COUNT},
        "alive_hosts": ${ALIVE_COUNT},
        "takeover_vulnerable": ${TAKEOVER_COUNT}
    },
    "subdomains": final_subs,
    "alive_hosts": alive_hosts,
    "takeover_vulnerable": takeover
}

json.dump(result, sys.stdout, indent=2)
PYEOF

# Plain text output for tool chaining
cp "$FINAL_SUBS" "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || true

echo ""
echo "============================================"
echo "  PHASE 0: SUBDOMAIN ENUMERATION COMPLETE"
echo "  Total subdomains resolved: $FINAL_COUNT"
echo "  Live hosts: $ALIVE_COUNT"
echo "  Takeover vulnerabilities: $TAKEOVER_COUNT"
echo "  Output: $OUTPUT_DIR/subdomains.json"
echo "============================================"
