#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# port_scan.sh — Phase 0: Port Scanning & Service Detection
# Uses naabu for fast port discovery + nmap for service fingerprinting.
# =============================================================================

VERSION="1.0.0"
TARGETS_FILE=""
OUTPUT_DIR=""
TOP_PORTS=1000
RATE=5000
TIMEOUT=1200

usage() {
    cat <<EOF
Usage: $0 --targets <file> --output-dir <path> [options]

Port scanning and service fingerprinting.

Options:
  --targets <file>       File with target subdomains/IPs (one per line)
  --output-dir <path>    Output directory (required)
  --top-ports <N>        Top N ports to scan (default: 1000)
  --rate <N>             Packets per second for naabu (default: 5000)
  --timeout <N>          Max runtime in seconds (default: 1200)
  --help                 Show this help

Output:
  <output-dir>/open_ports.json    — Open ports per host
  <output-dir>/services.json      — Service fingerprints
  <output-dir>/vulnerabilities.json — nmap vuln scan results
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets) TARGETS_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --top-ports) TOP_PORTS="$2"; shift 2 ;;
        --rate) RATE="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "[ERROR] Unknown flag: $1"; usage ;;
    esac
done

if [[ -z "$TARGETS_FILE" || -z "$OUTPUT_DIR" ]]; then
    echo "[ERROR] --targets and --output-dir are required"
    usage
fi

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "[ERROR] Targets file not found: $TARGETS_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  Phase 0: Port Scanning & Service Detection"
echo "  Targets: $(wc -l < "$TARGETS_FILE") hosts"
echo "  Top Ports: $TOP_PORTS"
echo "============================================"

TMP_DIR=$(mktemp -d -t portscan-XXXXXXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# =============================================================================
# STAGE 1: Fast Port Discovery (naabu)
# =============================================================================
echo "[1/3] Fast port discovery..."

PORTS_JSON="$OUTPUT_DIR/open_ports.json"

if command -v naabu &>/dev/null; then
    echo "  [*] naabu scanning..."
    naabu -list "$TARGETS_FILE" \
        -top-ports "$TOP_PORTS" \
        -rate "$RATE" \
        -silent \
        -json \
        -o "$TMP_DIR/naabu_ports.jsonl" \
        -timeout "$TIMEOUT" 2>/dev/null || true

    if [[ -s "$TMP_DIR/naabu_ports.jsonl" ]]; then
        # Convert JSONL to structured JSON
        python3 <<PYEOF > "$PORTS_JSON"
import json, sys

hosts = {}
with open("${TMP_DIR}/naabu_ports.jsonl") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            host = entry.get("host", "unknown")
            port = entry.get("port", 0)
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(port)
        except json.JSONDecodeError:
            continue

result = {
    "meta": {
        "tool": "naabu",
        "version": "1.0.0",
        "top_ports": ${TOP_PORTS},
        "rate": ${RATE}
    },
    "total_hosts_scanned": len(hosts),
    "hosts": {host: sorted(ports) for host, ports in hosts.items()}
}
json.dump(result, sys.stdout, indent=2)
PYEOF
        echo "  => $(python3 -c "import json; d=json.load(open('$PORTS_JSON')); print(d.get('total_hosts_scanned',0))" 2>/dev/null || echo 0) hosts with open ports"
    else
        echo "  [!] No open ports found by naabu"
        echo '{"meta":{},"total_hosts_scanned":0,"hosts":{}}' > "$PORTS_JSON"
    fi
else
    echo "  [!] naabu not found — using nmap fallback (slower)..."
    # Fallback: nmap fast scan
    HOSTS=$(tr '\n' ' ' < "$TARGETS_FILE")
    nmap -T4 --top-ports "$TOP_PORTS" --max-retries 1 \
        --min-rate 1000 -oG "$TMP_DIR/nmap_grep.txt" \
        $HOSTS 2>/dev/null || true

    python3 <<PYEOF > "$PORTS_JSON"
import json, sys, re

hosts = {}
try:
    with open("${TMP_DIR}/nmap_grep.txt") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                host = parts[1]
                ports_str = parts[4] if len(parts) > 4 else ""
                ports = []
                for match in re.finditer(r'(\d+)/open', ports_str):
                    ports.append(int(match.group(1)))
                if ports:
                    hosts[host] = sorted(ports)
except:
    pass

result = {
    "meta": {"tool": "nmap_fallback", "version": "1.0.0", "top_ports": ${TOP_PORTS}},
    "total_hosts_scanned": len(hosts),
    "hosts": hosts
}
json.dump(result, sys.stdout, indent=2)
PYEOF
fi

# =============================================================================
# STAGE 2: Service Fingerprinting (nmap -sV)
# =============================================================================
echo "[2/3] Service fingerprinting..."

SERVICES_JSON="$OUTPUT_DIR/services.json"

# Extract host:port pairs for targeted nmap
python3 <<PYEOF > "$TMP_DIR/targeted_hosts.txt"
import json
with open("$PORTS_JSON") as f:
    data = json.load(f)
for host, ports in data.get("hosts", {}).items():
    ports_str = ",".join(str(p) for p in ports)
    print(f"{host}:{ports_str}")
PYEOF

if [[ -s "$TMP_DIR/targeted_hosts.txt" ]]; then
    echo "  [*] nmap service detection..."
    nmap -sV --version-intensity 5 --max-retries 2 \
        -iL "$TARGETS_FILE" --top-ports "$TOP_PORTS" \
        -oX "$TMP_DIR/nmap_sv.xml" 2>/dev/null || true

    if command -v searchsploit &>/dev/null 2>&1; then
        echo "  [*] searchsploit version matching..."
        searchsploit --nmap "$TMP_DIR/nmap_sv.xml" 2>/dev/null > "$TMP_DIR/exploit_matches.txt" || true
    fi

    python3 <<PYEOF > "$SERVICES_JSON"
import json, sys, xml.etree.ElementTree as ET

services = {}
try:
    tree = ET.parse("${TMP_DIR}/nmap_sv.xml")
    root = tree.getroot()
    for host_elem in root.findall("host"):
        addr = None
        for addr_elem in host_elem.findall("address"):
            addr = addr_elem.get("addr")
        if not addr:
            continue
        hostname = addr
        for hn_elem in host_elem.findall("hostnames/hostname"):
            hostname = hn_elem.get("name")
        services[hostname] = []
        for port_elem in host_elem.findall("ports/port"):
            port_id = port_elem.get("portid")
            proto = port_elem.get("protocol")
            state = port_elem.find("state")
            service = port_elem.find("service")
            if state is not None and state.get("state") == "open":
                svc_info = {
                    "port": int(port_id),
                    "protocol": proto,
                    "service": service.get("name","unknown") if service is not None else "unknown",
                    "product": service.get("product","") if service is not None else "",
                    "version": service.get("version","") if service is not None else "",
                    "extrainfo": service.get("extrainfo","") if service is not None else ""
                }
                services[hostname].append(svc_info)
except Exception as e:
    pass

result = {
    "meta": {"tool": "nmap_sV", "version": "1.0.0"},
    "total_hosts": len(services),
    "hosts": services
}
json.dump(result, sys.stdout, indent=2)
PYEOF

    SV_COUNT=$(python3 -c "import json; d=json.load(open('$SERVICES_JSON')); print(d.get('total_hosts',0))" 2>/dev/null || echo 0)
    echo "  => $SV_COUNT hosts fingerprinted"
else
    echo "  [!] No hosts to fingerprint"
    echo '{"meta":{},"total_hosts":0,"hosts":{}}' > "$SERVICES_JSON"
fi

# =============================================================================
# STAGE 3: Vulnerability Scanning (nmap NSE vuln)
# =============================================================================
echo "[3/3] Light vulnerability scanning..."

VULNS_JSON="$OUTPUT_DIR/vulnerabilities.json"

if [[ -s "$TMP_DIR/targeted_hosts.txt" ]]; then
    echo "  [*] nmap vuln scripts..."

    # Run top NSE vulnerability scripts
    nmap -sV --script=vuln --script-timeout 30s \
        -iL "$TARGETS_FILE" --top-ports "$TOP_PORTS" \
        -oX "$TMP_DIR/nmap_vuln.xml" 2>/dev/null || true

    # Run vulners if installed
    if command -v nmap-vulners &>/dev/null 2>&1; then
        nmap -sV --script=vulners --script-args mincvss=7.0 \
            -iL "$TARGETS_FILE" --top-ports 100 \
            -oX "$TMP_DIR/nmap_vulners.xml" 2>/dev/null || true
    fi

    python3 <<PYEOF > "$VULNS_JSON"
import json, sys, xml.etree.ElementTree as ET

vulns = []
try:
    tree = ET.parse("${TMP_DIR}/nmap_vuln.xml")
    root = tree.getroot()
    for host_elem in root.findall("host"):
        addr = None
        for a in host_elem.findall("address"):
            addr = a.get("addr")
        hostname = addr
        for hn in host_elem.findall("hostnames/hostname"):
            hostname = hn.get("name")
        for port_elem in host_elem.findall("ports/port"):
            port_id = port_elem.get("portid")
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id","")
                script_output = script_elem.get("output","")
                if script_id and "VULNERABLE" in script_output or "CVE" in script_output:
                    vulns.append({
                        "host": hostname,
                        "port": int(port_id),
                        "script": script_id,
                        "finding": script_output[:500]
                    })
except Exception as e:
    pass

result = {
    "meta": {"tool": "nmap_vuln_scripts", "version": "1.0.0"},
    "total_findings": len(vulns),
    "vulnerabilities": vulns
}
json.dump(result, sys.stdout, indent=2)
PYEOF

    VULN_COUNT=$(python3 -c "import json; d=json.load(open('$VULNS_JSON')); print(d.get('total_findings',0))" 2>/dev/null || echo 0)
    echo "  => $VULN_COUNT vulnerability findings"
else
    echo "  [!] No hosts for vulnerability scan"
    echo '{"meta":{},"total_findings":0,"vulnerabilities":[]}' > "$VULNS_JSON"
fi

echo ""
echo "============================================"
echo "  PHASE 0: PORT SCANNING COMPLETE"
echo "  Open ports: $OUTPUT_DIR/open_ports.json"
echo "  Services: $OUTPUT_DIR/services.json"
echo "  Vulnerabilities: $OUTPUT_DIR/vulnerabilities.json"
echo "============================================"
