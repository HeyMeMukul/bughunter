#!/bin/bash
# setup.sh — Phase-Aware Engagement Setup (SAFE VERSION)
# 
# Three operating modes (auto-detected by default):
#   INIT    - Fresh engagement when no existing data
#   RESUME  - Re-launch browsers, keep all data (DEFAULT when engagement exists)
#   RESET   - Backup + wipe + init (requires --reset flag + confirmation)
#
# Usage:
#   ./setup.sh                                              # auto-detect, smart default
#   ./setup.sh "https://target.com" "program-name"          # smart-detect (won't wipe)
#   ./setup.sh "https://target.com" "program-name" "no"     # same + skip browsers
#   ./setup.sh --status                                     # just show current state
#   ./setup.sh --resume                                     # explicit resume (no data touched)
#   ./setup.sh --reset --url URL --program NAME             # explicit fresh start (with backup)
#   ./setup.sh --reset --force --url URL --program NAME     # reset, skip confirmation
#   ./setup.sh --help                                       # show this help

set -e

# ============================================================
# Argument parsing
# ============================================================
MODE=""              # auto | init | resume | reset | status
TARGET_URL=""
PROGRAM=""
LAUNCH_BROWSERS="yes"
FORCE="no"
SHOW_HELP="no"

# Backwards-compat: positional args (URL, PROGRAM, BROWSERS) still work
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --status)         MODE="status"; shift ;;
        --resume)         MODE="resume"; shift ;;
        --reset|--new)    MODE="reset"; shift ;;
        --init)           MODE="init"; shift ;;
        --url)            TARGET_URL="$2"; shift 2 ;;
        --program)        PROGRAM="$2"; shift 2 ;;
        --no-browsers)    LAUNCH_BROWSERS="no"; shift ;;
        --browsers)       LAUNCH_BROWSERS="yes"; shift ;;
        --force|-f)       FORCE="yes"; shift ;;
        --help|-h)        SHOW_HELP="yes"; shift ;;
        *)                POSITIONAL+=("$1"); shift ;;
    esac
done

# Apply positional args (backwards compat)
[ -z "$TARGET_URL" ] && [ -n "${POSITIONAL[0]}" ] && TARGET_URL="${POSITIONAL[0]}"
[ -z "$PROGRAM" ] && [ -n "${POSITIONAL[1]}" ] && PROGRAM="${POSITIONAL[1]}"
[ -n "${POSITIONAL[2]}" ] && LAUNCH_BROWSERS="${POSITIONAL[2]}"

# Help
if [ "$SHOW_HELP" = "yes" ]; then
    sed -n '1,20p' "$0" | grep -E '^#' | sed 's/^# \?//'
    exit 0
fi

# ============================================================
# Helper functions
# ============================================================

# Check if there's an active engagement
has_active_engagement() {
    if [ ! -f "state.json" ]; then return 1; fi
    
    # Check if state.json shows active engagement
    local status program endpoints
    status=$(python3 -c "import json; d=json.load(open('state.json')); print(d.get('engagement',{}).get('status',''))" 2>/dev/null)
    program=$(python3 -c "import json; d=json.load(open('state.json')); print(d.get('engagement',{}).get('program',''))" 2>/dev/null)
    endpoints=$(python3 -c "import json; d=json.load(open('state.json')); print(d.get('spider',{}).get('endpoints_total',0))" 2>/dev/null)
    
    # Active if status is "active" OR there's a program name OR spider has found endpoints
    if [ "$status" = "active" ] || [ -n "$program" ] || [ "${endpoints:-0}" -gt 0 ]; then
        return 0
    fi
    
    # Also check if engagement dir has files
    if [ -d "engagement/spider" ] && [ "$(ls -A engagement/spider 2>/dev/null | grep -v README.md | wc -l)" -gt 0 ]; then
        return 0
    fi
    if [ -d "engagement/mapping" ] && [ "$(ls -A engagement/mapping 2>/dev/null | wc -l)" -gt 0 ]; then
        return 0
    fi
    if [ -d "engagement/findings" ] && [ "$(ls -A engagement/findings 2>/dev/null | wc -l)" -gt 0 ]; then
        return 0
    fi
    
    return 1
}

# Print summary of current engagement
show_engagement_status() {
    if [ ! -f "state.json" ]; then
        echo "  Status: No engagement initialized (no state.json)"
        return
    fi
    
    python3 << 'PYEOF' 2>/dev/null
import json
import os

try:
    with open("state.json") as f:
        s = json.load(f)
except Exception as e:
    print(f"  Status: state.json exists but invalid ({e})")
    exit()

eng = s.get("engagement", {})
print(f"  Program:        {eng.get('program','(none)')}")
print(f"  Target:         {eng.get('target','(none)')}")
print(f"  Started:        {eng.get('started','(none)')}")
print(f"  Status:         {eng.get('status','(none)')}")
print(f"  Current focus:  {eng.get('current_focus','(none)')}")
print(f"")
print(f"  Phase Progress:")

recon = s.get("recon", {})
print(f"    Phase 0 RECON: {recon.get('status','not_started')} ({recon.get('subdomains_found',0)} subs, {recon.get('live_hosts',0)} live, {recon.get('takeover_candidates',0)} takeover)")

spider = s.get("spider", {})
print(f"    Spider:       {spider.get('status','not_started')} ({spider.get('endpoints_total',0)} endpoints)")

mapping = s.get("mapping", {})
print(f"    Mapping:      {mapping.get('status','not_started')} ({mapping.get('endpoints_mapped',0)} mapped, {mapping.get('hypotheses_generated_total',0)} hypotheses)")

testing = s.get("testing", {})
print(f"    Testing:      {testing.get('status','not_started')} ({testing.get('hypotheses_confirmed',0)} confirmed, {testing.get('hypotheses_negative',0)} negative)")

validating = s.get("validating", {})
print(f"    Validating:   {validating.get('status','not_started')} ({validating.get('validated_count',0)} validated)")

reporting = s.get("reporting", {})
print(f"    Reporting:    {reporting.get('status','not_started')} ({reporting.get('reports_written',0)} reports)")

findings = s.get("findings", [])
if findings:
    print(f"")
    print(f"  Findings ({len(findings)}):")
    for f in findings[:5]:
        print(f"    - {f.get('id','?')}: {f.get('type','?')} on {f.get('endpoint','?')} ({f.get('severity','?')}, {f.get('status','?')})")
    if len(findings) > 5:
        print(f"    ... and {len(findings)-5} more")

# Count engagement artifacts
counts = {}
for d in ["recon", "spider", "mapping", "findings", "reports"]:
    path = f"engagement/{d}"
    if os.path.isdir(path):
        files = [f for f in os.listdir(path) if not f.startswith('.') and f != 'README.md']
        counts[d] = len(files)
    else:
        counts[d] = 0

print(f"")
print(f"  Artifact counts:")
print(f"    engagement/spider:   {counts['spider']} items")
print(f"    engagement/mapping:  {counts['mapping']} items")
print(f"    engagement/findings: {counts['findings']} items")
print(f"    engagement/reports:  {counts['reports']} items")

next_session = s.get("next_session", {})
if next_session:
    print(f"")
    print(f"  Next session notes:")
    for k, v in next_session.items():
        print(f"    {k}: {v}")
PYEOF
}

# Archive current engagement to engagement-archive/<program>-<timestamp>/
archive_current_engagement() {
    local archive_name archive_dir
    local current_program
    
    if [ -f "state.json" ]; then
        current_program=$(python3 -c "import json; d=json.load(open('state.json')); print(d.get('engagement',{}).get('program','unknown'))" 2>/dev/null)
    fi
    current_program="${current_program:-unknown}"
    # Sanitize program name for filesystem
    current_program=$(echo "$current_program" | tr ' /\\' '___' | tr -cd 'a-zA-Z0-9_.-')
    [ -z "$current_program" ] && current_program="unknown"
    
    archive_name="${current_program}-$(date +%Y%m%d-%H%M%S)"
    archive_dir="engagement-archive/${archive_name}"
    
    echo "    Backing up to: $archive_dir"
    mkdir -p "$archive_dir"
    
    # Copy everything that matters
    [ -f "state.json" ] && cp state.json "$archive_dir/" 2>/dev/null
    [ -f "target_prompt.md" ] && cp target_prompt.md "$archive_dir/" 2>/dev/null
    [ -d "engagement" ] && cp -r engagement "$archive_dir/" 2>/dev/null
    [ -d "tasks" ] && find tasks -maxdepth 1 -name "task-[0-9]*.md" -exec cp {} "$archive_dir/" \; 2>/dev/null
    [ -d "results" ] && find results -maxdepth 1 -name "result-*.md" -exec cp {} "$archive_dir/" \; 2>/dev/null
    
    # Write metadata
    cat > "$archive_dir/_ARCHIVE_INFO.md" << ARCHEOF
# Archived Engagement: $current_program

- Archived at: $(date)
- Reason: Reset by setup.sh
- Original location: $(pwd)

## Contents
- state.json — snapshot of engagement state
- target_prompt.md — target prompt at time of archive
- engagement/ — all spider/mapping/findings/reports artifacts
- task-*.md — Lead-generated tasks
- result-*.md — Worker-generated results

## To Restore
\`\`\`bash
# Stop any running browsers, then:
cp $archive_dir/state.json .
cp -r $archive_dir/engagement/* engagement/
cp $archive_dir/task-*.md tasks/ 2>/dev/null
cp $archive_dir/result-*.md results/ 2>/dev/null
\`\`\`
ARCHEOF
    
    local size=$(du -sh "$archive_dir" 2>/dev/null | cut -f1)
    echo "    ✓ Archived (${size:-unknown size})"
}

# Initialize fresh state.json
init_state_json() {
    cat > state.json << STATEEOF
{
  "engagement": {
    "program": "$PROGRAM",
    "target": "$TARGET_URL",
    "started": "$(date +%Y-%m-%dT%H:%M:%SZ)",
    "status": "active",
    "current_focus": "phase_0_recon"
  },
  "sessions": {
    "session_a": {
      "role": "attacker",
      "browser_port": 9222,
      "status": "not_logged_in",
      "cookie_extracted_path": null
    },
    "session_b": {
      "role": "victim",
      "browser_port": 9223,
      "status": "not_logged_in",
      "cookie_extracted_path": null
    }
  },
  "recon": {
    "status": "not_started",
    "subdomains_found": 0,
    "live_hosts": 0,
    "takeover_candidates": 0,
    "hosts_with_open_ports": 0,
    "tech_profiles_created": 0,
    "cloud_buckets_found": 0,
    "public_buckets": 0,
    "email_security_risk": "unknown",
    "k8s_endpoints_found": 0,
    "api_frameworks_found": 0,
    "recon_json_path": null,
    "attack_surface_insights": [],
    "critical_findings": [],
    "live_hosts_list_path": null
  },
  "spider": {
    "status": "not_started",
    "endpoints_total": 0,
    "hidden_endpoints_found": 0,
    "sitemap_path": null,
    "comprehension": {
      "sources_recovered": 0,
      "webpack_chunks": 0,
      "api_specs_found": [],
      "csp_trusted_hosts": 0,
      "wayback_extras_not_in_sitemap": 0
    },
    "waf": {
      "name": null,
      "rate_limiting": false,
      "bypass_techniques": []
    },
    "hidden_params_found": 0
  },
  "mapping": {
    "status": "not_started",
    "endpoints_mapped": 0,
    "endpoints_pending": [],
    "hypotheses_generated_total": 0,
    "high_confidence_count": 0
  },
  "testing": {
    "status": "not_started",
    "hypotheses_total": 0,
    "hypotheses_tested": 0,
    "hypotheses_confirmed": 0,
    "hypotheses_negative": 0,
    "high_priority_pending": []
  },
  "validating": {
    "status": "not_started",
    "validated_count": 0,
    "pending": []
  },
  "reporting": {
    "status": "not_started",
    "reports_written": 0,
    "pending": []
  },
  "findings": [],
  "chains_identified": [],
  "blocked_chars": {},
  "waf_observations": [],
  "next_session": {}
}
STATEEOF
}

# Ensure directory structure exists
ensure_dirs() {
    mkdir -p engagement/recon/subdomains engagement/recon/ports engagement/recon/tech engagement/recon/cloud
    mkdir -p engagement/spider/unauth engagement/spider/auth engagement/spider/cdp_recon engagement/spider/raw
    mkdir -p engagement/spider/fuzz engagement/spider/fuzz_auth engagement/spider/waf engagement/spider/params
    mkdir -p engagement/mapping engagement/findings engagement/reports
    mkdir -p tasks/templates results
    mkdir -p knowledge/disclosed_reports knowledge/attack_patterns knowledge/triage_intelligence knowledge/hunter_calendar
    mkdir -p phases/0-recon phases/1-spidering phases/2-mapping phases/3-testing phases/4-validating phases/5-reporting
    mkdir -p engagement-archive
}

# Ensure tool permissions
ensure_perms() {
    chmod +x tools/recon/*.sh 2>/dev/null || true
    chmod +x tools/nuclei_runner.sh 2>/dev/null || true
    chmod +x tools/interactsh_launcher.sh 2>/dev/null || true
    chmod +x tools/sqlmap_runner.sh 2>/dev/null || true
    chmod +x tools/secret_scanner.sh 2>/dev/null || true
    chmod +x tools/spider/spider.sh 2>/dev/null || true
    chmod +x tools/spider/spider_comprehension.sh 2>/dev/null || true
    chmod +x tools/path_fuzzer.sh 2>/dev/null || true
    chmod +x tools/param_discover.sh 2>/dev/null || true
    chmod +x tools/waf_detect.sh 2>/dev/null || true
    chmod +x tools/cdp_browser.py 2>/dev/null || true
    chmod +x tools/response_diff.py 2>/dev/null || true
    chmod +x tools/oob_validator.py 2>/dev/null || true
    chmod +x setup.sh 2>/dev/null || true
}

# Check prerequisites
check_prereqs() {
    local missing=""
    command -v curl >/dev/null || missing+=" curl"
    command -v python3 >/dev/null || missing+=" python3"
    command -v jq >/dev/null || missing+=" jq"
    python3 -c "import websockets" 2>/dev/null || missing+=" python3-websockets"
    
    if [ "$LAUNCH_BROWSERS" = "yes" ]; then
        command -v google-chrome >/dev/null || missing+=" google-chrome"
    fi
    
    if [ -n "$missing" ]; then
        echo "    ⚠ Missing:$missing"
        echo "       Install hints:"
        [[ "$missing" == *curl* ]] && echo "       sudo apt install -y curl"
        [[ "$missing" == *python3* ]] && echo "       sudo apt install -y python3"
        [[ "$missing" == *jq* ]] && echo "       sudo apt install -y jq"
        [[ "$missing" == *websockets* ]] && echo "       pip install websockets --break-system-packages"
        [[ "$missing" == *google-chrome* ]] && echo "       sudo apt install -y google-chrome-stable"
        return 1
    else
        echo "    ✓ All prerequisites met"
        return 0
    fi
}

# Launch Chrome sessions
launch_browsers() {
    if [ "$LAUNCH_BROWSERS" != "yes" ]; then
        echo "    Skipping browser launch (--no-browsers)"
        return
    fi
    
    if ! command -v google-chrome >/dev/null; then
        echo "    ⚠ google-chrome not installed — skipping"
        return
    fi
    
    # Check if already running
    local a_running="no" b_running="no"
    if curl -s http://localhost:9222/json/version >/dev/null 2>&1; then a_running="yes"; fi
    if curl -s http://localhost:9223/json/version >/dev/null 2>&1; then b_running="yes"; fi
    
    if [ "$a_running" = "yes" ] && [ "$b_running" = "yes" ]; then
        echo "    ✓ Both Chrome sessions already running (9222, 9223)"
        return
    fi
    
    # Kill stale instances
    pkill -f "remote-debugging-port=9222" 2>/dev/null || true
    pkill -f "remote-debugging-port=9223" 2>/dev/null || true
    sleep 1
    
    local target="${TARGET_URL:-about:blank}"
    
    # Session A
    google-chrome \
	--ozone-platform=wayland \
        --remote-debugging-port=9222 \
        --user-data-dir=/tmp/chrome-session-a \
        --no-first-run \
        --no-default-browser-check \
        --window-size=1280,900 \
        --window-position=0,0 \
        "$target" &>/dev/null &
    sleep 2
    
    # Session B
    google-chrome \
	--ozone-platform=wayland \
        --remote-debugging-port=9223 \
        --user-data-dir=/tmp/chrome-session-b \
        --no-first-run \
        --no-default-browser-check \
        --window-size=1280,900 \
        --window-position=1300,0 \
        "$target" &>/dev/null &
    sleep 2
    
    if curl -s http://localhost:9222/json/version >/dev/null 2>&1; then
        echo "    ✓ Session A — Chrome on port 9222"
    else
        echo "    ✗ Session A failed (launch manually if needed)"
    fi
    
    if curl -s http://localhost:9223/json/version >/dev/null 2>&1; then
        echo "    ✓ Session B — Chrome on port 9223"
    else
        echo "    ✗ Session B failed (launch manually if needed)"
    fi
}

# ============================================================
# Auto-detect mode if not specified
# ============================================================
if [ -z "$MODE" ]; then
    if has_active_engagement; then
        MODE="resume"
    else
        MODE="init"
    fi
fi

# ============================================================
# Mode: STATUS
# ============================================================
if [ "$MODE" = "status" ]; then
    echo "==================================================="
    echo "  Bug Bounty Framework — Engagement Status"
    echo "==================================================="
    echo ""
    show_engagement_status
    echo ""
    
    # Show archives if any
    if [ -d "engagement-archive" ] && [ "$(ls -A engagement-archive 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "  Archived engagements:"
        for arch in engagement-archive/*/; do
            [ -d "$arch" ] || continue
            local_name=$(basename "$arch")
            local_size=$(du -sh "$arch" 2>/dev/null | cut -f1)
            echo "    - $local_name ($local_size)"
        done
    fi
    echo "==================================================="
    exit 0
fi

# ============================================================
# Mode: RESUME (safe — no data touched)
# ============================================================
if [ "$MODE" = "resume" ]; then
    echo "==================================================="
    echo "  Bug Bounty Framework — RESUME Mode"
    echo "  (no data will be modified)"
    echo "==================================================="
    echo ""
    echo "  Existing engagement detected. Resuming."
    echo ""
    show_engagement_status
    echo ""
    
    echo "  [1/3] Verifying directory structure..."
    ensure_dirs
    echo "    ✓ Directories present"
    
    echo "  [2/3] Setting tool permissions..."
    ensure_perms
    echo "    ✓ Tools executable"
    
    echo "  [3/3] Launching browser sessions..."
    launch_browsers
    
    echo ""
    echo "==================================================="
    echo "  RESUME COMPLETE — your engagement is intact"
    echo "==================================================="
    echo ""
    echo "  NEXT STEPS:"
    echo "    1. If browsers needed re-login, log in now"
    echo "    2. Start opencode (single session):"
    echo "       opencode"
    echo "       > Resume engagement. Read master_prompt.md,"
    echo "         lead_prompt.md, target_prompt.md, state.json."
    echo "         What is the next priority task? Spawn Worker subagents."
    echo ""
    echo "       Or use: opencode /resume"
    echo ""
    echo "  To start a NEW engagement (wipes current):"
    echo "    ./setup.sh --reset --url URL --program NAME"
    echo ""
    echo "  To check status anytime:"
    echo "    ./setup.sh --status"
    echo ""
    echo "==================================================="
    exit 0
fi

# ============================================================
# Mode: RESET (destructive — requires confirmation)
# ============================================================
if [ "$MODE" = "reset" ]; then
    echo "==================================================="
    echo "  Bug Bounty Framework — RESET Mode"
    echo "  (WARNING: this will wipe current engagement)"
    echo "==================================================="
    echo ""
    
    if has_active_engagement; then
        echo "  CURRENT ENGAGEMENT WILL BE BACKED UP THEN WIPED:"
        echo ""
        show_engagement_status
        echo ""
        
        if [ "$FORCE" != "yes" ]; then
            echo "  Type 'yes' to confirm reset (anything else cancels):"
            read -r CONFIRM
            if [ "$CONFIRM" != "yes" ]; then
                echo ""
                echo "  Cancelled. No changes made."
                echo ""
                echo "  To resume current engagement:"
                echo "    ./setup.sh --resume"
                exit 0
            fi
        fi
        
        echo ""
        echo "  [1/7] Archiving current engagement..."
        archive_current_engagement
    else
        echo "  No active engagement detected. Initializing fresh."
        echo ""
    fi
    
    # Fall through to INIT logic
    MODE="init"
fi

# ============================================================
# Mode: INIT (fresh engagement)
# ============================================================
if [ "$MODE" = "init" ]; then
    # Use defaults if not provided
    TARGET_URL="${TARGET_URL:-https://target.com}"
    PROGRAM="${PROGRAM:-engagement}"
    
    echo "==================================================="
    echo "  Bug Bounty Framework — INIT Mode"
    echo "  v4.0.0 — The GOATED Framework"
    echo "==================================================="
    echo "  Target:    $TARGET_URL"
    echo "  Program:   $PROGRAM"
    echo "  Browsers:  $LAUNCH_BROWSERS"
    echo "==================================================="
    echo ""
    
    # Safety check: don't accidentally wipe an active engagement during init
    if has_active_engagement && [ "$FORCE" != "yes" ]; then
        echo "  ⚠ SAFETY HALT: Active engagement detected."
        echo ""
        show_engagement_status
        echo ""
        echo "  Your existing engagement data is INTACT."
        echo ""
        echo "  Options:"
        echo "    To resume work:                ./setup.sh --resume"
        echo "    To start fresh (with backup):  ./setup.sh --reset --url URL --program NAME"
        echo "    To check status:               ./setup.sh --status"
        echo ""
        echo "  Use --force to override this safety check (NOT recommended)."
        echo ""
        exit 1
    fi
    
    echo "  [1/6] Initializing state.json..."
    init_state_json
    echo "    ✓ state.json initialized for: $PROGRAM"
    
    echo "  [2/6] Clearing previous engagement data..."
    rm -f tasks/task-[0-9]*.md 2>/dev/null || true
    rm -f results/result-*.md 2>/dev/null || true
    # Clear engagement subdirs but preserve README.md
    for d in spider mapping findings reports; do
        if [ -d "engagement/$d" ]; then
            find "engagement/$d" -mindepth 1 -not -name "README.md" -delete 2>/dev/null || true
        fi
    done
    echo "    ✓ Previous data cleared (templates and READMEs preserved)"
    
    echo "  [3/6] Verifying directory structure..."
    ensure_dirs
    echo "    ✓ Directories ready"
    
    echo "  [4/6] Setting tool permissions..."
    ensure_perms
    echo "    ✓ Tools executable"
    
    echo "  [5/6] Checking prerequisites..."
    check_prereqs || true
    
    echo "  [6/6] Launching browser sessions..."
    launch_browsers
    
    echo ""
    echo "==================================================="
    echo "  SETUP COMPLETE — fresh engagement ready"
    echo "==================================================="
    echo ""
    echo "  NEXT STEPS:"
    echo ""
    echo "  1. Edit target_prompt.md with program scope and rules"
    echo ""
    echo "  2. Manually log in to Chrome:"
    echo "     - Left window  (port 9222) → ATTACKER account"
    echo "     - Right window (port 9223) → VICTIM  account"
    echo ""
    echo "  3. Start opencode (ONE session — Lead + Worker subagents):"
    echo "       cd $(pwd)"
    echo "       opencode"
    echo ""
    echo "       First message:"
    echo "       > Read master_prompt.md, lead_prompt.md, target_prompt.md,"
    echo "         methodology.md, bug_bounty_master_methodology_lean.md,"
    echo "         phases/PHASE_ARCHITECTURE.md, and state.json."
    echo "         Dispatch Phase 0 Recon. Then Phase 1 Spidering."
    echo ""
    echo "  4. Verify MCP servers are connected (6 total):"
    echo "       - Playwright MCP (browser automation)"
    echo "       - Burp Suite MCP (port 9876 — ensure Burp Pro MCP extension is running)"
    echo "       - GitHub MCP (code + secret search — needs GITHUB_PERSONAL_ACCESS_TOKEN)"
    echo "       - Brave Search MCP (web dorking — needs BRAVE_API_KEY)"
    echo "       - Memory MCP (persistent knowledge graph — local, no config needed)"
    echo "       - Sequential Thinking MCP (chain reasoning — local, no config needed)"
    echo ""
    echo "  5. Read OPERATOR_GUIDE.md and AGENTS.md for the full workflow"
    echo ""
    echo "  SAFETY:"
    echo "    Re-running setup.sh on this engagement is SAFE"
    echo "    (defaults to --resume, won't wipe data)"
    echo ""
    echo "==================================================="
fi
