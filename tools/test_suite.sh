#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test_suite.sh — Framework Verification Test Suite
# Syntax checks all bash scripts, compiles all python, validates state.json.
# =============================================================================

PASS=0
FAIL=0
SKIP=0
BASE_DIR="$(cd "$(dirname "$0")" && pwd)/.."

green() { echo -e "\033[32m$1\033[0m"; }
red() { echo -e "\033[31m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; }

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" 2>/dev/null; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        red "  FAIL: $name"
    fi
}

echo "============================================"
echo "  Framework Test Suite — v4.0.0"
echo "============================================"
echo ""

# ─── Config Validation ───────────────────────────────────────────
echo "[1] Configuration Validation"
echo "----------------------------"

check "state.json valid JSON" "python3 -c 'import json; json.load(open(\"$BASE_DIR/state.json\"))'"
check "opencode.json valid JSON" "python3 -c 'import json; json.load(open(\"$BASE_DIR/opencode.json\"))'"
check "opencode.json has 6 MCPs" "python3 -c \"import json; d=json.load(open('$BASE_DIR/opencode.json')); m=set(d.get('mcp',{}).keys()); assert len(m)>=6, f'Expected 6 MCPs, got {len(m)}: {m}'\""
check "opencode.json has 12 commands" "python3 -c \"import json; d=json.load(open('$BASE_DIR/opencode.json')); c=set(d.get('command',{}).keys()); assert len(c)>=12, f'Expected 12 commands, got {len(c)}: {c}'\""
check "state.json schema v3.0.0" "python3 -c \"import json; d=json.load(open('$BASE_DIR/state.json')); assert d.get('_meta',{}).get('schema_version')=='3.0.0'\""
check "state.json has recon section" "python3 -c \"import json; d=json.load(open('$BASE_DIR/state.json')); assert 'recon' in d\""
check "state.json current_focus is phase_0_recon" "python3 -c \"import json; d=json.load(open('$BASE_DIR/state.json')); assert d.get('engagement',{}).get('current_focus')=='phase_0_recon'\""

echo ""

# ─── Bash Syntax ─────────────────────────────────────────────────
echo "[2] Bash Script Syntax Checks"
echo "-----------------------------"

BASH_SCRIPTS=$(find "$BASE_DIR/tools" -name "*.sh" -type f | sort)
BASH_SCRIPTS="$BASH_SCRIPTS $BASE_DIR/setup.sh"

for script in $BASH_SCRIPTS; do
    name=$(echo "$script" | sed "s|$BASE_DIR/||")
    check "$name" "bash -n '$script' 2>&1"
done

echo ""

# ─── Python Compilation ──────────────────────────────────────────
echo "[3] Python Syntax Checks"
echo "------------------------"

PY_FILES=$(find "$BASE_DIR/tools" -name "*.py" -type f -not -path "*/__pycache__/*" | sort)

for pyfile in $PY_FILES; do
    name=$(echo "$pyfile" | sed "s|$BASE_DIR/||")
    check "$name" "python3 -m py_compile '$pyfile' 2>&1"
done

echo ""

# ─── Skills Directory ────────────────────────────────────────────
echo "[4] Skill File Completeness"
echo "---------------------------"

SKILL_DIRS=$(ls -d "$BASE_DIR/skills"/*/ 2>/dev/null | sort)
for skill_dir in $SKILL_DIRS; do
    skill_name=$(basename "$skill_dir")
    has_skill=0
    has_summary=0

    if [[ -f "$skill_dir/SKILL.md" ]]; then has_skill=1; fi
    if [[ -f "$skill_dir/SUMMARY.md" ]]; then has_summary=1; fi

    if [[ $has_skill -eq 1 && $has_summary -eq 1 ]]; then
        check "skills/$skill_name (SKILL.md + SUMMARY.md)" "true"
    elif [[ $has_skill -eq 1 ]]; then
        yellow "  SKIP: skills/$skill_name (missing SUMMARY.md)"
        SKIP=$((SKIP + 1))
    else
        red "  FAIL: skills/$skill_name (missing SKILL.md)"
        FAIL=$((FAIL + 1))
    fi
done

echo ""

# ─── Tool Permissions ────────────────────────────────────────────
echo "[5] Tool Executable Permissions"
echo "-------------------------------"

EXEC_FILES=$(find "$BASE_DIR/tools" -name "*.sh" -type f | sort)
EXEC_FILES="$EXEC_FILES $BASE_DIR/setup.sh"

for f in $EXEC_FILES; do
    name=$(echo "$f" | sed "s|$BASE_DIR/||")
    check "$name executable" "test -x '$f'"
done

echo ""

# ─── Knowledge Base ──────────────────────────────────────────────
echo "[6] Knowledge Base Completeness"
echo "--------------------------------"

check "knowledge/INDEX.md exists" "test -f '$BASE_DIR/knowledge/INDEX.md'"
for expected in idor_patterns ssrf_patterns chain_patterns auth_bypass_patterns xss_patterns rce_patterns; do
    check "knowledge/disclosed_reports/${expected}.md" "test -f '$BASE_DIR/knowledge/disclosed_reports/${expected}.md'"
done
for expected in h1_acceptance_patterns bugcrowd_acceptance impact_thresholds common_duplicate_reasons; do
    check "knowledge/triage_intelligence/${expected}.md" "test -f '$BASE_DIR/knowledge/triage_intelligence/${expected}.md'"
done

echo ""

# ─── Summary ─────────────────────────────────────────────────────
echo "============================================"
TOTAL=$((PASS + FAIL + SKIP))
echo "  RESULTS"
echo "============================================"
green "  PASSED:  $PASS"
red   "  FAILED:  $FAIL"
yellow "  SKIPPED: $SKIP"
echo "  TOTAL:   $TOTAL"
echo ""

if [[ $FAIL -eq 0 ]]; then
    green "  ✅ ALL CHECKS PASSED"
    exit 0
else
    red "  ❌ $FAIL CHECK(S) FAILED"
    exit 1
fi
