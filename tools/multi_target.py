#!/usr/bin/env python3
"""
Multi-Target Manager — Improvement #13: Multi-Target Support
=============================================================
Manages multiple target domains within a single program engagement.

Features:
  - Target grouping (api.target.com, www.target.com, admin.target.com)
  - Cross-target correlation for M9 chain synthesis
  - Parallel spidering command generation for multiple targets
  - Cross-target credential/token leakage detection

Usage:
    python3 tools/multi_target.py init --targets api.example.com,www.example.com,admin.example.com
    python3 tools/multi_target.py spider-all   -- generates spider commands for all targets
    python3 tools/multi_target.py correlate    -- cross-target signal analysis
    python3 tools/multi_target.py status       -- show per-target progress

State: Managed via state.json under a "targets" key per domain.
"""

import sys
import json
import argparse
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
ENGAGEMENT_DIR = FRAMEWORK_ROOT / "engagement"
MAPPING_DIR = ENGAGEMENT_DIR / "mapping"


@dataclass
class Target:
    domain: str
    label: str               # api | www | admin | app | etc.
    base_url: str
    spider_status: str = "not_started"
    mapping_status: str = "not_started"
    endpoints_total: int = 0
    hypotheses_total: int = 0
    priority: int = 1        # 1=highest, relative order to spider


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        print("[ERROR] state.json not found. Run setup.sh first.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] state.json is malformed: {e}")
        sys.exit(1)


def save_state(state: dict) -> None:
    from datetime import timezone
    state.setdefault("_meta", {})
    state["_meta"]["last_updated_by"] = "multi_target"
    state["_meta"]["last_updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    STATE_FILE.write_text(json.dumps(state, indent=2))


def detect_label(domain: str) -> str:
    """Auto-detect target label from domain prefix."""
    prefix = domain.split(".")[0].lower()
    label_map = {
        "api": "api",
        "app": "app",
        "admin": "admin",
        "console": "admin",
        "dashboard": "admin",
        "www": "www",
        "portal": "portal",
        "staging": "staging",
        "dev": "dev",
        "beta": "beta",
        "m": "mobile",
        "mobile": "mobile",
        "auth": "auth",
        "sso": "auth",
        "login": "auth",
        "cdn": "cdn",
        "static": "static",
        "assets": "static",
    }
    return label_map.get(prefix, prefix)


def cmd_init(state: dict, target_strings: list[str]) -> None:
    """Initialize multi-target tracking in state.json."""
    targets_data = state.setdefault("targets", {})

    # Determine base target from engagement
    engagement_target = state.get("engagement", {}).get("target", "")

    priority = 1
    for target_str in target_strings:
        # Normalize — strip protocol
        domain = re.sub(r"^https?://", "", target_str).rstrip("/")
        base_url = f"https://{domain}"
        label = detect_label(domain)

        if domain in targets_data:
            print(f"  [SKIP] {domain} already in targets")
            continue

        targets_data[domain] = {
            "domain": domain,
            "label": label,
            "base_url": base_url,
            "spider_status": "not_started",
            "mapping_status": "not_started",
            "testing_status": "not_started",
            "endpoints_total": 0,
            "hypotheses_total": 0,
            "priority": priority,
            "spider_output_dir": f"engagement/spider/targets/{label}",
            "mapping_output_dir": f"engagement/mapping/targets/{label}",
            "credentials_shared": True,  # Assume same auth as main target unless overridden
        }
        priority += 1
        print(f"  + Added target: {domain} (label: {label}, priority: {priority - 1})")

        # Create output directories
        (ENGAGEMENT_DIR / "spider" / "targets" / label).mkdir(parents=True, exist_ok=True)
        (ENGAGEMENT_DIR / "mapping" / "targets" / label).mkdir(parents=True, exist_ok=True)

    save_state(state)
    print(f"\n✅ Multi-target initialized with {len(target_strings)} targets")
    print("   Run: python3 tools/multi_target.py spider-all  to generate spider commands")


def cmd_spider_all(state: dict) -> None:
    """Generate parallel spidering commands for all targets."""
    targets = state.get("targets", {})
    if not targets:
        print("[ERROR] No targets configured. Run: multi_target.py init --targets ...")
        sys.exit(1)

    engagement = state.get("engagement", {})
    base_target = engagement.get("target", "")

    print("# Multi-Target Spider Commands")
    print("# Run these in parallel (background jobs or separate terminals)")
    print()

    priority_sorted = sorted(targets.values(), key=lambda t: t.get("priority", 99))

    for i, target_data in enumerate(priority_sorted):
        domain = target_data["domain"]
        label = target_data["label"]
        output_dir = target_data.get("spider_output_dir", f"engagement/spider/targets/{label}")
        base_url = target_data["base_url"]

        print(f"# Target {i+1}: {domain} ({label})")
        print(f"./tools/spider/spider.sh \"{base_url}\" \\")
        print(f"    --output-dir {output_dir} \\")
        print(f"    --rate-limit 5 &")
        print()

    print("# Wait for all background jobs")
    print("wait")
    print()
    print("# After all spiders complete, run handoff for each target:")
    for target_data in priority_sorted:
        label = target_data["label"]
        output_dir = target_data.get("spider_output_dir", f"engagement/spider/targets/{label}")
        print(f"python3 tools/spider_to_mapping_handoff.py \\")
        print(f"    --sitemap {output_dir}/sitemap.json \\")
        print(f"    --output engagement/mapping/targets/{label}/ENDPOINT-PRIORITY-LIST.md")
        print()


def cmd_correlate(state: dict) -> None:
    """Analyze cross-target correlations (credentials, IDs, session tokens)."""
    targets = state.get("targets", {})
    if not targets:
        print("No targets configured.")
        return

    print("Cross-Target Correlation Analysis")
    print("=" * 60)
    print()

    # Load all endpoint profiles across all targets
    all_profiles = []
    for target_data in targets.values():
        label = target_data.get("label", "unknown")
        target_mapping = ENGAGEMENT_DIR / "mapping" / "targets" / label
        if target_mapping.exists():
            profiles = list(target_mapping.glob("EP-*.profile.yaml"))
            all_profiles.extend(
                (label, p.name, p.read_text()) for p in profiles
            )

    # Also include main target profiles
    main_profiles = list(MAPPING_DIR.glob("EP-*.profile.yaml"))
    all_profiles.extend(
        ("main", p.name, p.read_text()) for p in main_profiles
    )

    if not all_profiles:
        print("[INFO] No endpoint profiles found. Run Phase 2 (mapping) for each target first.")
        return

    print(f"Analyzing {len(all_profiles)} profiles across {len(targets) + 1} targets...")
    print()

    # Look for cross-target patterns
    correlations = []

    # 1. JWT/token sharing
    jwt_mentions = [
        (label, name) for label, name, content in all_profiles
        if "jwt" in content.lower() or "bearer" in content.lower()
    ]
    if len(set(l for l, _ in jwt_mentions)) > 1:
        correlations.append({
            "type": "JWT/token sharing",
            "description": "Multiple targets use JWT/Bearer tokens — credential from one may work on another",
            "targets": list(set(l for l, _ in jwt_mentions)),
            "risk": "HIGH",
        })

    # 2. Same ID format across targets (cross-target IDOR potential)
    id_patterns = {}
    for label, name, content in all_profiles:
        if "sequential" in content.lower():
            id_patterns.setdefault("sequential_int", []).append(label)
        if "uuid" in content.lower():
            id_patterns.setdefault("uuid", []).append(label)

    for pattern, pattern_labels in id_patterns.items():
        unique_labels = list(set(pattern_labels))
        if len(unique_labels) > 1:
            correlations.append({
                "type": f"Cross-target ID reuse ({pattern})",
                "description": f"Same ID format on {unique_labels} — IDs from one target may be usable on another",
                "targets": unique_labels,
                "risk": "HIGH",
            })

    # 3. Admin target present
    admin_targets = [t for t in targets if "admin" in t.lower() or "console" in t.lower()]
    if admin_targets:
        correlations.append({
            "type": "Admin target present",
            "description": f"Admin surfaces detected: {admin_targets}. Test credential reuse from user-facing targets.",
            "targets": admin_targets,
            "risk": "CRITICAL",
        })

    # Output report
    if correlations:
        print("⚠️  Cross-target correlations found:")
        print()
        for c in correlations:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(c["risk"], "⚪")
            print(f"  {icon} [{c['risk']}] {c['type']}")
            print(f"     {c['description']}")
            print(f"     Targets: {', '.join(c['targets'])}")
            print()

        # Save correlations
        output = MAPPING_DIR / "CROSS-TARGET-CORRELATIONS.md"
        lines = [
            "# Cross-Target Correlation Analysis",
            "",
            f"> Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "",
            "## Findings",
            "",
        ]
        for c in correlations:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(c["risk"], "⚪")
            lines += [
                f"### {icon} {c['type']} — {c['risk']}",
                "",
                c["description"],
                "",
                f"**Affected targets:** {', '.join(c['targets'])}",
                "",
            ]
        output.write_text("\n".join(lines))
        print(f"Correlation report saved: {output}")
    else:
        print("✅ No significant cross-target correlations found.")


def cmd_status(state: dict) -> None:
    """Show per-target progress."""
    targets = state.get("targets", {})
    if not targets:
        print("No multi-target configuration. Single-target mode active.")
        return

    print("MULTI-TARGET STATUS")
    print("=" * 60)
    for domain, data in sorted(targets.items(), key=lambda x: x[1].get("priority", 99)):
        spider_status = data.get("spider_status", "not_started")
        mapping_status = data.get("mapping_status", "not_started")
        sp_icon = {"complete": "✅", "in_progress": "🔄", "not_started": "⬜"}.get(spider_status, "?")
        mp_icon = {"complete": "✅", "in_progress": "🔄", "not_started": "⬜"}.get(mapping_status, "?")
        print(f"\n  [{data.get('priority', '?')}] {domain} ({data.get('label', '?')})")
        print(f"     Spider:  {sp_icon} {spider_status}")
        print(f"     Mapping: {mp_icon} {mapping_status}")
        print(f"     Endpoints: {data.get('endpoints_total', 0)}")
        print(f"     Hypotheses: {data.get('hypotheses_total', 0)}")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-target manager for the bug bounty framework"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    init_p = subparsers.add_parser("init", help="Initialize multi-target configuration")
    init_p.add_argument(
        "--targets",
        required=True,
        help="Comma-separated list of target domains",
    )

    # spider-all
    subparsers.add_parser("spider-all", help="Generate spider commands for all targets")

    # correlate
    subparsers.add_parser("correlate", help="Run cross-target correlation analysis")

    # status
    subparsers.add_parser("status", help="Show per-target progress")

    args = parser.parse_args()
    state = load_state()

    if args.command == "init":
        targets = [t.strip() for t in args.targets.split(",")]
        cmd_init(state, targets)
    elif args.command == "spider-all":
        cmd_spider_all(state)
    elif args.command == "correlate":
        cmd_correlate(state)
    elif args.command == "status":
        cmd_status(state)


if __name__ == "__main__":
    main()
