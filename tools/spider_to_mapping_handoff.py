#!/usr/bin/env python3
"""
Spider-to-Mapping Handoff — Improvement #6: Automated Spider-to-Mapping Handoff
================================================================================
Reads spider outputs and auto-generates a prioritized endpoint list with
suggested batch groupings for the Lead to use in mapping dispatch.

Consumes:
  - engagement/spider/<auth|unauth>/<group>/sitemap.json
  - engagement/spider/fuzz/hidden_endpoints.json
  - engagement/spider/waf/waf_fingerprint.json
  - engagement/spider/<auth|unauth>/understanding/ (optional)

Produces:
  - engagement/mapping/ENDPOINT-PRIORITY-LIST.md  (Lead dispatch guide)
  - engagement/mapping/endpoint_inventory.json     (machine-readable)

Usage:
    python3 tools/spider_to_mapping_handoff.py
    python3 tools/spider_to_mapping_handoff.py --sitemap engagement/spider/auth/sitemap.json
    python3 tools/spider_to_mapping_handoff.py --max-batch 5

This reduces Lead token consumption: the Lead reads ONE clean priority list
instead of a 1000-endpoint sitemap.json.
"""

import sys
import json
import re
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
SPIDER_DIR = FRAMEWORK_ROOT / "engagement" / "spider"
MAPPING_DIR = FRAMEWORK_ROOT / "engagement" / "mapping"
STATE_FILE = FRAMEWORK_ROOT / "state.json"

DEFAULT_MAX_BATCH = 5


# ─── Priority Scoring ─────────────────────────────────────────────────────────

# Methods with higher security relevance
HIGH_METHOD_SCORE = {"DELETE": 4, "PUT": 4, "PATCH": 3, "POST": 3, "GET": 1}

# Path segments that indicate high-value targets
HIGH_VALUE_PATHS = {
    "admin": 5,
    "internal": 5,
    "debug": 5,
    "config": 4,
    "settings": 4,
    "account": 4,
    "profile": 3,
    "password": 5,
    "token": 4,
    "secret": 5,
    "key": 4,
    "billing": 4,
    "payment": 4,
    "transfer": 4,
    "export": 3,
    "import": 3,
    "upload": 3,
    "users": 3,
    "roles": 4,
    "permissions": 4,
    "auth": 4,
    "oauth": 4,
    "api": 2,
    "graphql": 3,
    "webhook": 3,
    "reset": 4,
    "verify": 3,
    "invite": 3,
    "impersonate": 5,
    "sudo": 5,
    "backup": 4,
    "logs": 3,
    "metrics": 2,
    "health": 1,
    "ping": 0,
}

# Parameter patterns that imply ID-based access (IDOR candidates)
ID_PARAM_PATTERNS = re.compile(r"\b(id|uuid|user_id|account_id|order_id|ref|key)\b", re.IGNORECASE)


@dataclass
class EndpointEntry:
    ep_id: str
    url: str
    methods: list[str]
    params: dict
    discovered_from: list[str]
    auth_required: str
    priority_tier: int         # 1=Critical, 2=High, 3=Medium, 4=Low
    priority_score: float
    priority_reasons: list[str]
    source: str                 # "spider" | "fuzzer" | "wayback" | "sourcemap"
    batch_group: int = 0


def score_endpoint(ep: dict, waf_info: dict) -> tuple[int, float, list[str]]:
    """
    Score an endpoint and return (priority_tier, score, reasons).
    Priority tiers: 1=Critical, 2=High, 3=Medium, 4=Low
    """
    score = 0.0
    reasons = []
    url = ep.get("url", "")
    methods = [m.upper() for m in ep.get("methods_observed", ep.get("methods", ["GET"]))]
    params = ep.get("params", {})
    source = ep.get("discovered_from", ep.get("source", ["spider"]))
    if isinstance(source, str):
        source = [source]

    # Source bonus
    if any("hidden" in str(s).lower() or "fuzzer" in str(s).lower() for s in source):
        score += 8
        reasons.append("Discovered by path fuzzer (hidden endpoint)")
    if any("sourcemap" in str(s).lower() or ".map" in str(s).lower() for s in source):
        score += 6
        reasons.append("Exposed via source map")
    if any("wayback" in str(s).lower() for s in source):
        score += 3
        reasons.append("Found in Wayback Machine (old/forgotten endpoint)")

    # Method score
    max_method_score = max(
        (HIGH_METHOD_SCORE.get(m, 1) for m in methods), default=1
    )
    score += max_method_score
    if any(m in ("POST", "PUT", "DELETE", "PATCH") for m in methods):
        reasons.append(f"Writable methods: {[m for m in methods if m != 'GET']}")

    # Path segment scoring
    path = url.split("?")[0].lower()
    path_segments = re.split(r"[/.-]", path)
    for segment in path_segments:
        segment_score = HIGH_VALUE_PATHS.get(segment, 0)
        if segment_score > 0:
            score += segment_score
            reasons.append(f"High-value path segment: '{segment}' (+{segment_score})")

    # Parameter scoring
    all_params = []
    if isinstance(params, dict):
        for param_list in params.values():
            if isinstance(param_list, list):
                all_params.extend(param_list)
    elif isinstance(params, list):
        all_params = params

    for param in all_params:
        if ID_PARAM_PATTERNS.search(str(param)):
            score += 4
            reasons.append(f"ID-like parameter: '{param}' (IDOR candidate)")
            break

    # Determine priority tier
    if score >= 12:
        tier = 1  # Critical
    elif score >= 7:
        tier = 2  # High
    elif score >= 3:
        tier = 3  # Medium
    else:
        tier = 4  # Low

    return tier, score, reasons


def load_sitemap(sitemap_path: Path) -> list[dict]:
    """Load endpoints from a sitemap.json file."""
    if not sitemap_path.exists():
        return []
    try:
        data = json.loads(sitemap_path.read_text())
        return data.get("endpoints", [])
    except Exception as e:
        print(f"  [WARN] Failed to load {sitemap_path}: {e}", file=sys.stderr)
        return []


def load_hidden_endpoints(hidden_path: Path) -> list[dict]:
    """Load hidden endpoints from path_fuzzer output."""
    if not hidden_path.exists():
        return []
    try:
        data = json.loads(hidden_path.read_text())
        results = []
        # Support multiple possible structures
        for category, endpoints in data.items():
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, dict):
                        ep["source"] = ["fuzzer", category]
                        results.append(ep)
                    elif isinstance(ep, str):
                        results.append({
                            "url": ep,
                            "methods_observed": ["GET"],
                            "params": {},
                            "discovered_from": ["fuzzer"],
                            "auth_required": "unknown",
                            "source": ["fuzzer", category],
                        })
        return results
    except Exception as e:
        print(f"  [WARN] Failed to load hidden endpoints: {e}", file=sys.stderr)
        return []


def load_waf_info(waf_path: Path) -> dict:
    """Load WAF fingerprint info."""
    if not waf_path.exists():
        return {}
    try:
        return json.loads(waf_path.read_text())
    except Exception:
        return {}


def merge_endpoints(
    spider_endpoints: list[dict], hidden_endpoints: list[dict]
) -> list[dict]:
    """Merge spider and fuzzer endpoints, deduplicating by URL."""
    seen_urls: set[str] = set()
    merged = []
    for ep in spider_endpoints:
        url = ep.get("url", "")
        normalized = url.split("?")[0].rstrip("/")
        if normalized not in seen_urls:
            seen_urls.add(normalized)
            ep.setdefault("source", ["spider"])
            merged.append(ep)

    for ep in hidden_endpoints:
        url = ep.get("url", "")
        normalized = url.split("?")[0].rstrip("/")
        if normalized not in seen_urls:
            seen_urls.add(normalized)
            merged.append(ep)
        else:
            # Found by both — merge source info
            for existing in merged:
                if existing.get("url", "").split("?")[0].rstrip("/") == normalized:
                    existing_src = existing.get("source", [])
                    hidden_src = ep.get("source", ["fuzzer"])
                    if isinstance(existing_src, list):
                        existing_src.extend(hidden_src)
                    break
    return merged


def assign_ep_ids(endpoints: list[dict], start_id: int = 1) -> list[EndpointEntry]:
    """Assign EP-XXX IDs and score all endpoints."""
    entries = []
    for i, ep in enumerate(endpoints):
        ep_id = f"EP-{start_id + i:03d}"
        tier, score, reasons = score_endpoint(ep, {})

        url = ep.get("url", "")
        source_list = ep.get("discovered_from", ep.get("source", ["spider"]))
        if isinstance(source_list, str):
            source_list = [source_list]

        source_type = "spider"
        for s in source_list:
            if "fuzzer" in str(s).lower() or "hidden" in str(s).lower():
                source_type = "fuzzer"
                break
            if "sourcemap" in str(s).lower():
                source_type = "sourcemap"
                break
            if "wayback" in str(s).lower():
                source_type = "wayback"
                break

        entries.append(
            EndpointEntry(
                ep_id=ep_id,
                url=url,
                methods=ep.get("methods_observed", ep.get("methods", ["GET"])),
                params=ep.get("params", {}),
                discovered_from=source_list,
                auth_required=ep.get("auth_required", "unknown"),
                priority_tier=tier,
                priority_score=score,
                priority_reasons=reasons,
                source=source_type,
            )
        )
    return entries


def assign_batches(entries: list[EndpointEntry], max_batch: int) -> list[EndpointEntry]:
    """Assign batch groups, keeping same-tier endpoints together."""
    # Sort by tier then by score descending
    sorted_entries = sorted(entries, key=lambda e: (e.priority_tier, -e.priority_score))
    batch_num = 1
    for i, entry in enumerate(sorted_entries):
        if i > 0 and i % max_batch == 0:
            batch_num += 1
        entry.batch_group = batch_num
    return sorted_entries


def render_priority_list(entries: list[EndpointEntry], waf_info: dict) -> str:
    """Render the priority list as a markdown document for the Lead."""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tier_names = {1: "🔴 Critical", 2: "🟠 High", 3: "🟡 Medium", 4: "⚪ Low"}

    lines = [
        "# Endpoint Priority List — Spider-to-Mapping Handoff",
        "",
        f"> Generated: {now}",
        f"> Total endpoints: {len(entries)}",
        "> **Lead:** Use this list to dispatch mapping batches in order. Start with Batch 1.",
        "",
    ]

    if waf_info:
        waf_name = waf_info.get("waf_name", waf_info.get("name", "Unknown"))
        bypass_techs = waf_info.get("bypass_techniques", [])
        lines += [
            "## WAF Summary",
            "",
            f"- **WAF Detected:** {waf_name}",
            f"- **Rate Limiting:** {waf_info.get('rate_limiting', 'unknown')}",
            f"- **Working Bypass Techniques:** {', '.join(bypass_techs) if bypass_techs else 'None detected'}",
            "",
            "> Include bypass techniques in every mapping and testing task.",
            "",
        ]

    # Group by batch
    batches: dict[int, list[EndpointEntry]] = {}
    for entry in entries:
        batches.setdefault(entry.batch_group, []).append(entry)

    lines.append("## Mapping Batches (Dispatch in Order)")
    lines.append("")

    for batch_num in sorted(batches.keys()):
        batch_entries = batches[batch_num]
        tier_summary = ", ".join(
            sorted(set(tier_names.get(e.priority_tier, "?") for e in batch_entries))
        )
        lines.append(f"### Batch {batch_num} ({len(batch_entries)} endpoints — {tier_summary})")
        lines.append("")
        lines.append("| EP ID | URL | Methods | Priority | Sources | Reasons |")
        lines.append("|---|---|---|---|---|---|")
        for e in batch_entries:
            methods_str = ", ".join(e.methods)
            tier_label = tier_names.get(e.priority_tier, "?")
            sources = ", ".join(set(str(s) for s in e.discovered_from[:2]))
            reasons = "; ".join(e.priority_reasons[:2])[:100]
            lines.append(
                f"| {e.ep_id} | `{e.url[:60]}` | {methods_str} "
                f"| {tier_label} ({e.priority_score:.0f}) | {e.source} | {reasons} |"
            )
        lines.append("")

        # Generate task stub for Lead to copy
        ep_list = "\n".join(
            f"- {e.ep_id}: {', '.join(e.methods)} {e.url}" for e in batch_entries
        )
        lines += [
            f"<details>",
            f"<summary>📋 Task stub for Batch {batch_num} (copy to tasks/)</summary>",
            "",
            "```markdown",
            f"# Task NNN — MAPPING Phase (Batch {batch_num})",
            "",
            "## Phase: 2",
            "## Status: PENDING",
            "## Worker Role: Mapper",
            "",
            "## Objective",
            f"Map these endpoints using skills/mapping/SKILL.md:",
            ep_list,
            "",
            "## Context",
            "- Sitemap: engagement/spider/auth/sitemap.json",
            "- Hidden endpoints: engagement/spider/fuzz/hidden_endpoints.json",
            "- WAF fingerprint: engagement/spider/waf/waf_fingerprint.json",
            "- Session cookie (Session A — attacker): [from state.json]",
            "- Session cookie (Session B — victim): [from state.json]",
            "",
            "## Skill File",
            "Load: skills/mapping/SKILL.md",
            "Execute: All phases M1-M8 for EACH endpoint above.",
            "",
            "## What to Report",
            "Write engagement/mapping/EP-XXX.profile.yaml for each endpoint.",
            "After all are mapped, write summary to results/result-NNN-mapping.md",
            "```",
            "",
            "</details>",
            "",
        ]

    # Stats summary
    tier_counts = {}
    for entry in entries:
        tier_counts[entry.priority_tier] = tier_counts.get(entry.priority_tier, 0) + 1

    lines += [
        "---",
        "",
        "## Endpoint Distribution",
        "",
        "| Priority | Count |",
        "|---|---|",
    ]
    for tier in sorted(tier_counts.keys()):
        lines.append(f"| {tier_names.get(tier, tier)} | {tier_counts[tier]} |")

    lines += [
        "",
        "| Source | Count |",
        "|---|---|",
    ]
    source_counts: dict[str, int] = {}
    for entry in entries:
        source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
    for src, count in sorted(source_counts.items()):
        lines.append(f"| {src} | {count} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Automated spider-to-mapping handoff generator"
    )
    parser.add_argument(
        "--sitemap",
        type=Path,
        help="Path to sitemap.json (default: auto-detect from engagement/spider/)",
    )
    parser.add_argument(
        "--hidden-endpoints",
        type=Path,
        default=SPIDER_DIR / "fuzz" / "hidden_endpoints.json",
        help="Path to hidden_endpoints.json",
    )
    parser.add_argument(
        "--waf-fingerprint",
        type=Path,
        default=SPIDER_DIR / "waf" / "waf_fingerprint.json",
        help="Path to waf_fingerprint.json",
    )
    parser.add_argument(
        "--max-batch",
        type=int,
        default=DEFAULT_MAX_BATCH,
        help=f"Max endpoints per mapping batch (default: {DEFAULT_MAX_BATCH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=MAPPING_DIR / "ENDPOINT-PRIORITY-LIST.md",
        help="Output markdown file path",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=MAPPING_DIR / "endpoint_inventory.json",
        help="Output JSON inventory path",
    )
    args = parser.parse_args()

    # Auto-detect sitemap
    sitemap_path = args.sitemap
    if sitemap_path is None:
        # Prefer auth sitemap > unauth sitemap > first found
        candidates = [
            SPIDER_DIR / "auth" / "sitemap.json",
            SPIDER_DIR / "unauth" / "sitemap.json",
            SPIDER_DIR / "sitemap.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                sitemap_path = candidate
                break
        if sitemap_path is None:
            # Search recursively
            found = list(SPIDER_DIR.rglob("sitemap.json"))
            if found:
                sitemap_path = found[0]

    if sitemap_path is None or not sitemap_path.exists():
        print("ERROR: No sitemap.json found. Run Phase 1 (spidering) first.")
        sys.exit(1)

    print(f"Loading sitemap: {sitemap_path}")
    spider_eps = load_sitemap(sitemap_path)
    print(f"  → {len(spider_eps)} endpoints from spider")

    print(f"Loading hidden endpoints: {args.hidden_endpoints}")
    hidden_eps = load_hidden_endpoints(args.hidden_endpoints)
    print(f"  → {len(hidden_eps)} hidden endpoints from fuzzer")

    print(f"Loading WAF fingerprint: {args.waf_fingerprint}")
    waf_info = load_waf_info(args.waf_fingerprint)

    all_eps = merge_endpoints(spider_eps, hidden_eps)
    print(f"  → {len(all_eps)} unique endpoints after merge")

    entries = assign_ep_ids(all_eps)
    entries = assign_batches(entries, args.max_batch)

    MAPPING_DIR.mkdir(parents=True, exist_ok=True)

    # Write markdown
    report = render_priority_list(entries, waf_info)
    args.output.write_text(report)
    print(f"\nPriority list written: {args.output}")

    # Write JSON inventory
    inventory = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sitemap_source": str(sitemap_path),
        "total_endpoints": len(entries),
        "batches": args.max_batch,
        "endpoints": [asdict(e) for e in entries],
    }
    args.json_output.write_text(json.dumps(inventory, indent=2))
    print(f"JSON inventory written: {args.json_output}")

    # Stats
    tier_names = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
    for tier in sorted(set(e.priority_tier for e in entries)):
        count = sum(1 for e in entries if e.priority_tier == tier)
        print(f"  {tier_names[tier]}: {count} endpoints")

    total_batches = max((e.batch_group for e in entries), default=0)
    print(f"\nTotal mapping batches to dispatch: {total_batches}")


if __name__ == "__main__":
    main()
