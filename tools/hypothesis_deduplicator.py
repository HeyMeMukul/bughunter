#!/usr/bin/env python3
"""
Hypothesis Deduplicator — Improvement #3: Hypothesis Deduplication and Pruning
===============================================================================
Reads all EP-XXX.profile.yaml files in engagement/mapping/ and:
  1. Identifies duplicate/similar hypotheses across endpoints
  2. Applies "tested once, applies to similar" rule
  3. Enforces a cap of MAX_LOW_CONFIDENCE_PER_ENDPOINT LOW hypotheses per endpoint
  4. Outputs a prioritized, deduplicated hypothesis list for Lead dispatch

Usage:
    python3 tools/hypothesis_deduplicator.py
    python3 tools/hypothesis_deduplicator.py --output engagement/mapping/HYPOTHESIS-PRIORITY.md
    python3 tools/hypothesis_deduplicator.py --mark-confirmed HYP-007 --similar-endpoints EP-003,EP-007

Output: Prioritized hypothesis list with dedup annotations, written as markdown.
"""

import sys
import os
import json
import re
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

try:
    import yaml
except ImportError:
    yaml = None

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = FRAMEWORK_ROOT / "state.json"
MAPPING_DIR = FRAMEWORK_ROOT / "engagement" / "mapping"

MAX_LOW_CONFIDENCE_PER_ENDPOINT = 3

CONFIDENCE_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
IMPACT_SCORE = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": 1,
}

# Vuln types that can auto-propagate to similar endpoints when confirmed
AUTO_PROPAGATE_TYPES = {
    "IDOR",
    "SQLi",
    "SSRF",
    "SSTI",
    "XXE",
    "CORS",
    "CSRF",
    "JWT",
    "Mass-Assignment",
    "Path-Traversal",
}


@dataclass
class Hypothesis:
    hyp_id: str
    vuln_type: str
    endpoint_id: str
    endpoint_url: str
    target_param: str
    confidence: str
    rationale: str
    suggested_skill: str
    impact_floor: str = "unknown"
    impact_ceiling: str = "unknown"
    drop_unless_chain: bool = False
    dedup_status: str = "unique"          # unique | duplicate | auto_low | propagated
    dedup_reason: str = ""
    priority_score: float = 0.0


def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def load_profiles() -> list[dict]:
    """Load all EP-XXX.profile.yaml files. Returns list of dicts."""
    profiles = []
    if not MAPPING_DIR.exists():
        return profiles

    for profile_path in sorted(MAPPING_DIR.glob("EP-*.profile.yaml")):
        if yaml is not None:
            try:
                with open(profile_path) as f:
                    data = yaml.safe_load(f)
                    if data:
                        profiles.append(data)
                        continue
            except Exception:
                pass
        # Fallback: regex-based parsing for environments without PyYAML
        profiles.append(_parse_profile_regex(profile_path))

    return profiles


def _parse_profile_regex(profile_path: Path) -> dict:
    """Minimal regex-based profile parser (fallback when PyYAML not available)."""
    content = profile_path.read_text()
    data: dict = {"_source": str(profile_path)}

    # Extract endpoint_id
    m = re.search(r"endpoint_id:\s*(\S+)", content)
    if m:
        data["endpoint_id"] = m.group(1)

    # Extract url
    m = re.search(r"url:\s*(\S+)", content)
    if m:
        data["url"] = m.group(1)

    # Extract hypotheses section as raw text
    hyp_match = re.findall(
        r"-\s+id:\s*(HYP-\d+).*?type:\s*(\S+).*?target_param:\s*(.+?)\n"
        r".*?confidence:\s*(\S+).*?rationale:\s*(.+?)\n"
        r".*?suggested_skill:\s*(\S+)",
        content,
        re.DOTALL,
    )
    hypotheses = []
    for m in hyp_match:
        hypotheses.append(
            {
                "id": m[0],
                "type": m[1],
                "target_param": m[2].strip(),
                "confidence": m[3],
                "rationale": m[4].strip(),
                "suggested_skill": m[5],
            }
        )
    data["hypotheses_generated"] = hypotheses
    return data


def extract_hypotheses_from_profiles(profiles: list[dict]) -> list[Hypothesis]:
    """Extract all Hypothesis objects from loaded profiles."""
    hypotheses = []
    for profile in profiles:
        endpoint_id = profile.get("endpoint_id", "UNKNOWN")
        endpoint_url = profile.get("url", "")
        raw_hyps = profile.get("hypotheses_generated", [])
        if not isinstance(raw_hyps, list):
            continue
        for h in raw_hyps:
            if not isinstance(h, dict):
                continue
            hyp = Hypothesis(
                hyp_id=h.get("id", "HYP-???"),
                vuln_type=h.get("type", "Unknown"),
                endpoint_id=endpoint_id,
                endpoint_url=endpoint_url,
                target_param=str(h.get("target_param", "")),
                confidence=h.get("confidence", "LOW"),
                rationale=str(h.get("rationale", "")),
                suggested_skill=h.get("suggested_skill", ""),
                impact_floor=h.get("impact_floor", "unknown"),
                impact_ceiling=h.get("impact_ceiling", "unknown"),
                drop_unless_chain=h.get("drop_unless_chain_found", False),
            )
            # Compute raw priority score
            conf_score = CONFIDENCE_SCORE.get(hyp.confidence, 1)
            impact = IMPACT_SCORE.get(hyp.impact_floor, 1)
            hyp.priority_score = float(conf_score * impact)
            hypotheses.append(hyp)
    return hypotheses


def deduplicate(hypotheses: list[Hypothesis], state: dict) -> list[Hypothesis]:
    """
    Apply deduplication rules:
    1. Exact same vuln_type + param_name on very similar URL patterns → mark lower-priority as duplicate
    2. If confirmed in state.json → mark similar patterns as propagated (auto LOW priority)
    3. Enforce LOW hypothesis cap per endpoint
    """
    # Track tested/confirmed by vuln_type+param
    confirmed_patterns: set[tuple] = set()
    tested_ids: set[str] = set(state.get("testing", {}).get("tested_hypothesis_ids", []))
    confirmed_ids: set[str] = set()

    for finding in state.get("findings", []):
        ftype = finding.get("type", "")
        fep = finding.get("endpoint", "")
        confirmed_patterns.add((ftype, _normalize_url(fep)))
        confirmed_ids.add(finding.get("hypothesis_id", ""))

    # Group by (vuln_type, param_name) to detect cross-endpoint duplicates
    pattern_map: dict[tuple, list[Hypothesis]] = defaultdict(list)
    for hyp in hypotheses:
        param_name = hyp.target_param.split("(")[0].strip()
        key = (hyp.vuln_type, param_name)
        pattern_map[key].append(hyp)

    # Mark duplicates: same vuln+param seen on multiple endpoints → mark all but highest-scored
    for key, hyp_group in pattern_map.items():
        if len(hyp_group) <= 1:
            continue
        # Sort by priority score descending
        hyp_group.sort(key=lambda h: h.priority_score, reverse=True)
        primary = hyp_group[0]
        for dup in hyp_group[1:]:
            if dup.dedup_status == "unique":
                dup.dedup_status = "duplicate"
                dup.dedup_reason = (
                    f"Same vuln pattern ({key[0]} on '{key[1]}') already covered by "
                    f"{primary.hyp_id} ({primary.endpoint_id}). "
                    "Test primary first; if confirmed, this is also likely vulnerable."
                )
                dup.priority_score *= 0.2  # Dramatically lower priority

    # Mark auto-propagated patterns from confirmed findings
    for hyp in hypotheses:
        norm_url = _normalize_url(hyp.endpoint_url)
        pattern_key = (hyp.vuln_type, norm_url)
        if pattern_key in confirmed_patterns and hyp.vuln_type in AUTO_PROPAGATE_TYPES:
            if hyp.dedup_status == "unique":
                hyp.dedup_status = "propagated"
                hyp.dedup_reason = (
                    f"{hyp.vuln_type} already confirmed on similar URL pattern. "
                    "Very likely also vulnerable — mark LOW effort, HIGH value."
                )
                hyp.priority_score = max(hyp.priority_score * 0.4, 0.5)

    # Enforce LOW hypothesis cap per endpoint
    low_count_by_ep: dict[str, int] = defaultdict(int)
    for hyp in sorted(hypotheses, key=lambda h: h.priority_score, reverse=True):
        if hyp.confidence == "LOW" and hyp.dedup_status == "unique":
            low_count_by_ep[hyp.endpoint_id] += 1
            if low_count_by_ep[hyp.endpoint_id] > MAX_LOW_CONFIDENCE_PER_ENDPOINT:
                hyp.dedup_status = "auto_low"
                hyp.dedup_reason = (
                    f"LOW confidence cap reached for {hyp.endpoint_id} "
                    f"(max {MAX_LOW_CONFIDENCE_PER_ENDPOINT} LOW per endpoint). "
                    "Deferred — test only if higher-priority items are exhausted."
                )
                hyp.priority_score = 0.1

    return hypotheses


def _normalize_url(url: str) -> str:
    """Normalize URL by replacing numeric IDs and UUIDs with placeholders."""
    url = re.sub(r"/\d+", "/{id}", url)
    url = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}",
        url,
        flags=re.IGNORECASE,
    )
    return url.rstrip("/")


def render_report(hypotheses: list[Hypothesis]) -> str:
    """Render deduplicated hypothesis list as a markdown report."""
    from datetime import datetime

    lines = [
        "# Hypothesis Priority List — Deduplicated",
        "",
        f"> Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"> Total hypotheses: {len(hypotheses)}",
        "",
    ]

    # Sort: active unique/propagated first by priority_score, then duplicates, then auto_low
    def sort_key(h: Hypothesis):
        status_order = {"unique": 0, "propagated": 1, "duplicate": 2, "auto_low": 3}
        return (status_order.get(h.dedup_status, 9), -h.priority_score)

    sorted_hyps = sorted(hypotheses, key=sort_key)

    # Group by status
    groups = {
        "unique": "## ✅ Active (Unique) — Dispatch These",
        "propagated": "## 🔁 Propagated — From Confirmed Patterns",
        "duplicate": "## ⚠️ Duplicates — Test After Primary",
        "auto_low": "## 🔕 Deferred (LOW Cap) — Test Last",
    }

    for status, heading in groups.items():
        group_hyps = [h for h in sorted_hyps if h.dedup_status == status]
        if not group_hyps:
            continue
        lines.append(heading)
        lines.append("")
        lines.append(
            "| ID | Vuln | Endpoint | Param | Confidence | Priority | Notes |"
        )
        lines.append("|---|---|---|---|---|---|---|")
        for h in group_hyps:
            notes = h.dedup_reason[:80] if h.dedup_reason else "—"
            lines.append(
                f"| {h.hyp_id} | {h.vuln_type} | {h.endpoint_id} ({h.endpoint_url[:40]}) "
                f"| {h.target_param[:20]} | {h.confidence} | {h.priority_score:.1f} | {notes} |"
            )
        lines.append("")

    # Stats
    total = len(hypotheses)
    unique_count = sum(1 for h in hypotheses if h.dedup_status == "unique")
    dup_count = sum(1 for h in hypotheses if h.dedup_status == "duplicate")
    lines.extend(
        [
            "---",
            "",
            "## Summary",
            "",
            f"| Category | Count |",
            f"|---|---|",
            f"| Total hypotheses | {total} |",
            f"| Active (dispatch) | {unique_count} |",
            f"| Propagated | {sum(1 for h in hypotheses if h.dedup_status == 'propagated')} |",
            f"| Duplicates (deferred) | {dup_count} |",
            f"| LOW-cap deferred | {sum(1 for h in hypotheses if h.dedup_status == 'auto_low')} |",
            "",
            "> **Lead instruction:** Dispatch hypotheses in order from the Active table.",
            "> When a Duplicate's primary hypothesis is confirmed, promote the duplicate to Active.",
        ]
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Hypothesis deduplicator for the bug bounty framework"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=MAPPING_DIR / "HYPOTHESIS-PRIORITY.md",
        help="Output file path (default: engagement/mapping/HYPOTHESIS-PRIORITY.md)",
    )
    parser.add_argument(
        "--mark-confirmed",
        metavar="HYP_ID",
        help="Mark a hypothesis as confirmed and auto-propagate similar patterns",
    )
    parser.add_argument(
        "--similar-endpoints",
        metavar="EP-001,EP-002",
        help="Comma-separated list of similar endpoint IDs for propagation",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print report to stdout instead of writing to file",
    )
    args = parser.parse_args()

    print("Loading profiles from engagement/mapping/...")
    profiles = load_profiles()
    if not profiles:
        print("No profiles found. Run Phase 2 (mapping) first.")
        sys.exit(0)
    print(f"  Loaded {len(profiles)} endpoint profiles")

    state = load_state()
    hypotheses = extract_hypotheses_from_profiles(profiles)
    print(f"  Extracted {len(hypotheses)} raw hypotheses")

    # Handle --mark-confirmed propagation
    if args.mark_confirmed:
        hyp_id = args.mark_confirmed
        similar_eps = args.similar_endpoints.split(",") if args.similar_endpoints else []
        print(f"  Marking {hyp_id} as confirmed, propagating to {similar_eps}")
        # Update state (add to testing.tested_hypothesis_ids)
        if "testing" not in state:
            state["testing"] = {}
        tested_list = state["testing"].setdefault("tested_hypothesis_ids", [])
        if hyp_id not in tested_list:
            tested_list.append(hyp_id)

    hypotheses = deduplicate(hypotheses, state)

    report = render_report(hypotheses)

    if args.dry_run:
        print(report)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
        print(f"\n  Written to: {args.output}")
        print(
            f"  Active hypotheses to dispatch: "
            f"{sum(1 for h in hypotheses if h.dedup_status in ('unique', 'propagated'))}"
        )


if __name__ == "__main__":
    main()
