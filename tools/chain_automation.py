#!/usr/bin/env python3
"""
chain_automation.py — Automated M9 Chain Synthesis Engine
Reads all mapping profiles and automatically identifies cross-endpoint chain
opportunities. Replaces manual Lead-driven M9 analysis with automated scoring.

Key outputs:
  engagement/mapping/CHAIN-CANDIDATES.md — Auto-generated chain hypotheses
  engagement/mapping/CHAIN-INVENTORY.md — Gadget catalog with G-XXX IDs
"""

import json
import os
import sys
import argparse
import re
import yaml
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict


class ChainAutomator:
    """Automates M9 chain synthesis from endpoint profiles."""

    # Known gadget types and their primitives
    GADGET_PATTERNS = {
        "info_disclosure": {
            "triggers": ["user_id", "email", "token", "api_key", "secret", "uuid", "internal_ip", "admin_id"],
            "chain_enabler": ["idor", "privilege_escalation", "account_takeover"],
            "weight": 5,
        },
        "open_redirect": {
            "triggers": ["redirect", "url", "return", "next", "callback", "continue", "goto"],
            "chain_enabler": ["ssrf_bypass", "csrf", "token_theft", "xss"],
            "weight": 6,
        },
        "csrf_vulnerable": {
            "triggers": ["no_csrf_token", "csrf_missing", "same_site_none"],
            "chain_enabler": ["account_takeover", "profile_modification", "role_change"],
            "weight": 4,
        },
        "xss_reflected": {
            "triggers": ["reflected_xss", "echoed_param", "html_reflection"],
            "chain_enabler": ["session_theft", "csrf_bypass", "keylogger"],
            "weight": 6,
        },
        "xss_stored": {
            "triggers": ["stored_xss", "profile_xss", "comment_xss"],
            "chain_enabler": ["session_theft", "admin_takeover", "worm"],
            "weight": 7,
        },
        "token_leakage": {
            "triggers": ["jwt_in_url", "token_in_body", "session_in_log", "api_key_in_js"],
            "chain_enabler": ["account_takeover", "api_access", "privilege_escalation"],
            "weight": 5,
        },
        "idor_read": {
            "triggers": ["idor_confirmed", "sequential_id", "predictable_id"],
            "chain_enabler": ["mass_data_extraction", "pii_exposure"],
            "weight": 3,
        },
        "idor_write": {
            "triggers": ["idor_write", "put_idor", "delete_idor", "patch_idor"],
            "chain_enabler": ["privilege_escalation", "data_tampering", "denial_of_service"],
            "weight": 5,
        },
        "ssrf_blind": {
            "triggers": ["ssrf_oob", "blind_ssrf", "url_fetch"],
            "chain_enabler": ["internal_access", "metadata_access", "rce"],
            "weight": 7,
        },
        "ssrf_full": {
            "triggers": ["ssrf_response", "full_ssrf", "ssrf_with_body"],
            "chain_enabler": ["metadata_extraction", "internal_api_access", "rce"],
            "weight": 8,
        },
        "sql_injection": {
            "triggers": ["sqli_confirmed", "sql_injection", "error_based", "union_based"],
            "chain_enabler": ["data_extraction", "authentication_bypass", "rce_via_os_shell"],
            "weight": 6,
        },
        "file_upload": {
            "triggers": ["file_upload", "avatar_upload", "document_upload"],
            "chain_enabler": ["stored_xss", "rce", "phishing"],
            "weight": 4,
        },
        "race_condition": {
            "triggers": ["race_condition", "toctou", "concurrent_request"],
            "chain_enabler": ["coupon_abuse", "double_spend", "limit_bypass"],
            "weight": 5,
        },
        "auth_bypass": {
            "triggers": ["auth_bypass", "no_auth_required", "jwt_alg_none"],
            "chain_enabler": ["full_access", "admin_panel", "mass_data_access"],
            "weight": 8,
        },
        "cache_poisoning": {
            "triggers": ["cache_key_injection", "unkeyed_param", "cache_poison"],
            "chain_enabler": ["xss_for_all_users", "redirect_hijack"],
            "weight": 6,
        },
    }

    # Known chain templates from disclosed reports
    CHAIN_TEMPLATES = [
        {
            "name": "Info_Disclosure → IDOR → Mass_Data_Extraction",
            "required": ["info_disclosure", "idor_read"],
            "chain_weight": 8,
            "example_bounty": "$5,000 — Airbnb (leaked user IDs → IDOR on user endpoint → 100K+ user records)",
        },
        {
            "name": "Open_Redirect → SSRF_Bypass → Cloud_Metadata",
            "required": ["open_redirect", "ssrf_blind"],
            "chain_weight": 9,
            "example_bounty": "$50,000 — Shopify (open redirect on whitelisted domain → SSRF → AWS credentials)",
        },
        {
            "name": "CSRF → Profile_Update → XSS_via_Stored",
            "required": ["csrf_vulnerable", "xss_stored"],
            "chain_weight": 7,
            "example_bounty": "$3,000 — Self-XSS + CSRF = stored XSS for all users",
        },
        {
            "name": "IDOR_Read → Race_Condition → Double_Exploitation",
            "required": ["idor_read", "race_condition"],
            "chain_weight": 7,
            "example_bounty": "$8,000 — IDOR + race condition = unlimited coupon redemption",
        },
        {
            "name": "XSS → Session_Theft → Account_Takeover",
            "required": ["xss_reflected", "token_leakage"],
            "chain_weight": 8,
            "example_bounty": "$2,500 — XSS on login page → steal tokens → full ATO",
        },
        {
            "name": "SSRF → Internal_API → SQLi → Data_Extraction",
            "required": ["ssrf_full", "sql_injection"],
            "chain_weight": 9,
            "example_bounty": "$15,000 — SSRF to internal API → SQLi → customer database dump",
        },
        {
            "name": "File_Upload → RCE → Internal_Pivot",
            "required": ["file_upload", "ssrf_blind"],
            "chain_weight": 9,
            "example_bounty": "$20,000 — Upload webshell → SSRF to metadata → AWS account takeover",
        },
        {
            "name": "Cache_Poison → Reflected_XSS × All_Users",
            "required": ["cache_poisoning", "xss_reflected"],
            "chain_weight": 9,
            "example_bounty": "$10,000 — Cache poison + XSS = stored XSS for every visitor",
        },
    ]

    def __init__(self, mapping_dir: str):
        self.mapping_dir = mapping_dir

    def load_profiles(self) -> List[Dict[str, Any]]:
        """Load all EP-XXX.profile.yaml files from mapping directory."""
        profiles = []
        if not os.path.isdir(self.mapping_dir):
            return profiles

        for filename in sorted(os.listdir(self.mapping_dir)):
            if not filename.startswith("EP-") or not filename.endswith(".profile.yaml"):
                continue

            filepath = os.path.join(self.mapping_dir, filename)
            try:
                with open(filepath) as f:
                    profile = yaml.safe_load(f)
                    if profile:
                        profiles.append(profile)
            except Exception:
                continue

        return profiles

    def extract_gadgets(self, profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract gadget primitives from all profiles."""
        gadgets = []
        g_id = 1

        for profile in profiles:
            endpoint_id = profile.get("endpoint_id", "unknown")
            url = profile.get("url", "unknown")

            # Check hypotheses for known gadget types
            hypotheses = profile.get("hypotheses_generated", [])
            for hyp in hypotheses:
                hyp_type = hyp.get("type", "").lower().replace("-", "_")
                confidence = hyp.get("confidence", "LOW")

                for gadget_name, gadget_info in self.GADGET_PATTERNS.items():
                    triggers = gadget_info.get("triggers", [])
                    matched = False
                    for trigger in triggers:
                        if trigger in hyp_type or trigger in hyp.get("rationale", "").lower():
                            matched = True
                            break

                    if matched:
                        gadgets.append(
                            {
                                "gadget_id": f"G-{g_id:03d}",
                                "endpoint_id": endpoint_id,
                                "url": url,
                                "type": gadget_name,
                                "confidence": confidence,
                                "weight": gadget_info["weight"],
                                "chain_enablers": gadget_info["chain_enabler"],
                                "source_hypothesis": hyp.get("id", "unknown"),
                            }
                        )
                        g_id += 1

            # Check signals for additional gadgets
            signals = profile.get("signals_detected", [])
            for signal in signals:
                signal_text = signal.get("signal", "").lower()
                for gadget_name, gadget_info in self.GADGET_PATTERNS.items():
                    for trigger in gadget_info["triggers"]:
                        if trigger in signal_text:
                            # Avoid duplicates
                            already_gadget = any(
                                g["endpoint_id"] == endpoint_id
                                and g["type"] == gadget_name
                                for g in gadgets
                            )
                            if not already_gadget:
                                confidence = signal.get("confidence", "LOW")
                                gadgets.append(
                                    {
                                        "gadget_id": f"G-{g_id:03d}",
                                        "endpoint_id": endpoint_id,
                                        "url": url,
                                        "type": gadget_name,
                                        "confidence": confidence,
                                        "weight": gadget_info["weight"],
                                        "chain_enablers": gadget_info["chain_enabler"],
                                        "source_signal": signal_text,
                                    }
                                )
                                g_id += 1

        return gadgets

    def find_chains(
        self, gadgets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find chain candidates from gadget inventory."""
        chains = []

        # Match against known chain templates
        for template in self.CHAIN_TEMPLATES:
            required_types = set(template["required"])
            available_types = set(g["type"] for g in gadgets)

            if required_types.issubset(available_types):
                # Find the best gadgets for each required type
                best_gadgets = []
                for req_type in required_types:
                    type_gadgets = [g for g in gadgets if g["type"] == req_type]
                    # Prefer HIGH confidence
                    for conf in ["HIGH", "MEDIUM", "LOW"]:
                        for g in type_gadgets:
                            if g["confidence"] == conf:
                                best_gadgets.append(g)
                                break
                        if any(b["type"] == req_type for b in best_gadgets):
                            break

                # Calculate chain priority score
                weights = [g["weight"] for g in best_gadgets]
                chain_weight = template["chain_weight"]
                avg_gadget_weight = sum(weights) / len(weights) if weights else 1
                priority = chain_weight * avg_gadget_weight

                chains.append(
                    {
                        "chain_template": template["name"],
                        "gadgets": best_gadgets,
                        "priority_score": round(priority, 1),
                        "example_bounty": template["example_bounty"],
                        "endpoints_involved": list(set(g["endpoint_id"] for g in best_gadgets)),
                    }
                )

        # Also find novel chains (not in templates)
        # Cross-reference gadgets that enable each other
        for i, g1 in enumerate(gadgets):
            for j, g2 in enumerate(gadgets):
                if i >= j:
                    continue
                if g1["endpoint_id"] == g2["endpoint_id"]:
                    continue

                # Check if g1 enables g2's exploitation
                for enabler in g1.get("chain_enablers", []):
                    if enabler in g2.get("chain_enablers", []):
                        # Novel chain found
                        novel_weight = g1["weight"] + g2["weight"]
                        chains.append(
                            {
                                "chain_template": f"Novel: {g1['type']} → {g2['type']}",
                                "gadgets": [g1, g2],
                                "priority_score": round(novel_weight * 1.2, 1),
                                "example_bounty": "Novel chain — high payout potential",
                                "endpoints_involved": [g1["endpoint_id"], g2["endpoint_id"]],
                                "novel": True,
                            }
                        )

        # Sort by priority score
        chains.sort(key=lambda c: c["priority_score"], reverse=True)
        return chains

    def generate_inventory_markdown(
        self, gadgets: List[Dict[str, Any]], chains: List[Dict[str, Any]]
    ) -> str:
        """Generate CHAIN-INVENTORY.md content."""
        lines = []
        lines.append("# Chain Inventory — Gadget Catalog\n")
        lines.append(f"Auto-generated by chain_automation.py\n")
        lines.append(f"Total gadgets: {len(gadgets)}\n")
        lines.append(f"Total chain candidates: {len(chains)}\n\n")

        # Gadget catalog
        lines.append("## Gadget Catalog\n")
        lines.append("| G-ID | Type | Endpoint | Confidence | Weight | Chain Enablers |")
        lines.append("|------|------|----------|------------|--------|----------------|")
        for g in sorted(gadgets, key=lambda g: g["weight"], reverse=True):
            enablers = ", ".join(g["chain_enablers"][:3])
            lines.append(
                f"| {g['gadget_id']} | {g['type']} | {g['endpoint_id']} | "
                f"{g['confidence']} | {g['weight']} | {enablers} |"
            )
        lines.append("")

        # Chain candidates
        lines.append("## Chain Candidates (by Priority)\n")
        for i, chain in enumerate(chains[:15], 1):
            lines.append(f"### Chain #{i}: {chain['chain_template']}")
            lines.append(f"- **Priority Score:** {chain['priority_score']}")
            lines.append(f"- **Endpoints:** {', '.join(chain['endpoints_involved'])}")
            lines.append(f"- **Example Bounty:** {chain['example_bounty']}")
            if chain.get("novel"):
                lines.append(f"- **Type:** Novel chain (not in known templates)")
            lines.append(f"- **Gadgets:**")
            for g in chain["gadgets"]:
                lines.append(f"  - {g['gadget_id']} ({g['type']}, {g['confidence']}) — {g['endpoint_id']} {g['url']}")
            lines.append("")

        return "\n".join(lines)

    def generate_chain_hypothesis(
        self, chain: Dict[str, Any], chain_id: int
    ) -> str:
        """Generate CHAINS-NNN.hypothesis.md for a single chain."""
        lines = []
        lines.append(f"# CHAINS-{chain_id:03d}.hypothesis — {chain['chain_template']}")
        lines.append(f"\n## Metadata")
        lines.append(f"- **Priority Score:** {chain['priority_score']}")
        lines.append(f"- **Endpoints:** {', '.join(chain['endpoints_involved'])}")
        lines.append(f"- **Template:** {chain['chain_template']}")
        lines.append(f"- **Reference Bounty:** {chain['example_bounty']}")
        lines.append(f"\n## Chain Sequence")
        for i, g in enumerate(chain["gadgets"], 1):
            lines.append(f"### Step {i}: Exploit {g['type']} at {g['endpoint_id']}")
            lines.append(f"- **Gadget:** {g['gadget_id']}")
            lines.append(f"- **Endpoint:** {g['url']}")
            lines.append(f"- **Confidence:** {g['confidence']}")
            lines.append(f"- **Hypothesis:** {g.get('source_hypothesis', 'From signals')}")
            lines.append("")
        lines.append("## Testing Strategy")
        lines.append("1. Test gadgets in sequence (left to right)")
        lines.append("2. Each step produces output consumed by the next step")
        lines.append("3. If any step fails, the entire chain is invalidated")
        lines.append("4. Document the full chain exploitation steps")
        lines.append("\n## Impact Statement Template")
        lines.append(f"By chaining [{', '.join(g['type'] for g in chain['gadgets'])}], ")
        lines.append(
            "an attacker can [describe the combined impact]. "
            "This bypasses [name the security controls circumvented]. "
            "The impact is [quantify: users affected, data exposed, financial damage]."
        )
        return "\n".join(lines)

    def run(self) -> Dict[str, Any]:
        """Execute full chain synthesis pipeline."""
        profiles = self.load_profiles()
        if not profiles:
            return {"error": "No profiles found", "profiles_loaded": 0}

        gadgets = self.extract_gadgets(profiles)
        chains = self.find_chains(gadgets)

        return {
            "meta": {
                "profiles_loaded": len(profiles),
                "gadgets_extracted": len(gadgets),
                "chains_found": len(chains),
                "high_priority_chains": len([c for c in chains if c["priority_score"] >= 12]),
                "novel_chains": len([c for c in chains if c.get("novel")]),
            },
            "gadgets": gadgets,
            "chains": chains,
        }


def main():
    parser = argparse.ArgumentParser(description="Automated M9 Chain Synthesis")
    parser.add_argument(
        "--mapping-dir",
        default="engagement/mapping",
        help="Directory containing EP-XXX.profile.yaml files",
    )
    parser.add_argument(
        "--output-dir",
        default="engagement/mapping",
        help="Output directory for chain files",
    )
    parser.add_argument(
        "--min-priority",
        type=float,
        default=8.0,
        help="Minimum priority score to generate chain hypotheses",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of generating markdown files",
    )

    args = parser.parse_args()

    if not os.path.isdir(args.mapping_dir):
        print(f"[!] Mapping directory not found: {args.mapping_dir}")
        sys.exit(1)

    automator = ChainAutomator(args.mapping_dir)
    result = automator.run()

    if "error" in result:
        print(f"[!] {result['error']}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Generate files
    os.makedirs(args.output_dir, exist_ok=True)

    # CHAIN-INVENTORY.md
    inventory_md = automator.generate_inventory_markdown(
        result["gadgets"], result["chains"]
    )
    inventory_path = os.path.join(args.output_dir, "CHAIN-INVENTORY.md")
    with open(inventory_path, "w") as f:
        f.write(inventory_md)
    print(f"[+] CHAIN-INVENTORY.md written ({len(result['gadgets'])} gadgets, {len(result['chains'])} chains)")

    # Individual chain hypothesis files
    chain_id = 1
    for chain in result["chains"]:
        if chain["priority_score"] < args.min_priority:
            continue
        hyp_md = automator.generate_chain_hypothesis(chain, chain_id)
        hyp_path = os.path.join(args.output_dir, f"CHAINS-{chain_id:03d}.hypothesis.md")
        with open(hyp_path, "w") as f:
            f.write(hyp_md)
        print(f"[+] CHAINS-{chain_id:03d}.hypothesis.md (score={chain['priority_score']})")
        chain_id += 1

    print(f"\n[*] Summary:")
    print(f"    Profiles loaded:    {result['meta']['profiles_loaded']}")
    print(f"    Gadgets extracted:   {result['meta']['gadgets_extracted']}")
    print(f"    Chains found:        {result['meta']['chains_found']}")
    print(f"    High priority (>=12): {result['meta']['high_priority_chains']}")
    print(f"    Novel chains:        {result['meta']['novel_chains']}")


if __name__ == "__main__":
    main()
