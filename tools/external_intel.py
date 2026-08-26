#!/usr/bin/env python3
"""
External Intelligence Integrator — Improvement #10: External Intelligence Integration
======================================================================================
Pulls in external data to augment findings during engagement:
  1. GitHub dorking — public repos for hardcoded secrets, internal API docs
  2. Shodan/Censys — exposed services and misconfigs
  3. Known CVE checking — tech stack fingerprinted in Phase 1 vs known CVEs
  4. Similar program analysis — patterns from disclosed bug reports

Usage:
    python3 tools/external_intel.py --target example.com
    python3 tools/external_intel.py --github-dork --target example.com
    python3 tools/external_intel.py --cve-check --tech-stack nginx/1.18.0,express/4.17
    python3 tools/external_intel.py --all --target example.com

Output: engagement/spider/external_intel.md + engagement/spider/cve_matches.json

NOTE: This tool performs passive intelligence gathering only. No active scanning.
      GitHub API requires a GITHUB_TOKEN env var for higher rate limits.
      Shodan requires a SHODAN_API_KEY env var.
"""

import sys
import os
import json
import re
import argparse
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from datetime import datetime

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
SPIDER_DIR = FRAMEWORK_ROOT / "engagement" / "spider"
STATE_FILE = FRAMEWORK_ROOT / "state.json"

# ─── CVE Database (embedded lightweight version) ───────────────────────────────
# Format: {product_pattern: [(min_version, max_version, CVE_ID, severity, description)]}
# This is a curated subset of high-relevance CVEs for web apps.
# Update this list regularly or replace with a live NVD API call.
KNOWN_CVES = {
    "nginx": [
        ("1.0.0", "1.20.0", "CVE-2021-23017", "Critical",
         "Off-by-one error in DNS resolver allows RCE"),
        ("1.0.0", "1.16.0", "CVE-2019-9511", "High",
         "HTTP/2 DoS via Data Dribble Attack"),
        ("1.0.0", "1.17.6", "CVE-2019-20372", "Medium",
         "Header injection in certain error responses"),
    ],
    "apache": [
        ("2.4.0", "2.4.49", "CVE-2021-41773", "Critical",
         "Path traversal and RCE (Actively Exploited!)"),
        ("2.4.0", "2.4.50", "CVE-2021-42013", "Critical",
         "Path traversal bypass for CVE-2021-41773"),
        ("2.4.0", "2.4.51", "CVE-2021-40438", "Critical",
         "SSRF via mod_proxy"),
    ],
    "express": [
        ("0.0.0", "4.17.2", "CVE-2022-24999", "High",
         "Open redirect via crafted URL"),
    ],
    "struts": [
        ("2.0.0", "2.5.25", "CVE-2021-31805", "Critical",
         "OGNL expression injection RCE"),
        ("2.0.0", "2.3.36", "CVE-2018-11776", "Critical",
         "OGNL injection without namespace (S2-057)"),
    ],
    "spring": [
        ("5.0.0", "5.3.17", "CVE-2022-22965", "Critical",
         "Spring4Shell - RCE via data binder (ClassPathXML)"),
        ("5.0.0", "5.3.18", "CVE-2022-22963", "Critical",
         "Spring Cloud Function SpEL injection"),
    ],
    "tomcat": [
        ("9.0.0", "9.0.62", "CVE-2022-29885", "Medium",
         "Information disclosure via EncryptInterceptor"),
        ("8.5.0", "8.5.78", "CVE-2022-34305", "Medium",
         "XSS in FORM authentication error page"),
    ],
    "wordpress": [
        ("5.0.0", "5.8.3", "CVE-2022-21662", "Medium",
         "Authenticated XXE via media upload"),
    ],
    "drupal": [
        ("8.0.0", "9.3.9", "CVE-2022-25271", "High",
         "Access bypass via media module"),
    ],
    "log4j": [
        ("2.0.0", "2.14.1", "CVE-2021-44228", "Critical",
         "Log4Shell - JNDI lookup RCE (Actively Exploited!)"),
        ("2.0.0", "2.17.0", "CVE-2021-45105", "High",
         "Infinite recursion DoS in StrSubstitutor"),
    ],
    "openssl": [
        ("3.0.0", "3.0.6", "CVE-2022-3786", "Critical",
         "Buffer overflow in X.509 certificate verification"),
        ("3.0.0", "3.0.6", "CVE-2022-3602", "Critical",
         "Buffer overflow in X.509 email address verification"),
    ],
    "php": [
        ("7.0.0", "8.0.24", "CVE-2022-31625", "High",
         "Use-after-free in Postgres extension"),
        ("7.0.0", "8.1.7", "CVE-2022-31626", "High",
         "Buffer overflow in mysqlnd"),
    ],
    "grafana": [
        ("8.0.0", "8.3.0", "CVE-2021-43798", "Critical",
         "Path traversal allows reading arbitrary files"),
    ],
    "gitlab": [
        ("11.0.0", "14.8.5", "CVE-2022-0735", "Critical",
         "RCE via import feature"),
    ],
    "jenkins": [
        ("2.0.0", "2.346", "CVE-2022-34177", "High",
         "Improper permission check in Pipeline Shared Groovy Libraries"),
    ],
}


def parse_version(ver_str: str) -> tuple[int, ...]:
    """Parse version string into tuple of ints for comparison."""
    ver_str = re.sub(r"[^0-9.]", "", ver_str)
    parts = ver_str.split(".")
    try:
        return tuple(int(p) for p in parts[:4] if p)
    except ValueError:
        return (0,)


def version_lte(v1: str, v2: str) -> bool:
    """Return True if v1 <= v2."""
    return parse_version(v1) <= parse_version(v2)


def check_cves(tech_stack: list[str]) -> list[dict]:
    """Check tech stack against known CVEs."""
    matches = []
    for tech_str in tech_stack:
        tech_str = tech_str.strip().lower()
        # Parse "product/version" or "product version" or just "product"
        m = re.match(r"([a-zA-Z0-9._-]+)[/\s]?([0-9][0-9.a-z-]*)?", tech_str)
        if not m:
            continue
        product = m.group(1).lower()
        version = m.group(2) or "0.0.0"

        for known_product, cve_list in KNOWN_CVES.items():
            if known_product in product or product in known_product:
                for (min_ver, max_ver, cve_id, severity, description) in cve_list:
                    if version_lte(min_ver, version) and version_lte(version, max_ver):
                        matches.append({
                            "product": tech_str,
                            "cve_id": cve_id,
                            "severity": severity,
                            "description": description,
                            "version_range": f"{min_ver} - {max_ver}",
                            "detected_version": version,
                        })
    return matches


def github_dork(target_domain: str, github_token: str | None = None) -> list[dict]:
    """Search GitHub for hardcoded secrets related to the target domain."""
    results = []
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    # Search queries — conservative to avoid false positives
    queries = [
        f'"{target_domain}" password',
        f'"{target_domain}" api_key',
        f'"{target_domain}" secret_key',
        f'"{target_domain}" authorization Bearer',
        f'site:{target_domain} extension:env',
        f'"{target_domain}" credentials',
    ]

    print(f"  Performing GitHub dorking for {target_domain}...")
    if not github_token:
        print("  ⚠️  No GITHUB_TOKEN set — rate limiting applies (10 req/min)")

    for query in queries[:3]:  # Limit to 3 by default to avoid rate limits
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded}&per_page=5"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                items = data.get("items", [])
                for item in items:
                    results.append({
                        "query": query,
                        "repo": item.get("repository", {}).get("full_name", "?"),
                        "file": item.get("name", "?"),
                        "url": item.get("html_url", "?"),
                        "score": item.get("score", 0),
                    })
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  ⚠️  GitHub rate limited on query: {query[:50]}...")
            elif e.code == 422:
                pass  # Query too complex — skip silently
            else:
                print(f"  ⚠️  GitHub API error {e.code} for: {query[:50]}...")
        except Exception as e:
            print(f"  ⚠️  GitHub search failed: {e}")

    return results


def shodan_lookup(target_domain: str, api_key: str | None) -> dict:
    """Look up target on Shodan for exposed services."""
    if not api_key:
        return {"error": "SHODAN_API_KEY not set — skipping Shodan lookup"}

    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{target_domain}&facets=port,os&minify=true"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            return {
                "total": data.get("total", 0),
                "ports": list(set(
                    match.get("port", 0)
                    for match in data.get("matches", [])
                )),
                "oses": list(set(
                    match.get("os", "")
                    for match in data.get("matches", [])
                    if match.get("os")
                )),
                "interesting": [
                    match for match in data.get("matches", [])
                    if match.get("port", 0) in (21, 22, 23, 3389, 5900, 8080, 8443, 9200, 27017)
                ][:5],
            }
    except Exception as e:
        return {"error": str(e)}


def load_tech_stack_from_state() -> list[str]:
    """Load tech stack from state.json spider section."""
    try:
        state = json.loads(STATE_FILE.read_text())
        tech = []
        spider = state.get("spider", {})
        # Pull from various places tech might be stored
        tech.extend(state.get("_tech_stack", []))
        comprehension = spider.get("comprehension", {})
        # Look in waf section
        waf = spider.get("waf", {})
        if waf.get("name"):
            tech.append(waf["name"])
        return tech
    except Exception:
        return []


def render_intel_report(
    target: str,
    cve_matches: list[dict],
    github_results: list[dict],
    shodan_data: dict,
    tech_stack: list[str],
) -> str:
    """Render intelligence report as markdown."""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# External Intelligence Report",
        "",
        f"> Target: {target}",
        f"> Generated: {now}",
        "",
        "---",
        "",
    ]

    # CVE section
    lines.append("## CVE Matches (Tech Stack)")
    lines.append("")
    if cve_matches:
        lines.append("| CVE ID | Product | Severity | Description |")
        lines.append("|---|---|---|---|")
        for cve in sorted(cve_matches, key=lambda c: c["severity"] == "Critical", reverse=True):
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "⚪"}.get(
                cve["severity"], ""
            )
            lines.append(
                f"| [{cve['cve_id']}](https://nvd.nist.gov/vuln/detail/{cve['cve_id']}) "
                f"| {cve['product']} | {sev_icon} {cve['severity']} | {cve['description'][:80]} |"
            )
        lines.append("")
        critical_cves = [c for c in cve_matches if c["severity"] == "Critical"]
        if critical_cves:
            lines.append(
                f"> ⚠️  **{len(critical_cves)} CRITICAL CVE(s)** detected in target tech stack. "
                "Check if patched before testing."
            )
    else:
        lines.append("No CVE matches found for the detected tech stack.")
    lines.append("")

    # GitHub dorking section
    lines.append("## GitHub Intelligence")
    lines.append("")
    if github_results:
        lines.append(f"Found {len(github_results)} potentially interesting GitHub results:")
        lines.append("")
        lines.append("| Repo | File | Query | URL |")
        lines.append("|---|---|---|---|")
        for r in github_results[:20]:
            lines.append(
                f"| {r['repo']} | {r['file']} | {r['query'][:40]}... | [link]({r['url']}) |"
            )
        lines.append("")
        lines.append(
            "> ⚠️  Manually review each result. False positives are common. "
            "Only report if credentials/tokens are live."
        )
    else:
        lines.append("No significant GitHub results found.")
    lines.append("")

    # Shodan section
    lines.append("## Shodan / Exposed Services")
    lines.append("")
    if "error" in shodan_data:
        lines.append(f"⚠️  {shodan_data['error']}")
    else:
        total = shodan_data.get("total", 0)
        ports = shodan_data.get("ports", [])
        lines.append(f"- Total Shodan results: {total}")
        lines.append(f"- Open ports detected: {sorted(ports)}")
        interesting = shodan_data.get("interesting", [])
        if interesting:
            lines.append(
                f"- **{len(interesting)} potentially interesting services** "
                "(unusual ports: check for admin panels, databases, RDP)"
            )
    lines.append("")

    # Recommendations
    lines.append("## Testing Recommendations")
    lines.append("")
    if any(c["severity"] == "Critical" for c in cve_matches):
        lines.append(
            "1. **PRIORITY:** Critical CVEs in tech stack — verify patch status before other testing"
        )
    if github_results:
        lines.append("2. **Investigate GitHub results** — check if credentials are live")
    if shodan_data.get("interesting"):
        lines.append(
            "3. **Check exposed services** on non-standard ports for admin/debug access"
        )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="External intelligence integrator for the bug bounty framework"
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument(
        "--tech-stack",
        help="Comma-separated tech stack (e.g., nginx/1.18.0,express/4.17)",
    )
    parser.add_argument("--github-dork", action="store_true", help="Run GitHub dorking")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan lookup")
    parser.add_argument("--cve-check", action="store_true", help="Check tech stack for CVEs")
    parser.add_argument("--all", action="store_true", help="Run all intelligence checks")
    parser.add_argument(
        "--output",
        type=Path,
        default=SPIDER_DIR / "external_intel.md",
        help="Output markdown file",
    )
    args = parser.parse_args()

    run_github = args.github_dork or args.all
    run_shodan = args.shodan or args.all
    run_cve = args.cve_check or args.all

    # Load tech stack
    if args.tech_stack:
        tech_stack = [t.strip() for t in args.tech_stack.split(",")]
    else:
        tech_stack = load_tech_stack_from_state()
        if not tech_stack:
            print(
                "[INFO] No tech stack in state.json — specify --tech-stack or run Phase 1 first"
            )

    print(f"Target: {args.target}")
    print(f"Tech stack: {tech_stack or '(none detected)'}")
    print()

    # Run checks
    cve_matches = []
    github_results = []
    shodan_data = {}

    if run_cve and tech_stack:
        print("Checking tech stack for known CVEs...")
        cve_matches = check_cves(tech_stack)
        print(f"  → {len(cve_matches)} CVE matches")

        # Save JSON for Lead reference
        cve_output = SPIDER_DIR / "cve_matches.json"
        SPIDER_DIR.mkdir(parents=True, exist_ok=True)
        cve_output.write_text(json.dumps(cve_matches, indent=2))
        print(f"  → Saved to {cve_output}")

    if run_github:
        github_token = os.environ.get("GITHUB_TOKEN")
        github_results = github_dork(args.target, github_token)
        print(f"  → {len(github_results)} GitHub results")

    if run_shodan:
        shodan_key = os.environ.get("SHODAN_API_KEY")
        print(f"  Querying Shodan for {args.target}...")
        shodan_data = shodan_lookup(args.target, shodan_key)

    if not (run_cve or run_github or run_shodan):
        print("[INFO] No checks specified. Use --all, --cve-check, --github-dork, or --shodan")
        parser.print_help()
        sys.exit(0)

    # Render report
    report = render_intel_report(
        args.target, cve_matches, github_results, shodan_data, tech_stack
    )

    SPIDER_DIR.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    print(f"\nIntelligence report written: {args.output}")

    # Summary
    if cve_matches:
        critical = [c for c in cve_matches if c["severity"] == "Critical"]
        print(f"\n⚠️  {len(critical)} CRITICAL CVEs detected — review before testing!")


if __name__ == "__main__":
    main()
