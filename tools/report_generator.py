#!/usr/bin/env python3
"""
report_generator.py — Auto-Generate Bug Bounty Reports
Reads validated findings (FIND-XXX.validated.md) and generates 80% complete
professional reports. Lead only needs to fill in impact narrative and PoC details.
"""

import json
import os
import sys
import argparse
import re
from typing import Dict, Any, List, Optional
from datetime import datetime


class ReportGenerator:
    """Generates bug bounty reports from validated findings."""

    def __init__(self, findings_dir: str = "engagement/findings", output_dir: str = "engagement/reports"):
        self.findings_dir = findings_dir
        self.output_dir = output_dir

    def parse_validated_finding(self, filepath: str) -> Dict[str, Any]:
        """Parse a FIND-XXX.validated.md file."""
        with open(filepath) as f:
            content = f.read()

        finding = {
            "id": "",
            "title": "",
            "cvss_score": "",
            "cvss_vector": "",
            "severity": "",
            "endpoint": "",
            "vulnerability_type": "",
            "reproduction_steps": [],
            "impact": "",
            "affected_endpoints": [],
            "chain_potential": "",
            "validation_status": "",
        }

        # Extract finding ID and title from first heading
        title_match = re.search(r"# Validated Finding:\s*(FIND-\d+)\s*—\s*(.+)", content)
        if title_match:
            finding["id"] = title_match.group(1)
            finding["title"] = title_match.group(2).strip()

        # Extract CVSS
        cvss_match = re.search(r"## CVSS:\s*(\d+\.?\d*)\s*/\s*Vector:\s*(CVSS:3\.[01]/[A-Za-z:/]+)", content)
        if cvss_match:
            finding["cvss_score"] = cvss_match.group(1)
            finding["cvss_vector"] = cvss_match.group(2)

        # Extract severity
        sev_match = re.search(r"Severity:\s*(Critical|High|Medium|Low|Informational)", content, re.IGNORECASE)
        if sev_match:
            finding["severity"] = sev_match.group(1)

        # Extract endpoint
        ep_match = re.search(r"(?:Endpoint|URL):\s*(https?://\S+)", content)
        if ep_match:
            finding["endpoint"] = ep_match.group(1)

        # Extract vulnerability type
        vuln_match = re.search(r"(?:Type|Vulnerability):\s*(\S.*?)(?:\n|$)", content)
        if vuln_match:
            finding["vulnerability_type"] = vuln_match.group(1).strip()

        # Extract reproduction steps
        repro_section = re.search(r"## Reproduction Steps(.*?)(?=##\s|\Z)", content, re.DOTALL)
        if repro_section:
            steps_text = repro_section.group(1)
            steps = re.findall(r"(\d+\.\s+.+?)(?=\d+\.\s+|\Z)", steps_text, re.DOTALL)
            finding["reproduction_steps"] = [s.strip()[:300] for s in steps]

        # Extract impact
        impact_section = re.search(r"## Impact Analysis(.*?)(?=##\s|\Z)", content, re.DOTALL)
        if impact_section:
            finding["impact"] = impact_section.group(1).strip()[:500]

        return finding

    def generate_report(self, finding: Dict[str, Any]) -> str:
        """Generate a complete report from a validated finding."""

        lines = []

        # Header
        lines.append(f"# Bug Bounty Report — {finding['title']}")
        lines.append("")
        lines.append(f"**Finding ID:** {finding['id']}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}")
        lines.append(f"**Severity:** {finding.get('severity', 'TBD')}")
        lines.append(f"**CVSS Score:** {finding.get('cvss_score', 'TBD')}")
        lines.append(f"**CVSS Vector:** `{finding.get('cvss_vector', 'TBD')}`")
        lines.append(f"**Vulnerability Type:** {finding.get('vulnerability_type', 'TBD')}")
        lines.append(f"**Affected Endpoint:** `{finding.get('endpoint', 'TBD')}`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"The application at `{finding.get('endpoint', '')}` is vulnerable to ")
        lines.append(f"{finding.get('vulnerability_type', '[VULNERABILITY TYPE]')}. ")
        lines.append("This vulnerability allows an attacker to [DESCRIBE WHAT ATTACKER CAN DO]. ")
        lines.append("")

        # Severity justification
        lines.append(f"The CVSS v3.1 score of {finding.get('cvss_score', 'N/A')} reflects ")
        lines.append(f"the {finding.get('severity', 'medium').upper()} severity of this finding. ")
        lines.append("")

        # Assets affected
        lines.append("## Assets Affected")
        lines.append("")
        lines.append(f"- **Endpoint:** `{finding.get('endpoint', 'TBD')}`")
        if finding.get("affected_endpoints"):
            for ep in finding["affected_endpoints"]:
                lines.append(f"- {ep}")
        lines.append("")

        # Technical Details
        lines.append("## Technical Details")
        lines.append("")
        lines.append("### How the Vulnerability Works")
        lines.append("")
        lines.append("[Explain the root cause: what the developer did wrong, what assumption failed, ")
        lines.append("what trust boundary was violated.]")
        lines.append("")

        # Reproduction
        if finding.get("reproduction_steps"):
            lines.append("### Reproduction Steps")
            lines.append("")
            for step in finding["reproduction_steps"]:
                lines.append(step)
                lines.append("")
        else:
            lines.append("### Reproduction Steps")
            lines.append("")
            lines.append("[STEP 1: Describe the setup — accounts, sessions, required headers]")
            lines.append("[STEP 2: Exact HTTP request]")
            lines.append("[STEP 3: Observe the response — compare to expected behavior]")
            lines.append("[STEP 4: Show the impact — what data is exposed/action is performed]")
            lines.append("")

        # Proof of Concept
        lines.append("### Proof of Concept")
        lines.append("")
        lines.append("```bash")
        lines.append("# Curl PoC")
        lines.append(f"# curl -X [METHOD] {finding.get('endpoint', 'URL')} \\")
        lines.append("#   -H 'Header: Value' \\")
        lines.append("#   -d '{payload}'")
        lines.append("```")
        lines.append("")
        lines.append("[Include actual request/response or reference PoC files]")
        lines.append("")

        # Impact
        lines.append("## Business Impact")
        lines.append("")
        if finding.get("impact"):
            lines.append(finding["impact"])
            lines.append("")
        else:
            lines.append("[Describe the REAL-WORLD impact. What can an attacker actually DO?")
            lines.append("How many users affected? What data is exposed? What's the financial impact?]")
            lines.append("")

        # Chaining potential
        if finding.get("chain_potential"):
            lines.append("## Attack Chain Potential")
            lines.append("")
            lines.append(finding["chain_potential"])
            lines.append("")

        # Remediation
        lines.append("## Recommended Remediation")
        lines.append("")
        lines.append("[Brief, professional remediation suggestion. Not 'how to code' but 'what to fix'.]")
        lines.append("For example:")
        lines.append("- Implement server-side authorization checks for all user-owned resources")
        lines.append("- Validate and sanitize all user-supplied input before processing")
        lines.append("- Apply the principle of least privilege to API endpoints")
        lines.append("")

        # References
        lines.append("## References")
        lines.append("")
        lines.append(f"- [OWASP: {finding.get('vulnerability_type', 'Vulnerability Type')}]")
        lines.append("- [CWE Reference]")
        lines.append("")

        # Evidence
        lines.append("## Evidence")
        lines.append("")
        lines.append("[Reference screenshots, PoC files, raw HTTP dumps in poc/ directory]")

        return "\n".join(lines)

    def generate_all(self) -> List[str]:
        """Generate reports for all validated findings."""
        os.makedirs(self.output_dir, exist_ok=True)
        generated = []

        if not os.path.isdir(self.findings_dir):
            print(f"[!] Findings directory not found: {self.findings_dir}")
            return generated

        for filename in sorted(os.listdir(self.findings_dir)):
            if not filename.startswith("FIND-") or not filename.endswith(".validated.md"):
                continue

            filepath = os.path.join(self.findings_dir, filename)
            finding = self.parse_validated_finding(filepath)

            if not finding["id"]:
                print(f"[!] Could not parse {filename}")
                continue

            report = self.generate_report(finding)
            report_name = finding["id"].replace("FIND-", "report-").lower() + ".md"
            report_path = os.path.join(self.output_dir, report_name)

            with open(report_path, "w") as f:
                f.write(report)

            print(f"[+] Generated: {report_path}")
            generated.append(report_path)

        return generated


def main():
    parser = argparse.ArgumentParser(description="Auto-generate bug bounty reports")
    parser.add_argument("--findings-dir", default="engagement/findings",
                       help="Directory with FIND-XXX.validated.md files")
    parser.add_argument("--output-dir", default="engagement/reports",
                       help="Output directory for generated reports")
    parser.add_argument("--finding", help="Generate report for a specific finding ID")
    args = parser.parse_args()

    gen = ReportGenerator(args.findings_dir, args.output_dir)

    if args.finding:
        filepath = os.path.join(args.findings_dir, f"{args.finding}.validated.md")
        if not os.path.exists(filepath):
            print(f"[!] Finding not found: {filepath}")
            sys.exit(1)
        finding = gen.parse_validated_finding(filepath)
        report = gen.generate_report(finding)
        print(report)
    else:
        reports = gen.generate_all()
        print(f"\n[*] Generated {len(reports)} reports in {args.output_dir}")


if __name__ == "__main__":
    main()
