#!/usr/bin/env python3
"""
fp_database.py — False Positive Pattern Database
Tracks historical FP patterns and adjusts confidence scoring based on learning.
Integrates with hypothesis_deduplicator.py and state.json confidence calibration.
"""

import json
import os
import sys
import argparse
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime


class FPDatabase:
    """Tracks FP patterns and adjusts confidence scoring."""

    def __init__(self, db_path: str = "engagement/fp_database.json"):
        self.db_path = db_path
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load or initialize the FP database."""
        if os.path.exists(self.db_path):
            with open(self.db_path) as f:
                return json.load(f)
        return {
            "meta": {"version": "1.0.0", "created": datetime.now().isoformat(), "total_entries": 0},
            "fp_patterns": [],
            "vuln_type_fp_rates": {},
            "confidence_adjustments": {},
            "program_specific": {},
        }

    def _save(self):
        """Persist the FP database."""
        self.data["meta"]["last_updated"] = datetime.now().isoformat()
        self.data["meta"]["total_entries"] = len(self.data["fp_patterns"])
        with open(self.db_path, "w") as f:
            json.dump(self.data, f, indent=2)

    def add_false_positive(
        self,
        hypothesis_id: str,
        vuln_type: str,
        confidence: str,
        endpoint: str,
        pattern_detected: str,
        reason_fp: str,
        skill_used: str,
    ):
        """Record a false positive finding."""
        entry = {
            "hypothesis_id": hypothesis_id,
            "vuln_type": vuln_type,
            "confidence": confidence,
            "endpoint": endpoint,
            "pattern_detected": pattern_detected,
            "reason_fp": reason_fp,
            "skill_used": skill_used,
            "timestamp": datetime.now().isoformat(),
            "lessons": self._extract_lessons(vuln_type, pattern_detected, reason_fp),
        }

        self.data["fp_patterns"].append(entry)

        # Update vuln_type FP rates
        if vuln_type not in self.data["vuln_type_fp_rates"]:
            self.data["vuln_type_fp_rates"][vuln_type] = {"total": 0, "fp_count": 0}

        self.data["vuln_type_fp_rates"][vuln_type]["total"] += 1
        if confidence == "LOW":
            self.data["vuln_type_fp_rates"][vuln_type]["fp_count"] += 1

        # Update confidence adjustments
        self._update_confidence_adjustments(vuln_type)

        self._save()
        return entry

    def _extract_lessons(self, vuln_type: str, pattern: str, reason: str) -> str:
        """Extract learning from a false positive."""
        lessons = {
            "idor": "Sequential IDs alone do NOT confirm IDOR. Must verify actual authorization bypass.",
            "sqli": "Error messages with SQL keywords do NOT confirm injection. Must verify query manipulation.",
            "xss": "HTML reflection does NOT confirm XSS. Must verify code execution in browser context.",
            "ssrf": "Domain resolution alone does NOT confirm SSRF. Must verify actual server-side request.",
            "ssti": "Reflected brackets do NOT confirm SSTI. Must verify template engine evaluation.",
            "cmdi": "Error messages with 'command' do NOT confirm injection. Must verify actual OS command execution.",
            "open_redirect": "Same-domain redirects are NOT vulnerabilities. Must verify cross-domain redirect.",
            "csrf": "Missing CSRF token does NOT mean exploitable. Must verify referer/origin checks and SameSite.",
            "nosqli": "JSON operators in response do NOT confirm NoSQL injection. Must verify database behavior change.",
            "host_header": "Host header in response does NOT confirm injection. Must verify application behavior changes.",
        }
        base = lessons.get(vuln_type.lower(), "Verify actual exploitation before confirming hypothesis.")
        return f"PATTERN: {pattern[:100]}. REASON_FP: {reason[:200]}. LESSON: {base}"

    def _update_confidence_adjustments(self, vuln_type: str):
        """Update confidence modifier based on FP history."""
        stats = self.data["vuln_type_fp_rates"].get(vuln_type, {"total": 0, "fp_count": 0})
        total = stats["total"]

        if total < 3:
            return  # Not enough data

        fp_rate = stats["fp_count"] / total

        # Calculate confidence adjustment
        if fp_rate > 0.5:
            adjustment = -0.4  # HIGH FP rate → significantly reduce confidence
        elif fp_rate > 0.3:
            adjustment = -0.2  # Moderate FP rate
        elif fp_rate < 0.1 and total > 5:
            adjustment = 0.1  # Low FP rate → boost slightly
        else:
            adjustment = 0.0

        self.data["confidence_adjustments"][vuln_type] = {
            "total_tests": total,
            "fp_rate": round(fp_rate, 2),
            "confidence_modifier": adjustment,
            "reliability": "low" if fp_rate > 0.4 else "moderate" if fp_rate > 0.2 else "high",
        }

    def get_confidence_adjustment(self, vuln_type: str) -> float:
        """Get the confidence adjustment for a vulnerability type."""
        adj = self.data["confidence_adjustments"].get(vuln_type, {})
        return adj.get("confidence_modifier", 0.0)

    def get_fp_patterns_for_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get all FP patterns for a specific vulnerability type."""
        return [p for p in self.data["fp_patterns"] if p["vuln_type"] == vuln_type]

    def should_skip_hypothesis(
        self, vuln_type: str, pattern_detected: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a hypothesis should be skipped based on FP history."""
        # Check if this exact pattern has been a FP before
        for fp in self.data["fp_patterns"]:
            if fp["vuln_type"] == vuln_type and fp["pattern_detected"][:50] == pattern_detected[:50]:
                return {
                    "skip": True,
                    "reason": f"Pattern previously marked FP: {fp['reason_fp'][:100]}",
                    "previous_fp_id": fp["hypothesis_id"],
                    "confidence_was": fp["confidence"],
                }

        # Check if vuln type has >70% FP rate
        adj = self.data["confidence_adjustments"].get(vuln_type, {})
        if adj.get("fp_rate", 0) > 0.7 and adj.get("total_tests", 0) > 5:
            return {
                "skip": True,
                "reason": f"Vuln type {vuln_type} has {adj['fp_rate']*100:.0f}% FP rate — deprioritize",
            }

        return None

    def generate_report(self) -> str:
        """Generate a human-readable FP analysis report."""
        lines = []
        lines.append("=" * 60)
        lines.append("  FALSE POSITIVE PATTERN ANALYSIS")
        lines.append("=" * 60)
        lines.append(f"\nTotal FP entries: {len(self.data['fp_patterns'])}")
        lines.append("")

        lines.append("--- Vulnerability Type FP Rates ---")
        for vtype, stats in sorted(self.data["vuln_type_fp_rates"].items()):
            if stats["total"] > 0:
                fp_rate = stats["fp_count"] / stats["total"] * 100
                adj = self.data["confidence_adjustments"].get(vtype, {}).get("confidence_modifier", 0)
                lines.append(f"  {vtype:25s}: {fp_rate:5.1f}% FP ({stats['fp_count']}/{stats['total']}) — adj={adj:.1f}")

        lines.append("\n--- Top FP Patterns ---")
        pattern_counts = defaultdict(int)
        for fp in self.data["fp_patterns"]:
            pattern = fp["pattern_detected"][:60]
            pattern_counts[pattern] += 1

        for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  [{count}x] {pattern}")

        lines.append("\n--- Lessons Learned ---")
        seen_lessons = set()
        for fp in self.data["fp_patterns"]:
            lesson = fp.get("lessons", "")
            if lesson and lesson not in seen_lessons:
                seen_lessons.add(lesson)
                lines.append(f"  • {lesson[:200]}")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="FP Pattern Database")
    parser.add_argument("command", choices=["add", "check", "adjustment", "report", "stats"],
                       help="FP database command")
    parser.add_argument("--hypothesis-id", help="Hypothesis ID")
    parser.add_argument("--vuln-type", help="Vulnerability type")
    parser.add_argument("--confidence", help="Original confidence level")
    parser.add_argument("--endpoint", help="Endpoint identifier")
    parser.add_argument("--pattern", help="Pattern that was detected")
    parser.add_argument("--reason", help="Reason it was a false positive")
    parser.add_argument("--skill", help="Skill file used")
    parser.add_argument("--db-path", default="engagement/fp_database.json", help="Database path")
    parser.add_argument("--output", help="Output file for reports")

    args = parser.parse_args()
    db = FPDatabase(db_path=args.db_path)

    if args.command == "add":
        if not all([args.hypothesis_id, args.vuln_type, args.confidence, args.reason]):
            print("[ERROR] Required: --hypothesis-id, --vuln-type, --confidence, --reason")
            sys.exit(1)

        entry = db.add_false_positive(
            hypothesis_id=args.hypothesis_id,
            vuln_type=args.vuln_type,
            confidence=args.confidence,
            endpoint=args.endpoint or "unknown",
            pattern_detected=args.pattern or "unknown",
            reason_fp=args.reason,
            skill_used=args.skill or "unknown",
        )
        print(json.dumps(entry, indent=2))

    elif args.command == "check":
        if not all([args.vuln_type, args.pattern]):
            print("[ERROR] Required: --vuln-type, --pattern")
            sys.exit(1)

        result = db.should_skip_hypothesis(args.vuln_type, args.pattern)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps({"skip": False}, indent=2))

    elif args.command == "adjustment":
        if not args.vuln_type:
            print("[ERROR] Required: --vuln-type")
            sys.exit(1)
        print(f"{db.get_confidence_adjustment(args.vuln_type)}")

    elif args.command == "report":
        report = db.generate_report()
        print(report)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)

    elif args.command == "stats":
        print(json.dumps({
            "total_entries": len(db.data["fp_patterns"]),
            "vuln_type_fp_rates": db.data["vuln_type_fp_rates"],
            "confidence_adjustments": db.data["confidence_adjustments"],
        }, indent=2))


if __name__ == "__main__":
    main()
