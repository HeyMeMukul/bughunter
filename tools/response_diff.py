#!/usr/bin/env python3
"""
response_diff.py — Automated Response Comparison Engine
Performs 3-way baseline comparison and flags anomalies.
Replaces the manual "three baselines" noise elimination protocol.
"""

import json
import sys
import re
import argparse
from typing import Dict, Any, List, Optional, Tuple


class ResponseDiffer:
    """Compares HTTP responses to detect anomalies and signal vs noise."""

    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity
        self.thresholds = {
            "low": {"size_pct": 15, "time_factor": 3.0},
            "medium": {"size_pct": 10, "time_factor": 2.5},
            "high": {"size_pct": 5, "time_factor": 2.0},
        }.get(sensitivity, {"size_pct": 10, "time_factor": 2.5})

    def parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse a raw HTTP response into structured format."""
        lines = response_text.strip().split("\n")
        parsed = {
            "status": 0,
            "headers": {},
            "body": "",
            "size": len(response_text),
        }

        if not lines:
            return parsed

        # Parse status line
        status_match = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0])
        if status_match:
            parsed["status"] = int(status_match.group(1))

        # Parse headers
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                header_end = i
                break
            if ":" in line:
                key, val = line.split(":", 1)
                parsed["headers"][key.strip().lower()] = val.strip()

        # Parse body
        body_lines = lines[header_end + 1 :] if header_end > 0 else []
        parsed["body"] = "\n".join(body_lines)
        parsed["body_size"] = len(parsed["body"])

        return parsed

    def compare_responses(
        self,
        baseline_valid: str,
        baseline_invalid: str,
        probe_response: str,
        probe_name: str = "probe",
        probe_times: List[float] = None,
    ) -> Dict[str, Any]:
        """Compare a probe response against both baselines."""

        b_valid = self.parse_response(baseline_valid)
        b_invalid = self.parse_response(baseline_invalid)
        probe = self.parse_response(probe_response)

        result = {
            "probe": probe_name,
            "baseline_valid": {
                "status": b_valid["status"],
                "size": b_valid["size"],
                "headers_count": len(b_valid["headers"]),
            },
            "baseline_invalid": {
                "status": b_invalid["status"],
                "size": b_invalid["size"],
                "headers_count": len(b_invalid["headers"]),
            },
            "probe_response": {
                "status": probe["status"],
                "size": probe["size"],
                "headers_count": len(probe["headers"]),
            },
            "anomalies": [],
            "signal_confidence": "NONE",
            "verdict": "NOISE",
        }

        size_pct = self.thresholds["size_pct"]

        # Check 1: Status code anomaly
        if probe["status"] != b_valid["status"] and probe["status"] != b_invalid["status"]:
            result["anomalies"].append(
                {
                    "type": "status_code",
                    "expected_valid": b_valid["status"],
                    "expected_invalid": b_invalid["status"],
                    "actual": probe["status"],
                    "severity": "high",
                }
            )

        # Check 2: Size anomaly (compared to valid baseline)
        if b_valid["size"] > 0:
            size_diff_valid = abs(probe["size"] - b_valid["size"]) / b_valid["size"] * 100
            if size_diff_valid > size_pct:
                result["anomalies"].append(
                    {
                        "type": "size_vs_valid",
                        "baseline_size": b_valid["size"],
                        "probe_size": probe["size"],
                        "diff_pct": round(size_diff_valid, 1),
                        "direction": "larger" if probe["size"] > b_valid["size"] else "smaller",
                        "severity": "medium" if size_diff_valid > size_pct * 2 else "low",
                    }
                )

        # Check 3: Size anomaly (compared to invalid baseline)
        if b_invalid["size"] > 0:
            size_diff_invalid = (
                abs(probe["size"] - b_invalid["size"]) / b_invalid["size"] * 100
            )
            if size_diff_invalid > size_pct:
                result["anomalies"].append(
                    {
                        "type": "size_vs_invalid",
                        "baseline_size": b_invalid["size"],
                        "probe_size": probe["size"],
                        "diff_pct": round(size_diff_invalid, 1),
                        "severity": "high" if probe["size"] > b_invalid["size"] else "medium",
                    }
                )

        # Check 4: New headers
        new_headers = set(probe["headers"].keys()) - set(b_valid["headers"].keys())
        if new_headers:
            result["anomalies"].append(
                {
                    "type": "new_headers",
                    "headers": list(new_headers),
                    "severity": "medium",
                }
            )

        # Check 5: Missing headers
        missing_headers = set(b_valid["headers"].keys()) - set(probe["headers"].keys())
        important_headers = {
            "content-type",
            "content-length",
            "set-cookie",
            "location",
            "cache-control",
            "x-frame-options",
            "content-security-policy",
        }
        missing_important = missing_headers & important_headers
        if missing_important:
            result["anomalies"].append(
                {
                    "type": "missing_headers",
                    "headers": list(missing_important),
                    "severity": "high",
                }
            )

        # Check 6: Timing anomaly (if probe_times provided)
        if probe_times and len(probe_times) >= 3:
            avg_time = sum(probe_times) / len(probe_times)
            # Baseline timing would need to be provided separately
            # For now, just flag if average > 1 second
            if avg_time > 1.0:
                result["anomalies"].append(
                    {
                        "type": "timing",
                        "avg_response_time": round(avg_time, 2),
                        "severity": "low",
                    }
                )

        # Determine confidence
        high_severities = sum(1 for a in result["anomalies"] if a["severity"] == "high")
        medium_severities = sum(
            1 for a in result["anomalies"] if a["severity"] == "medium"
        )

        if high_severities >= 2:
            result["signal_confidence"] = "HIGH"
            result["verdict"] = "SIGNAL"
        elif high_severities >= 1 or medium_severities >= 2:
            result["signal_confidence"] = "MEDIUM"
            result["verdict"] = "SIGNAL"
        elif result["anomalies"]:
            result["signal_confidence"] = "LOW"
            result["verdict"] = "POTENTIAL_SIGNAL"
        else:
            result["signal_confidence"] = "NONE"
            result["verdict"] = "NOISE"

        return result

    def validate_noise_elimination(
        self,
        baseline: str,
        probe1: str,
        probe2: str,
        probe1_name: str = "probe_a",
        probe2_name: str = "probe_b",
    ) -> Dict[str, Any]:
        """Noise elimination protocol — compare 3 probes against baseline."""

        b = self.parse_response(baseline)
        p1 = self.parse_response(probe1)
        p2 = self.parse_response(probe2)

        result = {
            "baseline": {"status": b["status"], "size": b["size"]},
            "probes": {
                probe1_name: {"status": p1["status"], "size": p1["size"]},
                probe2_name: {"status": p2["status"], "size": p2["size"]},
            },
            "is_noise": False,
            "noise_reasons": [],
        }

        # If both probes show same anomaly, it's signal
        p1_size_diff = abs(p1["size"] - b["size"]) if b["size"] > 0 else 0
        p2_size_diff = abs(p2["size"] - b["size"]) if b["size"] > 0 else 0

        # If both probes differ but in DIFFERENT directions → noise
        if p1["status"] != b["status"] and p2["status"] == b["status"]:
            result["is_noise"] = True
            result["noise_reasons"].append("probe_a_status_differs_but_probe_b_does_not")

        if p1["status"] == b["status"] and p2["status"] != b["status"]:
            result["is_noise"] = True
            result["noise_reasons"].append("probe_b_status_differs_but_probe_a_does_not")

        # If sizes fluctuate randomly → noise
        if p1_size_diff > self.thresholds["size_pct"] * b["size"] / 100 and p2_size_diff < 2:
            result["is_noise"] = True
            result["noise_reasons"].append("size_variance_inconsistent")

        if not result["is_noise"]:
            result["verdict"] = (
                "SIGNAL" if p1["status"] != b["status"] else "NO_ANOMALY"
            )

        return result


def main():
    parser = argparse.ArgumentParser(description="Response diffing engine")
    parser.add_argument("--mode", choices=["compare", "noise-check", "batch"], default="compare",
                       help="Comparison mode")
    parser.add_argument("--baseline-valid", help="File with valid-input baseline response")
    parser.add_argument("--baseline-invalid", help="File with invalid-input baseline response")
    parser.add_argument("--probe", help="File with probe response to compare")
    parser.add_argument("--probe-name", default="probe", help="Probe identifier")
    parser.add_argument("--probe-a", help="First probe response file (noise check)")
    parser.add_argument("--probe-b", help="Second probe response file (noise check)")
    parser.add_argument("--batch-file", help="JSON file with multiple probe comparisons")
    parser.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--baseline", help="Baseline response file (noise check mode)")

    args = parser.parse_args()
    differ = ResponseDiffer(sensitivity=args.sensitivity)

    if args.mode == "compare":
        if not all([args.baseline_valid, args.baseline_invalid, args.probe]):
            print("[ERROR] --baseline-valid, --baseline-invalid, and --probe are required for compare mode")
            sys.exit(1)

        bv = open(args.baseline_valid).read()
        bi = open(args.baseline_invalid).read()
        probe = open(args.probe).read()

        result = differ.compare_responses(bv, bi, probe, args.probe_name)
        print(json.dumps(result, indent=2))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.mode == "noise-check":
        if not all([args.baseline, args.probe_a, args.probe_b]):
            print("[ERROR] --baseline, --probe-a, and --probe-b are required for noise-check mode")
            sys.exit(1)

        baseline = open(args.baseline).read()
        pa = open(args.probe_a).read()
        pb = open(args.probe_b).read()

        result = differ.validate_noise_elimination(baseline, pa, pb)
        print(json.dumps(result, indent=2))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.mode == "batch":
        if not args.batch_file:
            print("[ERROR] --batch-file is required for batch mode")
            sys.exit(1)

        with open(args.batch_file) as f:
            batch = json.load(f)

        results = []
        for item in batch:
            if "baseline_valid" in item and "baseline_invalid" in item and "probe" in item:
                result = differ.compare_responses(
                    item["baseline_valid"],
                    item["baseline_invalid"],
                    item["probe"],
                    item.get("probe_name", "batch_probe"),
                )
                results.append(result)

        output = {"batch_size": len(batch), "results": results}
        print(json.dumps(output, indent=2))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
