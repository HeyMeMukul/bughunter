#!/usr/bin/env python3
"""
oob_validator.py — OOB Callback Validator
Processes interactsh/Burp Collaborator logs and validates OOB vulnerabilities.
Correlates payloads with callbacks to confirm blind vulnerabilities.
"""

import json
import sys
import argparse
import re
from typing import Dict, Any, List, Optional
from datetime import datetime


class OOBValidator:
    """Validates OOB callbacks and confirms blind vulnerabilities."""

    def __init__(self):
        self.vuln_indicators = {
            "ssrf": ["http", "dns", "smtp", "ftp", "ldap"],
            "sqli": ["dns", "smb", "http"],
            "xss": ["http", "dns"],
            "cmdi": ["http", "dns"],
            "ssti": ["http", "dns"],
            "xxe": ["http", "ftp", "dns"],
        }

    def parse_callback(self, callback: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a raw OOB callback and extract useful info."""
        parsed = {
            "timestamp": callback.get("timestamp", ""),
            "protocol": callback.get("protocol", "unknown"),
            "remote_ip": callback.get("remote_address", "").split(":")[0],
            "remote_port": 0,
            "raw_request": callback.get("raw_request", "")[:500],
            "interaction_id": callback.get("unique_id", ""),
        }

        # Extract port
        addr = callback.get("remote_address", "")
        if ":" in addr:
            try:
                parsed["remote_port"] = int(addr.split(":")[1])
            except ValueError:
                pass

        # Extract User-Agent
        ua_match = re.search(
            r"User-Agent:\s*(.+?)(?:\r?\n|$)", parsed["raw_request"], re.IGNORECASE
        )
        if ua_match:
            parsed["user_agent"] = ua_match.group(1).strip()
        else:
            parsed["user_agent"] = "unknown"

        # Determine likely vulnerability based on protocol
        parsed["likely_vuln"] = []
        for vuln, protocols in self.vuln_indicators.items():
            if parsed["protocol"] in protocols:
                parsed["likely_vuln"].append(vuln)

        return parsed

    def correlate_with_payloads(
        self,
        callbacks: List[Dict[str, Any]],
        payloads: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Correlate OOB callbacks with the payloads that triggered them."""

        payload_list = payloads.get("payloads", [])
        oob_domain = payloads.get("domain", "")

        result = {
            "total_callbacks": len(callbacks),
            "matched_payloads": [],
            "unmatched_callbacks": [],
            "oob_confirmed": False,
            "vulnerability_type": payloads.get("type", "unknown"),
            "confidence": "NONE",
        }

        for cb in callbacks:
            parsed = self.parse_callback(cb)
            matched = False

            for payload in payload_list:
                payload_name = payload.get("name", "unknown")
                payload_value = payload.get("value", "")

                # Check if callback's interaction contains payload marker
                interaction_id = cb.get("unique_id", "") + cb.get("full-id", "")
                raw = cb.get("raw_request", "")

                # Extract marker from payload (the unique path component)
                marker = ""
                if payload_name in payload_value or True:  # Always check
                    # Extract the path component from the payload
                    for part in payload_value.split("/"):
                        if oob_domain in part or len(part) > 4:
                            marker = part
                            break

                if marker and (marker in interaction_id or marker in raw):
                    result["matched_payloads"].append(
                        {
                            "payload_name": payload_name,
                            "callback_protocol": parsed["protocol"],
                            "remote_ip": parsed["remote_ip"],
                            "user_agent": parsed["user_agent"],
                            "timestamp": parsed["timestamp"],
                        }
                    )
                    matched = True
                    break

            if not matched:
                result["unmatched_callbacks"].append(
                    {
                        "protocol": parsed["protocol"],
                        "remote_ip": parsed["remote_ip"],
                        "likely_vuln": parsed["likely_vuln"],
                    }
                )

        # Determine confidence
        matched_count = len(result["matched_payloads"])
        if matched_count >= 2:
            result["oob_confirmed"] = True
            result["confidence"] = "HIGH"
        elif matched_count == 1:
            result["oob_confirmed"] = True
            result["confidence"] = "MEDIUM"
        elif len(callbacks) > 0:
            result["oob_confirmed"] = False
            result["confidence"] = "LOW"
            result["note"] = "Callbacks received but payload correlation uncertain"

        return result

    def validate_burp_collaborator(
        self, collaborator_log: str
    ) -> Dict[str, Any]:
        """Parse Burp Collaborator log format."""
        callbacks = []

        # Burp Collaborator exports structured JSON
        try:
            data = json.loads(collaborator_log)
            for entry in data if isinstance(data, list) else [data]:
                cb = {
                    "timestamp": entry.get("time", ""),
                    "protocol": entry.get("protocol", "").lower(),
                    "remote_address": entry.get("client", ""),
                    "raw_request": entry.get("request", ""),
                    "unique_id": entry.get("interactionId", ""),
                    "full_id": entry.get("interactionId", ""),
                }
                callbacks.append(cb)
        except (json.JSONDecodeError, TypeError):
            # Plain text format
            for line in collaborator_log.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 3:
                        cb = {
                            "timestamp": parts[0] if len(parts) > 0 else "",
                            "protocol": parts[1] if len(parts) > 1 else "unknown",
                            "remote_address": parts[2] if len(parts) > 2 else "",
                            "raw_request": " ".join(parts[3:]) if len(parts) > 3 else "",
                            "unique_id": "",
                            "full_id": "",
                        }
                        callbacks.append(cb)

        return {
            "total_callbacks": len(callbacks),
            "callbacks": callbacks,
            "protocols_seen": list(set(c["protocol"] for c in callbacks)),
        }

    def generate_poc_hypothesis(
        self, validation_result: Dict[str, Any]
    ) -> str:
        """Generate a proof-of-concept statement from OOB validation."""
        if not validation_result.get("oob_confirmed"):
            return "OOB callback NOT confirmed. Blind vulnerability may still exist via different vector."

        vuln_type = validation_result.get("vulnerability_type", "unknown")
        confidence = validation_result.get("confidence", "NONE")

        poc = f"BLIND {vuln_type.upper()} CONFIRMED via OOB callback ({confidence} confidence).\n"
        poc += f"Callback(s) received from target server.\n\n"

        for match in validation_result.get("matched_payloads", []):
            poc += f"Payload: {match['payload_name']}\n"
            poc += f"Protocol: {match['callback_protocol']}\n"
            poc += f"Source IP: {match['remote_ip']}\n"
            poc += f"User-Agent: {match.get('user_agent', 'N/A')}\n\n"

        return poc.strip()


def main():
    parser = argparse.ArgumentParser(description="OOB Callback Validator")
    parser.add_argument(
        "--callbacks", help="JSON file with interactsh callbacks (from oob_callbacks.json)"
    )
    parser.add_argument(
        "--payloads", help="JSON file with payload list (from oob_payloads.json)"
    )
    parser.add_argument("--output", help="Output file for validation results")
    parser.add_argument(
        "--mode",
        choices=["correlate", "burp-parse", "poc"],
        default="correlate",
        help="Validation mode",
    )
    parser.add_argument("--burp-log", help="Burp Collaborator log file or raw JSON")

    args = parser.parse_args()

    validator = OOBValidator()

    if args.mode == "correlate":
        if not args.callbacks or not args.payloads:
            print("[ERROR] --callbacks and --payloads are required for correlate mode")
            sys.exit(1)

        with open(args.callbacks) as f:
            cb_data = json.load(f)
        with open(args.payloads) as f:
            pl_data = json.load(f)

        result = validator.correlate_with_payloads(
            cb_data.get("callbacks", cb_data if isinstance(cb_data, list) else []),
            pl_data,
        )

        print(json.dumps(result, indent=2))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.mode == "burp-parse":
        if not args.burp_log:
            print("[ERROR] --burp-log is required for burp-parse mode")
            sys.exit(1)

        with open(args.burp_log) as f:
            log = f.read()

        result = validator.validate_burp_collaborator(log)
        print(json.dumps(result, indent=2))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.mode == "poc":
        if not args.callbacks or not args.payloads:
            print("[ERROR] --callbacks and --payloads are required for poc mode")
            sys.exit(1)

        with open(args.callbacks) as f:
            cb_data = json.load(f)
        with open(args.payloads) as f:
            pl_data = json.load(f)

        result = validator.correlate_with_payloads(
            cb_data.get("callbacks", cb_data if isinstance(cb_data, list) else []),
            pl_data,
        )
        poc = validator.generate_poc_hypothesis(result)
        print(poc)
        if args.output:
            with open(args.output, "w") as f:
                f.write(poc)


if __name__ == "__main__":
    main()
