#!/usr/bin/env python3
"""Import public disclosed-report metadata into a redacted NDJSON corpus.

This importer intentionally handles metadata only. It does not crawl report pages,
execute payloads, contact targets, or collect private attachments.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{12,})\b")
URL_SECRET = re.compile(r"([?&](?:token|key|secret|password|auth)=[^&\s]+)", re.I)

CLASS_MAP = {
    "insecure direct object reference (idor)": "idor",
    "improper access control - generic": "access-control",
    "privilege escalation": "privilege-escalation",
    "improper authentication - generic": "authentication",
    "server-side request forgery (ssrf)": "ssrf",
    "sql injection": "sqli",
    "cross-site scripting (xss) - stored": "xss-stored",
    "cross-site scripting (xss) - reflected": "xss-reflected",
    "cross-site scripting (xss) - dom": "xss-dom",
    "cross-site scripting (xss) - generic": "xss",
    "cross-site request forgery (csrf)": "csrf",
    "business logic errors": "business-logic",
    "open redirect": "open-redirect",
    "path traversal": "path-traversal",
    "code injection": "code-injection",
    "information disclosure": "information-disclosure",
    "uncontrolled resource consumption": "resource-exhaustion",
    "memory corruption - generic": "memory-corruption",
}


def redact(text: str) -> str:
    text = EMAIL.sub("[REDACTED_EMAIL]", text or "")
    text = SECRET.sub("[REDACTED_SECRET]", text)
    return URL_SECRET.sub(r"\1[REDACTED]", text)


def canonicalize(label: str, title: str) -> list[str]:
    normalized = (label or "").strip().lower()
    mapped = CLASS_MAP.get(normalized)
    if mapped:
        return [mapped]
    title_lower = (title or "").lower()
    inferred = []
    for token, cls in (
        ("ssrf", "ssrf"), ("idor", "idor"), ("xss", "xss"), ("sql", "sqli"),
        ("oauth", "oauth"), ("csrf", "csrf"), ("race", "race-condition"),
        ("rce", "rce"), ("remote code execution", "rce"), ("authentication", "authentication"),
    ):
        if token in title_lower and cls not in inferred:
            inferred.append(cls)
    return inferred or ["unclassified"]


def parse_bounty(value: str) -> float:
    cleaned = str(value or "").replace("$", "").replace(",", "").strip()
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def make_record(row: dict[str, str], retrieved_at: str, minimum: float) -> dict:
    title = redact(row.get("title", "").strip())
    bounty = parse_bounty(row.get("bounty", ""))
    link = row.get("link", "").strip()
    if link and not link.startswith(("http://", "https://")):
        link = "https://" + link
    report_id = link.rstrip("/").rsplit("/", 1)[-1] if link else "unknown"
    record_id = f"h1-{report_id}" if report_id.isdigit() else hashlib.sha256(link.encode()).hexdigest()[:16]
    digest = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    classes = canonicalize(row.get("vuln_type", ""), title)
    return {
        "record_id": record_id,
        "source": {
            "platform": "hackerone",
            "url": link,
            "report_id": report_id,
            "retrieved_at": retrieved_at,
            "content_sha256": digest,
            "license_or_terms_checked": False,
        },
        "labels": {
            "canonical_classes": classes,
            "platform_labels": [row.get("vuln_type", "").strip()] if row.get("vuln_type", "").strip() else [],
            "application_surface": [],
            "trust_boundaries": [],
            "impact_class": "unknown",
            "outcome": "public-disclosed-paid",
        },
        "economics": {"bounty_usd": bounty, "threshold_passed": bounty > minimum},
        "content": {
            "title_redacted": title,
            "abstract": "",
            "reasoning_pattern": "",
            "evidence_pattern": "",
            "counterexample_or_limit": "",
        },
        "quality": {
            "source_quality": "mirror-index",
            "extraction_confidence": 0.5,
            "review_status": "unreviewed",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv")
    parser.add_argument("output_ndjson")
    parser.add_argument("--min-bounty", type=float, default=100.0)
    args = parser.parse_args()
    retrieved_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    count = 0
    with Path(args.input_csv).open(newline="", encoding="utf-8", errors="replace") as source, Path(args.output_ndjson).open("w", encoding="utf-8") as dest:
        for row in csv.DictReader(source):
            if parse_bounty(row.get("bounty", "")) <= args.min_bounty:
                continue
            dest.write(json.dumps(make_record(row, retrieved_at, args.min_bounty), ensure_ascii=False) + "\n")
            count += 1
    print(json.dumps({"output": args.output_ndjson, "records": count, "min_bounty": args.min_bounty, "metadata_only": True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
