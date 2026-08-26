#!/usr/bin/env python3
"""Validate the expanded >$1,000 public bug-bounty corpus."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(?:api[_ -]?key|authorization|cookie|password|secret|access[_ -]?token)\s*[:=]\s*[^\s,;]{8,}"),
    re.compile(r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
]


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "knowledge/corpus_seed/expanded_high_bounty_gt1000.ndjson")
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid JSON at line {line_no}: {exc}")

    if not rows:
        raise SystemExit("corpus is empty")

    ids = [row.get("record_id") for row in rows]
    if None in ids or len(ids) != len(set(ids)):
        raise SystemExit("missing or duplicate record_id")

    for row in rows:
        bounty = float(row.get("economics", {}).get("bounty_usd", 0))
        if bounty <= 1000:
            raise SystemExit(f"threshold failure: {row['record_id']} has bounty {bounty}")
        url = row.get("source", {}).get("url", "")
        if not url.startswith("https://"):
            raise SystemExit(f"provenance failure: {row['record_id']}")
        if not row.get("quality", {}).get("source_quality"):
            raise SystemExit(f"source-quality missing: {row['record_id']}")
        serialized = json.dumps(row, ensure_ascii=False)
        for pattern in SECRET_PATTERNS:
            if pattern.search(serialized):
                raise SystemExit(f"possible secret marker in {row['record_id']}")

    by_type = {}
    for row in rows:
        kind = row.get("economics", {}).get("bounty_type", "unknown")
        by_type[kind] = by_type.get(kind, 0) + 1
    print(json.dumps({"records": len(rows), "unique_ids": len(set(ids)), "bounty_types": by_type}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
