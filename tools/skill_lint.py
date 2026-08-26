#!/usr/bin/env python3
"""Lint SKILL.md files against the framework's shared authoring contract."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REQUIRED = {
    "frontmatter": re.compile(r"\A---\nname:\s*[a-z0-9-]+\ndescription:\s*.+\n---", re.I | re.S),
    "reasoning_checkpoint": re.compile(r"Reasoning Checkpoint", re.I),
    "things_to_do": re.compile(r"^## Things to Do\s*$", re.M),
    "things_not_to_do": re.compile(r"^## Things Not to Do\s*$", re.M),
    "negative_verdict": re.compile(r"Negative Verdict", re.I),
    "session_reverification": re.compile(r"Session Re-verification", re.I),
    "external_infra_marker": re.compile(r"\[EXTERNAL INFRA REQUIRED\]"),
}

DOMAIN_DIRS = {
    "brave-search-mcp", "browser-sessions", "burp-mcp", "github-mcp", "memory-mcp",
    "sequential-thinking", "report-writing", "mapping", "recon", "recon-infra", "_shared",
}


def lint(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    name = path.parent.name
    findings = []
    for key, pattern in REQUIRED.items():
        if key == "external_infra_marker":
            continue
        if not pattern.search(text):
            findings.append(key)
    lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    if lines > 500:
        findings.append("over_500_lines")
    if name not in DOMAIN_DIRS and "EXTERNAL INFRA" in text and not REQUIRED["external_infra_marker"].search(text):
        findings.append("missing_external_infra_marker")
    summary = path.parent / "SUMMARY.md"
    if name not in DOMAIN_DIRS and not summary.exists():
        findings.append("missing_summary")
    return {"file": str(path), "lines": lines, "missing": findings, "ok": not findings}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="skills")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = [lint(path) for path in sorted(Path(args.root).glob("*/SKILL.md"))]
    payload = {"skills": len(results), "passing": sum(item["ok"] for item in results), "results": results}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"skills={payload['skills']} passing={payload['passing']}")
        for item in results:
            if not item["ok"]:
                print(f"FAIL {item['file']} ({item['lines']} lines): {', '.join(item['missing'])}")
    return 0 if payload["passing"] == payload["skills"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
