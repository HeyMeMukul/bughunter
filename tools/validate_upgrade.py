#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'knowledge/corpus_seed/hackerone_paid_gt100.ndjson'
SECRET_PATTERNS = [
    re.compile(r'ghp_[A-Za-z0-9]{20,}'),
    re.compile(r'sk-[A-Za-z0-9_-]{12,}'),
    re.compile(r'AKIA[A-Z0-9]{12,}'),
    re.compile(r'Authorization:\s*Bearer\s+[^\s]+', re.I),
    re.compile(r'Cookie:\s*[^\s]+', re.I),
]

json.loads((ROOT / 'opencode.json').read_text())
json.loads((ROOT / 'config/omniroute.policy.json').read_text())
rows = [json.loads(line) for line in CORPUS.read_text(encoding='utf-8').splitlines()]
assert len(rows) == 2810
assert all(row['economics']['bounty_usd'] > 100 for row in rows)
assert all(row['source']['url'].startswith('https://') for row in rows)
text = CORPUS.read_text(encoding='utf-8')
assert not any(pattern.search(text) for pattern in SECRET_PATTERNS)
print(json.dumps({
    'json_configs': 'ok',
    'ndjson_records': len(rows),
    'all_bounty_gt_100': True,
    'https_provenance': True,
    'obvious_secret_patterns': False,
}, indent=2))
