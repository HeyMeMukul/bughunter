#!/usr/bin/env python3
"""Read-only OmniRoute connectivity and candidate-pool diagnostics."""
from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlsplit, urlunsplit

import requests


def root_url(base: str) -> str:
    parts = urlsplit(base.rstrip('/'))
    path = parts.path.rstrip('/')
    if path.endswith('/v1'):
        path = path[:-3]
    return urlunsplit((parts.scheme, parts.netloc, path, '', '')).rstrip('/')


def get_json(url: str, headers: dict[str, str], timeout: float) -> dict:
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        data = None
        try:
            data = response.json()
        except ValueError:
            data = {'text_prefix': response.text[:500]}
        return {'url': url, 'status': response.status_code, 'ok': response.ok, 'data': data}
    except requests.RequestException as exc:
        return {'url': url, 'status': None, 'ok': False, 'error': str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default=os.getenv('OMNIROUTE_BASE_URL', 'http://127.0.0.1:20128/v1'))
    parser.add_argument('--api-key', default=os.getenv('OMNIROUTE_API_KEY', ''))
    parser.add_argument('--channel', action='append', default=[])
    parser.add_argument('--timeout', type=float, default=5.0)
    args = parser.parse_args()
    headers = {'Accept': 'application/json'}
    if args.api_key:
        headers['Authorization'] = 'Bearer ' + args.api_key
    root = root_url(args.base_url)
    checks = [
        get_json(f'{root}/v1/models', headers, args.timeout),
        get_json(f'{root}/api/monitoring/health', headers, args.timeout),
    ]
    for channel in args.channel:
        checks.append(get_json(f'{root}/v1/auto-combo/{channel}/candidates', headers, args.timeout))
    result = {'base_url': args.base_url, 'read_only': True, 'checks': checks}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if all(check['ok'] for check in checks[:2]) else 1


if __name__ == '__main__':
    raise SystemExit(main())
