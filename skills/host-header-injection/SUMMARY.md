# Host Header Injection — Summary Card

**Phase:** 3 | **Type:** Server-Side | **Impact:** Critical

## Quick Summary
Exploit host header manipulation to poison password reset links, bypass authentication, poison web caches, and access internal resources. The #1 attack is password reset poisoning leading to complete account takeover.

## Key Indicators
- Application uses absolute URLs in emails (password reset, verification)
- Password reset links contain the Host header value
- X-Forwarded-Host or X-Forwarded-For headers are reflected
- Application generates URLs using request hostname
- Internal services use host-based routing

## Quick Test
```bash
# Basic host injection
curl -H "Host: evil.com" https://target.com/reset-password
curl -H "X-Forwarded-Host: evil.com" https://target.com/reset-password
# Check if reset link contains evil.com
```

## Critical Bounty Potential
- Password reset poisoning = full account takeover ($2000-$10000)
- Cache poisoning via Host header
- SSRF via Host header to internal services

## Token Cost
~3,500 tokens
