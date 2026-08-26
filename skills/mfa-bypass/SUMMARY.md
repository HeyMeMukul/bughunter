# MFA Bypass — Summary Card

**Phase:** 3 | **Type:** Authentication | **Impact:** Critical

## Quick Summary
Bypass multi-factor authentication (2FA/MFA) through response manipulation, rate limiting bypass, backup code abuse, OAuth MFA skip, session re-use after partial auth, and direct API endpoint access.

## Key Indicators
- Login flow with 2FA step (SMS, TOTP, email code)
- Backup/Recovery code system
- "Remember this device" option
- OAuth login that skips 2FA
- API endpoints that may not enforce 2FA

## Quick Test
- Intercept 2FA verification response, change "false" to "true"
- Brute-force 6-digit code (no rate limit = bypass)
- Try accessing authenticated endpoints directly after password login (before 2FA)
- Direct API access to post-password-login endpoints

## Critical Bounty Potential
- 2FA bypass = full account takeover despite "enhanced security"
- Report value: $1500-$5000+
- Particularly high impact on financial/sensitive accounts

## Token Cost
~3,500 tokens
