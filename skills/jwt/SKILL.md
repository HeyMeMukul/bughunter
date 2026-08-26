---
name: testing-jwt
description: JWT implementation flaw testing including algorithm confusion, key injection, claim manipulation, and signature bypass. Use when authentication relies on JSON Web Tokens — identified by base64-encoded three-part tokens (header.payload.signature) in Authorization headers, cookies, or request bodies.
---

# JWT Testing

JWT vulnerabilities arise from implementation flaws in how tokens are generated, validated, and trusted. The token structure (header.payload.signature) creates multiple attack surfaces: algorithm specification, key management, claim validation, and signature verification.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (decode/map)   (test flaws)     (declare secure)      (forge token)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Token Analysis

Decode the JWT (base64url decode each segment). Record:
- **Header:** `alg` (algorithm), `typ`, `kid` (key ID), `jku` (JWK Set URL), `x5u` (X.509 URL)
- **Payload:** All claims — `sub`, `iss`, `aud`, `exp`, `iat`, `role`, `admin`, custom claims
- **Signature:** Presence and algorithm type

### Step 1.2: Algorithm Classification

| Algorithm | Type | Testing Approach |
|-----------|------|-----------------|
| HS256/HS384/HS512 | Symmetric (shared secret) | Weak secret brute-force, algorithm confusion |
| RS256/RS384/RS512 | Asymmetric (RSA) | Algorithm confusion to HS256, key confusion |
| ES256/ES384/ES512 | Asymmetric (ECDSA) | Algorithm confusion, curve attacks |
| PS256/PS384/PS512 | Asymmetric (RSA-PSS) | Algorithm confusion |
| none | No signature | Direct token forgery |

### Step 1.3: Claim Mapping

Identify which claims control authorization:
- `role`, `admin`, `is_admin`, `permissions`, `groups` — direct role indicators
- `sub`, `user_id`, `email` — identity claims
- `org_id`, `tenant_id` — multi-tenancy claims
- `exp` — expiration (can it be extended?)

### Step 1.4: Baseline Request

Send a valid request with the unmodified JWT. Record normal response. Then send a request with a clearly invalid/expired JWT. Record the rejection response.

### Reasoning Checkpoint

```
[PHASE-1] Baseline
[ALGORITHM] {alg value}
[CLAIMS] {key claims identified}
[HEADER-FIELDS] {kid, jku, x5u if present}
[VALID-RESPONSE] Status: {code}
[INVALID-RESPONSE] Status: {code}
[DECISION] {Proceed — attack vectors identified}
```

---

## Phase 2: Confirmation

### Confidence Definitions

| Level | For JWT Specifically |
|-------|---------------------|
| HIGH | Modified token accepted by server — either signature bypass confirmed or claim manipulation changes server behavior |
| MEDIUM | Server behaves differently with modified tokens but not conclusively accepting them |
| LOW | All modifications properly rejected |

### Step 2.1: Algorithm None Attack

Change header `alg` to `none`, `None`, `NONE`, `nOnE`. Remove the signature (third segment). Send the token.

If accepted → algorithm validation is broken. HIGH confidence for token forgery.

### Step 2.2: Algorithm Confusion (RS256 → HS256)

If the server uses RSA (RS256), the public key is sometimes obtainable (JWKS endpoint, certificate, etc.). Change `alg` to `HS256` and sign the token with the RSA public key as the HMAC secret.

If the server uses the same variable for both RSA public key verification and HMAC secret, it will accept the token.

Finding the public key:
- `/.well-known/jwks.json`
- `/oauth/jwks`
- `/api/keys`
- SSL certificate's public key
- `jku` or `x5u` header values

### Step 2.3: Key ID (kid) Injection

If the header contains `kid`, test injection:
- Path traversal: `"kid": "../../etc/passwd"` — forces server to use file content as key
- SQL injection: `"kid": "' UNION SELECT 'known-secret' --"` — forces known key
- Empty key: `"kid": ""` — may default to empty string as secret
- Known file: `"kid": "/dev/null"` — null bytes as key

### Step 2.4: JKU/X5U Header Injection `[EXTERNAL INFRA REQUIRED]`

If `jku` (JWK Set URL) or `x5u` (X.509 Certificate URL) is present:
- Point to your own server hosting a JWK set with your key pair
- Sign the token with your private key
- Server fetches your JWK set and validates against your public key

### Step 2.5: Claim Manipulation (with valid signature)

If no signature bypass is found, test whether the server properly validates claims:
- Extend `exp` far into the future — does the server enforce expiration?
- Change `sub`/`user_id` to another user's — does the server use the claim directly?
- Add `role: admin` or `is_admin: true` — does the server trust JWT claims for authorization?

Note: Claim manipulation without signature bypass requires either a weak secret (crackable) or the claims are validated independently of the signature.

### Step 2.6: Weak Secret Brute-Force

For HMAC algorithms (HS256), attempt to crack the signing secret using wordlists. Common weak secrets: `secret`, `password`, `jwt_secret`, the application name, `changeme`.

**Max confirmation attempts: 12 distinct techniques.** If none succeed, evaluate negative verdict.

### Reasoning Checkpoint

```
[PHASE-2] Confirmation
[TECHNIQUE] {none alg / confusion / kid injection / jku/x5u / claim / brute-force}
[RESULT] {accepted / rejected for each technique}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try next technique / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions

- Algorithm `none` properly rejected
- Algorithm confusion (RS→HS) properly rejected or not applicable
- `kid` injection attempts properly rejected
- Modified claims with original signature properly rejected
- Secret brute-force with standard wordlist unsuccessful
- Token expiration properly enforced

### Structured Log

```
[VULN-NEGATIVE]
[PARAMETER] JWT
[STEPS-RUN] {all techniques attempted}
[SIGNAL] {all modifications rejected}
[CONCLUSION] {JWT implementation properly validates algorithm, signature, and claims}
[ACTION] JWT cleared. Do not proceed to exploitation.
```

---

## Phase 3: Exploitation

### Level 1: Token Forgery
Using the confirmed bypass, forge a token with modified identity claims (change `sub` or `user_id`).

### Level 2: Privilege Escalation
Forge a token with elevated role claims (`admin: true`, `role: superadmin`). Access admin-only endpoints.

### Level 3: Account Takeover
Forge a token for a specific target user. Demonstrate access to their resources.

**Stop condition:** At first confirmed unauthorized access via forged token, STOP.

### Reasoning Checkpoint

```
[PHASE-3] Exploitation
[BYPASS-USED] {technique}
[IMPACT] {identity change / privilege escalation / ATO}
[EVIDENCE] {specific access demonstrated}
[STOP-REASON] {impact threshold reached}
```

---

## Session Re-verification

Re-verify by sending the original unmodified JWT before each new technique. If it's rejected, the token may have expired — obtain a fresh token.

---

## Things to Do

- Always decode and fully analyze the token before testing
- Check for JWKS endpoints to obtain public keys
- Test algorithm confusion before brute-forcing — it's faster and more reliable
- Verify claim changes actually affect server behavior, not just token content

## Things Not to Do

- Do not assume RS256 is secure without testing algorithm confusion
- Do not spend excessive time brute-forcing secrets on strong algorithms
- Do not modify claims without understanding which claims the server actually uses for authorization
- Do not confuse token decoding (always possible) with token forgery (requires bypass)

---

## Cross-Skill Links

- [[oauth]] — JWT often used as OAuth access/ID tokens
- [[session-management]] — JWT is a session mechanism variant
- [[idor]] — Forged JWT may enable IDOR by changing user context
