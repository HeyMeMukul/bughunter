# Advanced Reconnaissance Techniques

## When to Use

Consult after basic passive/active recon is complete. These techniques extract attack surface that standard tools miss.

---

## GitHub/GitLab Deep Dorking

### Organization Reconnaissance
```
# Find all repositories
org:target-org

# Find secrets in code
org:target-org password OR secret OR api_key OR token OR credentials
org:target-org filename:.env
org:target-org filename:.npmrc
org:target-org filename:.dockerenv
org:target-org filename:docker-compose.yml
org:target-org filename:Dockerfile
org:target-org filename:application.properties
org:target-org filename:appsettings.json
org:target-org filename:config.yaml OR filename:config.yml
org:target-org filename:id_rsa OR filename:id_dsa
org:target-org filename:.htpasswd
org:target-org filename:wp-config.php
org:target-org filename:settings.py
org:target-org filename:database.yml
org:target-org filename:credentials.xml

# Find internal/staging URLs
org:target-org "staging" OR "internal" OR "dev" OR "preprod"
org:target-org "target.com" AND ("staging" OR "internal" OR "localhost")

# Find infrastructure details
org:target-org "amazonaws.com" OR "azure" OR "gcloud"
org:target-org "kubernetes" OR "kubectl" OR "helm"
org:target-org "jenkins" OR "circleci" OR "github-actions"

# Historical secrets (check commit history!)
# Use tools: truffleHog, gitleaks, git-secrets
trufflehog github --org=target-org
gitleaks detect --source=./cloned-repo
```

### Employee Reconnaissance
```
# Find personal repos of target employees
# LinkedIn → find engineering team → GitHub profiles
# Search their personal repos for target company references
"target.com" user:employee-username
```

### Commit History Mining
Even if secrets are removed from current code, they exist in commit history:
```bash
git clone https://github.com/target-org/repo.git
cd repo
# Search all commits for secrets
git log -p --all | grep -iE "(password|secret|api_key|token|aws_access|private_key)" | head -50
```

---

## Cloud-Specific Enumeration

### AWS
```bash
# S3 bucket discovery
# Naming conventions to try:
# target, target-com, target-assets, target-uploads, target-backups
# target-dev, target-staging, target-prod, target-logs
# target-static, target-media, target-data, target-exports
for bucket in target target-com target-assets target-uploads target-backups target-dev target-staging target-prod; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com/")
  if [ "$status" != "404" ]; then
    echo "$bucket → $status" >> s3_buckets.txt
  fi
done

# Check each region variant
aws s3 ls s3://target-bucket --no-sign-request 2>&1 | head -20
```

### GCP
```bash
# Google Cloud Storage buckets
for bucket in target target-com target-assets target-uploads; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$bucket/")
  if [ "$status" != "404" ]; then
    echo "$bucket → $status"
  fi
done

# Firebase databases
curl -s "https://target-name.firebaseio.com/.json" | head -100
# If this returns data → unauthenticated Firebase access
```

### Azure
```bash
# Blob storage
for container in assets uploads backups data; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://targetname.blob.core.windows.net/$container?restype=container&comp=list")
  if [ "$status" != "404" ]; then
    echo "$container → $status"
  fi
done
```

---

## Mobile API Extraction

Mobile apps often expose different (less secured) API endpoints than web apps.

### Android
```bash
# Download APK from device or APKPure
adb pull /data/app/com.target.app/base.apk

# Decompile
apktool d base.apk -o decompiled/
jadx base.apk -d jadx_output/

# Extract endpoints
grep -rhoE 'https?://[^\s"<>]+' jadx_output/ | sort -u > mobile_endpoints.txt
grep -rhoiE '(api[_-]?key|secret|token|password|auth)["\s:=]+["\s]*[a-zA-Z0-9_-]{16,}' jadx_output/ > mobile_secrets.txt

# Check for certificate pinning bypass (indicates they know the API is sensitive)
grep -ri "certificate\|pinning\|ssl\|trustmanager" jadx_output/
```

### iOS
```bash
# Extract IPA (requires jailbreak or tools like ipatool)
# Decrypt if needed (clutch, frida-ios-dump)

# Analyze binary
strings app_binary | grep -iE "https?://|api|secret|key|token" | sort -u

# Check Info.plist for app transport security exceptions
plutil -p Info.plist | grep -A5 "NSAppTransportSecurity"
```

**Mobile APIs are high-value because:**
- Often have different authentication (API keys instead of session cookies)
- May have endpoints not available on web
- Rate limiting may be different
- Authorization checks may be weaker
- Older API versions may be required for backward compatibility

---

## DNS Zone Walking (DNSSEC)

If the target uses DNSSEC with NSEC (not NSEC3), you can enumerate ALL records:
```bash
# Check if NSEC is used
dig target.com NSEC +short

# If NSEC records exist, walk the zone
ldns-walk @ns1.target.com target.com
# or
dnsrecon -d target.com -z
```

This reveals every DNS record in the zone, including internal hostnames, MX records, and service records.

---

## Virtual Host Discovery

Multiple websites can share the same IP address. Discover vhosts:
```bash
# Get the IP
ip=$(dig +short target.com)

# Test common vhost names
ffuf -u http://$ip -H "Host: FUZZ.target.com" -w subdomains_wordlist.txt -fs $DEFAULT_SIZE

# Check reverse DNS databases
curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip"
```

Virtual hosts often include: staging, internal, admin, legacy, and partner applications sharing the same server.

---

## Favicon Hash Fingerprinting

Different applications have unique favicon hashes. Use this to find the same application deployed elsewhere:
```bash
# Calculate favicon hash
curl -s https://target.com/favicon.ico | python3 -c "
import mmh3, codecs, sys
favicon = sys.stdin.buffer.read()
fhash = mmh3.hash(codecs.encode(favicon, 'base64'))
print(f'http.favicon.hash:{fhash}')
"
# Search this hash on Shodan/Censys to find other instances
```

Finding the same application on a different domain (staging, dev) often reveals a less-protected instance.

---

## Email Infrastructure Recon

Email systems reveal internal infrastructure:
```bash
# MX records
dig target.com MX

# Check for mail server misconfigurations
# Open relay, VRFY/EXPN commands, user enumeration
nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay mail.target.com

# Extract email addresses (for password spray candidates)
theHarvester -d target.com -b all
```

---

## Continuous Monitoring

For multi-day engagements, set up monitoring for new attack surface:
```bash
# Daily subdomain check
subfinder -d target.com -all -o subs_$(date +%Y%m%d).txt
diff subs_yesterday.txt subs_today.txt | grep ">" > new_subdomains.txt

# New certificate monitoring
# Subscribe to crt.sh RSS or use certstream
```

New subdomains appearing during your engagement may be new deployments with fresh (buggy) code.
