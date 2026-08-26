# Recon Tool Reference

## When to Use

Consult for specific tool commands, flags, and best practices during each recon phase.

---

## Subdomain Enumeration Tools

### subfinder
Best all-in-one passive subdomain enumerator. Aggregates 40+ sources.
```bash
# Basic
subfinder -d target.com -o subdomains.txt

# All sources (slower, more complete)
subfinder -d target.com -all -o subdomains.txt

# Multiple domains
subfinder -dL domains.txt -o subdomains.txt

# With specific sources
subfinder -d target.com -s crtsh,certspotter,dnsdumpster,hackertarget -o subdomains.txt

# Config file for API keys: ~/.config/subfinder/provider-config.yaml
# Adding API keys dramatically increases results
```

### amass
Most comprehensive but slowest. Use passive mode for speed.
```bash
# Passive only (fast)
amass enum -passive -d target.com -o amass_passive.txt

# Active (DNS brute-force + zone transfers)
amass enum -active -d target.com -brute -w wordlist.txt -o amass_active.txt

# Intel mode (find related domains via WHOIS, ASN)
amass intel -d target.com -whois
```

### assetfinder
Fast and lightweight.
```bash
assetfinder --subs-only target.com > assetfinder.txt
```

### crt.sh (API)
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt
```

### github-subdomains
```bash
github-subdomains -d target.com -t GITHUB_TOKEN -o github_subs.txt
```

---

## Live Host Discovery

### httpx
Best for HTTP-specific probing.
```bash
# Basic live check
cat subdomains.txt | httpx -silent -o live.txt

# Detailed output
cat subdomains.txt | httpx -silent -title -tech-detect -status-code -content-length -follow-redirects -o detailed.txt

# JSON output for parsing
cat subdomains.txt | httpx -json -o results.json

# Custom ports
cat subdomains.txt | httpx -ports 80,443,8080,8443,8000,3000,5000 -o live.txt

# Filter by status
cat subdomains.txt | httpx -mc 200,301,302,403 -o live.txt
```

### naabu (Port Scanner)
```bash
# Common web ports
naabu -list ips.txt -p 80,443,8080,8443,8000,3000,5000,9090 -o ports.txt

# Top 100 ports
naabu -list ips.txt -top-ports 100 -o ports.txt

# Service detection integration
naabu -list ips.txt -p - -nmap-cli "nmap -sV"
```

---

## Content Discovery

### ffuf (Directory/File Brute-Force)
```bash
# Basic directory scan
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -o dirs.json

# With extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.txt,.bak,.old,.env -mc 200,301,302,403

# Recursive (careful with depth)
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# POST parameter fuzzing
ffuf -u https://target.com/login -X POST -d "username=FUZZ&password=test" -w usernames.txt

# Header fuzzing
ffuf -u https://target.com/api -H "X-Custom-Header: FUZZ" -w values.txt

# Rate limiting
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50

# Filter by response size (remove noise)
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234  # filter size 1234 bytes
```

### gau (GetAllUrls)
```bash
# All sources
gau target.com --threads 5 --o all_urls.txt

# Filter parameters
gau target.com | grep "=" | sort -u > param_urls.txt

# Specific providers
gau target.com --providers wayback,commoncrawl,otx
```

### waymore
```bash
# URLs only
waymore -i target.com -mode U -oU urls.txt

# Responses too (downloads cached responses)
waymore -i target.com -mode R -oR responses/

# With filters
waymore -i target.com -mode U -f -oU filtered_urls.txt
```

### katana (Web Crawler)
```bash
# Crawl with JS rendering
katana -u https://target.com -d 3 -jc -o crawled.txt

# Headless browser crawl
katana -u https://target.com -hl -d 3 -o crawled.txt

# Multiple URLs
katana -list live_hosts.txt -d 2 -o all_crawled.txt
```

---

## JavaScript Analysis Tools

### getJS
```bash
# Extract JS URLs from pages
getJS --url https://target.com --complete --output js_urls.txt
```

### LinkFinder
```bash
# Extract endpoints from JS files
python3 linkfinder.py -i https://target.com/main.js -o cli
python3 linkfinder.py -i https://target.com -d -o results.html  # entire domain
```

### SecretFinder
```bash
# Find secrets in JS files
python3 SecretFinder.py -i https://target.com/main.js -o cli
```

### Manual Regex Extraction
```bash
# API endpoints
grep -rhoE '["'"'"'](\/api\/[^"'"'"'\s]+)["'"'"']' js/*.js | sort -u

# Full URLs
grep -rhoE 'https?://[^\s"'"'"'<>]+' js/*.js | sort -u

# API keys (generic)
grep -rhoiE '(api[_-]?key|apikey|secret|token|password|aws_access|firebase)['"'"'"\s]*[:=]['"'"'"\s]*[a-zA-Z0-9_\-]{16,}' js/*.js

# AWS keys
grep -rhoE 'AKIA[0-9A-Z]{16}' js/*.js
```

---

## Parameter Discovery

### Arjun
```bash
# GET parameters
arjun -u https://target.com/endpoint -m GET

# POST parameters
arjun -u https://target.com/endpoint -m POST

# JSON body
arjun -u https://target.com/api/endpoint -m JSON

# Custom wordlist
arjun -u https://target.com/endpoint -w params_wordlist.txt
```

### x8
```bash
x8 -u "https://target.com/endpoint" -w wordlist.txt --method GET
```

---

## Nuclei (Automated Scanning)

```bash
# All templates (slow but comprehensive)
nuclei -l live_hosts.txt -o nuclei_all.txt

# Severity filter
nuclei -l live_hosts.txt -severity critical,high -o nuclei_critical.txt

# Specific categories
nuclei -l live_hosts.txt -t exposures/ -o exposures.txt
nuclei -l live_hosts.txt -t technologies/ -o tech.txt
nuclei -l live_hosts.txt -t cves/ -o cves.txt
nuclei -l live_hosts.txt -t takeovers/ -o takeovers.txt
nuclei -l live_hosts.txt -t misconfiguration/ -o misconfigs.txt

# Custom rate
nuclei -l live_hosts.txt -rl 50 -c 10  # 50 req/s, 10 concurrent
```

---

## Useful One-Liners

```bash
# Complete subdomain pipeline
subfinder -d target.com -all | httpx -silent -title -tech-detect -status-code | tee live_detailed.txt

# Find all parameterized URLs from Wayback
gau target.com | grep "=" | uro | sort -u > unique_params.txt

# Find potential XSS endpoints (reflected params)
gau target.com | grep "=" | qsreplace "FUZZ" | httpx -silent -ms "FUZZ" | tee reflected.txt

# Find open redirects
gau target.com | grep -iE "(redirect|url|next|return|goto|dest)" | sort -u

# Find potential SSRF endpoints
gau target.com | grep -iE "(url=|uri=|path=|src=|dest=|redirect=|img=|fetch=|proxy=)" | sort -u

# Find potential SQLi endpoints
gau target.com | grep -iE "(id=|select=|report=|category=|search=|query=)" | sort -u
```
