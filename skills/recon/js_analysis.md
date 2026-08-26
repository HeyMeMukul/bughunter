# JavaScript Analysis Methodology

## When to Use

Consult during Phase 5 of recon. JavaScript files are the richest source of hidden endpoints, API routes, internal configurations, and hardcoded secrets.

---

## Collection Strategy

### Where to Find JS Files
1. **Page source:** `<script src="...">` tags
2. **Wayback Machine:** Historical JS files may contain endpoints removed from current version
3. **Source maps:** `//# sourceMappingURL=` — if present, download the `.map` file for full original source
4. **Webpack chunks:** `chunk.HASH.js`, `vendor.HASH.js` — contain bundled application code
5. **Service workers:** `navigator.serviceWorker.register('sw.js')` — intercepts network requests

### Download Strategy
```bash
# Collect all JS URLs
cat gau_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_urls.txt
katana -u https://target.com -d 3 -jc -ef css,png,jpg,gif,svg | grep "\.js" >> js_urls.txt
sort -u -o js_urls.txt js_urls.txt

# Download all
mkdir -p js/downloaded
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "js/downloaded/$filename"
  echo "$url → $filename" >> js/url_map.txt
done < js_urls.txt

# Beautify minified JS (makes analysis easier)
for f in js/downloaded/*.js; do
  js-beautify "$f" -o "${f%.js}_pretty.js" 2>/dev/null
done
```

---

## Extraction Targets

### 1. API Endpoints
```bash
# REST-style paths
grep -rhoE '["'"'"'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/?[a-zA-Z0-9_-]*)["'"'"']' js/downloaded/ | sort -u

# Patterns to look for:
# /api/v1/users, /api/admin/config, /internal/debug
# fetch("/api/...", ...), axios.get("/api/...", ...)
# this.baseUrl + "/endpoint"

# Common API route patterns in frameworks
grep -rhoE 'router\.(get|post|put|patch|delete)\s*\(\s*["'"'"'][^"'"'"']+' js/downloaded/
grep -rhoE '(fetch|axios|http)\s*[\.(]\s*["'"'"'][^"'"'"']+' js/downloaded/
```

### 2. Secrets & Credentials
```bash
# AWS Access Keys
grep -rhoE 'AKIA[0-9A-Z]{16}' js/downloaded/

# AWS Secret Keys (context needed)
grep -rhoiE '(aws_secret|secret_key|secretAccessKey)['"'"'"\s:=]+[A-Za-z0-9/+=]{40}' js/downloaded/

# Google API Keys
grep -rhoE 'AIza[0-9A-Za-z\-_]{35}' js/downloaded/

# Firebase
grep -rhoE 'firebase[a-zA-Z]*\.com' js/downloaded/

# Stripe
grep -rhoE '(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}' js/downloaded/

# Generic API Keys
grep -rhoiE '(apikey|api_key|secret|token|password|auth)['"'"'"\s]*[:=]['"'"'"\s]*[a-zA-Z0-9_\-]{16,}' js/downloaded/

# JWTs (three base64 segments separated by dots)
grep -rhoE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' js/downloaded/

# Private keys
grep -rl 'PRIVATE KEY' js/downloaded/

# Internal URLs
grep -rhoE 'https?://[a-zA-Z0-9.-]+\.(internal|local|corp|dev|staging|test)[a-zA-Z0-9./-]*' js/downloaded/
```

### 3. Hidden Functionality
```bash
# Admin/debug routes
grep -rhoiE '(admin|debug|test|internal|hidden|secret|staging|dev|config)['"'"'"/][a-zA-Z0-9_/-]+' js/downloaded/ | sort -u

# Feature flags
grep -rhoiE '(feature[_-]?flag|toggle|enabled|disabled|beta|canary|experiment)['"'"'"\s]*[:=]' js/downloaded/

# Environment checks
grep -rhoiE '(NODE_ENV|ENVIRONMENT|DEBUG|STAGE|PRODUCTION)' js/downloaded/

# Commented-out code
grep -rhoE '//\s*(TODO|FIXME|HACK|BUG|XXX|TEMP|DEBUG|REMOVE).*$' js/downloaded/
```

### 4. WebSocket Endpoints
```bash
grep -rhoE '(ws|wss)://[a-zA-Z0-9._/-]+' js/downloaded/
grep -rhoiE 'new\s+WebSocket\s*\([^)]+\)' js/downloaded/
```

### 5. Source Maps
```bash
# Find source map references
grep -rhoE '//[#@]\s*sourceMappingURL=[^\s]+' js/downloaded/

# Download source maps
grep -rhoE 'sourceMappingURL=([^\s]+)' js/downloaded/ | while read map; do
  curl -s "$map" -o "js/sourcemaps/$(basename $map)"
done

# Source maps contain ORIGINAL unminified source code — goldmine for analysis
```

---

## Analysis Workflow

### Manual Approach (High-Value Files)
1. Open beautified JS in editor
2. Search for: `fetch(`, `axios.`, `XMLHttpRequest`, `$.ajax`, `http.`
3. Trace the base URL construction — often: `config.apiUrl + "/endpoint"`
4. Look at route definitions — React Router, Angular routes, Vue Router
5. Check for authorization logic — `if (user.role === 'admin')` reveals role names
6. Look for environment-specific configs — different URLs for dev/staging/prod

### Automated Pipeline
```bash
# Full pipeline
cat js_urls.txt | while read url; do
  echo "=== $url ===" >> js/analysis.txt
  curl -s "$url" | js-beautify | tee temp.js | \
    grep -oiE '(api|internal|admin|secret|key|token|password|firebase|aws|fetch|axios)[^\s,;)]+' >> js/analysis.txt
  echo "" >> js/analysis.txt
done
```

---

## Prioritization of Findings

| Finding | Impact | Action |
|---------|--------|--------|
| Hardcoded AWS/GCP/Azure credentials | Critical | Verify immediately — report if valid |
| Admin API endpoints | High | Add to testing queue as priority |
| Internal/staging URLs | High | Check if accessible from external |
| JWT tokens | High | Decode — check if valid, what access |
| Source maps available | High | Download for deep source code analysis |
| Feature flags / debug modes | Medium | Test if togglable from client |
| WebSocket endpoints | Medium | Add to [[websocket]] testing queue |
| Old API versions (/v1/ when /v3/ is current) | Medium | Often less protected |
