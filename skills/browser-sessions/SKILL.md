---
name: browser-sessions
description: Browser automation via Playwright MCP and Chrome DevTools Protocol (CDP) for penetration testing. Playwright MCP is the PRIMARY browser tool — handles navigation, clicking, form filling, screenshots, cookie/storage management, network capture, and DOM analysis. CDP is the FALLBACK for extracting cookies from manually-logged Chrome sessions. Use when testing requires authenticated browser context — DOM XSS, postMessage vulnerabilities, client-side prototype pollution, cookie analysis, SPA interaction, two-account authorization testing, or any test requiring a real browser environment.
---

# Browser Session Management — Playwright MCP + CDP

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  opencode (Single Session — Lead + Worker Subagent)          │
│                                                               │
│  ├── Playwright MCP (PRIMARY)                                │
│  │   ├── browser_navigate     — Go to URL                    │
│  │   ├── browser_click        — Click elements              │
│  │   ├── browser_type         — Fill forms, type text       │
│  │   ├── browser_snapshot     — Accessibility snapshot      │
│  │   ├── browser_evaluate     — Run JavaScript              │
│  │   ├── browser_cookie_*     — Get/set/clear cookies       │
│  │   ├── browser_localstorage_* — Get/set localStorage      │
│  │   ├── browser_network_requests — Capture network traffic  │
│  │   ├── browser_take_screenshot — PoC screenshots          │
│  │   ├── browser_fill_form    — Fill multiple form fields   │
│  │   ├── browser_select_option — Dropdown selection         │
│  │   └── browser_file_upload  — File upload testing         │
│  │                                                            │
│  ├── CDP (FALLBACK — for manual login sessions)              │
│  │   └── tools/cdp_browser.py — Cookie extraction from      │
│  │       manually-logged Chrome on ports 9222/9223           │
│  │                                                            │
│  └── Auth Sessions                                            │
│      ├── Session A (Attacker) — Playwright persistent profile │
│      └── Session B (Victim)   — Playwright isolated profile   │
│          or CDP Chrome instance                               │
└─────────────────────────────────────────────────────────────┘
```

## When to Use What

| Need | Use |
|------|-----|
| Navigate SPA pages, click buttons, fill forms | **Playwright MCP** |
| Capture DOM after JS rendering | **Playwright MCP** (browser_snapshot) |
| Test DOM XSS, client-side prototype pollution | **Playwright MCP** (browser_evaluate) |
| Take PoC screenshots for reports | **Playwright MCP** (browser_take_screenshot) |
| Extract cookies from manually-logged Chrome | **CDP** (tools/cdp_browser.py) |
| Two-account IDOR testing | **Playwright** (two contexts) or **CDP** (two Chrome instances) |
| Capture all network requests during navigation | **Playwright MCP** (browser_network_requests) |
| Test WebSocket connections | **Playwright MCP** (browser_evaluate + WebSocket API) |

---

## Playwright MCP — Primary Browser Tool

### Setup

Playwright MCP is configured in `opencode.json`:
```json
{
  "mcp": {
    "playwright": {
      "type": "local",
      "command": ["npx", "@playwright/mcp@latest", "--caps", "core,pdf,vision,devtools,storage,network"],
      "enabled": true
    }
  }
}
```

### Core Workflows

#### Navigate and Snapshot

```
# Navigate to target
browser_navigate → url: "https://target.com/login"

# Take accessibility snapshot (better than screenshot for analysis)
browser_snapshot → captures the page structure, all interactive elements
```

#### Login Flow

```
# 1. Navigate to login page
browser_navigate → url: "https://target.com/login"

# 2. Take snapshot to see form fields
browser_snapshot

# 3. Fill login form
browser_fill_form → fields: [
  { name: "email", type: "textbox", ref: "<ref-from-snapshot>" },
  { name: "password", type: "textbox", ref: "<ref-from-snapshot>" }
]

# 4. Click submit
browser_click → target: "<submit-button-ref>"

# 5. Wait for navigation
browser_wait_for → text: "Dashboard"
```

#### Extract Auth Material

```
# Get all cookies
browser_cookie_list

# Get specific cookie
browser_cookie_get → name: "session_id"

# Get localStorage
browser_localstorage_list

# Get sessionStorage
browser_sessionstorage_list
```

#### SPA Interaction (Find Hidden Endpoints)

```
# 1. Navigate to main app
browser_navigate → url: "https://target.com/app"

# 2. Snapshot to find navigation elements
browser_snapshot

# 3. Click each menu item, settings, admin links
browser_click → target: "<settings-menu-ref>"
browser_snapshot  # Capture the new page state

# 4. Capture all network requests made during navigation
browser_network_requests → filter: "/api/.*"

# 5. These API calls are endpoints the spider missed
#    (they only fire on UI interaction, not page load)
```

#### DOM XSS Testing

```
# 1. Navigate to page with reflected input
browser_navigate → url: "https://target.com/search?q=test"

# 2. Evaluate JavaScript to check for DOM XSS sinks
browser_evaluate → function: "() => {
  const sinks = [];
  // Check for innerHTML assignments
  const scripts = document.querySelectorAll('script');
  scripts.forEach(s => {
    if (s.textContent.includes('innerHTML') ||
        s.textContent.includes('document.write') ||
        s.textContent.includes('eval(')) {
      sinks.push(s.textContent.substring(0, 200));
    }
  });
  // Check URL fragment handling
  if (window.location.hash) {
    sinks.push('hash: ' + window.location.hash);
  }
  // Check postMessage listeners
  sinks.push('postMessage listeners: ' +
    (typeof getEventListeners !== 'undefined' ? 'check manually' : 'unknown'));
  return JSON.stringify(sinks);
}"

# 3. Test XSS payload
browser_navigate → url: "https://target.com/search?q=<img/src=x onerror=alert(1)>"
browser_snapshot  # Check if payload rendered unencoded
```

#### Two-Account Testing (Playwright Isolated Mode)

```
# Method 1: Two browser contexts (tabs)
browser_tabs → action: "new", url: "https://target.com/login"
# Login as attacker in tab 1

browser_tabs → action: "new", url: "https://target.com/login"
# Login as victim in tab 2

# Switch between tabs to test IDOR:
browser_tabs → action: "select", index: 0  # Attacker tab
browser_cookie_list  # Get attacker cookies

browser_tabs → action: "select", index: 1  # Victim tab
browser_cookie_list  # Get victim cookies

# Method 2: Use CDP Chrome instances for persistent sessions
# (see CDP section below)
```

#### PoC Screenshot for Reports

```
# 1. Navigate to vulnerable page
browser_navigate → url: "https://target.com/vulnerable-page"

# 2. Trigger the vulnerability
browser_type → target: "<input-ref>", text: "<payload>"
browser_click → target: "<submit-ref>"

# 3. Wait for result
browser_wait_for → text: "alert"

# 4. Screenshot
browser_take_screenshot → filename: "poc-xss-confirmed.png", fullPage: true
```

#### Network Request Capture

```
# Navigate and interact, then capture all network requests:
browser_navigate → url: "https://target.com/app/dashboard"
browser_click → target: "<some-button>"

# Get all network requests
browser_network_requests → filter: "/api/.*"

# Get details of specific request
browser_network_request → index: 5
# Returns: full headers, body, response — perfect for evidence
```

---

## CDP — Fallback for Manual Login Sessions

Use CDP when you need cookies from a Chrome session where you manually logged in.

### Setup

Chrome sessions are launched by `setup.sh` on ports 9222 (attacker) and 9223 (victim).

### Cookie Extraction

```bash
# Extract cookies for curl-based testing
python3 ./tools/cdp_browser.py extract-cookies \
    --port 9222 \
    --output engagement/spider/cookies_a.txt \
    --format header

# Session B (victim)
python3 ./tools/cdp_browser.py extract-cookies \
    --port 9223 \
    --output engagement/spider/cookies_b.txt \
    --format header
```

### Auth Recon (SPA Navigation)

```bash
python3 ./tools/cdp_browser.py auth-recon \
    --port 9222 \
    --base-url "https://target.com" \
    --max-pages 20 \
    --output-dir engagement/spider/cdp_recon
```

---

## Troubleshooting

### Playwright MCP Not Connecting

```bash
# Verify Node.js is installed
node --version

# Install Playwright browsers
npx playwright install chromium

# Test MCP server directly
npx @playwright/mcp@latest
# Should start and wait for connections on stdio
```

### CDP Chrome Won't Start

```bash
# Install Chrome
sudo apt update && sudo apt install -y google-chrome-stable

# Check port availability
lsof -i :9222
kill $(lsof -t -i :9222)

# Headless mode (no display)
google-chrome --headless --remote-debugging-port=9222 \
    --user-data-dir=/tmp/chrome-session-a --disable-gpu "https://target.com" &
```

### Session Expired

```bash
# Playwright: re-login via browser_navigate + browser_fill_form
# CDP: manually re-login in the Chrome window
# Verify: navigate to authenticated page, check if redirected to login
```

---

## Things to Do

- Use Playwright MCP as the primary browser tool for all phases
- Use `browser_snapshot` instead of screenshots for analysis (token-efficient)
- Use `browser_network_requests` after every navigation to discover hidden API endpoints
- Use `browser_evaluate` for DOM XSS sink analysis
- Use `browser_cookie_list` to extract cookies for curl-based testing
- Route Playwright traffic through Burp proxy for passive scanning: add `--proxy-server http://127.0.0.1:8080` to Playwright MCP config args
- Keep CDP as fallback for manually-logged Chrome sessions

## Things Not to Do

- Do NOT use the same Playwright profile for both attacker and victim sessions
- Do NOT close the browser during testing — the session context is lost
- Do NOT use the browser for personal browsing — keep sessions clean
- Do NOT hardcode cookies — extract fresh from Playwright or CDP
