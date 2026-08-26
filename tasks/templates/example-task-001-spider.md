# EXAMPLE: Task 001 — Phase 1 Spidering

> This is an EXAMPLE of how Lead writes a Phase 1 task. Copy and customize.

## Status: PENDING
## Phase: 1 (Spidering)
## Worker Role: Tool Runner

## Objective
Run the spider tool to discover the attack surface. Both unauthenticated and authenticated.

## Prerequisites
- Both Chrome sessions launched (ports 9222, 9223)
- Manually logged in to both sessions
- target_prompt.md filled in with scope and required headers

## Commands to Run

### 1. Extract cookies from CDP browsers
```bash
python3 ./tools/cdp_browser.py extract-cookies --port 9222 \
    --output engagement/spider/cookies_a.txt --format header

python3 ./tools/cdp_browser.py extract-cookies --port 9223 \
    --output engagement/spider/cookies_b.txt --format header
```

### 2. Unauthenticated spider
```bash
./tools/spider/spider.sh "https://target.com" \
    --header "X-HackerOne-Handle: <your-handle>" \
    --output-dir engagement/spider/unauth
```

### 3. Authenticated spider
```bash
COOKIE=$(cat engagement/spider/cookies_a.txt)
./tools/spider/spider.sh "https://target.com" \
    --auth-cookie "$COOKIE" \
    --header "X-HackerOne-Handle: <your-handle>" \
    --output-dir engagement/spider/auth
```

### 4. CDP authenticated recon (SPA coverage)
```bash
python3 ./tools/cdp_browser.py auth-recon --port 9222 \
    --base-url "https://target.com" \
    --max-pages 30 \
    --output-dir engagement/spider/cdp_recon
```

## What to Report
Write a brief result to results/result-001-spider.md confirming completion.
Do NOT analyze sitemap content — Lead will do that.
