---
name: testing-file-upload
description: File upload vulnerability testing. Use when the application accepts file uploads — profile pictures, documents, attachments, imports, or any file submission feature. Covers extension bypass, content-type manipulation, path traversal in filenames, SVG/XML injection, and server-side processing exploits.
---

# File Upload Testing

File upload vulnerabilities arise from insufficient validation of uploaded files, enabling attackers to upload executable code, overwrite critical files, or inject malicious content. Impact ranges from stored XSS (SVG) to RCE (web shell).

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (upload behavior) (bypass validation) (declare secure)   (demonstrate impact)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Upload a Legitimate File
Upload a valid file of the expected type. Record: accepted file types, max size, response (URL where file is stored, filename transformation, storage location).

### Step 1.2: Determine Storage Location
Where is the file stored? Can you access it directly via URL? Is it served with the original Content-Type? Is it on the same domain or a separate storage domain (CDN, S3)?

### Step 1.3: Validation Probing
Upload files with wrong extensions, wrong content types, oversized files. Note which validations are enforced: extension check, Content-Type check, magic bytes check, file content analysis.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[UPLOAD-ENDPOINT] {URL}
[ACCEPTED-TYPES] {extensions / content types}
[STORAGE] {same domain / separate domain / not directly accessible}
[VALIDATIONS] {extension / content-type / magic bytes / content analysis}
[DECISION] {Proceed / No upload — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For File Upload |
|-------|----------------|
| HIGH | Executable or malicious file uploaded and accessible/processed by server |
| MEDIUM | File uploaded with bypassed validation but execution/processing not confirmed |
| LOW | All validation bypasses fail |

### Step 2.1: Extension Bypass
If extension validation exists, try:
- Case variation: `.pHp`, `.PhP`, `.JSP`
- Double extension: `file.php.jpg`, `file.jpg.php`
- Null byte: `file.php%00.jpg` (older systems)
- Alternative extensions: `.php5`, `.phtml`, `.shtml`, `.jsp`, `.jspx`
- Trailing characters: `file.php.`, `file.php;.jpg`, `file.php%20`

### Step 2.2: Content-Type Bypass
If Content-Type is validated:
- Change Content-Type header to accepted value while keeping malicious file content
- Some servers trust Content-Type over actual content

### Step 2.3: Magic Bytes Bypass
If the server checks file magic bytes:
- Prepend valid file header (GIF89a, PNG header, JFIF header) before malicious content
- Polyglot files: files that are valid as both image and PHP/HTML

### Step 2.4: SVG/XML Upload
Upload SVG files containing:
- XSS: `<svg onload="alert(1)">`
- XXE: SVG with external entity declarations (see [[xxe]])

### Step 2.5: Path Traversal in Filename
Manipulate the filename to write outside the upload directory:
- `../../../etc/cron.d/evil`
- `..%2f..%2f..%2fetc%2fcron.d%2fevil`
- Backslash variants on Windows: `..\..\..\`

### Step 2.6: Zip/Archive Exploits
If the server extracts archives:
- Zip slip: archive with entries containing `../../` paths
- Zip bomb: exponential decompression (document as DoS vector, do NOT upload)

**Max confirmation attempts: 12.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {extension bypass / content-type / magic bytes / SVG / path traversal}
[RESULT] {uploaded and accessible / uploaded but not accessible / rejected}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different technique / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- Extension whitelist strictly enforced (not blacklist)
- Content-Type and magic bytes validated
- Uploaded files served with forced Content-Type (Content-Disposition: attachment, or image/*)
- Uploaded files stored on separate domain (CDN/S3) without execution capability
- Path traversal in filenames prevented

### Structured Log
```
[VULN-NEGATIVE]
[ENDPOINT] {upload URL}
[STEPS-RUN] {bypass techniques attempted}
[SIGNAL] {all malicious uploads rejected or rendered harmless}
[CONCLUSION] {upload validation is comprehensive}
[ACTION] Endpoint cleared for file upload vulnerabilities.
```

---

## Phase 3: Exploitation

### Level 1: Stored XSS via SVG
If SVG upload + same-domain access works, demonstrate XSS execution when the SVG is viewed.

### Level 2: Web Shell Upload
If executable file upload confirmed, upload a minimal web shell and execute a single harmless command (`id`/`whoami`).

**Stop condition:** At first confirmed execution → STOP. Delete the uploaded file if possible.

---

## Session Re-verification
Re-verify by uploading a normal file between phases.

## Things to Do
- Determine where uploaded files are stored and how they're served BEFORE attempting bypasses
- Test SVG uploads even when only images are expected — SVG is technically an image format
- Check if uploaded files are served with forced Content-Disposition: attachment (mitigates XSS)

## Things Not to Do
- Do not upload zip bombs or excessively large files
- Do not leave web shells on production servers — clean up after PoC
- Do not assume S3/CDN storage means no impact — misconfigured buckets may execute code

## Cross-Skill Links
- [[xxe]] — SVG and DOCX uploads can contain XXE payloads
- [[xss]] — SVG upload = stored XSS if served on same domain
- [[path-traversal]] — Path traversal in filenames overlaps with LFI
