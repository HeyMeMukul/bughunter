# WebRTC IP Leak — Summary Card

**Phase:** 3 | **Type:** Client-Side / Privacy | **Impact:** Low/Medium

## Quick Summary
WebRTC ICE candidate gathering can expose the user's private and public IP. Default browsers hide private IPs behind mDNS (`*.local`) — so the *reportable* bug is the app that actively stores/exposes participants' candidates server-side, or environments where mDNS is off + a chained SSRF/XSS primitive exists.

## Key Indicators
- Video/voice/screen-share features, WebRTC-based widgets
- Signaling endpoints uploading `candidate`/`candidate-address` fields
- Room/participants metadata APIs returning network data
- Apps that configure non-default ICE (possible mDNS-off)

## Quick Test
```js
// Run in target page (Playwright browser_evaluate)
const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
pc.createDataChannel('x');
pc.onicecandidate = (e) => { if (e.candidate) console.log(e.candidate.candidate); };
pc.createOffer().then((o) => pc.setLocalDescription(o));
// "typ host 192.168.x.x" -> private IP exposed (mDNS off)
// "typ host *.local"      -> protected by default
```

## Bounty Potential
- App storing other users' private IPs = Medium ($500-$2,500)
- Alone, client-capability leak is usually informational/low
- Chains with SSRF/XSS for real value

## Token Cost
~3,700 tokens (Worker reads full SKILL.md)
