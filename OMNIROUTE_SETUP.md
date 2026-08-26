# OmniRoute Setup for This Framework

This framework now treats OmniRoute as a local OpenAI-compatible gateway. The Lead and Worker roles retain separate semantic responsibilities, but their model requests are routed through the local gateway rather than directly to a single provider.

## Setup

Install and start OmniRoute, connect the four operator-approved connections in the dashboard, and verify that the gateway is listening on `http://127.0.0.1:20128`. Then copy the credential template, set the gateway variables, and source the file before starting OpenCode:

```bash
cp engagement/.creds.sh.template engagement/.creds.sh
chmod 600 engagement/.creds.sh
# Edit only the local, ignored file and set OMNIROUTE_API_KEY if required.
source engagement/.creds.sh
python3 tools/omniroute_doctor.py --channel auto/coding:free --channel auto/reasoning:free
opencode
```

The doctor performs read-only checks against `/v1/models` and `/api/monitoring/health`. It does not send inference requests, create combos, alter settings, or test targets.

## Model roles

The active `opencode.json` maps the Lead to `omniroute/auto/reasoning:free` and the Worker to `omniroute/auto/coding:free`. The free-only provider entry uses `@ai-sdk/openai-compatible`, `OMNIROUTE_BASE_URL`, and `OMNIROUTE_API_KEY`. Its headers request offline-friendly scoring, coding-safe compression, a near-zero budget, and strict budget fallback, so it must not silently choose a paid candidate. The `auto/*` route is dynamic, so it uses currently active connections; inspect the live candidate pool before relying on it.

The `omniroute-cheap/auto/coding:cheap` model is intentionally isolated as an opt-in fallback, not as the default. Use it only for sanitized context after confirming that the free-only pool cannot serve the task and after accepting the cost policy. For sensitive evidence, use an operator-approved trusted combo rather than a free or web-session provider.

## Strict zero-cost decision

OmniRoute’s strict free-access policy is a separate operator setting. Enable it for the four selected connections only after checking the live catalog, usage adapters, hard-stop guarantees, and provider terms. The default request budget is an additional fail-closed control, not a substitute for strict free-access classification. A model being labeled “free” does not by itself prove that an exhausted account cannot bill or that its terms permit automated use. If strict mode yields no candidates, stop or use the explicitly approved low-cost route; do not silently spend.

## Data-handling rule

Do not send cookies, passwords, API keys, private report attachments, raw HTTP evidence, or unredacted personal data to external model providers. Redact evidence before routing it to free-only or web-session connections. Keep raw evidence in the local engagement directory and log only a hash or redacted excerpt in model-visible context.

## Four-connection operating pattern

Use OmniRoute’s candidate and health views to confirm that all four connections are active, eligible, and authorized. Let the gateway provide quota-aware selection and connection-level cooldowns. Maintain session affinity for multi-turn Lead/Worker conversations where the provider supports it, but do not pin a session to a connection that is not approved for the data class. Record the selected route/provider/model when the gateway exposes it in response headers or structured logs.

## Troubleshooting

If every model is missing, check the environment variables and `/v1/models`. If requests reach `/v1/v1`, remove the duplicate suffix and keep `OMNIROUTE_BASE_URL` at either the host root or exactly one `/v1`, as supported by the installed OmniRoute/OpenCode versions. If the doctor reports connection refused, start OmniRoute locally; this framework does not start it automatically.
