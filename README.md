# Clearance — by Nauti-Labs

Human Approval API for AI agent commerce, plus x402 pay-per-call APIs.

Agents ask for clearance. A person approves or denies. Any service can verify the signed token before it acts.

## What is sold

- **Approval API** — create a clearance, send the human an approval link, then verify the token at `/v1/verify/{token}`.
- **Agent Income** — paid review, audit, and blueprint endpoints for agent offers and payment flows. Discovery documents advertise the prices and return HTTP 402 until a Base USDC payment is verified.
- **Bot-Comm market** — machine-readable services other agents can quote and call. Admin login uses `BOT_COMM_PASSWORD`.
- **Scam-check / SCRAM** — inbound message scoring for SMS-style webhooks, plus a short public demo at `/scram`.
- **x402 discovery** — service manifests and payment challenges so buyer agents can find the paid endpoints.

## Run locally

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export BOT_COMM_PASSWORD="$(openssl rand -hex 24)"
python app.py
```

The process binds `HOST` (default `0.0.0.0`) and `PORT` (default `8000`). Open `http://localhost:8000` and `http://localhost:8000/health`.

Startup refuses to serve if `JWT_SECRET_KEY` or `BOT_COMM_PASSWORD` is missing. There is no built-in password or signing-key fallback.

```bash
python -m unittest test_clearance.py
```

## Environment

Names only. Put values in `.env` or the host's secret store. See [.env.example](.env.example).

Required:

- `JWT_SECRET_KEY`
- `BOT_COMM_PASSWORD`

Public origin and listeners:

- `BASE_URL` — approval links, token issuer fallback, and marketplace endpoint URLs. Default `http://localhost:8000`.
- `TOKEN_ISSUER` — defaults to `BASE_URL`.
- `PUBLIC_BASE_URL` — live-site check in the deploy script. Defaults to `BASE_URL`.
- `BRAND_URL` — default `https://nauti-labs.com`.
- `HOST` — default `0.0.0.0`.
- `PORT` — default `8000`.
- `LOCAL_DEV_ORIGINS` — extra browser origins for CORS. Brand and `www` are added from `BRAND_URL`.
- `BOT_COMM_CORS_ORIGINS` — full CORS list when you do not want the derived default.
- `SCRAM_BASE_URL` — scam-check public origin. Defaults to `BASE_URL` + `/scram`.
- `IP_LOOKUP_BASE_URL` — traffic label lookup. Default `http://ip-api.com`.

Payments and mail (set on the host; leave blank locally):

- `PAYMENT_WALLET`, `PAYMENT_ENS`, `USDC_CONTRACT`, `BASE_RPC_URL`, `MIN_CONFIRMATIONS`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL`
- `ADMIN_EMAIL`, `PAYMENT_SUPPORT_EMAIL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`

Optional:

- `TRAFFIC_BOARD_PASSWORD`, `TRAFFIC_KNOWN_USERS`, `AGENT_OUTREACH_TARGETS`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_WEBHOOK_SECRET`
- `NAUTI_TRAFFIC_ADMIN_PIN`, `NAUTI_TRAFFIC_ADMIN_PATH_TOKEN`

`static/trusted_by.json` ships with fictional sample profiles. Replace it with your own public refs. Real account avatars are not included.

An optional private ledger UI is off unless `LEDGER_TOOLS_ENABLED=true`. It is not part of the public commercial surface. When you enable it, set `LEDGER_USERS_JSON` and `LEDGER_SYNC_TOKEN`.

Scam-check credits, helper replies, message scoring, and outbound SMS are safe stubs. Each module has a TODO where the original logic was not in this checkout. They do not call a model provider and they do not send SMS.

## Deploy

Docker and Railway configs are in the repo. Set the variables above on the host before the first boot. `scripts/deploy-production.sh` refuses to upload a dirty or stale checkout and checks `PUBLIC_BASE_URL` (or `BASE_URL`) after Railway reports success.

See [DEPLOYMENT.md](DEPLOYMENT.md).

Do not commit `.env`, database files, or filled-in secrets.

## License

Source-available under MIT + Commons Clause. You can read, learn from, and fork this code. You may not sell a competing hosted service built on it without a commercial license.

Commercial licensing: consulting@nauti-labs.com

---

Built by **Nauti-Labs LLC**.

[nauti-labs.com](https://www.nauti-labs.com) · [github.com/Nauti-Labs](https://github.com/Nauti-Labs)
