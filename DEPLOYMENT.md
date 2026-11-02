# Clearance deployment

The public origin is whatever you set in `BASE_URL`. Local default is `http://localhost:8000`. A hosted example is `https://clearance.nauti-labs.com`; override it per environment.

- App: `$BASE_URL`
- Railway project: `clearance` (rename if you use another project)
- Railway service: `clearance`
- Stripe webhook: `$BASE_URL/v1/payments/stripe/webhook`
- Health check: `$BASE_URL/health` (Railway `healthcheckPath` is `/health`)

The process must listen on `0.0.0.0` and `PORT`. `python app.py` does that. `HOST` defaults to `0.0.0.0`.

## Required variables

Startup exits if either secret is missing:

- `JWT_SECRET_KEY`
- `BOT_COMM_PASSWORD`

Set them from stdin so they do not land in shell history:

```bash
openssl rand -hex 32 | railway variable set JWT_SECRET_KEY --stdin --skip-deploys
openssl rand -base64 24 | railway variable set BOT_COMM_PASSWORD --stdin --skip-deploys
```

Public origin and Stripe return URLs. Replace the example host with your own:

```bash
railway variable set \
  BASE_URL="https://clearance.nauti-labs.com" \
  TOKEN_ISSUER="https://clearance.nauti-labs.com" \
  PUBLIC_BASE_URL="https://clearance.nauti-labs.com" \
  BRAND_URL="https://www.nauti-labs.com" \
  ADMIN_EMAIL="consulting@nauti-labs.com" \
  PAYMENT_SUPPORT_EMAIL="consulting@nauti-labs.com" \
  STRIPE_SUCCESS_URL="https://clearance.nauti-labs.com/?checkout=success" \
  STRIPE_CANCEL_URL="https://clearance.nauti-labs.com/?checkout=cancelled" \
  --skip-deploys
```

When `STRIPE_SUCCESS_URL` and `STRIPE_CANCEL_URL` are unset, the app derives them from `BASE_URL`.

Payment identity, also from stdin:

```bash
printf '%s' 'sk_live_...' | railway variable set STRIPE_SECRET_KEY --stdin --skip-deploys
printf '%s' 'whsec_...' | railway variable set STRIPE_WEBHOOK_SECRET --stdin --skip-deploys
printf '%s' '0xaC73A1dC4FEc75b61478Fb34186C6a379EA01CC2' | railway variable set PAYMENT_WALLET --stdin --skip-deploys
# PAYMENT_ENS is optional. Set it only if you publish an ENS name.
printf '%s' '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' | railway variable set USDC_CONTRACT --stdin --skip-deploys
```

Optional chain settings:

```bash
railway variable set \
  PAYMENT_CHAIN="base" \
  PAYMENT_CHAIN_ID="8453" \
  BASE_RPC_URL="https://mainnet.base.org" \
  MIN_CONFIRMATIONS="12" \
  SCRAM_BASE_URL="https://clearance.nauti-labs.com/scram" \
  --skip-deploys
```

Production also requires `PAYMENT_WALLET` and `USDC_CONTRACT` when `BASE_URL` is not a localhost URL. `PAYMENT_ENS` is optional.

`PUBLIC_BASE_URL` is the origin used in 402 resource URLs and in `/.well-known/x402.json`, `/.well-known/x402-services.json`, `/x402/discovery`, and `/bot-comm/.well-known/x402.json`. It falls back to `BASE_URL`. In production those resource URLs are https. Set it to the same public origin you put in `BASE_URL`, for example `https://clearance.nauti-labs.com`.

Example USDC-on-Base receiving wallet: `0xaC73A1dC4FEc75b61478Fb34186C6a379EA01CC2`. Native USDC contract on Base: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.

## x402 payments

Paid Agent Income and Bot-Comm calls accept either of these:

- A standard x402 v2 `exact` payment in the `PAYMENT-SIGNATURE` header. The legacy `X-PAYMENT` header is also accepted. Clearance verifies and settles it through `X402_FACILITATOR_URL` (default `https://api.cdp.coinbase.com/platform/v2/x402`) using `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET`. The facilitator request includes `paymentPayload.resource` and `extensions.bazaar`. If those CDP variables are unset, this path returns HTTP 402 with an explanation.
- A direct Base USDC transfer. The caller first receives a `quote_id`. The retry sends `X-Payment-Tx` or `payment_tx` with that `quote_id`. The transfer must be newer than the quote, paid to the configured wallet, and at least the quoted amount. A transaction hash that was already used returns HTTP 409.

`GET /bot-comm/api/services/{id}?x402=1` with `Accept: application/json` returns 402 and a `PAYMENT-REQUIRED` header so a registry can probe the service without a body.

`GET /v1/revenue/payments` lists paid calls (time, service id, amount, tx hash, payer) and 24h, 7d, and all-time totals by service. Send `BOT_COMM_PASSWORD` or `ADMIN_TOKEN` as `Authorization: Bearer` or `X-Admin-Token`.

`TEST_PRICE_USD` (for example `0.05`) turns on one hidden endpoint, `POST /agent-income/test-ping`, priced at that amount. It is omitted from discovery. Leave the variable unset and the route is 404.

`AGENT_INCOME_OPERATOR_ENABLED`, `AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED`, and `AGENT_INCOME_AUTO_DEAL_LEADS` default to false. Set them to `true` only when outreach should run.

## Render

`render.yaml` defines one free Python web service. It does not create a paid database or disk. SQLite on the free plan is lost on restart. A persistent disk requires a paid plan; mount it at `/var/data` and set `DB_PATH=/var/data/clearance.db`. The free blueprint uses `DB_PATH=clearance.db`.

Fill `JWT_SECRET_KEY`, `BOT_COMM_PASSWORD`, and `PAYMENT_WALLET` in the Dashboard when the Blueprint asks (`sync: false`). Also set `BASE_URL` and `PUBLIC_BASE_URL` to the service's https origin, and set `CDP_API_KEY_ID` plus `CDP_API_KEY_SECRET` if standard x402 settlement should be live. The process listens on `0.0.0.0` and `PORT`. The health check path is `/health`.

## Domain

```bash
railway domain clearance.nauti-labs.com --json
```

Add the DNS record Railway returns. Use your own hostname if this one is not yours, and set `BASE_URL` to match.

## Deploy

```bash
PUBLIC_BASE_URL="https://clearance.nauti-labs.com" ./scripts/deploy-production.sh
```

Do not run `railway up --detach` directly for production. The deploy script fetches GitHub first and refuses to deploy if this checkout is behind `origin/main`, diverged from it, or has uncommitted changes.

Emergency override flags exist, but use them only when everyone working on the site knows a hotfix is going out:

```bash
ALLOW_AHEAD_DEPLOY=1 ./scripts/deploy-production.sh
ALLOW_DIRTY_DEPLOY=1 ./scripts/deploy-production.sh
```

## Stripe

1. Create a webhook endpoint for `$BASE_URL/v1/payments/stripe/webhook`.
2. Subscribe to `checkout.session.completed` and `checkout.session.async_payment_succeeded`.
3. Copy the webhook signing secret into `STRIPE_WEBHOOK_SECRET`.

## Smoke test

```bash
curl "$BASE_URL/health"
curl "$BASE_URL/v1/payments/info"
```

Then open `$BASE_URL`, claim a free key, and start a test Stripe checkout if Stripe is configured.

## Docker

`Dockerfile` installs `requirements.txt` and runs `python app.py`. Pass the same environment variables into the container. Do not bake secrets into the image.
