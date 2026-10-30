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
printf '%s' '0x...' | railway variable set PAYMENT_WALLET --stdin --skip-deploys
printf '%s' 'yourname.base.eth' | railway variable set PAYMENT_ENS --stdin --skip-deploys
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

Production also requires `PAYMENT_WALLET`, `PAYMENT_ENS`, and `USDC_CONTRACT` when `BASE_URL` is not a localhost URL.

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
