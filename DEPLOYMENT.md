# Clearance Deployment

Production target:

- App: `https://clearance.nauti-labs.com`
- Railway project: `clearance`
- Railway service: `clearance`
- Stripe webhook: `https://clearance.nauti-labs.com/v1/payments/stripe/webhook`

## Required Railway Variables

Set these before deploying production:

```bash
railway variable set \
  BASE_URL="https://clearance.nauti-labs.com" \
  TOKEN_ISSUER="https://clearance.nauti-labs.com" \
  BRAND_URL="https://www.nauti-labs.com" \
  ADMIN_EMAIL="consulting@nauti-labs.com" \
  PAYMENT_SUPPORT_EMAIL="consulting@nauti-labs.com" \
  STRIPE_SUCCESS_URL="https://clearance.nauti-labs.com/?checkout=success" \
  STRIPE_CANCEL_URL="https://clearance.nauti-labs.com/?checkout=cancelled" \
  --skip-deploys
```

Set secrets with stdin so they do not land in shell history:

```bash
openssl rand -hex 32 | railway variable set JWT_SECRET_KEY --stdin --skip-deploys
printf '%s' 'sk_live_...' | railway variable set STRIPE_SECRET_KEY --stdin --skip-deploys
printf '%s' 'whsec_...' | railway variable set STRIPE_WEBHOOK_SECRET --stdin --skip-deploys
printf '%s' '0x...' | railway variable set PAYMENT_WALLET --stdin --skip-deploys
printf '%s' 'yourname.base.eth' | railway variable set PAYMENT_ENS --stdin --skip-deploys
printf '%s' '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' | railway variable set USDC_CONTRACT --stdin --skip-deploys
```

Optional:

```bash
railway variable set \
  PAYMENT_CHAIN="base" \
  PAYMENT_CHAIN_ID="8453" \
  BASE_RPC_URL="https://mainnet.base.org" \
  MIN_CONFIRMATIONS="12" \
  --skip-deploys
```

## Domain

```bash
railway domain clearance.nauti-labs.com --json
```

Add the DNS record Railway returns at the DNS host for `nauti-labs.com`.

## Deploy

```bash
python3 -m pytest -q
railway up --detach
```

## Stripe Setup

In Stripe Workbench or Developers:

1. Create a webhook endpoint for `https://clearance.nauti-labs.com/v1/payments/stripe/webhook`.
2. Subscribe to `checkout.session.completed` and `checkout.session.async_payment_succeeded`.
3. Copy the webhook signing secret into `STRIPE_WEBHOOK_SECRET`.

## Smoke Test

```bash
curl https://clearance.nauti-labs.com/health
curl https://clearance.nauti-labs.com/v1/payments/info
```

Then open `https://clearance.nauti-labs.com`, claim a free key, and start a test Stripe checkout.
