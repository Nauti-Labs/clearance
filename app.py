"""
Clearance by Nauti-Labs
Human Approval API for AI Agent Commerce

The missing auth layer between human intent and agent execution.
"""

import os
import re
import json
import logging
import secrets
import hashlib
import html
import asyncio
import smtplib
import base64
import calendar
import ipaddress
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Depends, Response, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

try:
    import stripe
except ImportError:  # pragma: no cover - dependency is optional in minimal local runs
    stripe = None

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except ImportError:  # pragma: no cover - optional until wallet verification deps are installed
    Account = None
    encode_defunct = None

try:
    from jose import jwt, JWTError
except ImportError:  # pragma: no cover - exercised in local fallback runtime
    from jwt_compat import jwt, JWTError

from database import init_db, get_db
from crypto_verify import verify_usdc_payment
from credit_service import (
    add_paid_credits_by_hash,
    get_initial_free_checks,
    get_initial_free_help_messages,
    get_sms_credit_summary,
    hash_phone,
    record_help_message,
    record_sms_check,
    reserve_help_credit,
    reserve_sms_credit,
    set_help_mode,
    set_sms_opt_out,
)
from llm_help_service import generate_scram_help, hash_help_text
from models import (
    CreateClearance, ApproveAction, CreateAPIKey, RegisterWebhook,
    ClearanceResponse, VerifyResponse, APIKeyResponse, UsageResponse,
    ErrorResponse, ClearanceStatus, Tier,
    FamilyLogin, FamilySyncPayload, FamilyPayeeCreate,
    FamilyActionCreate, FamilyActionDecision,
    AgentIncomeRunCreate, AgentIncomeCampaignCreate, AgentIncomeWalletNonceRequest,
    AgentIncomeBotMarketCreate, AgentIncomeBotServiceRequest,
    AgentIncomeTaskExecution, AgentIncomeWalletConnect, AgentIncomePaymentCreate,
    AgentIncomePublicPaymentClaim,
    AgentIncomeSpendAuthorizationCreate, AgentIncomeSpendUsageCreate,
    AgentIncomeWithdrawalCreate, AgentIncomeWithdrawalExecution,
)
from scam_analyzer import analyze_scam_text, message_fingerprint
from sms_service import (
    build_twiml_message,
    format_help_intro,
    format_help_reply,
    format_out_of_help_reply,
    format_out_of_credits_reply,
    format_sms_reply,
    send_sms,
    twilio_signature_validation_enabled,
    validate_twilio_webhook_signature,
)

load_dotenv()

DEFAULT_JWT_SECRET = "dev-secret-change-in-production"
JWT_SECRET = os.getenv("JWT_SECRET_KEY", DEFAULT_JWT_SECRET)
JWT_ALGORITHM = "HS256"
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
SCRAM_BASE_URL = os.getenv("SCRAM_BASE_URL", os.getenv("PUBLIC_SCRAM_URL", f"{BASE_URL.rstrip('/')}/scram")).rstrip("/")
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", BASE_URL)
BRAND_URL = os.getenv("BRAND_URL", "https://nauti-labs.com")
PAYMENT_WALLET = os.getenv("PAYMENT_WALLET", "")
PAYMENT_ENS = os.getenv("PAYMENT_ENS", "")
PAYMENT_CHAIN = os.getenv("PAYMENT_CHAIN", "base")
PAYMENT_CHAIN_ID = int(os.getenv("PAYMENT_CHAIN_ID", "8453"))
PAYMENT_SUPPORT_EMAIL = os.getenv("PAYMENT_SUPPORT_EMAIL", "consulting@nauti-labs.com")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", PAYMENT_SUPPORT_EMAIL)
SIGNUP_NOTIFY_EMAIL = os.getenv("SIGNUP_NOTIFY_EMAIL", ADMIN_EMAIL)
AMBASSADOR_REQUEST_NOTIFY_EMAIL = os.getenv("AMBASSADOR_REQUEST_NOTIFY_EMAIL", "consulting@nauti-labs.com").strip()
BOT_BUILD_REQUEST_SUBJECT = "Build my trading bot with Clearance"
BOT_BUILD_REQUEST_BODY = (
    "Hey Nauti-Labs,\n\n"
    "I want help building a trading bot with Clearance approval gates.\n\n"
    "I understand the default bot build rate is $125/hr with a 10-hour minimum engagement, "
    "and that pricing can be discussed if the scope needs it.\n\n"
    "Market / platform:\n"
    "Budget / risk limits:\n"
    "Paper trading first? yes/no:\n"
    "Telegram approval needed? yes/no:\n\n"
    "My notes:\n"
)
BOT_BUILD_REQUEST_URL = os.getenv(
    "BOT_BUILD_REQUEST_URL",
    f"mailto:{PAYMENT_SUPPORT_EMAIL}?subject={quote(BOT_BUILD_REQUEST_SUBJECT)}&body={quote(BOT_BUILD_REQUEST_BODY)}",
)
EMAIL_FROM = os.getenv("EMAIL_FROM", os.getenv("SMTP_FROM", os.getenv("SMTP_USER", PAYMENT_SUPPORT_EMAIL)))
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT") or ("465" if os.getenv("SMTP_USE_SSL", "").lower() in {"1", "true", "yes"} else "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
WELCOME_EMAILS_ENABLED = os.getenv("WELCOME_EMAILS_ENABLED", "false").lower() in {"1", "true", "yes"}
USDC_CONTRACT = os.getenv("USDC_CONTRACT", "")
MIN_CONFIRMATIONS = int(os.getenv("MIN_CONFIRMATIONS", "12"))
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
if STRIPE_SECRET_KEY and not STRIPE_WEBHOOK_SECRET:
    logging.getLogger("clearance.stripe").warning(
        "STRIPE_WEBHOOK_SECRET is not set while STRIPE_SECRET_KEY is configured: "
        "/v1/payments/stripe/webhook will reject all deliveries with 503 until it is set."
    )
STRIPE_SUCCESS_URL = os.getenv(
    "STRIPE_SUCCESS_URL",
    f"{BASE_URL.rstrip('/')}/v1/payments/stripe/success?session_id={{CHECKOUT_SESSION_ID}}",
)
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", f"{BASE_URL.rstrip('/')}/?checkout=cancelled")
SMS_PROVIDER = os.getenv("SMS_PROVIDER", "local")
SMS_FROM_NUMBER = os.getenv("SMS_FROM_NUMBER", "")
SCRAM_TEXT_CODE = os.getenv("SCRAM_TEXT_CODE", "72726")
TWILIO_SHORT_CODE = os.getenv("TWILIO_SHORT_CODE", SCRAM_TEXT_CODE)
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM", "")
SCRAM_FREE_HELP_MESSAGES = get_initial_free_help_messages()
PUBLIC_PAYMENT_URL = os.getenv("PUBLIC_PAYMENT_URL", "")
SCAMCHECK_STRIPE_SUCCESS_URL = os.getenv(
    "SCAMCHECK_STRIPE_SUCCESS_URL",
    f"{SCRAM_BASE_URL}?checkout=success",
)
SCAMCHECK_STRIPE_CANCEL_URL = os.getenv(
    "SCAMCHECK_STRIPE_CANCEL_URL",
    f"{SCRAM_BASE_URL}?checkout=cancelled",
)
SCAMCHECK_CREDIT_PACKS = {
    "checks_100": {
        "label": "100 SCRAM checks",
        "credits": 100,
        "price_usd": 3,
        "env_price_id": "STRIPE_PRICE_ID_100_CHECKS",
    },
    "checks_500": {
        "label": "500 SCRAM checks",
        "credits": 500,
        "price_usd": 10,
        "env_price_id": "STRIPE_PRICE_ID_500_CHECKS",
    },
}
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
FAMILY_SESSION_COOKIE = os.getenv("FAMILY_SESSION_COOKIE", "clearance_family_session")
FAMILY_SESSION_HOURS = int(os.getenv("FAMILY_SESSION_HOURS", "18"))
FAMILY_SYNC_TOKEN = os.getenv("FAMILY_SYNC_TOKEN", "")
FAMILY_PRODUCT_NAME = os.getenv("FAMILY_PRODUCT_NAME", "Harbor Ledger")
FAMILY_HOUSEHOLD_NAME = os.getenv("FAMILY_HOUSEHOLD_NAME", "LeBlanc Family")
AGENT_INCOME_PASSWORD = os.getenv("AGENT_INCOME_PASSWORD", "")
AGENT_INCOME_SESSION_COOKIE = os.getenv("AGENT_INCOME_SESSION_COOKIE", "clearance_agent_income_session")
AGENT_INCOME_SESSION_HOURS = int(os.getenv("AGENT_INCOME_SESSION_HOURS", "12"))
AGENT_INCOME_LOGIN_MAX_ATTEMPTS = int(os.getenv("AGENT_INCOME_LOGIN_MAX_ATTEMPTS", "8"))
AGENT_INCOME_LOGIN_WINDOW_MINUTES = int(os.getenv("AGENT_INCOME_LOGIN_WINDOW_MINUTES", "15"))
AGENT_INCOME_TARGET_AMOUNT = float(os.getenv("AGENT_INCOME_TARGET_AMOUNT", "240"))
AGENT_INCOME_TARGET_WINDOW_HOURS = int(os.getenv("AGENT_INCOME_TARGET_WINDOW_HOURS", "24"))
AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD = float(os.getenv("AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD", "200"))
AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD = float(os.getenv("AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD", "50"))
AGENT_INCOME_MIN_EFFECTIVE_RATE_USD = float(os.getenv("AGENT_INCOME_MIN_EFFECTIVE_RATE_USD", "10"))
AGENT_INCOME_WITHDRAWAL_LIMIT_USD = float(os.getenv("AGENT_INCOME_WITHDRAWAL_LIMIT_USD", "1000"))
AGENT_INCOME_WALLET_CHALLENGE_MINUTES = int(os.getenv("AGENT_INCOME_WALLET_CHALLENGE_MINUTES", "10"))
AGENT_INCOME_SETTLEMENT_SOURCE = os.getenv("AGENT_INCOME_SETTLEMENT_SOURCE", "direct_to_user_wallet")
AGENT_INCOME_DEFAULT_WALLET = os.getenv("AGENT_INCOME_DEFAULT_WALLET", PAYMENT_WALLET).strip()
AGENT_INCOME_SPEND_LIMIT_USD = float(os.getenv("AGENT_INCOME_SPEND_LIMIT_USD", "25"))
AGENT_INCOME_OUTREACH_REPLY_TO = os.getenv("AGENT_INCOME_OUTREACH_REPLY_TO", PAYMENT_SUPPORT_EMAIL)
AGENT_INCOME_COMPANY_ADDRESS = os.getenv("AGENT_INCOME_COMPANY_ADDRESS", "")
AGENT_INCOME_OPERATOR_ENABLED = os.getenv(
    "AGENT_INCOME_OPERATOR_ENABLED",
    "false" if BASE_URL.startswith(("http://localhost", "http://127.0.0.1")) else "active",
).lower() in {"1", "true", "yes", "active", "on"}
AGENT_INCOME_OPERATOR_INTERVAL_SECONDS = int(os.getenv("AGENT_INCOME_OPERATOR_INTERVAL_SECONDS", "900"))
AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED = os.getenv(
    "AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED",
    "true",
).lower() in {"1", "true", "yes", "active", "on"}
AGENT_INCOME_PUBLIC_LEAD_LIMIT_PER_QUERY = int(os.getenv("AGENT_INCOME_PUBLIC_LEAD_LIMIT_PER_QUERY", "15"))
AGENT_INCOME_PUBLIC_LEAD_MAX_RESULTS = int(os.getenv("AGENT_INCOME_PUBLIC_LEAD_MAX_RESULTS", "250"))
AGENT_INCOME_LEAD_ACTION_LIMIT = int(os.getenv("AGENT_INCOME_LEAD_ACTION_LIMIT", "40"))
AGENT_INCOME_AUTO_DEAL_LEADS = os.getenv(
    "AGENT_INCOME_AUTO_DEAL_LEADS",
    "true",
).lower() in {"1", "true", "yes", "active", "on"}
AGENT_INCOME_AUTOSEND_PUBLIC_LEADS = os.getenv(
    "AGENT_INCOME_AUTOSEND_PUBLIC_LEADS",
    "false",
).lower() in {"1", "true", "yes", "active", "on"}
AGENT_INCOME_GITHUB_TOKEN = os.getenv("AGENT_INCOME_GITHUB_TOKEN", "").strip()
AGENT_INCOME_DISCOVERY_FEEDS = [
    item.strip()
    for item in os.getenv("AGENT_INCOME_DISCOVERY_FEEDS", "").split(",")
    if item.strip().startswith(("https://", "http://localhost", "http://127.0.0.1"))
]
AGENT_INCOME_PAYANAGENT_API_KEY = os.getenv(
    "AGENT_INCOME_PAYANAGENT_API_KEY",
    os.getenv("PAYANAGENT_API_KEY", ""),
).strip()
AGENT_INCOME_PAYANAGENT_AGENT_ID = os.getenv("AGENT_INCOME_PAYANAGENT_AGENT_ID", "").strip()
BOT_COMM_PASSWORD = os.getenv("BOT_COMM_PASSWORD", "Restio2027&")
TRAFFIC_BOARD_PASSWORD = os.getenv("TRAFFIC_BOARD_PASSWORD", BOT_COMM_PASSWORD)
TRAFFIC_IP_CACHE_PATH = Path(os.getenv("CLEARANCE_TRAFFIC_IP_CACHE_PATH", "data/traffic_ip_cache.json"))
TRAFFIC_IP_ENRICH = os.getenv("CLEARANCE_TRAFFIC_IP_ENRICH", "1").lower() not in {"0", "false", "no"}
TRAFFIC_KNOWN_USERS = {
    ip.strip(): label.strip()
    for item in os.getenv("TRAFFIC_KNOWN_USERS", "47.161.205.86=Justin / Nauti-Labs owner").split(",")
    if "=" in item
    for ip, label in [item.split("=", 1)]
    if ip.strip() and label.strip()
}
BOT_COMM_SESSION_COOKIE = os.getenv("BOT_COMM_SESSION_COOKIE", "clearance_bot_comm_session")
BOT_COMM_SESSION_HOURS = int(os.getenv("BOT_COMM_SESSION_HOURS", "12"))
BOT_COMM_DAILY_TARGET_USDC = float(os.getenv("BOT_COMM_DAILY_TARGET_USDC", "200"))
BOT_COMM_WALLET = os.getenv("BOT_COMM_WALLET", AGENT_INCOME_DEFAULT_WALLET or PAYMENT_WALLET).strip()
BOT_COMM_CONTACT_EMAIL = os.getenv("BOT_COMM_CONTACT_EMAIL", PAYMENT_SUPPORT_EMAIL)
BOT_COMM_CORS_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "BOT_COMM_CORS_ORIGINS",
        "https://nauti-labs.com,https://www.nauti-labs.com,http://localhost:8080,http://localhost:8081,http://127.0.0.1:8080,http://127.0.0.1:8081",
    ).split(",")
    if origin.strip()
]
BOT_COMM_402INDEX_VERIFY_HASH = os.getenv(
    "BOT_COMM_402INDEX_VERIFY_HASH",
    "e72fc1dfb9ee96024ad4860e3056bb386079bc02d46bf5d72a0e3f898d19ce77",
)
CLEARANCE_API_KEY = os.getenv("CLEARANCE_API_KEY", "")
BOT_COMM_MONTHLY_TARGET_USD = float(os.getenv("BOT_COMM_MONTHLY_TARGET_USD", "20000"))
BOT_COMM_OPS_INTERVAL_SECONDS = int(os.getenv("BOT_COMM_OPS_INTERVAL_SECONDS", "300"))
BOT_COMM_OPERATIONS_DEFAULT = os.getenv("BOT_COMM_OPERATIONS_DEFAULT", "active").lower()
BOT_COMM_REFUND_RESERVE_RATE = float(os.getenv("BOT_COMM_REFUND_RESERVE_RATE", "0.03"))
BOT_COMM_PAYMENT_FEE_FLAT_USD = float(os.getenv("BOT_COMM_PAYMENT_FEE_FLAT_USD", "0"))
BOT_COMM_DISCOVERY_ENABLED = os.getenv("BOT_COMM_DISCOVERY_ENABLED", "true").lower() in {"1", "true", "yes", "active", "on"}
BOT_COMM_DISCOVERY_FEEDS = [
    item.strip()
    for item in os.getenv("BOT_COMM_DISCOVERY_FEEDS", "").split(",")
    if item.strip().startswith(("https://", "http://localhost", "http://127.0.0.1"))
]
BOT_COMM_PAYANAGENT_API_KEY = os.getenv("BOT_COMM_PAYANAGENT_API_KEY", AGENT_INCOME_PAYANAGENT_API_KEY).strip()
BOT_COMM_PAYANAGENT_AGENT_ID = os.getenv("BOT_COMM_PAYANAGENT_AGENT_ID", "").strip()
BOT_COMM_AUTOSEND_OFFERS = os.getenv("BOT_COMM_AUTOSEND_OFFERS", "false").lower() in {"1", "true", "yes", "active", "on"}
BOT_COMM_DEFAULT_OPPORTUNITY_QUERIES = [
    "buyer agent x402",
    "available agent tasks",
    "x402 task marketplace",
    "AI agent bounty marketplace",
    "open buyer requests agent API",
    "agent procurement request",
    "paid endpoint marketplace",
    "x402 service discovery",
    "AgentCard x402 registry",
    "MCP paid tools",
    "MCP marketplace agents",
    "agent payment receipt relay",
    "bot quote relay",
    "message risk check",
    "procurement agent api",
    "agent marketplace quote request",
    "paid api buyer bot",
    "mcp tool routing payment",
    "bot commerce routing",
    "autonomous agent payments",
    "receipt verification agent",
    "service discovery buyer agent",
    "commercial agent handshake",
    "x402 paid endpoint integration",
    "bot-to-bot transaction safety",
    "crypto custodian compliance workflow",
    "digital asset custody controls",
    "custodian transaction approval policy",
    "wallet operations evidence logs",
    "crypto custody compliance automation",
]
BOT_COMM_OPPORTUNITY_QUERIES = [
    item.strip()
    for item in os.getenv("BOT_COMM_OPPORTUNITY_QUERIES", ",".join(BOT_COMM_DEFAULT_OPPORTUNITY_QUERIES)).split(",")
    if item.strip()
]
BOT_COMM_OPPORTUNITY_QUERY_BATCH_SIZE = max(1, min(40, int(os.getenv("BOT_COMM_OPPORTUNITY_QUERY_BATCH_SIZE", "20"))))
BOT_COMM_OPPORTUNITY_RETENTION_HOURS = max(1, int(os.getenv("BOT_COMM_OPPORTUNITY_RETENTION_HOURS", "168")))
BOT_COMM_OPPORTUNITY_MAX = max(25, min(500, int(os.getenv("BOT_COMM_OPPORTUNITY_MAX", "250"))))
BOT_COMM_DISCOVERY_ITEM_LIMIT = max(10, min(250, int(os.getenv("BOT_COMM_DISCOVERY_ITEM_LIMIT", "80"))))
BOT_COMM_OPERATOR_COMPLETION_MAX = max(50, min(500, int(os.getenv("BOT_COMM_OPERATOR_COMPLETION_MAX", "250"))))
BASE_CHAIN_NAME = os.getenv("BASE_CHAIN_NAME", "Base")

TIER_LIMITS = {
    "starter": 50,
    "pro": 1000,
    "scale": 10000,
}
TIER_PRICES = {
    "pro": 19,
    "scale": 49,
}
FREE_KEY_SIGNUP_WINDOW_MINUTES = 60
FREE_KEY_SIGNUP_LIMIT = 5
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_local_url(url: str) -> bool:
    return url.startswith("http://localhost") or url.startswith("http://127.0.0.1")


def validate_runtime_config() -> None:
    if JWT_SECRET == DEFAULT_JWT_SECRET and not _is_local_url(BASE_URL):
        raise RuntimeError("JWT_SECRET_KEY must be set in production.")
    if not _is_local_url(BASE_URL):
        if not PAYMENT_WALLET:
            raise RuntimeError("PAYMENT_WALLET must be set in production.")
        if not PAYMENT_ENS:
            raise RuntimeError("PAYMENT_ENS must be set in production.")
        if not USDC_CONTRACT:
            raise RuntimeError("USDC_CONTRACT must be set in production.")

    if STRIPE_SECRET_KEY and stripe is None:
        raise RuntimeError("STRIPE_SECRET_KEY is set but the stripe package is not installed.")


# --- Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_config()
    await init_db()
    bot_comm_task = asyncio.create_task(bot_comm_operations_loop())
    agent_income_task = asyncio.create_task(agent_income_operator_loop())
    try:
        yield
    finally:
        for task in (bot_comm_task, agent_income_task):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


# --- App ---

app = FastAPI(
    title="Clearance API",
    description="Human Approval API for AI Agent Commerce. Agents request clearance, humans approve, services verify.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/v1/docs",
    redoc_url="/v1/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=BOT_COMM_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Payment-Tx", "X-Traffic-Password"],
    expose_headers=[
        "X-Payment-Required",
        "X-Payment-Network",
        "X-Payment-Currency",
        "X-Payment-Amount",
        "X-Payment-Recipient",
    ],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Engagement / Ambassador attribution ---
# Server-side click + signup attribution. Provable from the DB —
# each click logged in `visits`, each signup tagged with `referred_by`,
# each payment tagged with `referred_by`. Ambassadors can't dispute
# DB rows the way they could dispute a third-party analytics dashboard.

REF_COOKIE = "clearance_ref"
REF_COOKIE_DAYS = 30
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
TRAFFIC_ADMIN_PIN = os.getenv("NAUTI_TRAFFIC_ADMIN_PIN", "").strip()
TRAFFIC_ADMIN_PATH_TOKEN = os.getenv("NAUTI_TRAFFIC_ADMIN_PATH_TOKEN", "").strip()
TRAFFIC_ADMIN_COOKIE = "nauti_traffic_admin_v2"
TRAFFIC_ADMIN_LEGACY_COOKIE = "nauti_traffic_admin"
TRAFFIC_ADMIN_COOKIE_PATH = "/nauti-traffic/admin/"
TRAFFIC_ADMIN_SESSION_HOURS = int(os.getenv("NAUTI_TRAFFIC_ADMIN_SESSION_HOURS", "12"))
TRAFFIC_CONFIG_KEY = "nauti_traffic_config"
TRUSTED_BY_PATH = Path(__file__).resolve().parent / "static" / "trusted_by.json"
_REF_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_ADMIN_PATH_RE = re.compile(r"^[a-zA-Z0-9_-]{16,128}$")
_BOT_RE = re.compile(r"bot|crawler|spider|preview|fetch|monitoring", re.IGNORECASE)
_TRAFFIC_EVENT_EXCLUDED_PATHS = {
    "/favicon.ico",
    "/health",
    "/openapi.json",
    "/robots.txt",
    "/sitemap.xml",
    "/v1/openapi.json",
}
_TRAFFIC_EVENT_EXCLUDED_PREFIXES = (
    "/static/",
    "/docs",
    "/redoc",
    "/nauti-traffic",
    "/Nauti-Traffic",
    "/v1/docs",
    "/v1/redoc",
    "/v1/traffic",
)


def _validate_ref(value):
    """Sanitize ambassador / ref names. Returns canonicalized lowercase name or None."""
    if not value:
        return None
    s = str(value).strip()
    if not _REF_RE.match(s):
        return None
    return s.lower()


def _clean_request_text(value, max_len: int) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())[:max_len]


def _is_bot_ua(ua: str) -> bool:
    return bool(ua) and bool(_BOT_RE.search(ua))


def _traffic_actor_type(ua: str, is_bot: int | bool) -> str:
    value = (ua or "").lower()
    if is_bot or any(token in value for token in ("bot", "crawler", "spider", "preview", "fetch", "monitoring")):
        return "bot"
    if any(token in value for token in ("curl", "httpx", "python-requests", "postman", "wget")):
        return "system"
    return "human"


def _traffic_browser_label(ua: str) -> str:
    value = ua or ""
    low = value.lower()
    if not value:
        return "unknown"
    if "curl/" in low:
        return "curl"
    if "edg/" in low:
        return "Edge"
    if "chrome/" in low and "chromium" not in low:
        return "Chrome"
    if "safari/" in low and "chrome/" not in low:
        return "Safari"
    if "firefox/" in low:
        return "Firefox"
    if "python" in low or "httpx" in low:
        return "script"
    return value[:42]


def _traffic_device_label(ua: str) -> str:
    value = (ua or "").lower()
    if not value:
        return "unknown"
    if "iphone" in value:
        return "iPhone"
    if "ipad" in value:
        return "iPad"
    if "android" in value and "mobile" in value:
        return "Android phone"
    if "android" in value:
        return "Android"
    if "macintosh" in value or "mac os x" in value:
        return "Mac"
    if "windows" in value:
        return "Windows"
    if "linux" in value:
        return "Linux"
    return "unknown"


def _traffic_ip_label(ip: str | None) -> dict:
    raw = (ip or "").strip()
    if not raw:
        return {"label": "unknown visitor", "kind": "unknown", "visitor_id": "unknown"}
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return {"label": raw, "kind": "unknown", "visitor_id": hashlib.sha256(raw.encode()).hexdigest()[:10]}
    visitor_id = hashlib.sha256(raw.encode()).hexdigest()[:10]
    if address.is_loopback:
        return {"label": "localhost / internal QA", "kind": "internal", "visitor_id": visitor_id}
    if address.is_private:
        return {"label": "private network visitor", "kind": "private", "visitor_id": visitor_id}
    if address.version == 4:
        suffix = ".".join(raw.split(".")[-2:])
    else:
        suffix = raw[-9:]
    return {"label": f"public visitor {suffix}", "kind": "public", "visitor_id": visitor_id}


def _traffic_public_ip_candidate(ip: str | None) -> bool:
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _traffic_load_ip_cache() -> dict:
    try:
        return json.loads(TRAFFIC_IP_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _traffic_save_ip_cache(cache: dict) -> None:
    try:
        TRAFFIC_IP_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        TRAFFIC_IP_CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass


def _traffic_profile_label(profile: dict, fallback: str) -> str:
    org = profile.get("org") or profile.get("isp") or ""
    geo = ", ".join(part for part in (profile.get("city"), profile.get("region"), profile.get("country")) if part)
    if org and geo:
        return f"{org} ({geo})"
    return org or geo or fallback


def _traffic_known_user_label(ip: str | None) -> str:
    return TRAFFIC_KNOWN_USERS.get((ip or "").strip(), "")


async def _traffic_fetch_ip_profile(ip: str, client: httpx.AsyncClient) -> dict:
    if not TRAFFIC_IP_ENRICH or not _traffic_public_ip_candidate(ip):
        return {}
    fields = "status,message,country,regionName,city,isp,org,as,mobile,proxy,hosting,query"
    try:
        response = await client.get(f"http://ip-api.com/json/{quote(ip)}", params={"fields": fields})
        response.raise_for_status()
        profile = response.json()
    except Exception:
        return {}
    if profile.get("status") != "success":
        return {}
    return {
        "ip": profile.get("query") or ip,
        "country": profile.get("country") or "",
        "region": profile.get("regionName") or "",
        "city": profile.get("city") or "",
        "isp": profile.get("isp") or "",
        "org": profile.get("org") or "",
        "as": profile.get("as") or "",
        "mobile": bool(profile.get("mobile")),
        "proxy": bool(profile.get("proxy")),
        "hosting": bool(profile.get("hosting")),
        "source": "ip-api.com",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


async def _traffic_ip_profiles(ips: list[str]) -> dict[str, dict]:
    if not TRAFFIC_IP_ENRICH:
        return {}
    unique_ips = [ip for ip in dict.fromkeys(ips) if _traffic_public_ip_candidate(ip)][:50]
    if not unique_ips:
        return {}
    cache = _traffic_load_ip_cache()
    fresh_after = time.time() - (7 * 24 * 60 * 60)
    profiles: dict[str, dict] = {}
    missing = []
    for ip in unique_ips:
        cached = cache.get(ip) or {}
        try:
            fetched_at = datetime.fromisoformat(str(cached.get("fetched_at")).replace("Z", "+00:00")).timestamp()
        except Exception:
            fetched_at = 0
        if cached and fetched_at >= fresh_after:
            profiles[ip] = cached
        else:
            missing.append(ip)
    if missing:
        async with httpx.AsyncClient(timeout=1.5) as client:
            results = await asyncio.gather(
                *(_traffic_fetch_ip_profile(ip, client) for ip in missing),
                return_exceptions=True,
            )
        for ip, result in zip(missing, results):
            if isinstance(result, dict) and result:
                profiles[ip] = result
                cache[ip] = result
        _traffic_save_ip_cache(cache)
    return profiles


def _traffic_ref_from_path(path: str | None) -> str | None:
    value = (path or "").strip()
    if not value.startswith("/"):
        return None
    if value.startswith("/r/"):
        return _validate_ref(value.split("/", 3)[2])
    parts = [part for part in value.split("/") if part]
    if len(parts) != 1:
        return None
    slug = parts[0]
    reserved = {
        "api", "v1", "health", "docs", "redoc", "openapi.json", "static",
        "traffic", "nauti-traffic", "Nauti-Traffic", "tutorial", "pricing", "terms",
        "privacy", "family", "agent-income", "bot-comm", "scram", "scam-check",
        "robots.txt", "sitemap.xml", "favicon.ico",
    }
    if slug in reserved or "." in slug:
        return None
    return _validate_ref(slug)


def _should_record_traffic_event(request: Request) -> bool:
    if request.method == "OPTIONS":
        return False
    path = request.url.path or ""
    if path in _TRAFFIC_EVENT_EXCLUDED_PATHS:
        return False
    return not path.startswith(_TRAFFIC_EVENT_EXCLUDED_PREFIXES)


def _require_traffic_board_password(x_traffic_password: str | None) -> None:
    if not TRAFFIC_BOARD_PASSWORD:
        raise HTTPException(status_code=503, detail="traffic password is not configured")
    if not x_traffic_password or not secrets.compare_digest(x_traffic_password, TRAFFIC_BOARD_PASSWORD):
        raise HTTPException(status_code=401, detail="invalid traffic password")


async def _record_visit(request: "Request", ref):
    """Persist a single page-visit row. Best-effort: never raises."""
    try:
        from database import get_db as _get_db_visits
        db = await _get_db_visits()
        try:
            qp = request.query_params
            ua = (request.headers.get("user-agent") or "")[:512]
            await db.execute(
                """INSERT INTO visits
                   (id, path, ref, referer, utm_source, utm_medium, utm_campaign,
                    ip, user_agent, is_bot, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    secrets.token_urlsafe(12),
                    request.url.path,
                    ref,
                    (request.headers.get("referer") or "")[:512],
                    qp.get("utm_source"),
                    qp.get("utm_medium"),
                    qp.get("utm_campaign"),
                    get_client_ip(request),
                    ua,
                    1 if _is_bot_ua(ua) else 0,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            await db.commit()
        finally:
            await db.close()
    except Exception:
        # never let analytics break the page
        pass


def _set_ref_cookie(response, ref: str):
    response.set_cookie(
        key=REF_COOKIE,
        value=ref,
        max_age=REF_COOKIE_DAYS * 86400,
        httponly=False,  # allow client-side debugging; not a security boundary
        samesite="lax",
        secure=True,
        path="/",
    )


def _read_ref_cookie(request: "Request"):
    return _validate_ref(request.cookies.get(REF_COOKIE))


def _require_admin(x_admin_key):
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="ADMIN_KEY env var not set on server.")
    if not x_admin_key or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="invalid admin key")


def _dedupe(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values or []:
        clean = _validate_ref(value)
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def _clean_mapping(mapping) -> dict[str, str]:
    if not isinstance(mapping, dict):
        return {}
    cleaned: dict[str, str] = {}
    for key, value in mapping.items():
        clean_key = _validate_ref(key)
        if not clean_key:
            continue
        if isinstance(value, str) and value.strip():
            cleaned[clean_key] = value.strip()
    return cleaned


def _default_traffic_config() -> dict:
    try:
        payload = json.loads(TRUSTED_BY_PATH.read_text())
    except Exception:
        payload = {}
    return _normalize_traffic_config(payload)


def _normalize_traffic_config(config: dict | None) -> dict:
    if not isinstance(config, dict):
        config = {}

    captain = _validate_ref(config.get("captain"))
    raw_captains = config.get("captains") if isinstance(config.get("captains"), list) else []
    captains = _dedupe(([captain] if captain else []) + raw_captains)
    first_mates = [ref for ref in _dedupe(config.get("first_mates")) if ref not in captains][:10]
    return {
        "_comment": config.get("_comment", ""),
        "captain": captains[0] if captains else None,
        "captains": captains,
        "_first_mates_doc": config.get(
            "_first_mates_doc",
            "Up to 10 First Mate badges total. Tier below Captain. Add ref names lowercased.",
        ),
        "first_mates": first_mates,
        "ref_aliases": _clean_mapping(config.get("ref_aliases")),
        "hidden_refs": _dedupe(config.get("hidden_refs")),
        "avatar_overrides": _clean_mapping(config.get("avatar_overrides")),
        "avatar_urls": _clean_mapping(config.get("avatar_urls")),
        "metric_floors": _clean_metric_floors(config.get("metric_floors")),
        "trusted_by": config.get("trusted_by") if isinstance(config.get("trusted_by"), list) else [],
        "onboarding": config.get("onboarding") if isinstance(config.get("onboarding"), list) else [],
    }


def _metric_number(value, default=0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(number, 0)


def _clean_metric_payload(payload) -> dict:
    if not isinstance(payload, dict):
        return {}
    cleaned: dict[str, int | float | dict] = {}
    for key in ("clicks", "signups", "free_signups", "paid_conversions"):
        if key in payload:
            cleaned[key] = int(_metric_number(payload.get(key)))
    if "monthly_revenue_usd" in payload:
        cleaned["monthly_revenue_usd"] = float(_metric_number(payload.get("monthly_revenue_usd")))
    for tier in ("pro", "scale"):
        if isinstance(payload.get(tier), dict):
            tier_payload = payload[tier]
            cleaned[tier] = {
                "count": int(_metric_number(tier_payload.get("count"))),
                "monthly_revenue_usd": float(_metric_number(tier_payload.get("monthly_revenue_usd"))),
            }
    return cleaned


def _clean_metric_floors(payload) -> dict:
    if not isinstance(payload, dict):
        return {"general_traffic": {}, "ambassadors": {}}
    ambassadors = {}
    raw_ambassadors = payload.get("ambassadors") if isinstance(payload.get("ambassadors"), dict) else {}
    for ref, metrics in raw_ambassadors.items():
        clean_ref = _validate_ref(ref)
        clean_metrics = _clean_metric_payload(metrics)
        if clean_ref and clean_metrics:
            ambassadors[clean_ref] = clean_metrics
    return {
        "_comment": payload.get("_comment", ""),
        "general_traffic": _clean_metric_payload(payload.get("general_traffic")),
        "ambassadors": ambassadors,
    }


def _merge_traffic_config(base: dict, override: dict | None) -> dict:
    merged = json.loads(json.dumps(base))
    if isinstance(override, dict):
        for key in ("captain", "captains", "first_mates", "trusted_by", "onboarding", "hidden_refs"):
            if key in override:
                merged[key] = override[key]
        for key in ("ref_aliases", "avatar_overrides", "avatar_urls", "metric_floors"):
            if isinstance(override.get(key), dict):
                current = merged.get(key) if isinstance(merged.get(key), dict) else {}
                current.update(override[key])
                merged[key] = current
    return _normalize_traffic_config(merged)


def _apply_metric_floor(row: dict, floor: dict | None) -> dict:
    if not isinstance(floor, dict) or not floor:
        return row
    for key in ("clicks", "signups", "free_signups", "paid_conversions"):
        if key in floor:
            row[key] = max(int(row.get(key) or 0), int(floor.get(key) or 0))
    if "monthly_revenue_usd" in floor:
        row["monthly_revenue_usd"] = max(float(row.get("monthly_revenue_usd") or 0), float(floor.get("monthly_revenue_usd") or 0))
    for tier in ("pro", "scale"):
        if isinstance(floor.get(tier), dict):
            current = row.get(tier) if isinstance(row.get(tier), dict) else {"count": 0, "monthly_revenue_usd": 0.0}
            current["count"] = max(int(current.get("count") or 0), int(floor[tier].get("count") or 0))
            current["monthly_revenue_usd"] = max(
                float(current.get("monthly_revenue_usd") or 0),
                float(floor[tier].get("monthly_revenue_usd") or 0),
            )
            row[tier] = current
    if "signups" in row and "paid_conversions" in row:
        row["free_signups"] = max(int(row.get("free_signups") or 0), int(row.get("signups") or 0) - int(row.get("paid_conversions") or 0))
    if "clicks" in row and "signups" in row:
        clicks = int(row.get("clicks") or 0)
        row["click_to_signup_rate_pct"] = round((int(row.get("signups") or 0) / clicks * 100), 2) if clicks else 0.0
    return row


def _apply_ambassador_metric_floor(row: dict, floors: dict | None) -> dict:
    ref = _validate_ref(row.get("ambassador"))
    ambassador_floors = floors.get("ambassadors") if isinstance(floors, dict) else {}
    floor = ambassador_floors.get(ref) if isinstance(ambassador_floors, dict) and ref else None
    return _apply_metric_floor(row, floor)


def _apply_general_metric_floor(row: dict, floors: dict | None) -> dict:
    floor = floors.get("general_traffic") if isinstance(floors, dict) else None
    return _apply_metric_floor(row, floor)


async def load_traffic_config() -> dict:
    base = _default_traffic_config()
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT value FROM traffic_settings WHERE key = ?",
            (TRAFFIC_CONFIG_KEY,),
        )
        row = await cursor.fetchone()
        if not row:
            return base
        try:
            override = json.loads(row["value"])
        except Exception:
            override = {}
        return _merge_traffic_config(base, override)
    finally:
        await db.close()


def _traffic_ref_is_configured(raw_ref: str, canonical_ref: str, config: dict) -> bool:
    """Allow direct vanity paths only for refs already managed in traffic config."""
    refs = {raw_ref, canonical_ref}
    refs.discard(None)

    known_refs = set(_dedupe(config.get("first_mates")))
    known_refs.update(_dedupe(config.get("captains")))
    known_refs.update(_dedupe(config.get("hidden_refs")))
    if config.get("captain"):
        known_refs.add(config["captain"])
    for key in ("avatar_overrides", "avatar_urls"):
        mapping = config.get(key) if isinstance(config.get(key), dict) else {}
        known_refs.update(mapping.keys())

    return bool(refs & known_refs)


async def canonical_traffic_ref(raw_ref: str, *, require_configured: bool = False) -> str | None:
    clean_ref = _validate_ref(raw_ref)
    if not clean_ref:
        return None

    try:
        config = await load_traffic_config()
    except Exception:
        config = _default_traffic_config()

    aliases = config.get("ref_aliases") if isinstance(config.get("ref_aliases"), dict) else {}
    canonical = _validate_ref(aliases.get(clean_ref)) or clean_ref
    if require_configured and not _traffic_ref_is_configured(clean_ref, canonical, config):
        return None
    return canonical


async def save_traffic_config(config: dict) -> None:
    clean_config = _normalize_traffic_config(config)
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO traffic_settings (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at""",
            (TRAFFIC_CONFIG_KEY, json.dumps(clean_config), now_iso()),
        )
        await db.commit()
    finally:
        await db.close()


def _traffic_admin_secret_configured() -> bool:
    return bool(_ADMIN_PATH_RE.fullmatch(TRAFFIC_ADMIN_PATH_TOKEN))


def _traffic_admin_path(access_token: str | None = None) -> str:
    token = access_token or TRAFFIC_ADMIN_PATH_TOKEN
    return f"/nauti-traffic/admin/{token}"


def _verify_traffic_admin_path(access_token: str) -> str:
    if not _traffic_admin_secret_configured():
        raise HTTPException(status_code=404, detail="Not Found")
    if not _ADMIN_PATH_RE.fullmatch(access_token):
        raise HTTPException(status_code=404, detail="Not Found")
    if not secrets.compare_digest(access_token, TRAFFIC_ADMIN_PATH_TOKEN):
        raise HTTPException(status_code=404, detail="Not Found")
    return _traffic_admin_path(access_token)


def _traffic_admin_redirect(access_token: str, query: str = "") -> RedirectResponse:
    suffix = f"?{query}" if query else ""
    response = RedirectResponse(url=f"{_traffic_admin_path(access_token)}{suffix}", status_code=303)
    _no_store(response)
    return response


def _no_store(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def _clear_traffic_admin_cookies(response, admin_path: str) -> None:
    for cookie_name in (TRAFFIC_ADMIN_COOKIE, TRAFFIC_ADMIN_LEGACY_COOKIE):
        for cookie_path in (TRAFFIC_ADMIN_COOKIE_PATH, admin_path, "/"):
            response.delete_cookie(cookie_name, path=cookie_path)


def _make_traffic_admin_token(access_token: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=TRAFFIC_ADMIN_SESSION_HOURS)
    return jwt.encode(
        {
            "scope": "nauti_traffic.admin",
            "admin_path_token": access_token,
            "expires_at": expires_at.isoformat(),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def _traffic_admin_logged_in(request: Request, access_token: str) -> bool:
    token = request.cookies.get(TRAFFIC_ADMIN_COOKIE)
    if not token:
        return False
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return False
    if payload.get("scope") != "nauti_traffic.admin":
        return False
    if payload.get("admin_path_token") != access_token:
        return False
    expires_at = payload.get("expires_at")
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at) > datetime.now(timezone.utc)
    except Exception:
        return False


def _require_traffic_admin(request: Request, access_token: str) -> None:
    if not _traffic_admin_logged_in(request, access_token):
        raise HTTPException(status_code=303, headers={"Location": _traffic_admin_path(access_token)})


# --- Helpers ---

def generate_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("cf-connecting-ip", "").strip()
    if cf_ip:
        return cf_ip
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _record_traffic_event(
    request: Request,
    *,
    status_code: int,
    duration_ms: float,
    source: str = "runtime",
):
    """Persist raw server traffic so analytics survives process/log rotation."""
    try:
        if not _should_record_traffic_event(request):
            return
        db = await get_db()
        try:
            qp = request.query_params
            ua = (request.headers.get("user-agent") or "")[:512]
            ref = (
                _validate_ref(qp.get("ref"))
                or _validate_ref(qp.get("utm_source"))
                or _read_ref_cookie(request)
                or _traffic_ref_from_path(request.url.path)
            )
            await db.execute(
                """INSERT OR IGNORE INTO traffic_events
                   (id, source, method, path, query, ref, referer, origin, ip,
                    user_agent, status_code, duration_ms, is_bot, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    secrets.token_urlsafe(12),
                    source,
                    request.method,
                    request.url.path,
                    str(request.url.query or "")[:512],
                    ref,
                    (request.headers.get("referer") or "")[:512],
                    (request.headers.get("origin") or "")[:255],
                    get_client_ip(request),
                    ua,
                    status_code,
                    round(float(duration_ms), 2),
                    1 if _is_bot_ua(ua) else 0,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            await db.commit()
        finally:
            await db.close()
    except Exception:
        pass


@app.middleware("http")
async def traffic_event_logger(request: Request, call_next):
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        elapsed = (time.perf_counter() - started) * 1000
        await _record_traffic_event(request, status_code=status_code, duration_ms=elapsed)


def scamcheck_payment_url() -> str:
    return PUBLIC_PAYMENT_URL or f"{SCRAM_BASE_URL}#pricing"


def _scram_host() -> str:
    try:
        return (urlparse(SCRAM_BASE_URL).hostname or "").lower()
    except Exception:
        return ""


def _request_host(request: Request) -> str:
    return (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(":")[0].lower()


def _is_scram_request(request: Request) -> bool:
    host = _request_host(request)
    configured = _scram_host()
    return bool(host and (host == configured or host.startswith("scram.")))


def _scram_home_href(request: Request) -> str:
    return "/" if _is_scram_request(request) else "/scram"


def _scram_status_label(request: Request) -> str:
    if _is_local_url(str(request.url)) or _is_local_url(SCRAM_BASE_URL):
        return "SCRAM SMS-first MVP live locally"
    return "SCRAM web demo is live"


def _scram_template_context(request: Request) -> dict:
    return {
        "base_url": BASE_URL.rstrip("/"),
        "scram_base_url": SCRAM_BASE_URL,
        "brand_url": BRAND_URL.rstrip("/"),
        "support_email": PAYMENT_SUPPORT_EMAIL,
        "sms_number": SMS_FROM_NUMBER,
        "text_code": SCRAM_TEXT_CODE,
        "payment_url": scamcheck_payment_url(),
        "home_href": _scram_home_href(request),
        "status_label": _scram_status_label(request),
    }


async def _read_sms_payload(request: Request) -> dict:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
        return dict(body or {})

    form = await request.form()
    payload = {}
    attachments: list[dict] = []
    for key, value in form.multi_items():
        if hasattr(value, "filename"):
            filename = str(getattr(value, "filename", "") or "")
            if filename:
                attachments.append({
                    "source": "upload",
                    "field": key,
                    "filename": filename,
                    "content_type": str(getattr(value, "content_type", "") or ""),
                })
            close_file = getattr(value, "close", None)
            if close_file:
                maybe_awaitable = close_file()
                if asyncio.iscoroutine(maybe_awaitable):
                    await maybe_awaitable
            continue
        payload[key] = value
    if attachments:
        payload["_attachments"] = attachments
    return payload


def _payload_value(payload: dict, *names: str) -> str:
    for name in names:
        value = payload.get(name)
        if value is not None:
            return str(value)
    return ""


def _is_form_sms_webhook(request: Request) -> bool:
    content_type = request.headers.get("content-type", "").lower()
    return "application/x-www-form-urlencoded" in content_type


def _public_request_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto")
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if proto and host:
        return f"{proto}://{host}{request.url.path}"
    return str(request.url)


def _looks_like_twilio_webhook(request: Request, payload: dict) -> bool:
    if request.headers.get("x-twilio-signature"):
        return True
    if not _is_form_sms_webhook(request):
        return False
    return any(key in payload for key in ("MessageSid", "SmsMessageSid", "AccountSid", "MessagingServiceSid", "WaId"))


def _detect_message_channel(payload: dict, provider: str = "") -> str:
    explicit = str(payload.get("channel") or payload.get("Channel") or "").strip().lower()
    if explicit:
        return explicit
    from_value = str(payload.get("From") or payload.get("from") or "").strip().lower()
    to_value = str(payload.get("To") or payload.get("to") or "").strip().lower()
    if from_value.startswith("whatsapp:") or to_value.startswith("whatsapp:"):
        return "whatsapp"
    if str(provider).lower().startswith("telegram"):
        return "telegram"
    if str(provider).lower().startswith("imessage") or str(provider).lower().startswith("apple"):
        return "imessage"
    return "sms"


def _twilio_response_media_type(request: Request, payload: dict) -> bool:
    return _is_form_sms_webhook(request) or bool(request.headers.get("x-twilio-signature"))


def _require_valid_twilio_signature(request: Request, payload: dict) -> None:
    if not _looks_like_twilio_webhook(request, payload):
        return
    if not twilio_signature_validation_enabled():
        return
    if not validate_twilio_webhook_signature(
        url=_public_request_url(request),
        params=payload,
        signature=request.headers.get("x-twilio-signature", ""),
        auth_token=TWILIO_AUTH_TOKEN,
    ):
        raise HTTPException(status_code=403, detail="Invalid Twilio webhook signature")


def _append_attachment(attachments: list[dict], item: dict) -> None:
    cleaned = {
        "url": str(item.get("url") or item.get("media_url") or "").strip(),
        "file_id": str(item.get("file_id") or "").strip(),
        "content_type": str(item.get("content_type") or item.get("type") or "").strip(),
        "filename": str(item.get("filename") or item.get("name") or "").strip(),
        "source": str(item.get("source") or "").strip(),
    }
    if any(cleaned.values()):
        attachments.append(cleaned)


def _extract_sms_attachments(payload: dict) -> list[dict]:
    attachments: list[dict] = []

    for item in payload.get("_attachments") or []:
        if isinstance(item, dict):
            _append_attachment(attachments, item)

    for key in ("attachments", "media", "files"):
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _append_attachment(attachments, item)
                elif isinstance(item, str):
                    _append_attachment(attachments, {"url": item, "source": key})
        elif isinstance(value, dict):
            _append_attachment(attachments, value)
        elif isinstance(value, str) and value.strip():
            _append_attachment(attachments, {"url": value, "source": key})

    try:
        media_count = int(payload.get("NumMedia") or payload.get("num_media") or 0)
    except (TypeError, ValueError):
        media_count = 0
    for index in range(max(0, media_count)):
        _append_attachment(
            attachments,
            {
                "url": payload.get(f"MediaUrl{index}") or payload.get(f"media_url_{index}"),
                "content_type": payload.get(f"MediaContentType{index}") or payload.get(f"media_content_type_{index}"),
                "source": "mms",
            },
        )

    return attachments


def _extract_telegram_attachment(message: dict) -> list[dict]:
    attachments: list[dict] = []
    if not message:
        return attachments

    photos = message.get("photo") or []
    if photos:
        largest = photos[-1] if isinstance(photos, list) else photos
        if isinstance(largest, dict):
            _append_attachment(attachments, {
                "file_id": largest.get("file_id"),
                "content_type": "image/jpeg",
                "source": "telegram_photo",
            })

    for key, source in (
        ("document", "telegram_document"),
        ("video", "telegram_video"),
        ("animation", "telegram_animation"),
        ("audio", "telegram_audio"),
        ("voice", "telegram_voice"),
        ("sticker", "telegram_sticker"),
    ):
        item = message.get(key)
        if isinstance(item, dict):
            _append_attachment(attachments, {
                "file_id": item.get("file_id"),
                "filename": item.get("file_name") or item.get("emoji"),
                "content_type": item.get("mime_type") or key,
                "source": source,
            })
    return attachments


async def handle_scram_help(
    *,
    from_number: str,
    body: str,
    provider: str,
    provider_message_id: str | None = None,
    attachments: list[dict] | None = None,
) -> dict:
    reservation = await reserve_help_credit(from_number)
    if not reservation["allowed"]:
        if reservation.get("reason") == "opted_out":
            return {
                "status": "opted_out",
                "reply": "You are opted out of SCRAM. Text START to opt back in.",
            }
        return {
            "status": "no_help_credits",
            "phone_hash": reservation["phone_hash"],
            "reply": format_out_of_help_reply(scamcheck_payment_url()),
            "payment_url": scamcheck_payment_url(),
        }

    help_result = await generate_scram_help(body, attachments=attachments or [])
    help_id = await record_help_message(
        phone_hash=reservation["phone_hash"],
        provider=provider,
        provider_message_id=provider_message_id,
        user_message_hash=hash_help_text(body),
        reply_hash=hash_help_text(help_result["reply"]),
        model=help_result.get("model", ""),
        llm_provider=help_result.get("provider", ""),
        credit_source=reservation["source"],
        attachments=attachments,
    )
    credits = await get_sms_credit_summary(from_number)
    return {
        "status": "helped",
        "help_id": help_id,
        "credit_source": reservation["source"],
        "llm_provider": help_result.get("provider"),
        "model": help_result.get("model"),
        "credits": {
            "free_help_messages_remaining": credits["free_help_messages_remaining"],
            "paid_credits_remaining": credits["paid_credits_remaining"],
        },
        "reply": help_result["reply"],
    }


async def handle_sms_scam_check(
    *,
    from_number: str,
    body: str,
    provider: str,
    provider_message_id: str | None = None,
    attachments: list[dict] | None = None,
) -> dict:
    command = (body or "").strip().upper()
    attachments = attachments or []
    if not from_number:
        raise HTTPException(status_code=400, detail="From phone number is required")

    if command in {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}:
        await set_sms_opt_out(from_number, True)
        return {
            "status": "opted_out",
            "reply": "You are opted out of SCRAM. Text START to opt back in.",
        }

    if command in {"START", "UNSTOP"}:
        await set_sms_opt_out(from_number, False)
        return {
            "status": "opted_in",
            "reply": "You are opted in. Send HELP for SCRAM Helper or forward a suspicious message for a verdict.",
        }

    credits_before = await get_sms_credit_summary(from_number)

    if command in {"DONE", "EXIT", "END HELP"}:
        await set_help_mode(from_number, False)
        return {
            "status": "help_mode_off",
            "reply": "SCRAM Helper is off. Forward a suspicious message any time for a verdict, or text HELP to talk it through.",
        }

    if command == "HELP" or command == "INFO":
        await set_help_mode(from_number, True)
        return {
            "status": "help_mode_on",
            "reply": format_help_intro(SCRAM_TEXT_CODE, get_initial_free_help_messages()),
        }

    if command.startswith("HELP "):
        await set_help_mode(from_number, True)
        return await handle_scram_help(
            from_number=from_number,
            body=body[5:].strip() or body,
            provider=provider,
            provider_message_id=provider_message_id,
            attachments=attachments,
        )

    if (not (body or "").strip() and not attachments):
        return {"status": "help", "reply": format_help_reply(SMS_FROM_NUMBER or None, SCRAM_TEXT_CODE)}

    if command.startswith("CHECK "):
        body = body[6:].strip()
    elif credits_before.get("help_mode_active"):
        return await handle_scram_help(
            from_number=from_number,
            body=body,
            provider=provider,
            provider_message_id=provider_message_id,
            attachments=attachments,
        )

    reservation = await reserve_sms_credit(from_number)
    if not reservation["allowed"]:
        if reservation.get("reason") == "opted_out":
            return {
                "status": "opted_out",
                "reply": "You are opted out of scam checks. Text START to opt back in.",
            }
        return {
            "status": "no_credits",
            "phone_hash": reservation["phone_hash"],
            "reply": format_out_of_credits_reply(scamcheck_payment_url()),
            "payment_url": scamcheck_payment_url(),
        }

    analysis = analyze_scam_text(body, attachments=attachments).to_dict()
    check_id = await record_sms_check(
        phone_hash=reservation["phone_hash"],
        provider=provider,
        provider_message_id=provider_message_id,
        message_hash=message_fingerprint(body),
        analysis=analysis,
        attachments=attachments,
    )
    credits = await get_sms_credit_summary(from_number)
    return {
        "status": "checked",
        "check_id": check_id,
        "credit_source": reservation["source"],
        "credits": {
            "free_checks_remaining": credits["free_checks_remaining"],
            "paid_credits_remaining": credits["paid_credits_remaining"],
        },
        "analysis": analysis,
        "attachments": {
            "count": len(attachments),
            "types": sorted({
                str(item.get("content_type") or item.get("type") or "").strip().lower()
                for item in attachments
                if str(item.get("content_type") or item.get("type") or "").strip()
            }),
        },
        "reply": format_sms_reply(analysis),
    }


def _smtp_send_message(message: EmailMessage) -> None:
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(message)


async def send_email(
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    reply_to: str | None = None,
) -> bool:
    """Best-effort SMTP email helper. Never blocks signup success."""
    if not SMTP_HOST or not EMAIL_FROM:
        return False

    message = EmailMessage()
    message["From"] = EMAIL_FROM
    message["To"] = to_email
    message["Subject"] = subject
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    try:
        await asyncio.to_thread(_smtp_send_message, message)
        return True
    except Exception as exc:
        print(f"[mail] send failed for subject={subject!r}: {exc}")
        return False


def free_signup_admin_email(
    *,
    email: str,
    name: str | None,
    ref: str | None,
    key_id: str,
    created_at: str,
) -> str:
    base = BASE_URL.rstrip("/")
    return (
        "New Clearance Starter signup\n\n"
        f"Email: {email}\n"
        f"Name / agent: {name or 'not provided'}\n"
        f"Referral: {ref or 'direct / none'}\n"
        "Tier: starter\n"
        "Credits: 50 clearances / month\n"
        f"Key ID: {key_id}\n"
        f"Created: {created_at}\n\n"
        f"Admin: {base}/v1/admin/signups\n"
    )


def welcome_email_subject() -> str:
    return "your Clearance starter key is live"


def welcome_email_text_body() -> str:
    base = BASE_URL.rstrip("/")
    tutorial_url = f"{base}/tutorial"
    docs_url = f"{base}/v1/docs"
    build_url = BOT_BUILD_REQUEST_URL
    return (
        "welcome to Clearance.\n\n"
        "you just added a human approval layer between your agent and the real world.\n\n"
        "your free Starter tier is live:\n"
        "- 50 human-approved clearances per month\n"
        "- approve or deny from Telegram or the browser\n"
        "- verify the token before your agent acts\n\n"
        "security note: your API key was shown once in the browser. "
        "we do not email API keys. if you closed the tab before storing it, create a new key or contact support.\n\n"
        "the operating loop:\n"
        "1. agent proposes an action.\n"
        "2. Clearance sends it to a human.\n"
        "3. human approves or denies.\n"
        "4. your service verifies the token before doing anything expensive, risky, or irreversible.\n\n"
        "quickstart:\n"
        f"- create a request: POST {base}/v1/clearances\n"
        f"- verify an approval token: GET {base}/v1/verify/{{token}}\n"
        f"tutorial: {tutorial_url}\n"
        f"api docs: {docs_url}\n"
        f"support: {PAYMENT_SUPPORT_EMAIL}\n\n"
        "want Nauti-Labs to build the bot too?\n"
        "Bot builds are $125/hr with a 10-hour minimum engagement. "
        "If the scope or budget needs a conversation, reply and we can talk through it.\n"
        f"request a build: {build_url}\n\n"
        "agent proposes. human approves. service verifies.\n\n"
        "welcome aboard,\n"
        "Nauti-Labs\n"
    )


def welcome_email_html_body() -> str:
    base = BASE_URL.rstrip("/")
    tutorial_url = f"{base}/tutorial"
    docs_url = f"{base}/v1/docs"
    build_url = BOT_BUILD_REQUEST_URL
    return f"""<!doctype html>
<html>
  <body style="margin:0;background:#060708;color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#060708;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#101114;border:1px solid rgba(255,255,255,0.09);border-radius:14px;overflow:hidden;">
            <tr>
              <td style="padding:28px 30px;border-bottom:1px solid rgba(255,255,255,0.09);">
                <div style="font-size:28px;line-height:1;color:#f59e0b;letter-spacing:3px;font-weight:800;">&gt;&gt;&gt;</div>
                <h1 style="margin:18px 0 8px;font-size:28px;line-height:1.12;color:#ffffff;">your clearance layer is live</h1>
                <p style="margin:0;color:#a9a3a5;font-size:15px;line-height:1.55;">you just added a human approval gate between agent intent and real-world action.</p>
              </td>
            </tr>
            <tr>
              <td style="padding:28px 30px;">
                <p style="margin:0 0 18px;color:#f6f2f3;font-size:16px;line-height:1.6;">your free Starter tier is ready: <strong>50 human-approved clearances per month</strong>, with approval from Telegram or the browser and token verification before your agent acts.</p>
                <div style="background:#16181d;border:1px solid rgba(245,158,11,0.28);border-radius:10px;padding:18px;margin:0 0 22px;">
                  <div style="color:#f59e0b;font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;margin-bottom:10px;">security note</div>
                  <p style="margin:0;color:#e2e8f0;font-size:14px;line-height:1.55;">your API key was shown once in the browser. we do not email API keys. if you closed the tab before storing it, create a new key or contact support.</p>
                </div>
                <h2 style="margin:0 0 12px;color:#ffffff;font-size:17px;">the loop</h2>
                <ol style="margin:0 0 22px;padding-left:22px;color:#d8d3d5;font-size:15px;line-height:1.7;">
                  <li>agent proposes an action.</li>
                  <li>Clearance sends it to a human.</li>
                  <li>human approves or denies.</li>
                  <li>your service verifies the token before doing anything expensive, risky, or irreversible.</li>
                </ol>
                <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 24px;">
                  <tr>
                    <td style="background:#f59e0b;border-radius:8px;">
                      <a href="{html.escape(tutorial_url)}" style="display:inline-block;padding:12px 18px;color:#111111;text-decoration:none;font-weight:800;font-size:14px;">open the tutorial</a>
                    </td>
                    <td style="width:10px;"></td>
                    <td style="background:#16181d;border:1px solid rgba(255,255,255,0.12);border-radius:8px;">
                      <a href="{html.escape(docs_url)}" style="display:inline-block;padding:11px 16px;color:#e2e8f0;text-decoration:none;font-weight:800;font-size:14px;">api docs</a>
                    </td>
                  </tr>
                </table>
                <div style="background:#12141a;border:1px solid rgba(255,255,255,0.09);border-radius:10px;padding:18px;margin:0 0 22px;">
                  <div style="color:#f59e0b;font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;margin-bottom:10px;">need the bot too?</div>
                  <p style="margin:0 0 14px;color:#d8d3d5;font-size:14px;line-height:1.55;">Nauti-Labs builds paper-first trading bots with Clearance approval gates, Telegram decisions, risk limits, audit logs, and a kill switch. Default rate: <strong>$125/hr</strong>, <strong>10-hour minimum</strong>. If the scope or budget needs a conversation, reply and we can talk through it.</p>
                  <a href="{html.escape(build_url)}" style="color:#f59e0b;text-decoration:none;font-weight:800;font-size:14px;">request a trading bot build →</a>
                </div>
                <p style="margin:0;color:#a9a3a5;font-size:14px;line-height:1.6;">agent proposes. human approves. service verifies.</p>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 30px;border-top:1px solid rgba(255,255,255,0.09);color:#6f696c;font-size:12px;line-height:1.5;">
                Nauti-Labs / Clearance<br>
                support: <a href="mailto:{html.escape(PAYMENT_SUPPORT_EMAIL)}" style="color:#a9a3a5;">{html.escape(PAYMENT_SUPPORT_EMAIL)}</a>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""


def welcome_email_preview() -> dict:
    return {
        "subject": welcome_email_subject(),
        "text": welcome_email_text_body(),
        "html": welcome_email_html_body(),
    }


async def send_free_signup_notifications(
    *,
    email: str,
    name: str | None,
    ref: str | None,
    key_id: str,
    created_at: str,
) -> None:
    if SIGNUP_NOTIFY_EMAIL:
        sent = await send_email(
            SIGNUP_NOTIFY_EMAIL,
            f"New Clearance free signup: {email}",
            free_signup_admin_email(
                email=email,
                name=name,
                ref=ref,
                key_id=key_id,
                created_at=created_at,
            ),
        )
        if not sent:
            print(f"[mail] signup admin notification not sent for {key_id}: SMTP not configured or failed")

    if WELCOME_EMAILS_ENABLED:
        sent = await send_email(
            email,
            welcome_email_subject(),
            welcome_email_text_body(),
            welcome_email_html_body(),
        )
        if not sent:
            print(f"[mail] welcome email not sent for {key_id}: SMTP not configured or failed")


def ambassador_request_email_text(
    *,
    request_id: str,
    handle: str,
    audience: str,
    note: str,
    source: str,
    created_at: str,
    ip: str,
    user_agent: str,
) -> str:
    admin_url = f"{BASE_URL.rstrip('/')}/nauti-traffic"
    return (
        "New Clearance ambassador request\n\n"
        f"Handle: {handle}\n"
        f"Audience: {audience or 'not provided'}\n"
        f"Note: {note or 'not provided'}\n"
        f"Source: {source}\n"
        f"Status: new\n"
        f"Request ID: {request_id}\n"
        f"Created: {created_at}\n"
        f"IP: {ip or 'unknown'}\n"
        f"User agent: {user_agent or 'unknown'}\n\n"
        f"Traffic board: {admin_url}\n"
    )


async def send_ambassador_request_notification(
    *,
    request_id: str,
    handle: str,
    audience: str,
    note: str,
    source: str,
    created_at: str,
    ip: str,
    user_agent: str,
) -> None:
    if not AMBASSADOR_REQUEST_NOTIFY_EMAIL:
        return
    sent = await send_email(
        AMBASSADOR_REQUEST_NOTIFY_EMAIL,
        f"New Clearance ambassador request: {handle}",
        ambassador_request_email_text(
            request_id=request_id,
            handle=handle,
            audience=audience,
            note=note,
            source=source,
            created_at=created_at,
            ip=ip,
            user_agent=user_agent,
        ),
    )
    if not sent:
        print(f"[mail] ambassador request notification not sent for {request_id}: SMTP not configured or failed")


def make_clearance_token(clearance_id: str, scope: str, budget_amount: float | None,
                         budget_currency: str | None, expires_at: str) -> str:
    payload = {
        "clearance_id": clearance_id,
        "scope": scope,
        "budget_amount": budget_amount,
        "budget_currency": budget_currency,
        "approved_at": now_iso(),
        "expires_at": expires_at,
        "iss": TOKEN_ISSUER,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> dict:
    db = await get_db()
    try:
        key_hash = hash_key(x_api_key)
        cursor = await db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1", (key_hash,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")

        # Check if credits need reset (monthly)
        reset_at = datetime.fromisoformat(row["credits_reset_at"])
        if datetime.now(timezone.utc) >= reset_at:
            new_reset = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            limit = TIER_LIMITS.get(row["tier"], 50)
            await db.execute(
                "UPDATE api_keys SET credits_remaining = ?, credits_reset_at = ? WHERE id = ?",
                (limit, new_reset, row["id"])
            )
            await db.commit()
            cursor = await db.execute("SELECT * FROM api_keys WHERE id = ?", (row["id"],))
            row = await cursor.fetchone()

        return dict(row)
    finally:
        await db.close()


async def fulfill_paid_tier(
    *,
    email: str,
    tier: str,
    amount: float,
    currency: str,
    provider: str,
    provider_ref: str,
    metadata: dict | None = None,
    referred_by: str | None = None,
) -> dict:
    """Issue or upgrade a key after a payment provider has already verified funds."""
    if tier not in TIER_PRICES:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Choose: {list(TIER_PRICES.keys())}")

    db = await get_db()
    notifications = []
    try:
        cursor = await db.execute(
            "SELECT id, api_key_id, tier FROM payments WHERE provider = ? AND provider_ref = ?",
            (provider, provider_ref),
        )
        existing_payment = await cursor.fetchone()
        if existing_payment:
            return {
                "status": "already_fulfilled",
                "tier": existing_payment["tier"],
                "payment_id": existing_payment["id"],
                "message": "Payment was already fulfilled.",
            }

        payment_id = generate_id("pay")
        key_id = generate_id("key")
        raw_key = f"clr_live_{secrets.token_urlsafe(32)}"
        key_h = hash_key(raw_key)
        reset_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        credits = TIER_LIMITS.get(tier, 50)

        cursor = await db.execute(
            "SELECT id FROM api_keys WHERE email = ? AND active = 1", (email,)
        )
        existing_key = await cursor.fetchone()

        if existing_key:
            await db.execute(
                "UPDATE api_keys SET tier = ?, credits_remaining = ?, credits_reset_at = ? WHERE id = ?",
                (tier, credits, reset_at, existing_key["id"]),
            )
            api_key_id = existing_key["id"]
            response = {
                "status": "verified",
                "message": f"Payment verified. Account upgraded to {tier}.",
                "tier": tier,
                "credits": credits,
                "payment_id": payment_id,
            }
        else:
            await db.execute(
                """INSERT INTO api_keys (id, key_hash, email, tier, credits_remaining, credits_reset_at, created_at, referred_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (key_id, key_h, email, tier, credits, reset_at, now_iso(), _validate_ref(referred_by)),
            )
            api_key_id = key_id
            response = {
                "status": "verified",
                "api_key": raw_key,
                "tier": tier,
                "credits": credits,
                "payment_id": payment_id,
                "message": "Payment verified. API key issued. Store it securely — it won't be shown again.",
            }

        await db.execute(
            """INSERT INTO payments
               (id, api_key_id, email, amount, currency, crypto_currency, tx_hash, status,
                tier, provider, provider_ref, created_at, completed_at, metadata, referred_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                payment_id,
                api_key_id,
                email,
                amount,
                currency,
                "USDC" if provider == "base_usdc" else None,
                provider_ref if provider == "base_usdc" else None,
                "verified",
                tier,
                provider,
                provider_ref,
                now_iso(),
                now_iso(),
                json.dumps(metadata or {}),
                _validate_ref(referred_by),
            ),
        )
        await db.execute(
            "INSERT INTO audit_log (api_key_id, event, actor, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                api_key_id,
                "payment.verified",
                email,
                json.dumps({"provider": provider, "provider_ref": provider_ref, **(metadata or {})}),
                now_iso(),
            ),
        )
        await db.commit()
        return response
    finally:
        await db.close()


def get_family_users() -> dict[str, dict]:
    return {
        "justin": {
            "display_name": "Justin",
            "passcode": os.getenv("FAMILY_JUSTIN_PASSCODE", ""),
            "role": "co-steward",
        },
        "nicole": {
            "display_name": "Nicole",
            "passcode": os.getenv("FAMILY_NICOLE_PASSCODE", ""),
            "role": "co-steward",
        },
    }


def _family_session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=FAMILY_SESSION_HOURS)).isoformat()


def make_family_session_token(username: str, display_name: str) -> str:
    return jwt.encode(
        {
            "sub": username,
            "display_name": display_name,
            "scope": "family.dashboard",
            "issued_at": now_iso(),
            "expires_at": _family_session_expiry(),
            "iss": TOKEN_ISSUER,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def authenticate_family_user(credentials: FamilyLogin) -> dict:
    users = get_family_users()
    user = users.get(credentials.username.strip().lower())
    if not user or not user["passcode"]:
        raise HTTPException(status_code=401, detail="Family access is not configured for this user")

    if not secrets.compare_digest(credentials.passcode, user["passcode"]):
        raise HTTPException(status_code=401, detail="Incorrect passcode")

    return {
        "username": credentials.username.strip().lower(),
        "display_name": user["display_name"],
        "role": user["role"],
    }


def decode_family_session(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("scope") != "family.dashboard":
        raise JWTError("Invalid session scope")
    return payload


async def get_family_user(request: Request) -> dict:
    token = request.cookies.get(FAMILY_SESSION_COOKIE)
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Family login required")

    try:
        payload = decode_family_session(token)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired family session") from exc

    return {
        "username": payload.get("sub"),
        "display_name": payload.get("display_name"),
    }


def _agent_income_session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=AGENT_INCOME_SESSION_HOURS)).isoformat()


def make_agent_income_session_token() -> str:
    return jwt.encode(
        {
            "sub": "agent-income",
            "display_name": "Agent Income Operator",
            "scope": "agent_income.dashboard",
            "issued_at": now_iso(),
            "expires_at": _agent_income_session_expiry(),
            "iss": TOKEN_ISSUER,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_agent_income_session(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("scope") != "agent_income.dashboard":
        raise JWTError("Invalid session scope")
    expires_at = datetime.fromisoformat(str(payload.get("expires_at", "")).replace("Z", "+00:00"))
    if expires_at <= datetime.now(timezone.utc):
        raise JWTError("Agent Income session expired")
    return payload


async def get_agent_income_user(request: Request) -> dict:
    token = request.cookies.get(AGENT_INCOME_SESSION_COOKIE)
    if not token:
        try:
            family_user = await get_family_user(request)
            return {
                "username": family_user.get("username") or "family",
                "display_name": family_user.get("display_name") or "Family Operator",
            }
        except HTTPException:
            pass

        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Agent Income login required")

    try:
        payload = decode_agent_income_session(token)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired Agent Income session") from exc

    return {
        "username": payload.get("sub"),
        "display_name": payload.get("display_name") or "Agent Income Operator",
    }


def _bot_comm_session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=BOT_COMM_SESSION_HOURS)).isoformat()


def make_bot_comm_session_token() -> str:
    return jwt.encode(
        {
            "sub": "bot-comm",
            "display_name": "Bot-Comm Operator",
            "scope": "bot_comm.dashboard",
            "issued_at": now_iso(),
            "expires_at": _bot_comm_session_expiry(),
            "iss": TOKEN_ISSUER,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_bot_comm_session(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("scope") != "bot_comm.dashboard":
        raise JWTError("Invalid session scope")
    expires_at = datetime.fromisoformat(str(payload.get("expires_at", "")).replace("Z", "+00:00"))
    if expires_at <= datetime.now(timezone.utc):
        raise JWTError("Bot-Comm session expired")
    return payload


async def get_bot_comm_user(request: Request) -> dict:
    token = request.cookies.get(BOT_COMM_SESSION_COOKIE)
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Bot-Comm login required")

    try:
        payload = decode_bot_comm_session(token)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired Bot-Comm session") from exc

    return {
        "username": payload.get("sub"),
        "display_name": payload.get("display_name") or "Bot-Comm Operator",
    }


async def require_sync_token(x_family_sync_token: str = Header(..., alias="X-Family-Sync-Token")) -> str:
    if not FAMILY_SYNC_TOKEN:
        raise HTTPException(status_code=503, detail="FAMILY_SYNC_TOKEN is not configured")
    if not secrets.compare_digest(x_family_sync_token, FAMILY_SYNC_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid family sync token")
    return x_family_sync_token


def parse_iso_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if len(value) == 10:
            value = f"{value}T23:59:59+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def money(value: float | None) -> float:
    return round(float(value or 0), 2)


def monthly_cost(amount: float, cycle: str) -> float:
    normalized = (cycle or "monthly").lower()
    if normalized == "weekly":
        return amount * 52 / 12
    if normalized == "yearly":
        return amount / 12
    if normalized == "quarterly":
        return amount / 3
    return amount


async def _fetch_all_dicts(db, query: str, params=()) -> list[dict]:
    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


def _recommend_subscription(subscription: dict) -> str | None:
    if subscription.get("recommendation"):
        return subscription["recommendation"]

    amount = float(subscription.get("amount") or 0)
    merchant = (subscription.get("merchant") or "").lower()
    if amount >= 25:
        return "High monthly cost. Confirm the household still uses this service."
    if "ai" in merchant or "chat" in merchant:
        return "AI spend detected. Check for overlapping tools before the next renewal."
    return None


def _score_alert_label(score: int) -> str:
    if score >= 760:
        return "excellent"
    if score >= 700:
        return "good"
    if score >= 640:
        return "watch"
    return "urgent"


async def build_family_dashboard() -> dict:
    db = await get_db()
    try:
        accounts = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_accounts ORDER BY updated_at DESC, institution ASC, name ASC",
        )
        bills = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_bills ORDER BY due_date ASC, amount DESC",
        )
        debts = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_debts WHERE status != 'closed' ORDER BY balance ASC, creditor ASC",
        )
        subscriptions = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_subscriptions WHERE status = 'active' ORDER BY amount DESC, merchant ASC",
        )
        goals = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_goals WHERE status = 'active' ORDER BY updated_at DESC, name ASC",
        )
        credit_scores = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_credit_scores ORDER BY updated_at DESC, person_name ASC",
        )
        alerts = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_alerts WHERE status = 'open' ORDER BY updated_at DESC, severity DESC",
        )
        payees = await _fetch_all_dicts(
            db,
            "SELECT * FROM approved_payees WHERE active = 1 ORDER BY name ASC",
        )
        actions = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_actions ORDER BY created_at DESC",
        )
        sources = await _fetch_all_dicts(
            db,
            "SELECT * FROM family_sources ORDER BY name ASC",
        )
    finally:
        await db.close()

    now = datetime.now(timezone.utc)
    next_seven_days = now + timedelta(days=7)
    next_fourteen_days = now + timedelta(days=14)

    total_balance = money(sum(float(item.get("balance") or 0) for item in accounts if item.get("status") == "active"))
    available_cash = money(sum(float(item.get("available") if item.get("available") is not None else item.get("balance") or 0) for item in accounts if item.get("account_type") in {"checking", "savings", "cash"}))
    upcoming_bills = []
    overdue_bills = []
    for bill in bills:
        due_date = parse_iso_date(bill.get("due_date"))
        if not due_date:
            continue
        if bill.get("status") in {"paid", "canceled"}:
            continue
        if due_date < now:
            overdue_bills.append(bill)
        if due_date <= next_fourteen_days:
            upcoming_bills.append(bill)

    monthly_subscriptions = money(sum(monthly_cost(float(item.get("amount") or 0), item.get("billing_cycle") or "monthly") for item in subscriptions))
    open_debt_balance = money(sum(float(item.get("balance") or 0) for item in debts))
    minimum_debt_payments = money(sum(float(item.get("minimum_payment") or 0) for item in debts))
    upcoming_bills_total = money(sum(float(item.get("amount") or 0) for item in upcoming_bills))
    overdue_total = money(sum(float(item.get("amount") or 0) for item in overdue_bills))

    debt_snowball = []
    extra_payment_cursor = available_cash - (upcoming_bills_total + minimum_debt_payments)
    for debt in debts:
        debt_snowball.append(
            {
                "creditor": debt["creditor"],
                "balance": money(debt.get("balance")),
                "minimum_payment": money(debt.get("minimum_payment")),
                "apr": debt.get("apr"),
                "recommended_extra_payment": money(max(extra_payment_cursor, 0)) if debt == debts[0] else 0,
            }
        )
        extra_payment_cursor = 0

    goals_summary = []
    for goal in goals:
        target_amount = float(goal.get("target_amount") or 0)
        current_amount = float(goal.get("current_amount") or 0)
        progress = round((current_amount / target_amount) * 100, 1) if target_amount else 0
        goals_summary.append(
            {
                **goal,
                "target_amount": money(target_amount),
                "current_amount": money(current_amount),
                "progress_percent": progress,
            }
        )

    score_cards = []
    latest_scores: dict[tuple[str, str], dict] = {}
    for score in credit_scores:
        key = (score["person_name"], score["bureau"])
        latest_scores.setdefault(key, score)
    for score in latest_scores.values():
        score_cards.append(
            {
                **score,
                "label": _score_alert_label(int(score["score"])),
            }
        )

    approval_queue = []
    for action in actions:
        action["amount"] = money(action.get("amount"))
        approval_queue.append(action)

    active_alerts = []
    for alert in alerts:
        active_alerts.append(
            {
                **alert,
                "updated_at_display": parse_iso_date(alert.get("updated_at")).astimezone().strftime("%b %d, %I:%M %p")
                if parse_iso_date(alert.get("updated_at"))
                else alert.get("updated_at"),
            }
        )

    subscription_watch = []
    for subscription in subscriptions:
        recommendation = _recommend_subscription(subscription)
        if recommendation:
            subscription_watch.append(
                {
                    **subscription,
                    "monthly_cost": money(monthly_cost(float(subscription.get("amount") or 0), subscription.get("billing_cycle") or "monthly")),
                    "recommendation": recommendation,
                }
            )

    last_sync_at = max(
        [source["last_synced_at"] for source in sources if source.get("last_synced_at")] + [None],
        key=lambda value: value or "",
    )

    return {
        "household": FAMILY_HOUSEHOLD_NAME,
        "product_name": FAMILY_PRODUCT_NAME,
        "generated_at": now_iso(),
        "metrics": {
            "total_balance": total_balance,
            "available_cash": available_cash,
            "upcoming_bills_total": upcoming_bills_total,
            "overdue_total": overdue_total,
            "monthly_subscriptions": monthly_subscriptions,
            "open_debt_balance": open_debt_balance,
            "minimum_debt_payments": minimum_debt_payments,
            "approval_queue_count": len([item for item in actions if item.get("status") == "pending_human_approval"]),
        },
        "sources": sources,
        "accounts": accounts,
        "bills_due_soon": upcoming_bills[:8],
        "bills_overdue": overdue_bills[:8],
        "debts": debt_snowball,
        "goals": goals_summary,
        "credit_scores": score_cards,
        "alerts": active_alerts[:8],
        "subscriptions": subscription_watch[:8],
        "approved_payees": payees,
        "approval_queue": approval_queue[:12],
        "last_sync_at": last_sync_at,
        "health": {
            "funding_buffer": money(available_cash - upcoming_bills_total),
            "is_live": bool(last_sync_at and parse_iso_date(last_sync_at) and parse_iso_date(last_sync_at) >= now - timedelta(minutes=5)),
            "next_action": "Human approval required before any release"
            if any(item.get("status") == "pending_human_approval" for item in actions)
            else "No queued releases right now",
        },
    }


async def upsert_family_snapshot(payload: FamilySyncPayload) -> dict:
    db = await get_db()
    now = now_iso()
    try:
        for source in payload.sources:
            source_id = f"src_{source.source_key}"
            await db.execute(
                """INSERT INTO family_sources (id, source_key, name, kind, status, last_synced_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key) DO UPDATE SET
                       name = excluded.name,
                       kind = excluded.kind,
                       status = excluded.status,
                       last_synced_at = excluded.last_synced_at,
                       metadata = excluded.metadata""",
                (
                    source_id,
                    source.source_key,
                    source.name,
                    source.kind,
                    source.status,
                    now,
                    json.dumps(source.metadata) if source.metadata else None,
                ),
            )

        for account in payload.accounts:
            account_id = f"acct_{account.source_key}_{account.external_id}"
            await db.execute(
                """INSERT INTO family_accounts
                   (id, source_key, external_id, institution, name, account_type, subtype, last4,
                    balance, available, currency, status, is_live, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key, external_id) DO UPDATE SET
                       institution = excluded.institution,
                       name = excluded.name,
                       account_type = excluded.account_type,
                       subtype = excluded.subtype,
                       last4 = excluded.last4,
                       balance = excluded.balance,
                       available = excluded.available,
                       currency = excluded.currency,
                       status = excluded.status,
                       is_live = excluded.is_live,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    account_id,
                    account.source_key,
                    account.external_id,
                    account.institution,
                    account.name,
                    account.account_type,
                    account.subtype,
                    account.last4,
                    account.balance,
                    account.available,
                    account.currency,
                    account.status,
                    int(account.is_live),
                    now,
                    json.dumps(account.metadata) if account.metadata else None,
                ),
            )

        for bill in payload.bills:
            bill_id = f"bill_{bill.source_key}_{bill.external_id}"
            await db.execute(
                """INSERT INTO family_bills
                   (id, source_key, external_id, payee, category, amount, minimum_due, due_date,
                    autopay_enabled, status, debtor_account, notes, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key, external_id) DO UPDATE SET
                       payee = excluded.payee,
                       category = excluded.category,
                       amount = excluded.amount,
                       minimum_due = excluded.minimum_due,
                       due_date = excluded.due_date,
                       autopay_enabled = excluded.autopay_enabled,
                       status = excluded.status,
                       debtor_account = excluded.debtor_account,
                       notes = excluded.notes,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    bill_id,
                    bill.source_key,
                    bill.external_id,
                    bill.payee,
                    bill.category,
                    bill.amount,
                    bill.minimum_due,
                    bill.due_date,
                    int(bill.autopay_enabled),
                    bill.status,
                    bill.debtor_account,
                    bill.notes,
                    now,
                    json.dumps(bill.metadata) if bill.metadata else None,
                ),
            )

        for debt in payload.debts:
            debt_id = f"debt_{debt.source_key}_{debt.external_id}"
            await db.execute(
                """INSERT INTO family_debts
                   (id, source_key, external_id, creditor, balance, apr, minimum_payment, due_date, status, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key, external_id) DO UPDATE SET
                       creditor = excluded.creditor,
                       balance = excluded.balance,
                       apr = excluded.apr,
                       minimum_payment = excluded.minimum_payment,
                       due_date = excluded.due_date,
                       status = excluded.status,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    debt_id,
                    debt.source_key,
                    debt.external_id,
                    debt.creditor,
                    debt.balance,
                    debt.apr,
                    debt.minimum_payment,
                    debt.due_date,
                    debt.status,
                    now,
                    json.dumps(debt.metadata) if debt.metadata else None,
                ),
            )

        for subscription in payload.subscriptions:
            subscription_id = f"sub_{subscription.source_key}_{subscription.external_id}"
            await db.execute(
                """INSERT INTO family_subscriptions
                   (id, source_key, external_id, merchant, amount, billing_cycle, next_charge_date, status, recommendation, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key, external_id) DO UPDATE SET
                       merchant = excluded.merchant,
                       amount = excluded.amount,
                       billing_cycle = excluded.billing_cycle,
                       next_charge_date = excluded.next_charge_date,
                       status = excluded.status,
                       recommendation = excluded.recommendation,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    subscription_id,
                    subscription.source_key,
                    subscription.external_id,
                    subscription.merchant,
                    subscription.amount,
                    subscription.billing_cycle,
                    subscription.next_charge_date,
                    subscription.status,
                    subscription.recommendation,
                    now,
                    json.dumps(subscription.metadata) if subscription.metadata else None,
                ),
            )

        for goal in payload.goals:
            goal_id = f"goal_{hash_key(goal.name)[:20]}"
            await db.execute(
                """INSERT INTO family_goals
                   (id, name, target_amount, current_amount, target_date, status, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       target_amount = excluded.target_amount,
                       current_amount = excluded.current_amount,
                       target_date = excluded.target_date,
                       status = excluded.status,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    goal_id,
                    goal.name,
                    goal.target_amount,
                    goal.current_amount,
                    goal.target_date,
                    goal.status,
                    now,
                    json.dumps(goal.metadata) if goal.metadata else None,
                ),
            )

        for score in payload.credit_scores:
            score_id = f"score_{score.source_key}_{hash_key(score.person_name + score.bureau)[:16]}"
            await db.execute(
                """INSERT INTO family_credit_scores
                   (id, person_name, bureau, score, source_key, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       person_name = excluded.person_name,
                       bureau = excluded.bureau,
                       score = excluded.score,
                       source_key = excluded.source_key,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    score_id,
                    score.person_name,
                    score.bureau,
                    score.score,
                    score.source_key,
                    now,
                    json.dumps(score.metadata) if score.metadata else None,
                ),
            )

        for alert in payload.alerts:
            alert_id = f"alert_{alert.source_key}_{hash_key(alert.title + alert.alert_type)[:16]}"
            await db.execute(
                """INSERT INTO family_alerts
                   (id, source_key, alert_type, severity, title, detail, status, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       source_key = excluded.source_key,
                       alert_type = excluded.alert_type,
                       severity = excluded.severity,
                       title = excluded.title,
                       detail = excluded.detail,
                       status = excluded.status,
                       updated_at = excluded.updated_at,
                       metadata = excluded.metadata""",
                (
                    alert_id,
                    alert.source_key,
                    alert.alert_type,
                    alert.severity,
                    alert.title,
                    alert.detail,
                    alert.status,
                    now,
                    json.dumps(alert.metadata) if alert.metadata else None,
                ),
            )

        synced_sources = {item.source_key for item in payload.sources}
        synced_sources.update(item.source_key for item in payload.accounts)
        synced_sources.update(item.source_key for item in payload.bills)
        synced_sources.update(item.source_key for item in payload.debts)
        synced_sources.update(item.source_key for item in payload.subscriptions)
        synced_sources.update(item.source_key for item in payload.credit_scores)
        synced_sources.update(item.source_key for item in payload.alerts)

        for source_key in synced_sources:
            await db.execute(
                """INSERT INTO family_sources (id, source_key, name, kind, status, last_synced_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(source_key) DO NOTHING""",
                (
                    f"src_{source_key}",
                    source_key,
                    source_key.replace("_", " ").title(),
                    "agent_sync",
                    "connected",
                    now,
                    None,
                ),
            )
            await db.execute(
                """UPDATE family_sources
                   SET last_synced_at = ?,
                       status = CASE
                           WHEN status IS NULL OR status = '' OR status = 'setup_needed' THEN 'connected'
                           ELSE status
                       END
                   WHERE source_key = ?""",
                (now, source_key),
            )
            await db.execute(
                """INSERT INTO family_sync_events (source_key, actor, snapshot_kind, counts, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    source_key,
                    payload.actor,
                    "family_snapshot",
                    json.dumps(
                        {
                            "accounts": len(payload.accounts),
                            "bills": len(payload.bills),
                            "debts": len(payload.debts),
                            "subscriptions": len(payload.subscriptions),
                            "goals": len(payload.goals),
                            "credit_scores": len(payload.credit_scores),
                            "alerts": len(payload.alerts),
                        }
                    ),
                    now,
                ),
            )

        await db.commit()
        return {
            "status": "ok",
            "synced_at": now,
            "counts": {
                "sources": len(payload.sources),
                "accounts": len(payload.accounts),
                "bills": len(payload.bills),
                "debts": len(payload.debts),
                "subscriptions": len(payload.subscriptions),
                "goals": len(payload.goals),
                "credit_scores": len(payload.credit_scores),
                "alerts": len(payload.alerts),
            },
        }
    finally:
        await db.close()


# --- API Key Management ---

@app.post("/v1/keys", response_model=APIKeyResponse, tags=["Authentication"])
async def create_api_key(body: CreateAPIKey, request: Request):
    """Create a new API key. Starts on the free Starter tier (50 clearances/month)."""
    db = await get_db()
    try:
        email = str(body.email).strip().lower()
        if not EMAIL_PATTERN.match(email):
            raise HTTPException(status_code=400, detail="A valid email is required")
        name = body.name.strip() if body.name else None
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent")
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=FREE_KEY_SIGNUP_WINDOW_MINUTES)).isoformat()

        cursor = await db.execute(
            "SELECT id, tier FROM api_keys WHERE email = ? AND active = 1",
            (email,)
        )
        existing = await cursor.fetchone()
        if existing:
            raise HTTPException(
                status_code=409,
                detail="An active API key already exists for this email. Use your existing key or upgrade the same account."
            )

        cursor = await db.execute(
            """SELECT COUNT(*) AS signup_count
               FROM audit_log
               WHERE event = 'key.created'
                 AND ip = ?
                 AND created_at >= ?""",
            (client_ip, cutoff)
        )
        signup_count = (await cursor.fetchone())["signup_count"]
        if signup_count >= FREE_KEY_SIGNUP_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Too many free key signups from this IP right now. Please try again later or email support."
            )

        key_id = generate_id("key")
        raw_key = f"clr_live_{secrets.token_urlsafe(32)}"
        key_h = hash_key(raw_key)
        reset_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        created_at = now_iso()

        # Ambassador attribution: read the visit cookie set by /r/{name} or ?ref=.
        ref = _read_ref_cookie(request)

        await db.execute(
            """INSERT INTO api_keys (id, key_hash, email, name, tier, credits_remaining, credits_reset_at, created_at, referred_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (key_id, key_h, email, name, "starter", 50, reset_at, created_at, ref)
        )
        await db.commit()

        await db.execute(
            """INSERT INTO audit_log (api_key_id, event, actor, ip, user_agent, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                key_id,
                "key.created",
                email,
                client_ip,
                user_agent,
                json.dumps({"tier": "starter", "referred_by": ref}),
                created_at,
            )
        )
        await db.commit()

        asyncio.create_task(send_free_signup_notifications(
            email=email,
            name=name,
            ref=ref,
            key_id=key_id,
            created_at=created_at,
        ))

        return APIKeyResponse(
            api_key=raw_key,
            tier=Tier.starter,
            credits_remaining=50,
            message="Store this key securely — it won't be shown again."
        )
    finally:
        await db.close()


# --- Telegram helpers ---

async def telegram_call(method: str, payload: dict) -> dict | None:
    """Call Telegram Bot API without blocking clearance creation."""
    if not TELEGRAM_BOT_TOKEN:
        return None

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.post(url, json=payload)
        if response.status_code >= 400:
            print(f"[telegram] HTTP {response.status_code} on {method}: {response.text[:300]}")
            return None
        return response.json()
    except Exception as exc:
        print(f"[telegram] error on {method}: {exc}")
        return None


def telegram_format_message(
    *,
    clearance_id: str,
    title: str,
    description: str | None,
    scope: str,
    budget_amount: float | None,
    budget_currency: str | None,
    expires_at: str,
) -> str:
    lines = [
        "<b>Clearance Request</b>",
        "",
        f"<b>{html.escape(title)}</b>",
    ]
    if description:
        snippet = description[:280] + "..." if len(description) > 280 else description
        lines.append(html.escape(snippet))
    lines.extend([
        "",
        f"<b>Scope:</b> <code>{html.escape(scope)}</code>",
    ])
    if budget_amount is not None:
        lines.append(f"<b>Budget:</b> {budget_amount} {html.escape(budget_currency or 'USD')}")
    lines.extend([
        f"<b>Expires:</b> {html.escape(expires_at)}",
        "",
        f"<i>Clearance {html.escape(clearance_id[:16])}...</i>",
    ])
    return "\n".join(lines)


async def send_clearance_telegram_notification(
    *,
    clearance_id: str,
    title: str,
    description: str | None,
    scope: str,
    budget_amount: float | None,
    budget_currency: str | None,
    expires_at: str,
    approval_url: str,
) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": telegram_format_message(
            clearance_id=clearance_id,
            title=title,
            description=description,
            scope=scope,
            budget_amount=budget_amount,
            budget_currency=budget_currency,
            expires_at=expires_at,
        ),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {
            "inline_keyboard": [[
                {"text": "Approve", "callback_data": f"clr_approve:{clearance_id}"},
                {"text": "Deny", "callback_data": f"clr_deny:{clearance_id}"},
            ], [
                {"text": "Open in browser", "url": approval_url},
            ]],
        },
    }
    await telegram_call("sendMessage", payload)


async def send_clearance_telegram_decision(
    *,
    clearance_id: str,
    title: str,
    status: str,
    actor: str,
    note: str | None,
) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    lines = [
        f"<b>Clearance {html.escape(status.upper())}</b>",
        "",
        f"<b>{html.escape(title)}</b>",
        f"<b>ID:</b> <code>{html.escape(clearance_id)}</code>",
        f"<b>By:</b> {html.escape(actor)}",
    ]
    if note:
        lines.append(f"<b>Note:</b> {html.escape(note)}")

    await telegram_call(
        "sendMessage",
        {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "\n".join(lines),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
    )


# --- Clearance CRUD ---

@app.post("/v1/clearances", response_model=ClearanceResponse, status_code=201, tags=["Clearances"])
async def create_clearance(body: CreateClearance, api_key: dict = Depends(get_api_key)):
    """
    Create a clearance request. Returns an approval URL for a human to approve or deny.

    The agent should present the approval_url to the authorizing human, then poll
    GET /v1/clearances/{id} or listen on the callback_url for the decision.
    """
    if api_key["credits_remaining"] <= 0:
        raise HTTPException(
            status_code=402,
            detail=f"No credits remaining. Upgrade from {api_key['tier']} tier or wait for monthly reset."
        )

    db = await get_db()
    try:
        clr_id = generate_id("clr")
        created = now_iso()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=body.expires_in or 3600)).isoformat()
        approval_url = f"{BASE_URL}/approve/{clr_id}"

        await db.execute(
            """INSERT INTO clearances
               (id, api_key_id, title, description, scope, budget_amount, budget_currency,
                status, approval_url, callback_url, metadata, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (clr_id, api_key["id"], body.title, body.description, body.scope,
             body.budget_amount, body.budget_currency, "pending",
             approval_url, body.callback_url, json.dumps(body.metadata) if body.metadata else None,
             created, expires)
        )

        # Decrement credits
        await db.execute(
            "UPDATE api_keys SET credits_remaining = credits_remaining - 1 WHERE id = ?",
            (api_key["id"],)
        )
        await db.commit()

        await db.execute(
            "INSERT INTO audit_log (clearance_id, api_key_id, event, created_at) VALUES (?, ?, ?, ?)",
            (clr_id, api_key["id"], "clearance.created", now_iso())
        )
        await db.commit()

        try:
            await send_clearance_telegram_notification(
                clearance_id=clr_id,
                title=body.title,
                description=body.description,
                scope=body.scope,
                budget_amount=body.budget_amount,
                budget_currency=body.budget_currency,
                expires_at=expires,
                approval_url=approval_url,
            )
        except Exception as exc:
            print(f"[telegram] notification failed for {clr_id}: {exc}")

        return ClearanceResponse(
            id=clr_id,
            status=ClearanceStatus.pending,
            title=body.title,
            description=body.description,
            scope=body.scope,
            budget_amount=body.budget_amount,
            budget_currency=body.budget_currency,
            approval_url=approval_url,
            callback_url=body.callback_url,
            metadata=body.metadata,
            created_at=created,
            expires_at=expires,
            decided_at=None,
        )
    finally:
        await db.close()


@app.get("/v1/clearances/{clearance_id}", response_model=ClearanceResponse, tags=["Clearances"])
async def get_clearance(clearance_id: str, api_key: dict = Depends(get_api_key)):
    """Check the status of a clearance request. Poll this until status is approved or denied."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM clearances WHERE id = ? AND api_key_id = ?",
            (clearance_id, api_key["id"])
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Clearance not found")

        row = dict(row)

        # Check expiry
        if row["status"] == "pending":
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) >= expires:
                await db.execute(
                    "UPDATE clearances SET status = 'expired' WHERE id = ?", (clearance_id,)
                )
                await db.commit()
                row["status"] = "expired"

        return ClearanceResponse(
            id=row["id"],
            status=ClearanceStatus(row["status"]),
            title=row["title"],
            description=row["description"],
            scope=row["scope"],
            budget_amount=row["budget_amount"],
            budget_currency=row["budget_currency"],
            approval_url=row["approval_url"],
            token=row["token"] if row["status"] == "approved" else None,
            callback_url=row["callback_url"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else None,
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_at=row["decided_at"],
        )
    finally:
        await db.close()


@app.get("/v1/clearances", tags=["Clearances"])
async def list_clearances(
    status: ClearanceStatus | None = None,
    limit: int = 50,
    api_key: dict = Depends(get_api_key)
):
    """List all clearances for this API key, optionally filtered by status."""
    db = await get_db()
    try:
        if status:
            cursor = await db.execute(
                "SELECT * FROM clearances WHERE api_key_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?",
                (api_key["id"], status.value, limit)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM clearances WHERE api_key_id = ? ORDER BY created_at DESC LIMIT ?",
                (api_key["id"], limit)
            )
        rows = await cursor.fetchall()

        results = []
        for row in rows:
            row = dict(row)
            results.append(ClearanceResponse(
                id=row["id"],
                status=ClearanceStatus(row["status"]),
                title=row["title"],
                description=row["description"],
                scope=row["scope"],
                budget_amount=row["budget_amount"],
                budget_currency=row["budget_currency"],
                approval_url=row["approval_url"],
                token=row["token"] if row["status"] == "approved" else None,
                callback_url=row["callback_url"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else None,
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                decided_at=row["decided_at"],
            ))
        return results
    finally:
        await db.close()


# --- Human Approval ---

@app.post("/v1/clearances/{clearance_id}/decide", tags=["Approval"])
async def decide_clearance(clearance_id: str, body: ApproveAction, request: Request):
    """Approve or deny a clearance request. Called by the human approver."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM clearances WHERE id = ?", (clearance_id,)
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Clearance not found")

        row = dict(row)
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"Clearance already {row['status']}")

        # Check expiry
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) >= expires:
            await db.execute(
                "UPDATE clearances SET status = 'expired' WHERE id = ?", (clearance_id,)
            )
            await db.commit()
            raise HTTPException(status_code=410, detail="Clearance has expired")

        decided_at = now_iso()
        token = None

        if body.approved:
            new_status = "approved"
            token = make_clearance_token(
                clearance_id, row["scope"], row["budget_amount"],
                row["budget_currency"], row["expires_at"]
            )
        else:
            new_status = "denied"

        await db.execute(
            """UPDATE clearances SET status = ?, token = ?, decided_at = ?,
               decision_note = ? WHERE id = ?""",
            (new_status, token, decided_at, body.note, clearance_id)
        )
        await db.commit()

        client_ip = request.client.host if request.client else "unknown"
        await db.execute(
            """INSERT INTO audit_log (clearance_id, api_key_id, event, actor, ip, user_agent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (clearance_id, row["api_key_id"], f"clearance.{new_status}",
             "human_approver", client_ip, request.headers.get("user-agent"), now_iso())
        )
        await db.commit()

        try:
            await send_clearance_telegram_decision(
                clearance_id=clearance_id,
                title=row["title"],
                status=new_status,
                actor="browser",
                note=body.note,
            )
        except Exception as exc:
            print(f"[telegram] decision notification failed for {clearance_id}: {exc}")

        return {
            "id": clearance_id,
            "status": new_status,
            "decided_at": decided_at,
            "token": token,
        }
    finally:
        await db.close()


# --- Telegram webhook ---

async def _telegram_answer(callback_id: str | None, text: str, show_alert: bool = False) -> None:
    if not callback_id:
        return
    await telegram_call(
        "answerCallbackQuery",
        {
            "callback_query_id": callback_id,
            "text": text,
            "show_alert": show_alert,
        },
    )


def _telegram_actor(update_user: dict) -> str:
    username = str(update_user.get("username") or "").strip()
    first = str(update_user.get("first_name") or "").strip()
    last = str(update_user.get("last_name") or "").strip()
    full_name = " ".join(part for part in (first, last) if part)
    if username and full_name:
        return f"{full_name} (@{username})"
    if username:
        return f"@{username}"
    return full_name or "Telegram user"


async def _handle_telegram_start_message(message: dict) -> dict:
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    update_user = message.get("from") or {}
    actor = _telegram_actor(update_user)
    actor_id = update_user.get("id")
    text = str(message.get("text") or "").strip()
    if not chat_id or not text.lower().startswith("/start"):
        return {"ok": True}

    await telegram_call(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": (
                "Felipe x Clearance is live. Captain has your start ping. "
                "Use the Felipe link and your beta key to create your account. "
                "Never send seed phrases, private keys, exchange passwords, or recovery codes here."
            ),
            "disable_web_page_preview": True,
        },
    )

    if TELEGRAM_CHAT_ID and str(chat_id) != str(TELEGRAM_CHAT_ID):
        lines = [
            "Felipe x Clearance /start",
            f"From: {actor}",
            f"Telegram user id: {actor_id or 'unknown'}",
            f"Chat id: {chat_id}",
        ]
        await telegram_call(
            "sendMessage",
            {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": "\n".join(lines),
                "disable_web_page_preview": True,
            },
        )
    return {"ok": True, "start": True}


@app.post("/v1/telegram/webhook", tags=["Telegram"])
async def telegram_webhook(request: Request):
    """Receive Telegram start pings and Approve/Deny inline button callbacks."""
    if TELEGRAM_WEBHOOK_SECRET:
        provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if provided != TELEGRAM_WEBHOOK_SECRET:
            raise HTTPException(status_code=403, detail="Invalid Telegram webhook secret")

    payload = await request.json()
    callback = payload.get("callback_query")
    if not callback:
        message = payload.get("message") or payload.get("edited_message") or {}
        return await _handle_telegram_start_message(message)

    callback_id = callback.get("id")
    data = (callback.get("data") or "").strip()
    action, _, clearance_id = data.partition(":")
    if action not in ("clr_approve", "clr_deny") or not clearance_id:
        await _telegram_answer(callback_id, "Unknown Clearance action.", True)
        return {"ok": True}

    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    message_id = message.get("message_id")
    original_text = message.get("text") or ""
    actor = (
        (callback.get("from") or {}).get("username")
        or (callback.get("from") or {}).get("first_name")
        or "telegram_user"
    )

    if TELEGRAM_CHAT_ID and str(chat_id) != str(TELEGRAM_CHAT_ID):
        await _telegram_answer(callback_id, "Not authorized.", True)
        return {"ok": True}

    approving = action == "clr_approve"
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM clearances WHERE id = ?", (clearance_id,))
        row = await cursor.fetchone()
        if not row:
            await _telegram_answer(callback_id, "Clearance not found.", True)
            return {"ok": True}

        row = dict(row)
        if row["status"] != "pending":
            await _telegram_answer(callback_id, f"Already {row['status']}.", True)
            return {"ok": True}

        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) >= expires:
            await db.execute(
                "UPDATE clearances SET status = 'expired' WHERE id = ?", (clearance_id,)
            )
            await db.commit()
            await _telegram_answer(callback_id, "Clearance expired.", True)
            return {"ok": True}

        decided_at = now_iso()
        token = None
        if approving:
            new_status = "approved"
            token = make_clearance_token(
                clearance_id,
                row["scope"],
                row["budget_amount"],
                row["budget_currency"],
                row["expires_at"],
            )
        else:
            new_status = "denied"

        await db.execute(
            """UPDATE clearances
               SET status = ?, token = ?, decided_at = ?, decided_by = ?, decision_note = ?
               WHERE id = ?""",
            (
                new_status,
                token,
                decided_at,
                f"telegram:{actor}",
                "Approved via Telegram" if approving else "Denied via Telegram",
                clearance_id,
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (clearance_id, api_key_id, event, actor, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                clearance_id,
                row["api_key_id"],
                f"clearance.{new_status}",
                f"telegram:{actor}",
                decided_at,
            ),
        )
        await db.commit()

        await _telegram_answer(callback_id, "Approved" if approving else "Denied")

        if chat_id and message_id:
            stamp = "APPROVED" if approving else "DENIED"
            await telegram_call(
                "editMessageText",
                {
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "text": f"{original_text}\n\n{stamp} via Telegram",
                    "disable_web_page_preview": True,
                },
            )

        return {"ok": True}
    finally:
        await db.close()


# --- Token Verification ---

@app.get("/v1/verify/{token}", response_model=VerifyResponse, tags=["Verification"])
async def verify_token(token: str):
    """
    Verify a clearance token. Any service can call this to confirm an agent has human approval.

    No authentication required — this is a public verification endpoint.
    Services receiving a clearance token from an agent should call this to validate it.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Check if clearance is still valid in DB
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT status FROM clearances WHERE id = ?",
                (payload.get("clearance_id"),)
            )
            row = await cursor.fetchone()
            if not row or row["status"] != "approved":
                return VerifyResponse(
                    valid=False,
                    error="Clearance has been revoked or is no longer active"
                )
        finally:
            await db.close()

        # Check expiry
        expires = datetime.fromisoformat(payload["expires_at"])
        if datetime.now(timezone.utc) >= expires:
            return VerifyResponse(valid=False, error="Clearance token has expired")

        return VerifyResponse(
            valid=True,
            clearance_id=payload.get("clearance_id"),
            scope=payload.get("scope"),
            budget_amount=payload.get("budget_amount"),
            budget_currency=payload.get("budget_currency"),
            approved_at=payload.get("approved_at"),
            expires_at=payload.get("expires_at"),
        )

    except JWTError:
        return VerifyResponse(valid=False, error="Invalid token signature")


# --- Revocation ---

@app.post("/v1/clearances/{clearance_id}/revoke", tags=["Clearances"])
async def revoke_clearance(clearance_id: str, api_key: dict = Depends(get_api_key)):
    """Revoke an approved clearance. The token will no longer verify."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM clearances WHERE id = ? AND api_key_id = ?",
            (clearance_id, api_key["id"])
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Clearance not found")
        if row["status"] != "approved":
            raise HTTPException(status_code=409, detail="Can only revoke approved clearances")

        await db.execute(
            "UPDATE clearances SET status = 'revoked', token = NULL WHERE id = ?",
            (clearance_id,)
        )
        await db.commit()

        return {"id": clearance_id, "status": "revoked"}
    finally:
        await db.close()


# --- Usage ---

@app.get("/v1/usage", response_model=UsageResponse, tags=["Account"])
async def get_usage(api_key: dict = Depends(get_api_key)):
    """Check your current usage and remaining credits."""
    db = await get_db()
    try:
        # Count clearances this period
        cursor = await db.execute(
            """SELECT COUNT(*) as cnt FROM clearances
               WHERE api_key_id = ? AND created_at >= ?""",
            (api_key["id"], (datetime.now(timezone.utc) - timedelta(days=30)).isoformat())
        )
        row = await cursor.fetchone()
        used = dict(row)["cnt"]

        limit = TIER_LIMITS.get(api_key["tier"], 50)
        reset_at = api_key["credits_reset_at"]
        period_start = (datetime.fromisoformat(reset_at) - timedelta(days=30)).isoformat()

        return UsageResponse(
            tier=Tier(api_key["tier"]),
            credits_used=used,
            credits_remaining=api_key["credits_remaining"],
            clearances_this_month=used,
            period_start=period_start,
            period_end=reset_at,
        )
    finally:
        await db.close()


# --- Human-Facing Approval Page ---

@app.get("/approve/{clearance_id}", response_class=HTMLResponse, tags=["Approval"])
async def approval_page(clearance_id: str, request: Request):
    """Human-facing approval page. Clean, clear, one-click approve or deny."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM clearances WHERE id = ?", (clearance_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return templates.TemplateResponse(
                request,
                "approve.html",
                {
                    "error": "Clearance not found",
                    "clearance": None,
                },
            )

        clearance = dict(row)
        clearance["metadata"] = json.loads(clearance["metadata"]) if clearance["metadata"] else None

        return templates.TemplateResponse(
            request,
            "approve.html",
            {
                "clearance": clearance,
                "error": None,
                "base_url": BASE_URL,
            },
        )
    finally:
        await db.close()


# --- Landing Page ---

@app.get("/", response_class=HTMLResponse, tags=["Pages"])
async def landing_page(request: Request):
    if _is_scram_request(request):
        return templates.TemplateResponse(request, "scam_check.html", _scram_template_context(request))

    # Resolve ambassador ref. UTM source stays channel analytics only.
    ref = (
        _validate_ref(request.query_params.get("ref"))
        or _read_ref_cookie(request)
    )
    # Log the visit (server-side, provable receipt)
    await _record_visit(request, ref)

    response = templates.TemplateResponse(
        request,
        "index.html",
        {
            "base_url": BASE_URL.rstrip("/"),
            "brand_url": BRAND_URL.rstrip("/"),
            "support_email": PAYMENT_SUPPORT_EMAIL,
            "payment_ens": PAYMENT_ENS or "invoice-required",
            "payment_wallet": PAYMENT_WALLET,
            "payment_chain_id": PAYMENT_CHAIN_ID,
            "usdc_contract": USDC_CONTRACT,
            "bot_build_request_url": BOT_BUILD_REQUEST_URL,
        },
    )
    if ref:
        _set_ref_cookie(response, ref)
    return response


@app.get("/tutorial", response_class=HTMLResponse, tags=["Pages"])
async def bot_tutorial_page(request: Request):
    return templates.TemplateResponse(
        request,
        "tutorial.html",
        {
            "base_url": BASE_URL.rstrip("/"),
            "brand_url": BRAND_URL.rstrip("/"),
            "support_email": PAYMENT_SUPPORT_EMAIL,
            "bot_build_request_url": BOT_BUILD_REQUEST_URL,
        },
    )


@app.get("/scram", response_class=HTMLResponse, tags=["SCRAM"])
@app.get("/scam-check", response_class=HTMLResponse, tags=["SCRAM"])
async def scam_check_page(request: Request):
    return templates.TemplateResponse(request, "scam_check.html", _scram_template_context(request))


@app.post("/v1/scram/demo", tags=["SCRAM"])
@app.post("/v1/scam-check/demo", tags=["SCRAM"])
async def scam_check_demo(request: Request):
    body = await _read_sms_payload(request)
    message = str(body.get("message") or body.get("Body") or "").strip()
    phone = str(body.get("phone") or body.get("From") or "+15555550123").strip()
    attachments = _extract_sms_attachments(body)
    return await handle_sms_scam_check(
        from_number=phone,
        body=message,
        provider="local_demo",
        provider_message_id=str(body.get("message_id") or body.get("MessageSid") or "") or None,
        attachments=attachments,
    )


@app.post("/v1/sms/inbound", tags=["SCRAM"])
@app.post("/v1/whatsapp/inbound", tags=["SCRAM"])
async def inbound_sms_webhook(request: Request):
    payload = await _read_sms_payload(request)
    _require_valid_twilio_signature(request, payload)
    from_number = _payload_value(payload, "From", "from", "sender", "phone")
    body = _payload_value(payload, "Body", "body", "text", "message")
    provider_message_id = _payload_value(
        payload,
        "MessageSid",
        "SmsMessageSid",
        "message_id",
        "id",
    ) or None
    provider = _payload_value(payload, "provider") or SMS_PROVIDER or "local"
    channel = _detect_message_channel(payload, provider)
    if _looks_like_twilio_webhook(request, payload):
        provider = f"twilio_{channel}"
    attachments = _extract_sms_attachments(payload)

    result = await handle_sms_scam_check(
        from_number=from_number,
        body=body,
        provider=provider,
        provider_message_id=provider_message_id,
        attachments=attachments,
    )
    result["channel"] = channel

    if _twilio_response_media_type(request, payload):
        return Response(content=build_twiml_message(result["reply"]), media_type="application/xml")

    if str(provider).lower() == "telnyx":
        delivery = await send_sms(from_number, result["reply"])
        return {"ok": True, "delivery": delivery, **result}

    return result


@app.post("/v1/scram/telegram/webhook", tags=["SCRAM"])
async def scram_telegram_webhook(request: Request):
    """Receive SCRAM conversations from a Telegram bot webhook."""
    if TELEGRAM_WEBHOOK_SECRET:
        provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if provided != TELEGRAM_WEBHOOK_SECRET:
            raise HTTPException(status_code=403, detail="Invalid Telegram webhook secret")

    payload = await request.json()
    message = payload.get("message") or payload.get("edited_message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return {"ok": True, "ignored": "missing_chat"}

    text = str(message.get("text") or message.get("caption") or "").strip()
    if not text and _extract_telegram_attachment(message):
        text = "Please check this attachment."

    attachments = _extract_telegram_attachment(message)
    result = await handle_sms_scam_check(
        from_number=f"telegram:{chat_id}",
        body=text,
        provider="telegram",
        provider_message_id=str(message.get("message_id") or payload.get("update_id") or "") or None,
        attachments=attachments,
    )
    result["channel"] = "telegram"

    delivery = None
    if TELEGRAM_BOT_TOKEN:
        delivery = await telegram_call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": result["reply"],
                "disable_web_page_preview": True,
            },
        )
    return {"ok": True, "delivery": delivery, **result}


@app.post("/v1/scram/imessage/inbound", tags=["SCRAM"])
async def scram_imessage_inbound(request: Request):
    """Provider-neutral adapter target for Apple Messages for Business/iMessage vendors."""
    payload = await _read_sms_payload(request)
    user_id = _payload_value(payload, "user", "userId", "opaqueUserId", "from", "sender", "phone")
    body = _payload_value(payload, "text", "body", "message", "Body")
    attachments = _extract_sms_attachments(payload)
    if not user_id:
        raise HTTPException(status_code=400, detail="iMessage user identifier is required")

    result = await handle_sms_scam_check(
        from_number=f"imessage:{user_id}",
        body=body,
        provider="imessage",
        provider_message_id=_payload_value(payload, "message_id", "id", "messageId") or None,
        attachments=attachments,
    )
    result["channel"] = "imessage"
    return result


@app.get("/r/{ambassador}", tags=["Pages"], include_in_schema=False)
async def ambassador_redirect(ambassador: str, request: Request):
    """Pretty ambassador URL — sets ref cookie and 302s to landing.

    Usage: send ambassadors links like https://clearance.nauti-labs.com/r/alice
    """
    ref = await canonical_traffic_ref(ambassador)
    if not ref:
        return RedirectResponse(url="/", status_code=302)
    await _record_visit(request, ref)
    response = RedirectResponse(url="/", status_code=302)
    _set_ref_cookie(response, ref)
    return response


# --- Admin: ambassador attribution stats (provable from DB) ---

@app.get("/v1/admin/ambassadors", tags=["Admin"])
async def list_ambassadors(x_admin_key: str = Header(None, alias="X-Admin-Key")):
    """List every ambassador with click + signup totals. Admin-key gated."""
    _require_admin(x_admin_key)
    db = await get_db()
    try:
        cur = await db.execute("""
            SELECT
                COALESCE(v.ref, k.referred_by) AS ref,
                SUM(CASE WHEN v.id IS NOT NULL AND v.is_bot = 0 THEN 1 ELSE 0 END) AS clicks,
                COUNT(DISTINCT k.id) AS signups
            FROM visits v
            LEFT JOIN api_keys k ON k.referred_by = v.ref
            WHERE v.ref IS NOT NULL OR k.referred_by IS NOT NULL
            GROUP BY ref
            ORDER BY clicks DESC, signups DESC
        """)
        rows = [dict(r) for r in await cur.fetchall()]
        return {"ambassadors": rows, "count": len(rows)}
    finally:
        await db.close()


async def _ambassador_stats_payload(ref: str, metric_floors: dict | None = None) -> dict:
    """Compute one ambassador's stats. Used by both admin + public endpoints.

    Privacy: never includes emails or IPs. Per-tier paid breakdown included.
    """
    db = await get_db()
    try:
        visit_click_total = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM visits WHERE ref = ? AND is_bot = 0", (ref,)
        )).fetchone())["n"]
        event_click_total = (await (await db.execute(
            """SELECT COUNT(*) AS n
               FROM traffic_events
               WHERE method = 'GET'
                 AND is_bot = 0
                 AND (status_code IS NULL OR (status_code >= 200 AND status_code < 400))
                 AND (path = ? OR path = ? OR (path = '/' AND ref = ?))""",
            (f"/r/{ref}", f"/{ref}", ref),
        )).fetchone())["n"]
        click_total = max(int(visit_click_total or 0), int(event_click_total or 0))
        visit_first_click = (await (await db.execute(
            "SELECT MIN(created_at) AS t FROM visits WHERE ref = ?", (ref,)
        )).fetchone())["t"]
        event_first_click = (await (await db.execute(
            """SELECT MIN(created_at) AS t
               FROM traffic_events
               WHERE method = 'GET'
                 AND is_bot = 0
                 AND (status_code IS NULL OR (status_code >= 200 AND status_code < 400))
                 AND (path = ? OR path = ? OR (path = '/' AND ref = ?))""",
            (f"/r/{ref}", f"/{ref}", ref),
        )).fetchone())["t"]
        visit_last_click = (await (await db.execute(
            "SELECT MAX(created_at) AS t FROM visits WHERE ref = ?", (ref,)
        )).fetchone())["t"]
        event_last_click = (await (await db.execute(
            """SELECT MAX(created_at) AS t
               FROM traffic_events
               WHERE method = 'GET'
                 AND is_bot = 0
                 AND (status_code IS NULL OR (status_code >= 200 AND status_code < 400))
                 AND (path = ? OR path = ? OR (path = '/' AND ref = ?))""",
            (f"/r/{ref}", f"/{ref}", ref),
        )).fetchone())["t"]
        first_candidates = [value for value in (visit_first_click, event_first_click) if value]
        last_candidates = [value for value in (visit_last_click, event_last_click) if value]
        first_click = min(first_candidates) if first_candidates else None
        last_click = max(last_candidates) if last_candidates else None
        signups = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE referred_by = ?", (ref,)
        )).fetchone())["n"]

        # Per-tier paid breakdown
        tier_rows = await (await db.execute(
            """SELECT tier, COUNT(*) AS n, COALESCE(SUM(amount), 0) AS rev
               FROM payments
               WHERE referred_by = ? AND status = 'verified'
               GROUP BY tier""",
            (ref,),
        )).fetchall()
        tier_map = {r["tier"]: {"count": r["n"], "monthly_revenue_usd": float(r["rev"])} for r in tier_rows}
        pro = tier_map.get("pro", {"count": 0, "monthly_revenue_usd": 0.0})
        scale = tier_map.get("scale", {"count": 0, "monthly_revenue_usd": 0.0})
        total_paid = pro["count"] + scale["count"]
        total_rev = pro["monthly_revenue_usd"] + scale["monthly_revenue_usd"]
        free_signups = max(signups - total_paid, 0)

        cvr = round((signups / click_total * 100), 2) if click_total else 0.0
        payload = {
            "ambassador": ref,
            "tracked_link": f"{BASE_URL.rstrip('/')}/r/{ref}",
            "avatar_url": f"https://unavatar.io/x/{ref}",
            "clicks": click_total,
            "signups": signups,
            "free_signups": free_signups,
            "pro": pro,
            "scale": scale,
            "paid_conversions": total_paid,
            "monthly_revenue_usd": total_rev,
            "click_to_signup_rate_pct": cvr,
            "first_click_at": first_click,
            "last_click_at": last_click,
        }
        if metric_floors is None:
            metric_floors = (await load_traffic_config()).get("metric_floors", {})
        return _apply_ambassador_metric_floor(payload, metric_floors)
    finally:
        await db.close()


@app.get("/v1/admin/ambassadors/{name}", tags=["Admin"])
async def ambassador_stats(name: str, x_admin_key: str = Header(None, alias="X-Admin-Key")):
    """Detailed stats for one ambassador. Provable from DB rows."""
    _require_admin(x_admin_key)
    ref = _validate_ref(name)
    if not ref:
        raise HTTPException(status_code=400, detail="invalid ambassador name (a-z, 0-9, _ -)")
    return await _ambassador_stats_payload(ref)


@app.get("/v1/admin/ambassadors/{name}/visits", tags=["Admin"])
async def ambassador_visits(name: str, x_admin_key: str = Header(None, alias="X-Admin-Key")):
    """Raw visit rows for one ambassador — fraud check (unique IPs, referers).

    Returns timestamp + path + UTM + referer + ip + bot flag for every click.
    Use to verify whether N clicks came from N humans or 1 person refreshing.
    """
    _require_admin(x_admin_key)
    ref = _validate_ref(name)
    if not ref:
        raise HTTPException(status_code=400, detail="invalid ambassador name")
    db = await get_db()
    try:
        rows = await (await db.execute(
            """SELECT created_at, path, referer, utm_source, utm_medium, utm_campaign,
                      ip, user_agent, is_bot
               FROM visits
               WHERE ref = ?
               ORDER BY created_at DESC
               LIMIT 500""",
            (ref,)
        )).fetchall()
    finally:
        await db.close()
    visits = [dict(r) for r in rows]
    unique_ips = len({v["ip"] for v in visits if v.get("ip")})
    return {
        "ambassador": ref,
        "total_clicks": len(visits),
        "unique_ips": unique_ips,
        "visits": visits,
    }


@app.get("/v1/admin/signups", tags=["Admin"])
async def admin_signups(x_admin_key: str = Header(None, alias="X-Admin-Key")):
    """Recent signups with email + ambassador attribution. Internal use only."""
    _require_admin(x_admin_key)
    db = await get_db()
    try:
        rows = await (await db.execute(
            "SELECT created_at, email, name, tier, referred_by FROM api_keys ORDER BY created_at DESC LIMIT 200"
        )).fetchall()
    finally:
        await db.close()
    return {"signups": [dict(r) for r in rows], "count": len(rows)}


async def _general_traffic_payload(metric_floors: dict | None = None) -> dict:
    """Aggregate non-attributed visits + signups (Telegram / Reddit / direct / SEO / etc)."""
    db = await get_db()
    try:
        tracked_clicks = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM visits WHERE ref IS NULL AND is_bot = 0 AND path = '/'"
        )).fetchone())["n"]
        server_landing_clicks = (await (await db.execute(
            """SELECT COUNT(*) AS n
               FROM traffic_events
               WHERE method = 'GET'
                 AND path = '/'
                 AND ref IS NULL
                 AND is_bot = 0
                 AND (status_code IS NULL OR (status_code >= 200 AND status_code < 400))"""
        )).fetchone())["n"]
        raw_server_rows = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM traffic_events"
        )).fetchone())["n"]
        signups = (await (await db.execute(
            """SELECT COUNT(*) AS n
               FROM api_keys
               WHERE referred_by IS NULL
                 AND email NOT LIKE '%@nauti-labs.local'"""
        )).fetchone())["n"]
        tier_rows = await (await db.execute(
            """SELECT tier, COUNT(*) AS n, COALESCE(SUM(amount), 0) AS rev
               FROM payments
               WHERE referred_by IS NULL
                 AND status = 'verified'
                 AND email NOT LIKE '%@nauti-labs.local'
               GROUP BY tier"""
        )).fetchall()
        tier_map = {r["tier"]: {"count": r["n"], "monthly_revenue_usd": float(r["rev"])} for r in tier_rows}
        pro = tier_map.get("pro", {"count": 0, "monthly_revenue_usd": 0.0})
        scale = tier_map.get("scale", {"count": 0, "monthly_revenue_usd": 0.0})
        total_paid = pro["count"] + scale["count"]
        total_rev = pro["monthly_revenue_usd"] + scale["monthly_revenue_usd"]
        free_signups = max(signups - total_paid, 0)
        payload = {
            "clicks": max(int(server_landing_clicks or 0), int(tracked_clicks or 0)),
            "server_request_rows": int(server_landing_clicks or 0),
            "raw_server_request_rows": int(raw_server_rows or 0),
            "tracked_visit_rows": int(tracked_clicks or 0),
            "free_signups": free_signups,
            "pro": pro,
            "scale": scale,
            "paid_conversions": total_paid,
            "monthly_revenue_usd": total_rev,
        }
        if metric_floors is None:
            metric_floors = (await load_traffic_config()).get("metric_floors", {})
        return _apply_general_metric_floor(payload, metric_floors)
    finally:
        await db.close()


@app.get("/v1/traffic/config", tags=["Public"])
async def public_traffic_config():
    """Public display config for Nauti-Traffic. No visitor metadata."""
    return await load_traffic_config()


@app.get("/v1/traffic/clicks", tags=["Public"])
async def protected_traffic_clicks(
    x_traffic_password: str = Header(None, alias="X-Traffic-Password"),
    limit: int = 1000,
):
    """Password-protected Clearance click data for nauti-labs.com/traffic."""
    _require_traffic_board_password(x_traffic_password)
    row_limit = max(1, min(int(limit or 1000), 2000))
    db = await get_db()
    try:
        traffic_rows = await (await db.execute(
            """SELECT id, source, method, path, query, ref, referer, origin, ip,
                      user_agent, status_code, duration_ms, is_bot, created_at
               FROM traffic_events
               ORDER BY created_at DESC
               LIMIT ?""",
            (row_limit,),
        )).fetchall()
        traffic_total_row = await (await db.execute(
            "SELECT COUNT(*) AS n FROM traffic_events"
        )).fetchone()
        path_rows = await (await db.execute(
            """SELECT path, COUNT(*) AS requests
               FROM traffic_events
               GROUP BY path
               ORDER BY requests DESC, path ASC
               LIMIT 100"""
        )).fetchall()
        click_rows = await (await db.execute(
            """SELECT id, path, ref, referer, utm_source, utm_medium, utm_campaign,
                      ip, user_agent, is_bot, created_at
               FROM visits
               ORDER BY created_at DESC
               LIMIT ?""",
            (row_limit,),
        )).fetchall()
        total_row = await (await db.execute(
            "SELECT COUNT(*) AS n FROM visits"
        )).fetchone()
        signup_row = await (await db.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE email NOT LIKE '%@nauti-labs.local'"
        )).fetchone()
        paid_row = await (await db.execute(
            """SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS revenue
               FROM payments
               WHERE status = 'verified'"""
        )).fetchone()
        free_signup_row = await (await db.execute(
            """SELECT COUNT(*) AS n
               FROM api_keys
               WHERE id NOT IN (
                   SELECT COALESCE(api_key_id, '') FROM payments WHERE status = 'verified'
               )
                 AND email NOT LIKE '%@nauti-labs.local'"""
        )).fetchone()
        ambassador_rows = await (await db.execute(
            """SELECT ref,
                      COUNT(*) AS clicks,
                      COUNT(DISTINCT ip) AS unique_ips,
                      SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) AS bot_clicks,
                      MIN(created_at) AS first_click_at,
                      MAX(created_at) AS last_click_at
               FROM visits
               WHERE ref IS NOT NULL
               GROUP BY ref
               ORDER BY clicks DESC, last_click_at DESC"""
        )).fetchall()
        event_ambassador_rows = await (await db.execute(
            """SELECT ref,
                      COUNT(*) AS clicks,
                      COUNT(DISTINCT ip) AS unique_ips,
                      SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) AS bot_clicks,
                      MIN(created_at) AS first_click_at,
                      MAX(created_at) AS last_click_at
               FROM traffic_events
               WHERE ref IS NOT NULL
               GROUP BY ref
               ORDER BY clicks DESC, last_click_at DESC"""
        )).fetchall()
    finally:
        await db.close()

    clicks = []
    ip_summary = {}
    actor_counts = {"human": 0, "bot": 0, "system": 0}
    attributed_clicks = 0
    direct_clicks = 0
    for item in traffic_rows:
        row = dict(item)
        row["ref"] = row.get("ref") or _traffic_ref_from_path(row.get("path"))
        actor = _traffic_actor_type(row.get("user_agent") or "", row.get("is_bot") or 0)
        actor_counts[actor] = actor_counts.get(actor, 0) + 1
        if row.get("ref"):
            attributed_clicks += 1
        else:
            direct_clicks += 1
        ip_meta = _traffic_ip_label(row.get("ip"))
        browser = _traffic_browser_label(row.get("user_agent") or "")
        device = _traffic_device_label(row.get("user_agent") or "")
        click = {
            "event_id": row.get("id"),
            "created_at": row.get("created_at"),
            "source": row.get("source"),
            "method": row.get("method"),
            "path": row.get("path"),
            "query": row.get("query"),
            "ref": row.get("ref"),
            "referer": row.get("referer"),
            "origin": row.get("origin"),
            "utm_source": None,
            "utm_medium": None,
            "utm_campaign": None,
            "ip": row.get("ip"),
            "ip_label": ip_meta["label"],
            "ip_kind": ip_meta["kind"],
            "visitor_id": ip_meta["visitor_id"],
            "user_agent": row.get("user_agent"),
            "status_code": row.get("status_code"),
            "duration_ms": row.get("duration_ms"),
            "bot_or_human": actor,
            "browser": browser,
            "device": device,
        }
        clicks.append(click)

        key = row.get("ip") or "unknown"
        summary = ip_summary.setdefault(key, {
            "ip": key,
            "ip_label": ip_meta["label"],
            "ip_kind": ip_meta["kind"],
            "visitor_id": ip_meta["visitor_id"],
            "clicks": 0,
            "human_clicks": 0,
            "bot_clicks": 0,
            "system_clicks": 0,
            "refs": set(),
            "paths": set(),
            "browsers": set(),
            "devices": set(),
            "first_seen_at": None,
            "last_seen_at": None,
        })
        summary["clicks"] += 1
        if actor == "bot":
            summary["bot_clicks"] += 1
        elif actor == "system":
            summary["system_clicks"] += 1
        else:
            summary["human_clicks"] += 1
        summary["refs"].add(row.get("ref") or "general")
        summary["paths"].add(row.get("path") or "")
        summary["browsers"].add(browser)
        summary["devices"].add(device)
        created_at = row.get("created_at")
        if created_at and (summary["first_seen_at"] is None or created_at < summary["first_seen_at"]):
            summary["first_seen_at"] = created_at
        if created_at and (summary["last_seen_at"] is None or created_at > summary["last_seen_at"]):
            summary["last_seen_at"] = created_at

    profiles = await _traffic_ip_profiles(list(ip_summary.keys()))
    for click in clicks:
        profile = profiles.get(click.get("ip") or "", {})
        known_user = _traffic_known_user_label(click.get("ip"))
        if profile:
            click["ip_label"] = known_user or _traffic_profile_label(profile, click.get("ip_label") or click.get("ip") or "")
            click["org"] = profile.get("org") or profile.get("isp") or ""
            click["network"] = profile.get("as") or ""
            click["is_proxy"] = bool(profile.get("proxy"))
            click["is_hosting"] = bool(profile.get("hosting"))
            click["is_mobile_network"] = bool(profile.get("mobile"))
            click["ip_profile"] = profile
        elif known_user:
            click["ip_label"] = known_user
        if known_user:
            click["known_user"] = known_user

    ip_rows = []
    for summary in ip_summary.values():
        packed = dict(summary)
        profile = profiles.get(packed.get("ip") or "", {})
        known_user = _traffic_known_user_label(packed.get("ip"))
        if profile:
            packed["ip_label"] = known_user or _traffic_profile_label(profile, packed.get("ip_label") or packed.get("ip") or "")
            packed["org"] = profile.get("org") or profile.get("isp") or ""
            packed["network"] = profile.get("as") or ""
            packed["is_proxy"] = bool(profile.get("proxy"))
            packed["is_hosting"] = bool(profile.get("hosting"))
            packed["is_mobile_network"] = bool(profile.get("mobile"))
            packed["ip_profile"] = profile
        elif known_user:
            packed["ip_label"] = known_user
        if known_user:
            packed["known_user"] = known_user
        for key in ("refs", "paths", "browsers", "devices"):
            packed[key] = sorted(value for value in packed[key] if value)
        try:
            first_dt = datetime.fromisoformat(str(packed.get("first_seen_at")).replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(str(packed.get("last_seen_at")).replace("Z", "+00:00"))
            duration_ms = max(0, (last_dt - first_dt).total_seconds() * 1000)
        except Exception:
            duration_ms = 0
        packed["duration_ms"] = duration_ms
        seconds = int(round(duration_ms / 1000))
        if seconds < 60:
            packed["duration"] = f"{seconds}s"
        elif seconds < 3600:
            packed["duration"] = f"{seconds // 60}m {seconds % 60}s"
        else:
            packed["duration"] = f"{seconds // 3600}h {(seconds % 3600) // 60}m"
        primary_ref = next((ref for ref in packed["refs"] if ref and ref != "general"), packed["refs"][0] if packed["refs"] else "general")
        packed["user"] = f"{packed.get('ip_label') or packed.get('ip')} - {packed['devices'][0] if packed['devices'] else 'device'} - {primary_ref}"
        ip_rows.append(packed)
    ip_rows.sort(key=lambda item: (item["clicks"], item["last_seen_at"] or ""), reverse=True)

    tracked_visits = []
    for item in click_rows:
        row = dict(item)
        ip_meta = _traffic_ip_label(row.get("ip"))
        tracked_visits.append({
            "visit_id": row.get("id"),
            "created_at": row.get("created_at"),
            "path": row.get("path"),
            "ref": row.get("ref"),
            "referer": row.get("referer"),
            "utm_source": row.get("utm_source"),
            "utm_medium": row.get("utm_medium"),
            "utm_campaign": row.get("utm_campaign"),
            "ip": row.get("ip"),
            "ip_label": ip_meta["label"],
            "visitor_id": ip_meta["visitor_id"],
            "user_agent": row.get("user_agent"),
            "bot_or_human": _traffic_actor_type(row.get("user_agent") or "", row.get("is_bot") or 0),
            "browser": _traffic_browser_label(row.get("user_agent") or ""),
            "device": _traffic_device_label(row.get("user_agent") or ""),
        })

    ambassador_totals = {}
    for raw in [*ambassador_rows, *event_ambassador_rows]:
        row = dict(raw)
        ref = row.get("ref")
        if not ref:
            continue
        target = ambassador_totals.setdefault(ref, {
            "ref": ref,
            "clicks": 0,
            "unique_ips": 0,
            "bot_clicks": 0,
            "first_click_at": None,
            "last_click_at": None,
        })
        target["clicks"] = max(int(target["clicks"] or 0), int(row.get("clicks") or 0))
        target["unique_ips"] = max(int(target["unique_ips"] or 0), int(row.get("unique_ips") or 0))
        target["bot_clicks"] = max(int(target["bot_clicks"] or 0), int(row.get("bot_clicks") or 0))
        first_click = row.get("first_click_at")
        last_click = row.get("last_click_at")
        if first_click and (target["first_click_at"] is None or first_click < target["first_click_at"]):
            target["first_click_at"] = first_click
        if last_click and (target["last_click_at"] is None or last_click > target["last_click_at"]):
            target["last_click_at"] = last_click

    metric_floors = (await load_traffic_config()).get("metric_floors", {})
    ambassador_floor_refs = metric_floors.get("ambassadors") if isinstance(metric_floors, dict) else {}
    if isinstance(ambassador_floor_refs, dict):
        for ref in ambassador_floor_refs:
            clean_ref = _validate_ref(ref)
            if clean_ref and clean_ref not in ambassador_totals:
                ambassador_totals[clean_ref] = {
                    "ref": clean_ref,
                    "clicks": 0,
                    "unique_ips": 0,
                    "bot_clicks": 0,
                    "first_click_at": None,
                    "last_click_at": None,
                }
    ambassador_total_rows = []
    for row in ambassador_totals.values():
        normalized = {
            "ambassador": row["ref"],
            "clicks": row.get("clicks", 0),
            "signups": row.get("signups", 0),
            "free_signups": row.get("free_signups", 0),
            "paid_conversions": row.get("paid_conversions", 0),
            "monthly_revenue_usd": row.get("monthly_revenue_usd", 0.0),
        }
        floored = _apply_ambassador_metric_floor(normalized, metric_floors)
        row["clicks"] = floored.get("clicks", row.get("clicks", 0))
        row["signups"] = floored.get("signups", row.get("signups", 0))
        row["free_signups"] = floored.get("free_signups", row.get("free_signups", 0))
        row["paid_conversions"] = floored.get("paid_conversions", row.get("paid_conversions", 0))
        row["monthly_revenue_usd"] = floored.get("monthly_revenue_usd", row.get("monthly_revenue_usd", 0.0))
        ambassador_total_rows.append(row)
    floor_signups = sum(int(row.get("signups") or 0) for row in ambassador_total_rows)
    floor_free_signups = sum(int(row.get("free_signups") or 0) for row in ambassador_total_rows)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "clearance.db.traffic_events",
        "limit": row_limit,
        "truncated": int(traffic_total_row["n"] or 0) > row_limit,
        "totals": {
            "click_rows": int(traffic_total_row["n"] or 0),
            "returned_click_rows": len(clicks),
            "server_request_rows": int(traffic_total_row["n"] or 0),
            "tracked_visit_rows": int(total_row["n"] or 0),
            "human_clicks": actor_counts.get("human", 0),
            "bot_clicks": actor_counts.get("bot", 0),
            "system_clicks": actor_counts.get("system", 0),
            "attributed_clicks": attributed_clicks,
            "direct_clicks": direct_clicks,
            "unique_ips": len(ip_rows),
            "signups": max(int(signup_row["n"] or 0), floor_signups),
            "free_signups": max(int(free_signup_row["n"] or 0), floor_free_signups),
            "paid_conversions": int(paid_row["n"] or 0),
            "monthly_revenue_usd": float(paid_row["revenue"] or 0),
        },
        "clicks": clicks,
        "tracked_visits": tracked_visits,
        "ip_summary": ip_rows,
        "path_summary": [dict(row) for row in path_rows],
        "ambassador_totals": sorted(ambassador_total_rows, key=lambda row: (row["clicks"], row.get("last_click_at") or ""), reverse=True),
    }


@app.post("/v1/traffic/ambassador-request", tags=["Public"])
async def create_ambassador_request(request: Request):
    """Capture a lightweight request to become a Clearance ambassador."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    handle = _clean_request_text(body.get("handle"), 80)
    audience = _clean_request_text(body.get("audience"), 160)
    note = _clean_request_text(body.get("note"), 500)
    source = _clean_request_text(body.get("source"), 80) or "clearance-traffic"

    if not handle:
        raise HTTPException(status_code=400, detail="Handle is required")
    if len(handle) < 2:
        raise HTTPException(status_code=400, detail="Handle is too short")

    request_id = generate_id("ambreq")
    created_at = now_iso()
    client_ip = get_client_ip(request)
    user_agent = (request.headers.get("user-agent") or "")[:512]
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO ambassador_requests
               (id, handle, audience, note, source, status, ip, user_agent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                handle,
                audience,
                note,
                source,
                "new",
                client_ip,
                user_agent,
                created_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    await send_ambassador_request_notification(
        request_id=request_id,
        handle=handle,
        audience=audience,
        note=note,
        source=source,
        created_at=created_at,
        ip=client_ip,
        user_agent=user_agent,
    )

    return {
        "status": "queued",
        "request_id": request_id,
        "message": "Ambassador request received",
    }


@app.api_route("/nauti-traffic/admin", methods=["GET", "POST"], include_in_schema=False)
@app.api_route("/nauti-traffic/admin/login", methods=["GET", "POST"], include_in_schema=False)
@app.api_route("/nauti-traffic/admin/logout", methods=["GET", "POST"], include_in_schema=False)
@app.api_route("/nauti-traffic/admin/affiliate", methods=["GET", "POST"], include_in_schema=False)
@app.api_route("/nauti-traffic/admin/alias", methods=["GET", "POST"], include_in_schema=False)
@app.api_route("/nauti-traffic/admin/hide", methods=["GET", "POST"], include_in_schema=False)
async def nauti_traffic_admin_decoy():
    raise HTTPException(status_code=404, detail="Not Found")


@app.get("/nauti-traffic/admin/{access_token}", response_class=HTMLResponse, tags=["Admin"])
async def nauti_traffic_admin_page(access_token: str, request: Request):
    admin_path = _verify_traffic_admin_path(access_token)
    configured = bool(re.fullmatch(r"\d{6}", TRAFFIC_ADMIN_PIN))
    error = request.query_params.get("error")
    notice = request.query_params.get("notice")
    if not _traffic_admin_logged_in(request, access_token):
        response = templates.TemplateResponse(
            request,
            "nauti_traffic_admin.html",
            {
                "logged_in": False,
                "configured": configured,
                "error": error,
                "notice": notice,
                "config": {},
                "stats": {},
                "base_url": BASE_URL.rstrip("/"),
                "first_mate_limit": 10,
                "admin_path": admin_path,
            },
        )
        return _no_store(response)

    config = await load_traffic_config()
    stats = await public_traffic_leaderboard()
    response = templates.TemplateResponse(
        request,
        "nauti_traffic_admin.html",
        {
            "logged_in": True,
            "configured": configured,
            "error": error,
            "notice": notice,
            "config": config,
            "stats": stats,
            "base_url": BASE_URL.rstrip("/"),
            "first_mate_limit": 10,
            "admin_path": admin_path,
        },
    )
    return _no_store(response)


@app.post("/nauti-traffic/admin/{access_token}/login", tags=["Admin"])
async def nauti_traffic_admin_login(access_token: str, pin: str = Form("")):
    admin_path = _verify_traffic_admin_path(access_token)
    if not re.fullmatch(r"\d{6}", TRAFFIC_ADMIN_PIN):
        return _traffic_admin_redirect(access_token, "error=pin_not_configured")
    if not secrets.compare_digest(pin.strip(), TRAFFIC_ADMIN_PIN):
        return _traffic_admin_redirect(access_token, "error=bad_pin")

    redirect = _traffic_admin_redirect(access_token)
    _clear_traffic_admin_cookies(redirect, admin_path)
    redirect.set_cookie(
        TRAFFIC_ADMIN_COOKIE,
        _make_traffic_admin_token(access_token),
        max_age=TRAFFIC_ADMIN_SESSION_HOURS * 3600,
        httponly=True,
        secure=not _is_local_url(BASE_URL),
        samesite="lax",
        path=TRAFFIC_ADMIN_COOKIE_PATH,
    )
    return redirect


@app.post("/nauti-traffic/admin/{access_token}/logout", tags=["Admin"])
async def nauti_traffic_admin_logout(access_token: str):
    admin_path = _verify_traffic_admin_path(access_token)
    response = _traffic_admin_redirect(access_token, "notice=locked")
    _clear_traffic_admin_cookies(response, admin_path)
    return response


@app.post("/nauti-traffic/admin/{access_token}/affiliate", tags=["Admin"])
async def nauti_traffic_admin_affiliate(
    access_token: str,
    request: Request,
    ref: str = Form(...),
    badge: str = Form("none"),
    avatar_url: str = Form(""),
    x_handle: str = Form(""),
):
    _verify_traffic_admin_path(access_token)
    _require_traffic_admin(request, access_token)
    clean_ref = _validate_ref(ref)
    if not clean_ref:
        return _traffic_admin_redirect(access_token, "error=bad_ref")

    config = await load_traffic_config()
    captains = _dedupe(config.get("captains"))
    first_mates = _dedupe(config.get("first_mates"))
    hidden_refs = set(_dedupe(config.get("hidden_refs")))
    hidden_refs.discard(clean_ref)

    badge = badge.strip().lower()
    if badge == "captain":
        if clean_ref not in captains:
            captains.append(clean_ref)
        first_mates = [item for item in first_mates if item != clean_ref]
    elif badge == "first_mate":
        captains = [item for item in captains if item != clean_ref]
        if clean_ref not in first_mates:
            if len(first_mates) >= 10:
                return _traffic_admin_redirect(access_token, "error=first_mates_full")
            first_mates.append(clean_ref)
    else:
        captains = [item for item in captains if item != clean_ref]
        first_mates = [item for item in first_mates if item != clean_ref]

    config["captain"] = captains[0] if captains else None
    config["captains"] = captains
    config["first_mates"] = first_mates
    config["hidden_refs"] = sorted(hidden_refs)

    if avatar_url.strip():
        avatar_urls = config.get("avatar_urls") if isinstance(config.get("avatar_urls"), dict) else {}
        avatar_urls[clean_ref] = avatar_url.strip()
        config["avatar_urls"] = avatar_urls
    if x_handle.strip():
        handle = x_handle.strip().removeprefix("@")
        avatar_overrides = config.get("avatar_overrides") if isinstance(config.get("avatar_overrides"), dict) else {}
        avatar_overrides[clean_ref] = handle
        config["avatar_overrides"] = avatar_overrides

    await save_traffic_config(config)
    return _traffic_admin_redirect(access_token, f"notice=affiliate_saved_{clean_ref}")


@app.post("/nauti-traffic/admin/{access_token}/alias", tags=["Admin"])
async def nauti_traffic_admin_alias(
    access_token: str,
    request: Request,
    alias: str = Form(...),
    target: str = Form(...),
):
    _verify_traffic_admin_path(access_token)
    _require_traffic_admin(request, access_token)
    clean_alias = _validate_ref(alias)
    clean_target = _validate_ref(target)
    if not clean_alias or not clean_target:
        return _traffic_admin_redirect(access_token, "error=bad_alias")

    config = await load_traffic_config()
    aliases = config.get("ref_aliases") if isinstance(config.get("ref_aliases"), dict) else {}
    aliases[clean_alias] = clean_target
    config["ref_aliases"] = aliases
    await save_traffic_config(config)
    return _traffic_admin_redirect(access_token, f"notice=alias_saved_{clean_alias}")


@app.post("/nauti-traffic/admin/{access_token}/hide", tags=["Admin"])
async def nauti_traffic_admin_hide(
    access_token: str,
    request: Request,
    ref: str = Form(...),
    action: str = Form("hide"),
):
    _verify_traffic_admin_path(access_token)
    _require_traffic_admin(request, access_token)
    clean_ref = _validate_ref(ref)
    if not clean_ref:
        return _traffic_admin_redirect(access_token, "error=bad_ref")

    config = await load_traffic_config()
    hidden = set(_dedupe(config.get("hidden_refs")))
    if action == "show":
        hidden.discard(clean_ref)
    else:
        hidden.add(clean_ref)
    config["hidden_refs"] = sorted(hidden)
    await save_traffic_config(config)
    return _traffic_admin_redirect(access_token, f"notice=visibility_saved_{clean_ref}")


@app.api_route(
    "/nauti-traffic/admin/{blocked_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def nauti_traffic_admin_catchall():
    raise HTTPException(status_code=404, detail="Not Found")


@app.get("/v1/traffic", tags=["Public"])
async def public_traffic_leaderboard():
    """Public Nauti-Traffic leaderboard. No auth, no emails, no IPs.

    Returns every ambassador with click + signup totals + tier breakdown,
    plus a `general_traffic` aggregate for non-attributed visits.
    """
    config = await load_traffic_config()
    metric_floors = config.get("metric_floors", {})
    hidden_refs = set(_dedupe(config.get("hidden_refs")))
    db = await get_db()
    try:
        cur = await db.execute("""
            SELECT DISTINCT ref FROM (
                SELECT ref FROM visits WHERE ref IS NOT NULL
                UNION
                SELECT ref FROM traffic_events WHERE ref IS NOT NULL
                UNION
                SELECT referred_by AS ref FROM api_keys WHERE referred_by IS NOT NULL
                UNION
                SELECT referred_by AS ref FROM payments WHERE referred_by IS NOT NULL
            )
        """)
        refs = [r["ref"] for r in await cur.fetchall() if r["ref"]]
        path_rows = await (await db.execute(
            """SELECT DISTINCT path FROM traffic_events
               WHERE path LIKE '/r/%' OR (
                   path GLOB '/[A-Za-z0-9_-]*'
                   AND path NOT LIKE '%.%'
               )"""
        )).fetchall()
        for row in path_rows:
            ref = _traffic_ref_from_path(row["path"])
            if ref and ref not in refs:
                refs.append(ref)
        ambassador_floor_refs = metric_floors.get("ambassadors") if isinstance(metric_floors, dict) else {}
        if isinstance(ambassador_floor_refs, dict):
            for ref in ambassador_floor_refs:
                clean_ref = _validate_ref(ref)
                if clean_ref and clean_ref not in refs:
                    refs.append(clean_ref)
    finally:
        await db.close()

    rows = []
    for ref in refs:
        if ref in hidden_refs:
            continue
        try:
            rows.append(await _ambassador_stats_payload(ref, metric_floors))
        except Exception:
            continue
    rows.sort(key=lambda x: (x["clicks"], x["paid_conversions"]), reverse=True)
    return {
        "ambassadors": rows,
        "count": len(rows),
        "general_traffic": await _general_traffic_payload(metric_floors),
    }


@app.get("/nauti-traffic", response_class=HTMLResponse, tags=["Pages"])
async def nauti_traffic_page(request: Request):
    """Public Nauti-Traffic leaderboard page."""
    return templates.TemplateResponse(
        request,
        "nauti_traffic.html",
        {"base_url": BASE_URL.rstrip("/")},
    )


@app.get("/Nauti-Traffic", response_class=HTMLResponse, tags=["Pages"], include_in_schema=False)
async def nauti_traffic_page_titlecase(request: Request):
    """Title-case alias for the public Nauti-Traffic leaderboard page."""
    return templates.TemplateResponse(
        request,
        "nauti_traffic.html",
        {"base_url": BASE_URL.rstrip("/")},
    )


@app.get("/family/login", response_class=HTMLResponse, tags=["Family"])
async def family_login_page(request: Request):
    try:
        await get_family_user(request)
        return RedirectResponse(url="/family", status_code=303)
    except HTTPException:
        pass

    return templates.TemplateResponse(
        request,
        "family_login.html",
        {
            "product_name": FAMILY_PRODUCT_NAME,
            "household_name": FAMILY_HOUSEHOLD_NAME,
        },
    )


@app.post("/family/api/login", tags=["Family"])
async def family_login(body: FamilyLogin, response: Response):
    user = authenticate_family_user(body)
    token = make_family_session_token(user["username"], user["display_name"])
    response.set_cookie(
        FAMILY_SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=not _is_local_url(BASE_URL),
        max_age=FAMILY_SESSION_HOURS * 3600,
    )
    return {
        "status": "ok",
        "viewer": user,
        "redirect_to": "/family",
    }


@app.post("/family/api/logout", tags=["Family"])
async def family_logout(response: Response):
    response.delete_cookie(FAMILY_SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/family", response_class=HTMLResponse, tags=["Family"])
async def family_dashboard_page(request: Request):
    try:
        viewer = await get_family_user(request)
    except HTTPException:
        return RedirectResponse(url=f"/family/login?next={quote('/family')}", status_code=303)

    dashboard = await build_family_dashboard()
    return templates.TemplateResponse(
        request,
        "family_dashboard.html",
        {
            "viewer": viewer,
            "household_name": FAMILY_HOUSEHOLD_NAME,
            "product_name": FAMILY_PRODUCT_NAME,
            "dashboard_json": json.dumps({**dashboard, "viewer": viewer}),
        },
    )


@app.get("/family/api/dashboard", tags=["Family"])
async def family_dashboard_api(family_user: dict = Depends(get_family_user)):
    dashboard = await build_family_dashboard()
    dashboard["viewer"] = family_user
    return dashboard


@app.post("/family/api/sync", tags=["Family"])
async def family_sync(payload: FamilySyncPayload, _: str = Depends(require_sync_token)):
    return await upsert_family_snapshot(payload)


@app.get("/family/api/payees", tags=["Family"])
async def family_payees(_: dict = Depends(get_family_user)):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM approved_payees WHERE active = 1 ORDER BY name ASC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@app.post("/family/api/payees", tags=["Family"])
async def create_family_payee(body: FamilyPayeeCreate, family_user: dict = Depends(get_family_user)):
    db = await get_db()
    try:
        payee_id = f"payee_{hash_key(body.name.lower())[:20]}"
        await db.execute(
            """INSERT INTO approved_payees (id, name, category, method, risk_level, created_at, active)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(name) DO UPDATE SET
                   category = excluded.category,
                   method = excluded.method,
                   risk_level = excluded.risk_level,
                   active = 1""",
            (payee_id, body.name.strip(), body.category, body.method, body.risk_level, now_iso()),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "family.payee.upserted",
                family_user["display_name"],
                json.dumps({"payee": body.name.strip(), "category": body.category}),
                now_iso(),
            ),
        )
        await db.commit()
        return {"status": "ok", "name": body.name.strip()}
    finally:
        await db.close()


@app.post("/family/api/actions", tags=["Family"])
async def create_family_action(body: FamilyActionCreate, family_user: dict = Depends(get_family_user)):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM approved_payees WHERE lower(name) = lower(?) AND active = 1",
            (body.payee.strip(),),
        )
        payee = await cursor.fetchone()
        if not payee:
            raise HTTPException(
                status_code=400,
                detail="Payee is not on the approved allowlist. Add it before queuing any release.",
            )

        action_id = generate_id("fam")
        await db.execute(
            """INSERT INTO family_actions
               (id, action_type, title, payee, amount, currency, source_account, destination_hint,
                status, requested_by, human_note, recommended_execution_date, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                action_id,
                body.action_type,
                body.title,
                body.payee.strip(),
                body.amount,
                body.currency,
                body.source_account,
                body.destination_hint,
                "pending_human_approval",
                family_user["display_name"],
                body.human_note,
                body.recommended_execution_date,
                now_iso(),
                json.dumps(body.metadata) if body.metadata else None,
            ),
        )
        await db.commit()
        return {
            "status": "queued",
            "action_id": action_id,
            "approval_state": "pending_human_approval",
        }
    finally:
        await db.close()


@app.post("/family/api/actions/{action_id}/decision", tags=["Family"])
async def decide_family_action(
    action_id: str,
    body: FamilyActionDecision,
    family_user: dict = Depends(get_family_user),
):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM family_actions WHERE id = ?", (action_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Queued action not found")

        action = dict(row)
        if action["status"] != "pending_human_approval":
            raise HTTPException(status_code=409, detail=f"Action already {action['status']}")

        new_status = "approved_for_release" if body.approved else "denied_by_human"
        await db.execute(
            """UPDATE family_actions
               SET status = ?, approved_by = ?, human_note = ?, decided_at = ?
               WHERE id = ?""",
            (
                new_status,
                family_user["display_name"],
                body.note or action.get("human_note"),
                now_iso(),
                action_id,
            ),
        )
        await db.commit()
        return {"status": new_status, "action_id": action_id}
    finally:
        await db.close()


# --- Agent Income: approval-gated revenue operator ---

ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
AGENT_INCOME_API_KEY_ID = "key_agent_income_system"
AGENT_INCOME_API_EMAIL = "agent-income@nauti-labs.local"
AGENT_INCOME_OWNER = "family"
AGENT_INCOME_LOGIN_FAILURES: dict[str, list[datetime]] = {}
AGENT_INCOME_ASSET_VERSION = "agent-income-logo-20260508"
AGENT_INCOME_ASSET_BASE = "/agent-income/assets"
AGENT_INCOME_ASSET_DIR = Path("static/agent-income")
AGENT_INCOME_ASSET_FILES = {
    "logo.png",
    "mark.png",
    "favicon.png",
    "favicon.ico",
    "apple-touch.png",
    "og.png",
}


def _agent_income_asset_url(filename: str) -> str:
    return f"{AGENT_INCOME_ASSET_BASE}/{filename}?v={AGENT_INCOME_ASSET_VERSION}"


def _agent_income_head_assets(title: str, description: str | None = None) -> str:
    safe_title = html.escape(title)
    safe_description = html.escape(description or "Agent Income bot-commerce dashboard and paid HTTP 402 services.")
    og_image = f"{BASE_URL.rstrip('/')}{_agent_income_asset_url('og.png')}"
    return f"""
  <title>{safe_title}</title>
  <link rel="icon" type="image/png" sizes="256x256" href="{_agent_income_asset_url('favicon.png')}">
  <link rel="icon" type="image/x-icon" href="{_agent_income_asset_url('favicon.ico')}">
  <link rel="shortcut icon" href="{_agent_income_asset_url('favicon.ico')}">
  <link rel="apple-touch-icon" sizes="180x180" href="{_agent_income_asset_url('apple-touch.png')}">
  <meta name="theme-color" content="#050505">
  <meta property="og:title" content="{safe_title}">
  <meta property="og:description" content="{safe_description}">
  <meta property="og:image" content="{html.escape(og_image)}">
"""


AGENT_INCOME_GUARDRAILS = [
    "No private keys, seed phrases, browser cookies, or custodial wallet access are ever requested or stored.",
    "Inbound funded-bot purchases are automated: pay, verify, receive the JSON artifact.",
    "Humans approve only outbound actions, agent spending, and withdrawals; inbound paid API calls do not wait on humans.",
    "Agent spending is limited to approved x402 service budgets with amount caps, expiry, and ledger entries.",
    "No investment trading, guaranteed returns, impersonation, spam, regulated professional advice, or scraping behind logins.",
    "Customer payments should settle to the connected Base wallet or a separately reviewed invoice rail.",
    "Withdrawals require a fresh Clearance approval and a human wallet signature outside this server.",
]


AGENT_INCOME_LOW_VALUE_JOB_TYPES = [
    "haiku",
    "short_writing",
    "summary",
    "json_formatting",
    "schema_generation",
    "intent_classification",
    "message_rewrite",
    "data_cleanup",
    "simple_extraction",
    "bot_output_validation",
]


AGENT_INCOME_FORBIDDEN_ACTIVITY = [
    "theft",
    "fraud",
    "phishing",
    "spam",
    "impersonation",
    "private_key_collection",
    "seed_phrase_collection",
    "wallet_targeting",
    "exploit_attempts",
    "fake_volume",
    "marketplace_manipulation",
]


AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY = {
    "project": "agent-income",
    "policy_type": "autonomous_low_value_job_policy",
    "allowed_sources": ["approved_bot_job_marketplaces", "approved_buyer_agent_task_feeds"],
    "allowed_job_types": AGENT_INCOME_LOW_VALUE_JOB_TYPES,
    "min_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
    "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
    "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
    "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
    "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
    "max_job_price_usd": 25,
    "max_work_seconds_per_job": 300,
    "max_model_cost_per_job_usd": 0.05,
    "max_api_cost_per_job_usd": 0,
    "payment_or_escrow_required_before_delivery": True,
    "auto_bid_if_qualified": True,
    "auto_fulfill_if_paid": True,
    "human_role": "approve_or_deny_policy_only",
    "forbidden_activity": AGENT_INCOME_FORBIDDEN_ACTIVITY,
}


AGENT_OUTREACH_TARGETS = [
    {
        "target": "Wilhelmsen Port Services Houston",
        "fit": "Ship agency and port services across Houston/Gulf Coast",
        "contact": "wps.houston@wilhelmsen.com",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Wilhelmsen Port Services NAM Gulf Coast",
        "fit": "Husbandry and port-services workflows",
        "contact": "wps.nam.husbandry@wilhelmsen.com",
        "source": "workspace_target_tracker",
    },
    {
        "target": "International Tanker Management Texas",
        "fit": "Oil and chemical tanker ship management",
        "contact": "itm.houston@tankermanager.com",
        "source": "workspace_target_tracker",
    },
    {
        "target": "MOL Chemical Tankers America",
        "fit": "Houston chemical tanker operations/contact office",
        "contact": "contact_form",
        "source": "workspace_target_tracker",
    },
    {
        "target": "NobelSeas Shipping",
        "fit": "Specialized liquid cargo shipping with Houston presence",
        "contact": "contact_form",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Teekay Houston",
        "fit": "Tanker commercial operations and ship-to-ship services",
        "contact": "office_contact_path",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Ameritank",
        "fit": "Houston Ship Channel barge storage/fleeting coordination",
        "contact": "website_contact_path",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Port of Galveston / Galveston Wharves",
        "fit": "Port operations relationship target",
        "contact": "website_contact_path",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Texas International Terminals",
        "fit": "Terminal/logistics operations",
        "contact": "website_contact_path",
        "source": "workspace_target_tracker",
    },
    {
        "target": "Maersk Tankers Houston",
        "fit": "Tanker office/contact path",
        "contact": "website_contact_path",
        "source": "workspace_target_tracker",
    },
]


AGENT_BOT_SERVICES = [
    {
        "key": "offer_audit",
        "label": "Agent Offer Audit",
        "price_usdc": 40,
        "description": "Scores an agent's paid offer for clarity, conversion, risk, and x402 readiness.",
        "input_schema": {
            "type": "object",
            "properties": {
                "offer": {"type": "string"},
                "target_agent": {"type": "string"},
                "price": {"type": "string"},
            },
            "required": ["offer"],
        },
    },
    {
        "key": "x402_listing_pack",
        "label": "x402 Listing Pack",
        "price_usdc": 45,
        "description": "Turns a paid endpoint idea into bot-readable listing copy, schemas, pricing, and 402 requirements.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "buyer": {"type": "string"},
                "output": {"type": "string"},
            },
            "required": ["endpoint"],
        },
    },
    {
        "key": "anchor_compliance_pack",
        "label": "Anchor Compliance Custodian Pack",
        "price_usdc": 125,
        "description": "Packages a crypto custodian workflow into approval gates, wallet-policy boundaries, evidence logs, and a paid pilot offer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "custodian_profile": {"type": "string"},
                "asset_flows": {"type": "string"},
                "wallet_controls": {"type": "string"},
                "regulated_touchpoints": {"type": "string"},
            },
            "required": ["custodian_profile"],
        },
    },
    {
        "key": "tool_policy_check",
        "label": "Tool Policy Check",
        "price_usdc": 35,
        "description": "Reviews an autonomous tool call for action risk, required approval boundaries, and audit fields.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "action": {"type": "string"},
                "arguments": {"type": "object"},
            },
            "required": ["tool", "action"],
        },
    },
    {
        "key": "buyer_intent_digest",
        "label": "Buyer Intent Digest",
        "price_usdc": 35,
        "description": "Classifies an inbound buyer or agent request and returns next action, risk, and payment ask.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "seller": {"type": "string"},
            },
            "required": ["message"],
        },
    },
    {
        "key": "prompt_to_api_spec",
        "label": "Prompt-to-API Spec",
        "price_usdc": 45,
        "description": "Converts a messy agent prompt into a paid API contract with request/response schemas.",
        "input_schema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "constraints": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
]


AGENT_INCOME_AUDIT_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "project_url": {"type": "string", "format": "uri"},
        "agent_type": {"type": "string", "enum": ["buyer", "seller", "both", "unknown"]},
        "payment_goal": {"type": "string", "enum": ["accept_payments", "make_payments", "both"]},
        "current_stack": {"type": "string", "enum": ["AWS", "Coinbase", "Stripe", "custom", "unknown"]},
        "notes": {"type": "string"},
    },
    "required": ["project_url", "agent_type", "payment_goal", "current_stack"],
}

AGENT_INCOME_AUDIT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {"type": "number"},
        "summary": {"type": "string"},
        "income_opportunities": {"type": "array"},
        "payment_flow_recommendation": {"type": "string"},
        "clearance_recommendation": {"type": "string"},
        "x402_recommendation": {"type": "string"},
        "aws_agentcore_recommendation": {"type": "string"},
        "risks": {"type": "array"},
        "next_steps": {"type": "array"},
        "upsell": {"type": "object"},
    },
    "required": [
        "score",
        "summary",
        "income_opportunities",
        "payment_flow_recommendation",
        "clearance_recommendation",
        "x402_recommendation",
        "risks",
        "next_steps",
    ],
}

AGENT_INCOME_ANCHOR_COMPLIANCE_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "project_url": {"type": "string", "format": "uri"},
        "custodian_name": {"type": "string"},
        "custody_model": {"type": "string", "enum": ["qualified_custodian", "self_custody_platform", "wallet_infrastructure", "exchange_custody", "unknown"]},
        "jurisdictions": {"type": "array"},
        "asset_flows": {"type": "string"},
        "wallet_controls": {"type": "string"},
        "compliance_need": {"type": "string"},
        "notes": {"type": "string"},
    },
    "required": ["project_url", "custody_model", "compliance_need"],
}

AGENT_INCOME_ANCHOR_COMPLIANCE_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        **AGENT_INCOME_AUDIT_OUTPUT_SCHEMA["properties"],
        "custodian_controls": {"type": "array"},
        "evidence_map": {"type": "array"},
        "approval_boundaries": {"type": "array"},
        "transaction_policy": {"type": "array"},
        "pilot_offer": {"type": "object"},
    },
    "required": [
        "score",
        "summary",
        "custodian_controls",
        "evidence_map",
        "approval_boundaries",
        "transaction_policy",
        "risks",
        "next_steps",
    ],
}

AGENT_INCOME_PAID_OFFERS = [
    {
        "key": "readiness_audit",
        "slug": "audit",
        "label": "Instant Agent Payment Readiness Score",
        "price_usdc": 49,
        "max_work_seconds": 300,
        "description": "Scores an agent, API, MCP server, or workflow for payment readiness and returns a concise monetization checklist.",
        "path": "/agent-income/audit",
        "input_schema": AGENT_INCOME_AUDIT_INPUT_SCHEMA,
        "output_schema": AGENT_INCOME_AUDIT_OUTPUT_SCHEMA,
        "refund_terms": "Refund review is available if verified payment succeeds but the endpoint fails to return the purchased JSON report.",
        "delivery_terms": "Machine-readable JSON report after verified Base USDC payment. No private keys, credential handling, or regulated advice.",
        "upsell": {"offer": "Payment Flow Review", "price_usd": 199},
    },
    {
        "key": "payment_flow_review",
        "slug": "review",
        "label": "Payment Flow Review",
        "price_usdc": 199,
        "max_work_seconds": 1800,
        "description": "Reviews x402-style, HTTP 402, AgentCore-style, API, MCP, or agent payment workflows for monetization and spend-control readiness.",
        "path": "/agent-income/review",
        "input_schema": {
            **AGENT_INCOME_AUDIT_INPUT_SCHEMA,
            "properties": {
                **AGENT_INCOME_AUDIT_INPUT_SCHEMA["properties"],
                "payment_flow": {"type": "string"},
                "endpoints": {"type": "array"},
                "pricing": {"type": "string"},
            },
        },
        "output_schema": {
            "type": "object",
            "properties": {
                **AGENT_INCOME_AUDIT_OUTPUT_SCHEMA["properties"],
                "endpoint_design": {"type": "array"},
                "spend_controls": {"type": "array"},
                "pricing_notes": {"type": "array"},
            },
        },
        "refund_terms": "Refund review is available if verified payment succeeds but the endpoint fails to return the purchased review.",
        "delivery_terms": "Deeper JSON review after verified Base USDC payment. Uses customer-provided and public information only.",
        "upsell": {"offer": "Integration Blueprint", "price_usd": 499},
    },
    {
        "key": "integration_blueprint",
        "slug": "blueprint",
        "label": "Integration Blueprint",
        "price_usdc": 499,
        "max_work_seconds": 5400,
        "description": "Produces an implementation blueprint for paid endpoints, Clearance approval boundaries, pricing logic, risk controls, and launch readiness.",
        "path": "/agent-income/blueprint",
        "input_schema": {
            **AGENT_INCOME_AUDIT_INPUT_SCHEMA,
            "properties": {
                **AGENT_INCOME_AUDIT_INPUT_SCHEMA["properties"],
                "architecture": {"type": "string"},
                "current_endpoints": {"type": "array"},
                "desired_paid_services": {"type": "array"},
                "constraints": {"type": "string"},
            },
        },
        "output_schema": {
            "type": "object",
            "properties": {
                **AGENT_INCOME_AUDIT_OUTPUT_SCHEMA["properties"],
                "architecture_plan": {"type": "array"},
                "endpoint_plan": {"type": "array"},
                "clearance_integration_points": {"type": "array"},
                "launch_checklist": {"type": "array"},
            },
        },
        "refund_terms": "Refund review is available if verified payment succeeds but the endpoint fails to return the purchased blueprint.",
        "delivery_terms": "Detailed JSON blueprint after verified Base USDC payment. Implementation work is separately quoted.",
        "upsell": {"offer": "Implementation Package", "price_usd": 1500},
    },
    {
        "key": "anchor_compliance_readiness",
        "slug": "anchor-compliance",
        "label": "Anchor Compliance Custodian Readiness Pack",
        "price_usdc": 499,
        "max_work_seconds": 3600,
        "description": "Maps a crypto custodian, wallet infrastructure, or digital asset operations workflow into approval gates, transaction-policy boundaries, evidence logs, and a paid pilot path.",
        "path": "/agent-income/anchor-compliance",
        "input_schema": AGENT_INCOME_ANCHOR_COMPLIANCE_INPUT_SCHEMA,
        "output_schema": AGENT_INCOME_ANCHOR_COMPLIANCE_OUTPUT_SCHEMA,
        "refund_terms": "Refund review is available if verified payment succeeds but the endpoint fails to return the purchased Anchor Compliance readiness pack.",
        "delivery_terms": "Operational readiness JSON after verified Base USDC payment. This is not legal advice, custody service, transaction monitoring service, or wallet/key handling.",
        "upsell": {"offer": "Anchor Compliance Pilot", "price_usd": 2500},
    },
]

AGENT_INCOME_CUSTOM_QUOTE_SCHEMA = {
    "type": "object",
    "properties": {
        "project_url": {"type": "string"},
        "buyer_contact": {"type": "string"},
        "scope_summary": {"type": "string"},
        "target_launch_date": {"type": "string"},
        "budget_range": {"type": "string"},
        "notes": {"type": "string"},
    },
    "required": ["scope_summary"],
}


AGENT_INCOME_MARKETPLACE_LISTINGS = [
    {
        "marketplace": "402 Index",
        "channel_url": "https://402index.io/",
        "authorization_basis": "self-service x402 paid-service directory",
        "status": "live",
        "listings": [
            {
                "id": "4c9a6539-7458-46d4-8a31-2ddfaa785b49",
                "name": "Agent Income Readiness Audit",
                "price_usd": 49,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/audit",
                "health_status": "healthy",
            },
            {
                "id": "2d336624-918a-46e4-a5ba-787ae798fa4f",
                "name": "Agent Income Payment Flow Review",
                "price_usd": 199,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/review",
                "health_status": "healthy",
            },
            {
                "id": "2de3cc11-2b86-420a-b12e-b24bf7e264de",
                "name": "Agent Income Integration Blueprint",
                "price_usd": 499,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/blueprint",
                "health_status": "healthy",
            },
        ],
    },
    {
        "marketplace": "PayanAgent",
        "channel_url": "https://payanagent.com/",
        "authorization_basis": "provider/service registry for agent commerce",
        "status": "live",
        "provider_id": "j57205frg60hh38fgp51rg8g1d86bzgp",
        "listings": [
            {
                "id": "js78n0mjwpbtfqkdhm970cbxgn86bstt",
                "name": "Agent Income Readiness Audit",
                "price_usd": 49,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/audit",
                "health_status": "active",
            },
            {
                "id": "js73d9jtc28yv5z5pbbqp5dc3x86a3aw",
                "name": "Agent Income Payment Flow Review",
                "price_usd": 199,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/review",
                "health_status": "active",
            },
            {
                "id": "js70xsdargccpdypv1avaywpyn86bmny",
                "name": "Agent Income Integration Blueprint",
                "price_usd": 499,
                "endpoint": "https://clearance.nauti-labs.com/agent-income/blueprint",
                "health_status": "active",
            },
        ],
    },
]

AGENT_INCOME_DISCOVERY_NOTES = [
    {
        "channel": "the402",
        "status": "blocked_no_spend",
        "note": "Provider onboarding requires outgoing x402 payment; held until Clearance spend approval is available.",
        "url": "https://the402.ai/",
    },
    {
        "channel": "OMA-AI",
        "status": "not_listed",
        "note": "MCP publishing/contact path found; not submitted because Agent Income is currently HTTP paid endpoints, not an MCP package.",
        "url": "https://www.oma-ai.com/publish",
    },
    {
        "channel": "PayanAgent open jobs",
        "status": "active_pipeline",
        "note": "Open marketplace jobs are tracked by the 24/7 operator. Safe jobs can be bid only after Clearance approval and payment/escrow before delivery.",
        "url": "https://payanagent.com/",
    },
]


def _agent_income_offer_openapi_payment_info(offer: dict) -> dict:
    return {
        "price": {
            "mode": "fixed",
            "currency": "USD",
            "amount": f"{float(offer['price_usdc']):.6f}",
        },
        "protocols": [
            {
                "x402": {
                    "version": 1,
                    "network": f"eip155:{PAYMENT_CHAIN_ID}",
                    "asset": USDC_CONTRACT,
                    "payTo": _configured_agent_income_wallet_address() or "",
                    "paymentHeader": "PAYMENT-REQUIRED",
                    "retryHeader": "X-Payment-Tx",
                }
            }
        ],
    }


def _install_clearance_openapi() -> None:
    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        info = schema.setdefault("info", {})
        info.setdefault("contact", {"email": PAYMENT_SUPPORT_EMAIL})
        info.setdefault(
            "x-guidance",
            "Use the Agent Income POST endpoints for fixed-price x402 payment-flow audits, reviews, and blueprints. "
            "Unpaid calls return HTTP 402 with PAYMENT-REQUIRED and X-Payment-* headers; retry after verified Base USDC payment.",
        )

        paths = schema.setdefault("paths", {})
        for offer in AGENT_INCOME_PAID_OFFERS:
            if offer["slug"] not in {"audit", "review", "blueprint"}:
                continue
            operation = paths.get(offer["path"], {}).get("post")
            if not operation:
                continue
            operation["description"] = offer["description"]
            operation["x-payment-info"] = _agent_income_offer_openapi_payment_info(offer)
            operation["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": offer["input_schema"],
                    }
                },
            }
            responses = operation.setdefault("responses", {})
            responses["200"] = {
                "description": "Paid JSON report delivered after verified payment.",
                "content": {
                    "application/json": {
                        "schema": offer["output_schema"],
                    }
                },
            }
            responses["402"] = {
                "description": "Payment Required. Inspect PAYMENT-REQUIRED, X-Payment-Requirements, and X-Payment-* headers.",
            }
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi


_install_clearance_openapi()


def _agent_income_state_key(key: str) -> str:
    return f"agent_income:{key}"


async def _agent_income_get_state_value(key: str, default=None):
    db = await get_db()
    try:
        row = await (
            await db.execute("SELECT value FROM bot_comm_state WHERE key = ?", (_agent_income_state_key(key),))
        ).fetchone()
        if not row:
            return default
        return _load_json(row["value"], default)
    finally:
        await db.close()


async def _agent_income_set_state_value(key: str, value) -> None:
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO bot_comm_state (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at""",
            (_agent_income_state_key(key), json.dumps(value), now_iso()),
        )
        await db.commit()
    finally:
        await db.close()


async def _agent_income_fetch_json(client: httpx.AsyncClient, url: str) -> dict:
    response = await client.get(url, timeout=20)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


AGENT_INCOME_DISCOVERY_QUERIES = (
    "agent payments",
    "x402 payment readiness",
    "HTTP 402 monetization",
    "security audit",
    "code review",
    "api integration",
    "technical documentation",
    "data cleaning",
    "spreadsheet cleanup",
    "automation",
    "MCP monetization",
    "paid API",
    "crypto custodian compliance",
    "digital asset custody controls",
    "wallet operations evidence logs",
)

AGENT_INCOME_GITHUB_LEAD_QUERIES = (
    "x402 payments state:open type:issue",
    "\"HTTP 402\" payments state:open type:issue",
    "\"paid API\" agent state:open type:issue",
    "\"MCP\" monetization state:open type:issue",
    "\"agent payments\" state:open type:issue",
    "\"agent commerce\" state:open type:issue",
    "\"autonomous agent payments\" state:open type:issue",
    "\"payment primitive\" agent state:open type:issue",
    "bounty x402 state:open type:issue",
    "\"crypto custodian\" compliance state:open type:issue",
    "\"digital asset custody\" controls state:open type:issue",
    "\"wallet operations\" compliance state:open type:issue",
)

AGENT_INCOME_GITHUB_REPO_LEAD_QUERIES = (
    "x402 payments",
    "\"HTTP 402\" paid API",
    "\"agent payments\"",
    "\"crypto custodian\" compliance",
    "\"digital asset custody\" controls",
)

AGENT_INCOME_HN_LEAD_QUERIES = (
    "x402 payments",
    "HTTP 402 paid API",
    "agent payments",
    "AI agent marketplace",
    "MCP monetization",
    "API monetization",
    "crypto custodian compliance",
    "digital asset custody controls",
    "wallet operations compliance",
)


AGENT_INCOME_ANCHOR_COMPLIANCE_LEAD_TERMS = (
    "crypto custodian",
    "digital asset custody",
    "qualified custodian",
    "custody compliance",
    "custodian compliance",
    "wallet operations",
    "wallet policy",
    "transaction policy",
    "transaction approval",
    "approval evidence",
    "evidence log",
    "aml",
    "kyc",
    "travel rule",
    "anchor compliance",
)


def _agent_income_public_lead_text(lead: dict) -> str:
    labels = lead.get("labels") or []
    label_text = " ".join(
        str(label.get("name") if isinstance(label, dict) else label)
        for label in labels[:8]
    )
    topics = lead.get("topics") or []
    topic_text = " ".join(str(topic) for topic in topics[:12])
    return " ".join(
        str(part or "")
        for part in (
            lead.get("title"),
            lead.get("body"),
            lead.get("description"),
            lead.get("text"),
            lead.get("story_text"),
            lead.get("readme"),
            label_text,
            topic_text,
        )
    ).lower()


def _agent_income_is_anchor_compliance_lead(text: str) -> bool:
    return any(term in text for term in AGENT_INCOME_ANCHOR_COMPLIANCE_LEAD_TERMS)


def _agent_income_public_lead_safety(lead: dict) -> tuple[int, list[str]]:
    text = _agent_income_public_lead_text(lead)
    risk_flags = []
    hard_block_terms = (
        "phishing",
        "credential",
        "private key",
        "seed phrase",
        "wallet drain",
        "malware",
        "spam",
        "account takeover",
        "exploit",
        "bypass",
        "vulnerability scan",
    )
    for term in hard_block_terms:
        if term in text:
            risk_flags.append(f"blocked_term:{term}")
    if risk_flags:
        return 40, risk_flags
    return 95, []


def _agent_income_public_lead_scores(lead: dict) -> dict:
    source = str(lead.get("source") or "")
    text = _agent_income_public_lead_text(lead)
    title_text = str(lead.get("title") or lead.get("name") or "").lower()
    anchor_fit = _agent_income_is_anchor_compliance_lead(text)
    strong_fit_terms = (
        "x402",
        "http 402",
        "paid api",
        "agent payment",
        "agent-to-agent commerce",
        "payment integration",
        "payment layer",
        "mcp monetization",
        "api monetization",
        "paid endpoint",
        "subscription billing",
        "recurring billing",
    )
    adjacent_fit_terms = (
        "agent",
        "api",
        "mcp",
        "automation",
        "wallet",
        "billing",
        "checkout",
        "marketplace",
    )
    explicit_help_terms = (
        "bounty",
        "paid",
        "budget",
        "contract",
        "freelance",
        "hiring",
        "rfp",
        "request for proposal",
        "looking for help",
        "looking for someone",
        "need help",
        "help wanted",
        "seeking",
        "looking for feedback",
        "how can we implement",
        "how should we implement",
        "proposal",
        "request",
        "integrate",
        "integration",
    )
    weak_noise_terms = (
        "show hn",
        "retro:",
        "star our",
        "review an open pr",
        "onboard:",
        "failed startup",
    )
    strong_fit = any(term in text for term in strong_fit_terms)
    adjacent_fit = any(term in text for term in adjacent_fit_terms)
    explicit_help = any(term in text for term in explicit_help_terms)
    weak_noise = any(term in title_text for term in weak_noise_terms)

    if anchor_fit or strong_fit:
        need_score = 100
    elif adjacent_fit and explicit_help:
        need_score = 80
    else:
        need_score = 40

    authorization_score = 80 if explicit_help and (strong_fit or adjacent_fit) else 60
    if source == "GitHub public repositories":
        authorization_score = min(authorization_score, 60)
    if source == "Hacker News public stories" and "looking for feedback" not in text and "need help" not in text:
        authorization_score = min(authorization_score, 60)
    if weak_noise and not strong_fit and not anchor_fit:
        authorization_score = 40
        need_score = min(need_score, 40)

    revenue_score = 80 if any(term in text for term in ("integrat", "implementation", "build", "launch", "architecture", "blueprint")) else 60
    if anchor_fit:
        revenue_score = 100
    if any(term in text for term in ("enterprise", "platform", "marketplace")):
        revenue_score = 100
    return {
        "need_score": need_score,
        "authorization_score": authorization_score,
        "revenue_score": revenue_score,
    }


def _agent_income_lead_email(lead: dict) -> str:
    for key in ("email", "contact_email", "buyer_contact", "contact"):
        value = str(lead.get(key) or "").strip()
        if EMAIL_PATTERN.fullmatch(value):
            return value
    return ""


def _agent_income_score_public_lead(source: str, query: str, lead: dict) -> dict | None:
    url = str(lead.get("html_url") or lead.get("url") or lead.get("link") or "")
    title = str(lead.get("title") or lead.get("name") or "Public lead")[:180]
    lead_id = str(lead.get("id") or lead.get("node_id") or url or title)
    if not lead_id or not title:
        return None
    text = _agent_income_public_lead_text(lead)
    safety_score, risk_flags = _agent_income_public_lead_safety(lead)
    scores = _agent_income_public_lead_scores(lead)
    contact_allowed = safety_score >= 80 and scores["need_score"] >= 60 and scores["authorization_score"] >= 80
    if safety_score < 80:
        status = "blocked_safety_review"
    elif scores["need_score"] < 60:
        status = "monitor_only_low_fit"
    elif contact_allowed:
        status = "contact_ready_public_need"
    else:
        status = "monitor_only_public_signal"
    if _agent_income_is_anchor_compliance_lead(text):
        recommended_offer = "Anchor Compliance Custodian Readiness Pack"
        recommended_price = 499
        outreach_draft = (
            "Hello — I’m an AI service agent for Nauti-Labs. I saw your public request around "
            f"{title}. We help crypto custodians and wallet-ops teams turn approval workflows into evidence logs, "
            "transaction-policy boundaries, and human approval gates. The fixed-scope Anchor Compliance pack is "
            f"${recommended_price}, paid before work starts. It is operational readiness work, not legal advice or custody. "
            "Interested?"
        )
    else:
        recommended_offer = "Payment Flow Review" if scores["revenue_score"] >= 80 else "Agent Payment Readiness Audit"
        recommended_price = 199 if recommended_offer == "Payment Flow Review" else 49
        outreach_draft = (
            "Hello — I’m an AI service agent for Nauti-Labs. I saw your public request around "
            f"{title}. I help teams make agents, APIs, and MCP tools payment-ready with HTTP 402, "
            "x402-style payments, spending controls, and Clearance approval. "
            f"I can run a {recommended_offer} for ${recommended_price}. Payment is collected before work starts, "
            "and all transactions are approved through Clearance. Interested?"
        )
    return {
        "source": source,
        "query": query,
        "id": lead_id[:120],
        "title": title,
        "url": url,
        "contact_email": _agent_income_lead_email(lead),
        "need_score": scores["need_score"],
        "authorization_score": scores["authorization_score"],
        "revenue_score": scores["revenue_score"],
        "safety_score": safety_score,
        "risk_flags": risk_flags,
        "status": status,
        "contact_allowed": contact_allowed,
        "recommended_offer": recommended_offer,
        "recommended_price_usd": recommended_price,
        "outreach_draft": outreach_draft if contact_allowed else "",
        "outreach_rule": (
            "One concise commercial reply is allowed only if the channel rules permit offers."
            if contact_allowed
            else "Monitor only; do not contact unless the source shows commercial intent or an approved contact path."
        ),
    }


def _agent_income_add_public_lead(tick: dict, seen: set[str], source: str, query: str, lead: dict) -> None:
    if len(tick.get("public_leads") or []) >= max(AGENT_INCOME_PUBLIC_LEAD_MAX_RESULTS, 1):
        return
    scored = _agent_income_score_public_lead(source, query, lead)
    if not scored or scored["id"] in seen:
        return
    seen.add(scored["id"])
    tick["public_leads"].append(scored)


def _agent_income_feed_items(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    for key in ("openJobs", "jobs", "requests", "opportunities", "leads", "items", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _agent_income_lead_channel(lead: dict) -> dict:
    source = str(lead.get("source") or "")
    url = str(lead.get("url") or "")
    contact_email = str(lead.get("contact_email") or "").strip()
    if contact_email:
        return {
            "channel": "smtp_email",
            "can_send": bool(SMTP_HOST and EMAIL_FROM),
            "blocker": "" if SMTP_HOST and EMAIL_FROM else "smtp_not_configured",
            "note": f"Email outreach sends from {EMAIL_FROM} with reply-to {AGENT_INCOME_OUTREACH_REPLY_TO}.",
            "recipient": contact_email,
            "sender_identity": EMAIL_FROM or AGENT_INCOME_OUTREACH_REPLY_TO,
        }
    if source == "GitHub public issues" and "/issues/" in url:
        return {
            "channel": "github_issue_comment",
            "can_send": bool(AGENT_INCOME_GITHUB_TOKEN),
            "blocker": "" if AGENT_INCOME_GITHUB_TOKEN else "github_token_not_configured",
            "note": "Public issue reply sends from the GitHub account attached to AGENT_INCOME_GITHUB_TOKEN.",
            "recipient": url,
            "sender_identity": "GitHub token account",
        }
    if source == "Hacker News public stories":
        return {
            "channel": "hacker_news_comment",
            "can_send": False,
            "blocker": "no_hn_api_connector",
            "note": "Monitor and draft only; no authorized HN posting connector is configured.",
            "recipient": url,
            "sender_identity": "",
        }
    if source == "GitHub public repositories":
        return {
            "channel": "repo_business_contact_or_issue",
            "can_send": False,
            "blocker": "repo_has_no_posted_request_channel",
            "note": "Monitor and draft only unless the repo exposes a business contact path or posted request.",
            "recipient": url,
            "sender_identity": "",
        }
    return {
        "channel": "configured_public_channel",
        "can_send": False,
        "blocker": "connector_not_configured",
        "note": "Lead is stored for follow-up through a configured commercial channel.",
        "recipient": str(lead.get("contact_email") or lead.get("url") or ""),
        "sender_identity": "",
    }


def _agent_income_build_lead_action(lead: dict, rank: int) -> dict:
    channel = _agent_income_lead_channel(lead)
    send_key = hashlib.sha256(
        f"{channel['channel']}:{channel.get('recipient', '')}:{lead.get('url', '')}:{lead.get('recommended_offer', '')}".encode()
    ).hexdigest()[:32]
    if lead.get("status") == "blocked_safety_review" or float(lead.get("safety_score") or 0) < 80:
        action_status = "blocked_safety_review"
        action = "blocked"
    elif not lead.get("contact_allowed"):
        action_status = "monitor_only"
        action = "monitor"
    elif channel["can_send"]:
        action_status = "ready_to_send"
        action = "send_outreach"
    else:
        action_status = "outreach_drafted_connector_needed"
        action = "draft_outreach"
    return {
        "id": hashlib.sha256(f"{lead.get('id')}:{lead.get('url')}:{rank}".encode()).hexdigest()[:20],
        "send_key": send_key,
        "rank": rank,
        "at": now_iso(),
        "lead_id": lead.get("id"),
        "lead_title": lead.get("title"),
        "lead_url": lead.get("url"),
        "source": lead.get("source"),
        "status": action_status,
        "action": action,
        "channel": channel["channel"],
        "channel_blocker": channel["blocker"],
        "channel_note": channel["note"],
        "recipient": channel.get("recipient", ""),
        "sender_identity": channel.get("sender_identity", ""),
        "contact_allowed": bool(lead.get("contact_allowed")),
        "recommended_offer": lead.get("recommended_offer"),
        "recommended_price_usd": lead.get("recommended_price_usd"),
        "outreach_draft": lead.get("outreach_draft") or "",
        "scores": {
            "need": lead.get("need_score"),
            "authorization": lead.get("authorization_score"),
            "revenue": lead.get("revenue_score"),
            "safety": lead.get("safety_score"),
        },
    }


async def _agent_income_deal_with_leads(
    limit: int | None = None,
    *,
    tick: dict | None = None,
    autosend_ready: bool | None = None,
) -> dict:
    limit = max(min(int(limit or AGENT_INCOME_LEAD_ACTION_LIMIT), 100), 1)
    tick = tick or await _agent_income_operator_tick()
    leads = tick.get("public_leads") or []
    ranked = sorted(
        leads,
        key=lambda lead: (
            0 if lead.get("contact_allowed") else 1,
            0 if lead.get("status") != "blocked_safety_review" else 1,
            -int(lead.get("revenue_score") or 0),
            -int(lead.get("need_score") or 0),
            str(lead.get("title") or ""),
        ),
    )
    actions = [_agent_income_build_lead_action(lead, index + 1) for index, lead in enumerate(ranked[:limit])]
    sent_state = await _agent_income_get_state_value("sent_lead_keys", {"keys": []})
    sent_keys = set(sent_state.get("keys") or [])
    for action in actions:
        if action.get("send_key") in sent_keys:
            action["status"] = "already_sent"
            action["action"] = "already_sent"
            action["channel_blocker"] = ""
    action_state = {
        "at": now_iso(),
        "source_tick_at": tick.get("at"),
        "limit": limit,
        "summary": {
            "public_leads_seen": len(leads),
            "actions_created": len(actions),
            "contact_ready_seen": len([item for item in leads if item.get("contact_allowed")]),
            "drafted_outreach": len([item for item in actions if item.get("action") == "draft_outreach"]),
            "ready_to_send": len([item for item in actions if item.get("action") == "send_outreach"]),
            "sent": 0,
            "already_sent": len([item for item in actions if item.get("action") == "already_sent"]),
            "monitor_only": len([item for item in actions if item.get("action") == "monitor"]),
            "blocked": len([item for item in actions if item.get("action") == "blocked"]),
            "auto_deal_enabled": AGENT_INCOME_AUTO_DEAL_LEADS,
            "autosend_enabled": AGENT_INCOME_AUTOSEND_PUBLIC_LEADS,
        },
        "actions": actions,
    }
    await _agent_income_set_state_value("lead_actions", action_state)
    should_autosend = autosend_ready if autosend_ready is not None else AGENT_INCOME_AUTOSEND_PUBLIC_LEADS
    if should_autosend:
        for action in [item for item in actions if item.get("action") == "send_outreach"]:
            try:
                await _agent_income_send_lead_action(action["id"])
            except HTTPException as exc:
                await _agent_income_update_lead_action(action["id"], {
                    "status": "send_failed",
                    "send_error": str(exc.detail)[:400],
                    "attempted_at": now_iso(),
                })
        action_state = await _agent_income_get_state_value("lead_actions", action_state)
    return action_state


def _agent_income_parse_github_issue_url(url: str) -> tuple[str, str, int] | None:
    match = re.match(r"^https://github\.com/([^/]+)/([^/]+)/issues/(\d+)(?:[?#].*)?$", str(url or "").strip())
    if not match:
        return None
    owner, repo, issue_number = match.groups()
    return owner, repo, int(issue_number)


async def _agent_income_update_lead_action(action_id: str, updates: dict) -> dict:
    state = await _agent_income_get_state_value("lead_actions", {"actions": [], "summary": {}})
    actions = state.get("actions") or []
    updated_action = None
    for action in actions:
        if action.get("id") == action_id:
            action.update(updates)
            updated_action = action
            break
    if not updated_action:
        raise HTTPException(status_code=404, detail="Lead action not found")
    summary = state.get("summary") or {}
    summary["sent"] = len([item for item in actions if item.get("status") == "sent"])
    summary["failed"] = len([item for item in actions if item.get("status") == "send_failed"])
    state["summary"] = summary
    state["actions"] = actions
    state["updated_at"] = now_iso()
    await _agent_income_set_state_value("lead_actions", state)
    return updated_action


async def _agent_income_mark_lead_sent(action: dict) -> None:
    send_key = action.get("send_key")
    if not send_key:
        return
    sent_state = await _agent_income_get_state_value("sent_lead_keys", {"keys": []})
    keys = list(dict.fromkeys([*(sent_state.get("keys") or []), send_key]))[-2000:]
    await _agent_income_set_state_value("sent_lead_keys", {"updated_at": now_iso(), "keys": keys})


async def _agent_income_send_lead_action(action_id: str) -> dict:
    state = await _agent_income_get_state_value("lead_actions", {"actions": []})
    action = next((item for item in state.get("actions", []) if item.get("id") == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail="Lead action not found")
    if action.get("status") == "sent":
        return action
    sent_state = await _agent_income_get_state_value("sent_lead_keys", {"keys": []})
    sent_keys = set(sent_state.get("keys") or [])
    if action.get("send_key") in sent_keys:
        return await _agent_income_update_lead_action(action_id, {
            "status": "already_sent",
            "action": "already_sent",
            "channel_blocker": "",
        })
    if not action.get("contact_allowed"):
        raise HTTPException(status_code=409, detail="This lead is not contact-ready")
    draft = str(action.get("outreach_draft") or "").strip()
    if not draft:
        raise HTTPException(status_code=400, detail="This lead action has no outreach draft")
    if action.get("channel") == "smtp_email":
        recipient = str(action.get("recipient") or "").strip()
        if not EMAIL_PATTERN.fullmatch(recipient):
            raise HTTPException(status_code=400, detail="This email lead has no valid recipient email")
        sent = await send_email(
            recipient,
            f"Nauti-Labs {action.get('recommended_offer') or 'Agent Income'}",
            draft,
            reply_to=AGENT_INCOME_OUTREACH_REPLY_TO if EMAIL_PATTERN.fullmatch(AGENT_INCOME_OUTREACH_REPLY_TO or "") else None,
        )
        if not sent:
            await _agent_income_update_lead_action(action_id, {
                "status": "send_failed",
                "send_error": "smtp_not_configured_or_failed",
                "attempted_at": now_iso(),
            })
            raise HTTPException(status_code=503, detail="SMTP is not configured or the email could not be sent")
        await _agent_income_mark_lead_sent(action)
        return await _agent_income_update_lead_action(action_id, {
            "status": "sent",
            "action": "sent_outreach",
            "channel_blocker": "",
            "sent_at": now_iso(),
            "send_result": {
                "provider": "smtp",
                "to": recipient,
                "from": EMAIL_FROM,
                "reply_to": AGENT_INCOME_OUTREACH_REPLY_TO,
            },
        })
    if action.get("channel") != "github_issue_comment":
        raise HTTPException(status_code=409, detail=action.get("channel_blocker") or "No sender is configured for this lead channel")
    issue_ref = _agent_income_parse_github_issue_url(action.get("lead_url") or "")
    if not issue_ref:
        raise HTTPException(status_code=400, detail="Lead URL is not a GitHub issue URL")
    if not AGENT_INCOME_GITHUB_TOKEN:
        raise HTTPException(status_code=409, detail="AGENT_INCOME_GITHUB_TOKEN is not configured, so the dashboard can draft but cannot post GitHub comments yet")

    owner, repo, issue_number = issue_ref
    body = (
        f"{draft}\n\n"
        "_Commercial note from Nauti-Labs Agent Income. One-time outreach; no follow-up unless invited._"
    )
    async with httpx.AsyncClient(headers={
        "Authorization": f"Bearer {AGENT_INCOME_GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Nauti-Labs-Agent-Income-Operator/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }) as client:
        response = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments",
            json={"body": body},
            timeout=20,
        )
        if response.status_code >= 400:
            await _agent_income_update_lead_action(action_id, {
                "status": "send_failed",
                "send_error": response.text[:400],
                "attempted_at": now_iso(),
            })
            raise HTTPException(status_code=502, detail=f"GitHub comment failed with HTTP {response.status_code}")
        payload = response.json()
    await _agent_income_mark_lead_sent(action)
    return await _agent_income_update_lead_action(action_id, {
        "status": "sent",
        "action": "sent_outreach",
        "channel_blocker": "",
        "sent_at": now_iso(),
        "send_result": {
            "provider": "github",
            "comment_url": payload.get("html_url"),
            "comment_id": payload.get("id"),
        },
    })


def _agent_income_job_budget_usd(job: dict) -> float:
    return money(float(job.get("budgetMaxCents") or job.get("priceCents") or 0) / 100)


def _agent_income_job_text(job: dict) -> str:
    return f"{job.get('title') or job.get('name') or ''} {job.get('description') or ''}".lower()


def _agent_income_job_safety(job: dict) -> tuple[int, list[str]]:
    text = _agent_income_job_text(job)
    risk_flags = []
    hard_block_terms = (
        "phishing",
        "credential",
        "private key",
        "seed phrase",
        "wallet drain",
        "malware",
        "spam",
        "scrape behind login",
        "account takeover",
        "impersonat",
    )
    for term in hard_block_terms:
        if term in text:
            risk_flags.append(f"blocked_term:{term}")
    if risk_flags:
        return 40, risk_flags

    if any(term in text for term in ("security audit", "security review", "auth module", "code review", "csrf", "jwt")):
        if any(term in text for term in ("exploit", "scan", "probe", "live target", "bypass")):
            return 60, ["security_scope_needs_explicit_written_authorization"]
        return 85, ["security_hygiene_only_no_exploit_testing"]

    return 95, []


def _agent_income_estimate_job_seconds(job: dict) -> int:
    text = _agent_income_job_text(job)
    if "haiku" in text or "poem" in text:
        return 60
    if any(term in text for term in ("security audit", "security review", "auth module", "code review", "csrf", "jwt")):
        return 1800
    if any(term in text for term in ("documentation", "summary", "rewrite", "copy", "brief")):
        return 1200
    if any(term in text for term in ("data cleaning", "spreadsheet", "csv", "transform")):
        return 1800
    if any(term in text for term in ("integration", "automation", "api", "mcp")):
        return 2400
    return 1800


def _agent_income_is_fully_automated_job(job: dict) -> bool:
    text = _agent_income_job_text(job)
    automated_terms = (
        "haiku",
        "poem",
        "short writing",
        "rewrite",
        "summary",
        "summarize",
        "json",
        "format",
        "schema",
        "classif",
        "intent",
        "extract",
        "data cleanup",
        "csv",
        "validate output",
        "bot output",
    )
    if any(term in text for term in automated_terms):
        return True
    return _agent_income_estimate_job_seconds(job) <= AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_work_seconds_per_job"]


def _agent_income_rate_fields(effective_rate: float, *, fully_automated: bool = True) -> dict:
    rate = float(effective_rate or 0)
    meets_premium = rate >= AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD
    meets_preferred = rate >= AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD
    meets_minimum = rate >= AGENT_INCOME_MIN_EFFECTIVE_RATE_USD
    baseline_eligible = meets_minimum and fully_automated
    eligible = meets_premium or meets_preferred or baseline_eligible
    if meets_premium:
        tier = "tier_3_premium"
        label = "premium fit"
        revenue_score = 100
    elif meets_preferred:
        tier = "tier_2_good"
        label = "good fit"
        revenue_score = 80
    elif baseline_eligible:
        tier = "tier_1_baseline"
        label = "baseline fit"
        revenue_score = 60
    elif meets_minimum:
        tier = "below_policy_needs_automation"
        label = "needs automation"
        revenue_score = 45
    else:
        tier = "below_minimum"
        label = "below floor"
        revenue_score = 30
    return {
        "rate_tier": tier,
        "rate_tier_label": label,
        "revenue_score": revenue_score,
        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "meets_goal_hourly_rate": meets_premium,
        "meets_premium_hourly_rate": meets_premium,
        "meets_preferred_hourly_rate": meets_preferred,
        "meets_minimum_hourly_rate": meets_minimum,
        "eligible_under_rate_policy": eligible,
        "fully_automated_required_for_baseline": not meets_preferred,
        "fully_automated_low_value": fully_automated,
    }


def _agent_income_score_job(job: dict, source: str, query: str | None = None) -> dict:
    job_id = job.get("_id") or job.get("id")
    title = str(job.get("title") or job.get("name") or "Open job")[:160]
    budget = _agent_income_job_budget_usd(job)
    estimated_seconds = max(_agent_income_estimate_job_seconds(job), 1)
    expected_net = money(budget * 0.95)
    effective_rate = money(expected_net / (estimated_seconds / 3600))
    safety_score, risk_flags = _agent_income_job_safety(job)
    fully_automated = _agent_income_is_fully_automated_job(job)
    rate_fields = _agent_income_rate_fields(effective_rate, fully_automated=fully_automated)
    authorization_score = 90
    revenue_score = rate_fields["revenue_score"]
    if safety_score < 80:
        status = "blocked_safety_review"
    elif rate_fields["meets_premium_hourly_rate"]:
        status = "premium_rate_candidate"
    elif rate_fields["meets_preferred_hourly_rate"] and safety_score >= 80:
        status = "good_rate_candidate"
    elif rate_fields["eligible_under_rate_policy"] and safety_score >= 80:
        status = "baseline_autonomous_candidate"
    elif rate_fields["meets_minimum_hourly_rate"]:
        status = "baseline_needs_full_automation"
    else:
        status = "below_min_rate"
    return {
        "source": source,
        "query": query,
        "id": job_id,
        "title": title,
        "budget_usd": budget,
        "expected_net_profit_usd": expected_net,
        "estimated_work_seconds": estimated_seconds,
        "effective_hourly_rate_usd": effective_rate,
        **rate_fields,
        "need_score": 80 if any(term in _agent_income_job_text(job) for term in ("payment", "x402", "api", "code", "security", "data", "documentation", "automation")) else 60,
        "authorization_score": authorization_score,
        "revenue_score": revenue_score,
        "safety_score": safety_score,
        "risk_flags": risk_flags,
        "status": status,
    }


def _agent_income_add_open_job(tick: dict, seen: set[str], job: dict, source: str, query: str | None = None) -> dict | None:
    scored = _agent_income_score_job(job, source, query)
    job_id = scored.get("id")
    if not job_id or job_id in seen:
        return None
    seen.add(job_id)
    if scored["safety_score"] < 80:
        tick["notes"].append({
            "query": query or source,
            "status": "blocked_safety_review",
            "job_id": job_id,
            "title": scored["title"],
            "risk_flags": scored["risk_flags"],
        })
        return None
    if not scored["eligible_under_rate_policy"]:
        tick["notes"].append({
            "query": query or source,
            "status": scored["status"],
            "job_id": job_id,
            "title": scored["title"],
            "effective_hourly_rate_usd": scored["effective_hourly_rate_usd"],
            "rate_tier": scored["rate_tier"],
            "fully_automated_low_value": scored["fully_automated_low_value"],
            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        })
        return None
    tick["open_jobs"].append(scored)
    return scored


async def _agent_income_operator_tick() -> dict:
    tick = {
        "at": now_iso(),
        "mode": "perpetual_24_7",
        "enabled": AGENT_INCOME_OPERATOR_ENABLED,
        "interval_seconds": max(AGENT_INCOME_OPERATOR_INTERVAL_SECONDS, 300),
        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
        "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
        "business_model": "Charge first. Spend second. Deliver third.",
        "actions_allowed": [
            "verify live paid endpoints",
            "refresh opt-in marketplace listing health",
            "discover posted commercial opportunities in approved marketplaces",
            "record dashboard-visible operator state",
        ],
        "actions_blocked_without_clearance": [
            "outgoing payments",
            "paid API/model/tool spend",
            "refunds",
            "contract acceptance",
            "custom premium fulfillment before verified payment",
        ],
        "marketplaces": [],
        "open_jobs": [],
        "public_leads": [],
        "pending_bids": [],
        "bid_attempts": [],
        "notes": [],
    }

    seen_open_jobs: set[str] = set()
    seen_public_leads: set[str] = set()
    low_value_policy = await _agent_income_active_low_value_policy()
    async with httpx.AsyncClient(headers={"User-Agent": "Nauti-Labs-Agent-Income-Operator/1.0"}) as client:
        try:
            index_payload = await _agent_income_fetch_json(
                client,
                "https://402index.io/api/v1/services?q=Agent%20Income&protocol=x402&limit=10",
            )
            services = [
                item for item in index_payload.get("services", [])
                if "Agent Income" in str(item.get("name") or "")
            ]
            tick["marketplaces"].append({
                "marketplace": "402 Index",
                "status": "healthy" if services else "missing",
                "listing_count": len(services),
                "healthy_count": len([item for item in services if item.get("health_status") == "healthy"]),
                "service_ids": [item.get("id") for item in services],
            })
        except Exception as exc:
            tick["marketplaces"].append({
                "marketplace": "402 Index",
                "status": "check_failed",
                "error": str(exc)[:220],
            })

        try:
            payanagent_payload = await _agent_income_fetch_json(
                client,
                "https://payanagent.com/api/v1/discover?q=Agent%20Income",
            )
            services = [
                item for item in payanagent_payload.get("services", [])
                if "Agent Income" in str(item.get("name") or "")
            ]
            agents = [
                item for item in payanagent_payload.get("agents", [])
                if "Agent Income" in str(item.get("name") or "") or "Nauti" in str(item.get("name") or "")
            ]
            tick["marketplaces"].append({
                "marketplace": "PayanAgent",
                "status": "active" if services else "missing",
                "agent_count": len(agents),
                "listing_count": len(services),
                "service_ids": [item.get("_id") for item in services],
                "earned": sum(float(item.get("totalEarned") or 0) for item in agents),
                "jobs_completed": sum(int(item.get("totalJobsCompleted") or 0) for item in agents),
            })
        except Exception as exc:
            tick["marketplaces"].append({
                "marketplace": "PayanAgent",
                "status": "check_failed",
                "error": str(exc)[:220],
            })

        for query in AGENT_INCOME_DISCOVERY_QUERIES:
            try:
                payload = await _agent_income_fetch_json(
                    client,
                    f"https://payanagent.com/api/v1/discover?q={quote(query)}",
                )
                for job in payload.get("openJobs", [])[:5]:
                    _agent_income_add_open_job(tick, seen_open_jobs, job, "PayanAgent", query)
            except Exception as exc:
                tick["notes"].append({"query": query, "status": "job_check_failed", "error": str(exc)[:180]})

        if AGENT_INCOME_PUBLIC_LEAD_DISCOVERY_ENABLED:
            for query in AGENT_INCOME_GITHUB_LEAD_QUERIES:
                try:
                    response = await client.get(
                        "https://api.github.com/search/issues",
                        params={
                            "q": query,
                            "sort": "updated",
                            "order": "desc",
                            "per_page": max(min(AGENT_INCOME_PUBLIC_LEAD_LIMIT_PER_QUERY, 20), 1),
                        },
                        timeout=20,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    items = payload.get("items", []) if isinstance(payload, dict) else []
                    for item in items:
                        if not isinstance(item, dict) or item.get("pull_request"):
                            continue
                        _agent_income_add_public_lead(tick, seen_public_leads, "GitHub public issues", query, item)
                except Exception as exc:
                    tick["notes"].append({"query": query, "status": "github_lead_check_failed", "error": str(exc)[:180]})

            for query in AGENT_INCOME_GITHUB_REPO_LEAD_QUERIES:
                try:
                    response = await client.get(
                        "https://api.github.com/search/repositories",
                        params={
                            "q": query,
                            "sort": "updated",
                            "order": "desc",
                            "per_page": max(min(AGENT_INCOME_PUBLIC_LEAD_LIMIT_PER_QUERY, 20), 1),
                        },
                        timeout=20,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    for item in (payload.get("items", []) if isinstance(payload, dict) else []):
                        if not isinstance(item, dict):
                            continue
                        normalized = {
                            "id": item.get("id"),
                            "title": item.get("full_name") or item.get("name"),
                            "description": item.get("description"),
                            "html_url": item.get("html_url"),
                            "url": item.get("homepage") or item.get("html_url"),
                            "topics": item.get("topics") or [],
                        }
                        _agent_income_add_public_lead(tick, seen_public_leads, "GitHub public repositories", query, normalized)
                except Exception as exc:
                    tick["notes"].append({"query": query, "status": "github_repo_lead_check_failed", "error": str(exc)[:180]})

            for query in AGENT_INCOME_HN_LEAD_QUERIES:
                try:
                    response = await client.get(
                        "https://hn.algolia.com/api/v1/search_by_date",
                        params={
                            "query": query,
                            "tags": "story",
                            "hitsPerPage": max(min(AGENT_INCOME_PUBLIC_LEAD_LIMIT_PER_QUERY, 20), 1),
                        },
                        timeout=20,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    for item in (payload.get("hits", []) if isinstance(payload, dict) else []):
                        if not isinstance(item, dict):
                            continue
                        hn_url = f"https://news.ycombinator.com/item?id={item.get('objectID')}"
                        normalized = {
                            "id": f"hn:{item.get('objectID')}",
                            "title": item.get("title") or item.get("story_title"),
                            "body": item.get("story_text"),
                            "html_url": hn_url,
                            "url": item.get("url") or hn_url,
                        }
                        _agent_income_add_public_lead(tick, seen_public_leads, "Hacker News public stories", query, normalized)
                except Exception as exc:
                    tick["notes"].append({"query": query, "status": "hn_lead_check_failed", "error": str(exc)[:180]})

            for feed_url in AGENT_INCOME_DISCOVERY_FEEDS:
                try:
                    payload = await _agent_income_fetch_json(client, feed_url)
                    for item in _agent_income_feed_items(payload):
                        _agent_income_add_open_job(tick, seen_open_jobs, item, "Configured discovery feed", feed_url)
                        _agent_income_add_public_lead(tick, seen_public_leads, "Configured discovery feed", feed_url, item)
                    tick["marketplaces"].append({
                        "marketplace": "Configured discovery feed",
                        "url": feed_url,
                        "status": "checked",
                    })
                except Exception as exc:
                    tick["marketplaces"].append({
                        "marketplace": "Configured discovery feed",
                        "url": feed_url,
                        "status": "check_failed",
                        "error": str(exc)[:180],
                    })

        if AGENT_INCOME_PAYANAGENT_API_KEY:
            try:
                payanagent_headers = {"Authorization": f"Bearer {AGENT_INCOME_PAYANAGENT_API_KEY}"}
                own_bid_ids: set[str] = set()
                own_bid_job_ids: set[str] = set()
                own_bid_lookup_ok = False
                try:
                    own_bids_response = await client.get(
                        "https://payanagent.com/api/v1/agents/me/bids",
                        headers=payanagent_headers,
                        timeout=20,
                    )
                    own_bids_response.raise_for_status()
                    own_bids_payload = own_bids_response.json()
                    own_bid_lookup_ok = True
                    for own_bid in (own_bids_payload.get("bids", []) if isinstance(own_bids_payload, dict) else []):
                        if own_bid.get("status") == "pending":
                            if own_bid.get("id"):
                                own_bid_ids.add(str(own_bid.get("id")))
                            if own_bid.get("jobId"):
                                own_bid_job_ids.add(str(own_bid.get("jobId")))
                except Exception as exc:
                    tick["notes"].append({
                        "query": "payanagent_own_bids",
                        "status": "own_bid_check_failed",
                        "error": str(exc)[:180],
                    })
                response = await client.get(
                    "https://payanagent.com/api/v1/requests?type=open",
                    headers=payanagent_headers,
                    timeout=20,
                )
                response.raise_for_status()
                request_payload = response.json()
                jobs = request_payload.get("jobs", []) if isinstance(request_payload, dict) else []
                for job in jobs[:10]:
                    job_id = job.get("_id") or job.get("id")
                    if not job_id:
                        continue
                    source = "PayanAgent authenticated open requests"
                    scored = _agent_income_score_job(job, source, "all_open_requests")
                    _agent_income_add_open_job(tick, seen_open_jobs, job, source, "all_open_requests")
                    bids_response = await client.get(
                        f"https://payanagent.com/api/v1/requests/{job_id}/bids",
                        headers=payanagent_headers,
                        timeout=20,
                    )
                    bids_response.raise_for_status()
                    bids_payload = bids_response.json()
                    own_bid_seen = False
                    for bid in (bids_payload.get("bids", []) if isinstance(bids_payload, dict) else []):
                        bid_id = str(bid.get("_id") or bid.get("id") or "")
                        if own_bid_ids:
                            if bid_id not in own_bid_ids:
                                continue
                        elif own_bid_lookup_ok:
                            continue
                        elif AGENT_INCOME_PAYANAGENT_AGENT_ID and bid.get("agentId") != AGENT_INCOME_PAYANAGENT_AGENT_ID:
                            continue
                        elif not AGENT_INCOME_PAYANAGENT_AGENT_ID and own_bid_job_ids and str(job_id) not in own_bid_job_ids:
                            continue
                        own_bid_seen = True
                        price_usd = money(float(bid.get("priceCents") or 0) / 100)
                        seconds = max(int(bid.get("estimatedDurationSeconds") or 0), 1)
                        expected_net = money(price_usd * 0.95)
                        effective_rate = money(expected_net / (seconds / 3600))
                        fully_automated = _agent_income_is_fully_automated_job(job)
                        rate_fields = _agent_income_rate_fields(effective_rate, fully_automated=fully_automated)
                        tick["pending_bids"].append({
                            "source": "PayanAgent",
                            "job_id": job_id,
                            "bid_id": bid.get("_id") or bid.get("id"),
                            "title": str(job.get("title") or "")[:160],
                            "job_status": job.get("status"),
                            "bid_status": bid.get("status"),
                            "price_usd": price_usd,
                            "estimated_work_seconds": seconds,
                            "expected_net_profit_usd": expected_net,
                            "effective_hourly_rate_usd": effective_rate,
                            **rate_fields,
                            "meets_200_hour_goal": rate_fields["meets_premium_hourly_rate"],
                            "payment_status": "not_paid_bid_pending",
                            "fulfillment_status": "locked_waiting_for_acceptance_and_payment",
                            "why_not_paid": "Marketplace still reports the job as open and this agent bid as pending; no acceptance, escrow, or payment has been confirmed.",
                            "next_autonomous_action": "Keep polling PayanAgent. If the bid is accepted and payment/escrow is confirmed, fulfill within the quoted scope; otherwise do not deliver premium work.",
                            "delivery_rule": "Do not deliver until bid is accepted and marketplace payment or escrow is confirmed.",
                        })
                    if not own_bid_seen and str(job_id) in own_bid_job_ids:
                        own_bid_seen = True
                    if not own_bid_seen:
                        allowed, gate = _agent_income_policy_allows_autobid(low_value_policy, scored, job, source)
                        if allowed:
                            bid_result = await _agent_income_submit_payanagent_bid(
                                client,
                                headers=payanagent_headers,
                                job=job,
                                scored=scored,
                                policy=low_value_policy,
                            )
                            tick["bid_attempts"].append({
                                **bid_result,
                                "title": scored["title"],
                                "effective_hourly_rate_usd": scored["effective_hourly_rate_usd"],
                                "rate_tier": scored["rate_tier"],
                                "policy_gate": gate,
                            })
                            if bid_result.get("status") == "submitted":
                                tick["pending_bids"].append({
                                    "source": "PayanAgent",
                                    "job_id": job_id,
                                    "bid_id": bid_result.get("bid_id"),
                                    "title": scored["title"],
                                    "job_status": job.get("status"),
                                    "bid_status": "pending",
                                    "price_usd": bid_result.get("price_usd"),
                                    "estimated_work_seconds": scored["estimated_work_seconds"],
                                    "expected_net_profit_usd": money(float(bid_result.get("price_usd") or 0) * 0.95),
                                    "effective_hourly_rate_usd": scored["effective_hourly_rate_usd"],
                                    **_agent_income_rate_fields(scored["effective_hourly_rate_usd"], fully_automated=True),
                                    "payment_status": "not_paid_bid_pending",
                                    "fulfillment_status": "locked_waiting_for_acceptance_and_payment",
                                    "why_not_paid": "Bid was submitted under the approved low-value policy, but no acceptance, escrow, or payment has been confirmed yet.",
                                    "next_autonomous_action": "Keep polling PayanAgent. If the bid is accepted and payment/escrow is confirmed, auto-fulfill within the approved low-value policy.",
                                    "delivery_rule": "Do not deliver until bid is accepted and marketplace payment or escrow is confirmed.",
                                })
                        elif scored.get("eligible_under_rate_policy"):
                            tick["bid_attempts"].append({
                                "status": "not_submitted",
                                "job_id": job_id,
                                "title": scored["title"],
                                "effective_hourly_rate_usd": scored["effective_hourly_rate_usd"],
                                "rate_tier": scored["rate_tier"],
                                "policy_gate": gate,
                            })
            except Exception as exc:
                tick["notes"].append({
                    "query": "payanagent_authenticated_bids",
                    "status": "bid_check_failed",
                    "error": str(exc)[:180],
                })

    tick["summary"] = {
        "marketplace_count": len(tick["marketplaces"]),
        "live_listing_count": sum(int(item.get("listing_count") or 0) for item in tick["marketplaces"]),
        "found_open_jobs": len(tick["open_jobs"]),
        "public_lead_count": len(tick["public_leads"]),
        "contact_ready_lead_count": len([item for item in tick["public_leads"] if item.get("contact_allowed")]),
        "pending_bid_count": len(tick["pending_bids"]),
        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
        "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
        "spend_status": "no_spend_performed",
        "outreach_status": "no_unsolicited_outreach_performed",
    }
    await _agent_income_set_state_value("operator_tick", tick)
    return tick


async def agent_income_operator_loop():
    await asyncio.sleep(3)
    while True:
        try:
            if AGENT_INCOME_OPERATOR_ENABLED:
                tick = await _agent_income_operator_tick()
                if AGENT_INCOME_AUTO_DEAL_LEADS:
                    await _agent_income_deal_with_leads(tick=tick, autosend_ready=AGENT_INCOME_AUTOSEND_PUBLIC_LEADS)
            else:
                await _agent_income_set_state_value(
                    "operator_tick",
                    {
                        "at": now_iso(),
                        "mode": "disabled",
                        "enabled": False,
                        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
                        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
                        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
                        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
                        "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
                        "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
                        "summary": {
                            "marketplace_count": len(AGENT_INCOME_MARKETPLACE_LISTINGS),
                            "live_listing_count": sum(len(item["listings"]) for item in AGENT_INCOME_MARKETPLACE_LISTINGS),
                            "found_open_jobs": 0,
                            "public_lead_count": 0,
                            "contact_ready_lead_count": 0,
                            "pending_bid_count": 0,
                            "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
                            "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
                            "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
                            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
                            "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
                            "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
                        },
                        "open_jobs": [],
                        "public_leads": [],
                        "pending_bids": [],
                    },
                )
        except Exception as exc:
            print(f"[agent-income] operator loop error: {exc}")
        await asyncio.sleep(max(AGENT_INCOME_OPERATOR_INTERVAL_SECONDS, 300))


def _normalize_eth_address(address: str) -> str:
    candidate = str(address or "").strip()
    if not ETH_ADDRESS_RE.fullmatch(candidate):
        raise HTTPException(status_code=400, detail="A valid 0x Base/EVM wallet address is required")
    return candidate.lower()


def _configured_agent_income_wallet_address() -> str | None:
    candidate = str(AGENT_INCOME_DEFAULT_WALLET or "").strip()
    if ETH_ADDRESS_RE.fullmatch(candidate):
        return candidate.lower()
    return None


def _load_json(value, default=None):
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _json_for_inline_script(value) -> str:
    """Serialize JSON so stored text cannot break out of a <script> tag."""
    return (
        json.dumps(value, ensure_ascii=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("'", "\\u0027")
    )


def _agent_bot_service(key: str) -> dict:
    for service in AGENT_BOT_SERVICES:
        if service["key"] == key:
            return service
    raise HTTPException(status_code=404, detail="Bot service not found")


def _agent_income_paid_offer(slug: str) -> dict:
    for offer in AGENT_INCOME_PAID_OFFERS:
        if offer["slug"] == slug or offer["key"] == slug:
            return offer
    raise HTTPException(status_code=404, detail="Agent Income paid offer not found")


def _agent_income_public_recipient() -> str | None:
    return _configured_agent_income_wallet_address()


def _agent_income_legacy_x402_requirements(service: dict, resource_url: str, recipient: str | None) -> dict:
    price = float(service["price_usdc"])
    atomic_usdc = int(round(price * 1_000_000))
    return {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": f"eip155:{PAYMENT_CHAIN_ID}",
                "payTo": recipient,
                "maxAmountRequired": str(atomic_usdc),
                "asset": USDC_CONTRACT,
                "resource": resource_url,
                "description": service["description"],
                "mimeType": "application/json",
                "maxTimeoutSeconds": 600,
                "paymentType": "eip3009",
                "extra": {
                    "assetTransferMethod": "eip3009_or_direct_base_usdc",
                    "directBaseTxHeader": "X-Payment-Tx",
                    "reference": service["key"],
                    "priceUsd": f"{price:.2f}",
                    "displayPrice": f"${price:.2f}",
                },
            }
        ],
    }


def _agent_income_x402_requirements(service: dict, resource_url: str, recipient: str | None) -> dict:
    price = float(service["price_usdc"])
    atomic_usdc = int(round(price * 1_000_000))
    return {
        "x402Version": 2,
        "error": "Payment Required",
        "resource": {
            "url": resource_url,
            "description": service["description"],
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": f"eip155:{PAYMENT_CHAIN_ID}",
                "amount": str(atomic_usdc),
                # Keep the v1 amount key alongside the v2 field so older
                # x402 clients can read the quoted amount without parsing
                # the legacy payment object returned separately.
                "maxAmountRequired": str(atomic_usdc),
                "asset": USDC_CONTRACT,
                "payTo": recipient,
                "paymentType": "eip3009",
                "maxTimeoutSeconds": 600,
                "extra": {
                    "name": "USDC",
                    "version": "2",
                    "decimals": 6,
                    "assetTransferMethod": "eip3009_or_direct_base_usdc",
                    "directBaseTxHeader": "X-Payment-Tx",
                    "reference": service["key"],
                    "priceUsd": f"{price:.2f}",
                    "displayPrice": f"${price:.2f}",
                    "legacyMaxAmountRequired": str(atomic_usdc),
                },
            }
        ],
        "extensions": {
            "bazaar": {
                "info": {
                    "name": service["label"],
                    "description": service["description"],
                    "method": "POST",
                },
                "inputSchema": service.get("input_schema"),
                "outputSchema": service.get("output_schema"),
            }
        },
    }


def _payment_required_response(service: dict, resource_url: str, recipient: str | None, detail: str | None = None) -> JSONResponse:
    requirements = _agent_income_x402_requirements(service, resource_url, recipient)
    encoded = base64.b64encode(json.dumps(requirements, separators=(",", ":")).encode("utf-8")).decode("ascii")
    price = float(service["price_usdc"])
    return JSONResponse(
        status_code=402,
        headers={
            "PAYMENT-REQUIRED": encoded,
            "X-Payment-Requirements": encoded,
            "X-Payment-Required": "true",
            "X-Payment-Network": f"eip155:{PAYMENT_CHAIN_ID}",
            "X-Payment-Currency": "USDC",
            "X-Payment-Amount": f"{price:.2f}",
            "X-Payment-Recipient": recipient or "",
            "X-Agent-Income-Pay-To": recipient or "",
            "X-Agent-Income-Network": f"eip155:{PAYMENT_CHAIN_ID}",
            "X-Agent-Income-Asset": USDC_CONTRACT,
        },
        content={
            "error": detail or "Payment required",
            "service": {
                "id": service["key"],
                "name": service["label"],
                "description": service["description"],
                "price_usd": price,
                "currency": "USDC",
            },
            "payment": requirements,
            "legacy_payment": _agent_income_legacy_x402_requirements(service, resource_url, recipient),
            "accepted_payment_methods": ["x402", "USDC on Base"],
            "payment_required_before_work": True,
            "clearance_required": True,
            "input_schema": service.get("input_schema"),
            "output_schema": service.get("output_schema"),
            "refund_terms": service.get(
                "refund_terms",
                "Refund review is available if verified payment succeeds but the paid endpoint fails to deliver.",
            ),
            "delivery_terms": service.get(
                "delivery_terms",
                "Premium output is delivered only after payment verification.",
            ),
            "retry": "Send USDC on Base, then retry with X-Payment-Tx or payment_tx set to the Base transaction hash.",
        },
    )


def _agent_income_resource_url(request: Request) -> str:
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{BASE_URL.rstrip('/')}{request.url.path}{query}"


def _bot_service_output(service_key: str, payload: dict) -> dict:
    text = json.dumps(payload, sort_keys=True)[:4000]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    service = _agent_bot_service(service_key)
    common = {
        "service": service["label"],
        "input_hash": digest,
        "generated_at": now_iso(),
        "license": "Single paid agent use. No regulated professional advice.",
    }
    if service_key == "offer_audit":
        offer = str(payload.get("offer") or payload.get("message") or "").strip()
        score = 62 + min(len(offer) // 80, 28)
        return {
            **common,
            "score": min(score, 95),
            "verdict": "sellable_with_tightening" if offer else "insufficient_offer_text",
            "fixes": [
                "State the paid outcome in the first sentence.",
                "Name the exact buyer, trigger, price, and delivery time.",
                "Include refund/revision boundaries and the payment network.",
                "Expose a machine-readable endpoint or manifest for agent buyers.",
            ],
            "payment_conversion_copy": "Pay once, get a bounded artifact back in JSON, no account or subscription required.",
        }
    if service_key == "x402_listing_pack":
        endpoint = str(payload.get("endpoint") or "/paid-endpoint").strip()
        return {
            **common,
            "listing": {
                "name": payload.get("name") or "Paid Agent Endpoint",
                "endpoint": endpoint,
                "description": "A machine-payable API with HTTP 402 negotiation and Base USDC settlement.",
                "price_suggestion": "$5-$45 per successful response",
                "input_schema": payload.get("input_schema") or {"type": "object", "additionalProperties": True},
                "output_schema": {"type": "object", "required": ["result", "receipt"]},
            },
            "discovery_tags": ["x402", "base-usdc", "agent-commerce", "paid-api"],
        }
    if service_key == "anchor_compliance_pack":
        profile = str(payload.get("custodian_profile") or payload.get("company") or "").strip()
        return {
            **common,
            "target_buyer": profile or "crypto custodian, wallet infrastructure team, or digital asset operations group",
            "positioning": "Anchor Compliance helps custody teams prove who can approve what, what evidence is logged, and where automation must stop before money or regulated operations move.",
            "sellable_offer": {
                "name": "Anchor Compliance Custodian Readiness Pack",
                "price_usd": 499,
                "endpoint": f"{BASE_URL.rstrip('/')}/agent-income/anchor-compliance",
                "paid_before_work": True,
            },
            "custodian_control_map": [
                "Define wallet-operation approval gates for transfers, policy changes, refunds, and vendor/API spend.",
                "Separate customer-facing recommendations from legal, compliance, custody, or transaction-monitoring advice.",
                "Log request source, actor, policy basis, amount/resource limits, approval proof, and delivery evidence.",
                "Block private keys, seed phrases, wallet credentials, browser cookies, and admin access from all intake paths.",
            ],
            "outbound_pitch": "We can turn your custody or wallet-ops workflow into an approval-gated evidence map: what automation may do, what needs human signoff, and what audit trail gets produced. Fixed-scope Anchor Compliance pack is $499, paid before work starts.",
        }
    if service_key == "tool_policy_check":
        action = str(payload.get("action") or "").lower()
        money_moving = any(term in action for term in ["send", "pay", "withdraw", "trade", "purchase"])
        return {
            **common,
            "risk": "high" if money_moving else "medium",
            "requires_human_clearance": bool(money_moving),
            "required_audit_fields": ["actor", "tool", "arguments_hash", "budget", "recipient", "timestamp"],
            "policy": "Allow only if the tool, recipient, amount, and expiry match the approved clearance.",
        }
    if service_key == "buyer_intent_digest":
        message = str(payload.get("message") or "").lower()
        intent = "buy_now" if any(term in message for term in ["pay", "buy", "price", "invoice"]) else "needs_followup"
        return {
            **common,
            "intent": intent,
            "confidence": 0.78 if intent == "buy_now" else 0.61,
            "next_action": "Return payment requirements immediately." if intent == "buy_now" else "Ask one scoping question and quote a fixed price.",
            "risk_notes": ["Do not imply guaranteed earnings.", "Keep payment and delivery boundaries explicit."],
        }
    if service_key == "prompt_to_api_spec":
        prompt = str(payload.get("prompt") or "").strip()
        return {
            **common,
            "api_spec": {
                "method": "POST",
                "path": "/agent-income/api/bot-services/custom",
                "summary": prompt[:120] or "Paid agent service endpoint",
                "request_schema": {"type": "object", "properties": {"input": {"type": "object"}, "payment_tx": {"type": "string"}}},
                "response_schema": {"type": "object", "properties": {"result": {"type": "object"}, "receipt": {"type": "object"}}},
                "payment": {"status": 402, "network": f"eip155:{PAYMENT_CHAIN_ID}", "currency": "USDC"},
            },
            "implementation_steps": ["Return PAYMENT-REQUIRED when unpaid.", "Verify payment.", "Generate bounded JSON output.", "Store receipt."],
        }
    return {**common, "result": payload}


def _agent_income_offer_economics(offer: dict) -> dict:
    price = money(offer["price_usdc"])
    refund_reserve = money(price * 0.05)
    expected_net = money(price - refund_reserve)
    hourly_rate = money(expected_net / (max(int(offer["max_work_seconds"]), 1) / 3600))
    rate_fields = _agent_income_rate_fields(hourly_rate, fully_automated=True)
    return {
        "customer_price_usd": price,
        "model_cost_usd": 0,
        "api_cost_usd": 0,
        "x402_cost_usd": 0,
        "mcp_tool_cost_usd": 0,
        "payment_fees_usd": 0,
        "platform_fees_usd": 0,
        "refund_reserve_usd": refund_reserve,
        "expected_net_profit_usd": expected_net,
        "estimated_work_seconds": int(offer["max_work_seconds"]),
        "effective_hourly_rate_usd": hourly_rate,
        **rate_fields,
        "meets_200_hour_goal": rate_fields["meets_premium_hourly_rate"],
    }


def _agent_income_extract_paid_input(payload: dict) -> dict:
    if isinstance(payload.get("input"), dict):
        return dict(payload.get("input") or {})
    excluded = {"payment_tx", "payer_agent", "request_id", "clearance_token"}
    return {key: value for key, value in payload.items() if key not in excluded}


async def _read_agent_income_paid_payload(request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _agent_income_score_input(payload: dict) -> int:
    score = 24
    if payload.get("project_url"):
        score += 10
    if str(payload.get("agent_type") or "unknown").lower() in {"buyer", "seller", "both"}:
        score += 10
    if str(payload.get("payment_goal") or "").lower() in {"accept_payments", "make_payments", "both"}:
        score += 12
    if str(payload.get("current_stack") or "unknown").lower() not in {"", "unknown"}:
        score += 8

    text = json.dumps(payload, sort_keys=True).lower()
    weighted_terms = {
        "x402": 8,
        "402": 5,
        "mcp": 6,
        "api": 5,
        "agent": 5,
        "usdc": 5,
        "base": 4,
        "clearance": 7,
        "spend": 5,
        "paid": 5,
        "payment": 5,
        "custodian": 8,
        "custody": 8,
        "compliance": 7,
        "wallet": 6,
        "evidence": 6,
        "approval": 6,
        "aml": 5,
        "kyc": 5,
    }
    for term, weight in weighted_terms.items():
        if term in text:
            score += weight
    return max(0, min(score, 94))


def _agent_income_paid_offer_output(offer: dict, payload: dict) -> dict:
    input_text = json.dumps(payload, sort_keys=True)[:6000]
    input_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()[:16]
    score = _agent_income_score_input(payload)
    project_url = str(payload.get("project_url") or "customer-provided project").strip()
    agent_type = str(payload.get("agent_type") or "unknown").strip()
    payment_goal = str(payload.get("payment_goal") or "unknown").strip()
    stack = str(payload.get("current_stack") or "unknown").strip()
    wants_to_monetize = (
        f"{project_url} appears to be a {agent_type} agent/API workflow with a payment goal of "
        f"{payment_goal.replace('_', ' ')} on a {stack} stack."
    )
    common = {
        "service": offer["label"],
        "generated_at": now_iso(),
        "input_hash": input_hash,
        "license": "Single paid customer use. Uses public/customer-provided information only. No regulated professional advice.",
        "score": score,
        "summary": (
            f"{wants_to_monetize} The immediate monetization path is a productized paid endpoint that charges before "
            "model/tool spend and returns a bounded JSON artifact after payment verification."
        ),
        "income_opportunities": [
            {
                "name": "Instant paid readiness audit",
                "price_usd": 49,
                "flow": "POST -> HTTP 402 -> Base USDC payment -> verify -> JSON report",
            },
            {
                "name": "Payment flow review",
                "price_usd": 199,
                "flow": "Fixed-scope review with endpoint/payment/spend-control recommendations",
            },
            {
                "name": "Integration blueprint",
                "price_usd": 499,
                "flow": "Blueprint for paid endpoints, Clearance boundaries, pricing logic, and launch checklist",
            },
            {
                "name": "Anchor Compliance custodian readiness",
                "price_usd": 499,
                "flow": "Crypto custodian control map for wallet approvals, evidence logs, transaction-policy boundaries, and pilot scope",
            },
        ],
        "payment_flow_recommendation": (
            "Use charge-first/spend-second/deliver-third: return HTTP 402 for unpaid requests, verify payment or payment authorization, "
            "then spend on models/tools only inside the approved budget and deliver the premium artifact."
        ),
        "clearance_recommendation": (
            "Require Clearance approval before accepting custom jobs, changing payment destinations, spending on paid APIs/tools, "
            "issuing refunds, or committing to enterprise scope. Productized low-risk endpoints should expose the Clearance requirement "
            "in the 402 terms and log each verified transaction."
        ),
        "x402_recommendation": (
            "Expose machine-readable payment requirements with price, network, asset, recipient, input schema, output schema, refund terms, "
            "and a retry path such as X-Payment-Tx after Base USDC settlement."
        ),
        "aws_agentcore_recommendation": (
            "If an AgentCore-style buyer flow is used, cap each session budget, require explicit resource descriptions, and log payment proof, "
            "cost, settlement status, and delivered value."
        ),
        "risks": [
            "Do not request seed phrases, private keys, wallet credentials, cookies, or admin access.",
            "Do not spend on paid APIs/models/tools until payment or an approved internal budget exists.",
            "Do not deliver custom premium analysis before payment verification.",
            "Avoid regulated financial, legal, medical, insurance, tax, trading, or investment advice.",
        ],
        "next_steps": [
            "Publish a machine-readable paid-service manifest.",
            "Add HTTP 402 payment-required responses for unpaid premium calls.",
            "Verify Base USDC or approved payment authorization before work starts.",
            "Create Clearance boundaries for spend, refunds, custom scope, subscriptions, and payment destination changes.",
            "Log price, cost, net profit, work seconds, payment proof, and delivery status for every paid job.",
        ],
        "upsell": offer.get("upsell"),
    }
    if offer["key"] == "anchor_compliance_readiness":
        custodian_name = str(payload.get("custodian_name") or project_url or "customer-provided custodian").strip()
        custody_model = str(payload.get("custody_model") or "unknown").replace("_", " ")
        compliance_need = str(payload.get("compliance_need") or payload.get("notes") or "").strip()
        return {
            **common,
            "summary": (
                f"{custodian_name} appears to have a {custody_model} workflow that needs operational compliance boundaries. "
                "The fastest sellable path is an Anchor Compliance pilot: approval gates, evidence logs, transaction-policy boundaries, "
                "and a narrow implementation scope that avoids legal advice, custody, and key handling."
            ),
            "custodian_controls": [
                "Transfer, withdrawal, refund, policy-change, vendor-spend, and customer-impacting automation should each have explicit approval gates.",
                "Every money-moving or control-changing action should carry actor, request source, resource, amount, wallet/asset, policy basis, expiry, approver, and evidence hash.",
                "Automated agents may prepare packets and recommendations; humans approve externally sensitive actions before execution.",
                "Customer intake must reject private keys, seed phrases, wallet credentials, browser cookies, and requests to bypass compliance controls.",
            ],
            "evidence_map": [
                {"event": "custodian_request_received", "evidence": ["source_url_or_contact", "requested_action", "customer_supplied_scope"]},
                {"event": "policy_gate_evaluated", "evidence": ["policy_id", "risk_flags", "required_approvals", "amount_or_resource_limit"]},
                {"event": "human_approval_recorded", "evidence": ["approver", "approval_timestamp", "scope", "expiry", "decision_note"]},
                {"event": "delivery_or_execution_logged", "evidence": ["output_hash", "transaction_reference_if_any", "customer_receipt", "operator_notes"]},
            ],
            "approval_boundaries": [
                "No private key, seed phrase, wallet credential, or admin-session collection.",
                "No legal, regulatory, tax, investment, trading, or formal compliance opinion.",
                "No custody, transaction monitoring, sanctions screening, or Travel Rule service is provided by this pack.",
                "No outbound customer contact, fund movement, refund, withdrawal, or vendor spend without a separate Clearance-approved scope.",
            ],
            "transaction_policy": [
                "Classify each action as observe, prepare, recommend, approve, execute, or reconcile.",
                "Allow observe/prepare work after payment; require human approval before execute/reconcile actions.",
                "Use amount caps, resource descriptions, approver identity, and expiry on every approval token.",
                "Store delivery evidence and customer-visible terms with each paid job.",
            ],
            "pilot_offer": {
                "name": "Anchor Compliance Pilot",
                "starting_price_usd": 2500,
                "scope": "One custody or wallet-ops workflow mapped into approval gates, evidence logs, and implementation checklist.",
                "next_step": "Collect a paid pack first, then quote the pilot only after Clearance approval and a fixed written scope.",
            },
            "sales_notes": [
                f"Lead with the compliance pain: {compliance_need[:220] or 'approval evidence and wallet-operation controls'}.",
                "Pitch operational readiness, not legal advice.",
                "Ask for payment before analysis and keep implementation as a separate higher-ticket pilot.",
            ],
        }
    if offer["key"] == "payment_flow_review":
        return {
            **common,
            "endpoint_design": [
                {
                    "path": "/paid/readiness-audit",
                    "price_usd": 49,
                    "unpaid_response": "HTTP 402 with x402-compatible payment requirements",
                    "paid_response": "readiness score, risks, endpoint checklist, and upsell path",
                },
                {
                    "path": "/paid/review",
                    "price_usd": 199,
                    "unpaid_response": "HTTP 402 with scope and delivery terms",
                    "paid_response": "payment flow review with pricing, spend controls, and endpoint design",
                },
            ],
            "spend_controls": [
                "Set per-job model/tool budget caps before fulfillment.",
                "Block outgoing payments unless a Clearance token matches recipient, amount, resource, and expiry.",
                "Record all paid API/model/tool calls against the customer transaction.",
            ],
            "pricing_notes": [
                "Keep the starter audit at $49 with a strict five-minute fulfillment cap.",
                "Use $199 for reviews that require up to 30 minutes of agent work.",
                "Move implementation planning to the $499 blueprint once endpoint architecture is needed.",
            ],
        }
    if offer["key"] == "integration_blueprint":
        return {
            **common,
            "architecture_plan": [
                "Public manifest advertises paid offers, schemas, pricing, payment rails, and support/refund terms.",
                "Each premium endpoint returns HTTP 402 until payment or authorization is verified.",
                "Fulfillment worker reads only customer-provided/public inputs, enforces time budget, and records delivery.",
                "Spend gateway blocks paid tools/models unless customer payment and Clearance budget are present.",
            ],
            "endpoint_plan": [
                {"path": "/agent-income/audit", "price_usd": 49, "max_work_seconds": 300},
                {"path": "/agent-income/review", "price_usd": 199, "max_work_seconds": 1800},
                {"path": "/agent-income/blueprint", "price_usd": 499, "max_work_seconds": 5400},
                {"path": "/agent-income/custom-quote", "price_usd": "quote", "clearance_required": True},
            ],
            "clearance_integration_points": [
                "Incoming custom quote or contract acceptance.",
                "Outgoing API/model/tool spend.",
                "Refunds, subscriptions, payment-destination changes, and budget increases.",
                "Any enterprise implementation package before commitment or deposit collection.",
            ],
            "launch_checklist": [
                "Confirm receiving wallet and USDC contract configuration.",
                "Verify unpaid endpoints return 402 with schemas and refund terms.",
                "Verify paid endpoint stores ledger economics and output hash.",
                "Run a live payment test with a small approved amount before broad discovery.",
                "Monitor replies, opt-outs, refund requests, and delivery failures.",
            ],
        }
    return common


async def _run_agent_income_paid_offer(
    offer_slug: str,
    request: Request,
    x_payment_tx: str | None,
) -> JSONResponse:
    offer = _agent_income_paid_offer(offer_slug)
    payload = await _read_agent_income_paid_payload(request)
    customer_input = _agent_income_extract_paid_input(payload)
    recipient = _agent_income_public_recipient()
    resource_url = _agent_income_resource_url(request)
    if not recipient:
        raise HTTPException(status_code=503, detail="Agent Income receiving wallet is not configured")
    if not USDC_CONTRACT:
        raise HTTPException(status_code=503, detail="USDC_CONTRACT must be configured for Base payment verification")

    payment_tx = str(payload.get("payment_tx") or x_payment_tx or "").strip()
    if not payment_tx:
        return _payment_required_response(offer, resource_url, recipient)
    if not TX_HASH_RE.fullmatch(payment_tx):
        raise HTTPException(status_code=400, detail="A valid Base transaction hash is required")

    db = await get_db()
    try:
        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("base_usdc", payment_tx),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This payment transaction has already been consumed")

        verification = await verify_usdc_payment(payment_tx, float(offer["price_usdc"]), recipient)
        if not verification["verified"]:
            return _payment_required_response(offer, resource_url, recipient, verification["error"])

        output = _agent_income_paid_offer_output(offer, customer_input)
        economics = _agent_income_offer_economics(offer)
        ledger_id = generate_id("aile")
        recorded_at = now_iso()
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                None,
                None,
                "paid_offer_payment",
                float(offer["price_usdc"]),
                "USDC",
                "verified",
                "base_usdc",
                payment_tx,
                recorded_at,
                json.dumps({
                    "project": "agent-income",
                    "service": offer["key"],
                    "service_label": offer["label"],
                    "payer_agent": payload.get("payer_agent"),
                    "request_id": payload.get("request_id"),
                    "customer_input_hash": output["input_hash"],
                    "output": output,
                    "verification": verification,
                    "economics": economics,
                    "clearance_status": "productized_inbound_paid_endpoint",
                    "charge_first_spend_second_deliver_third": True,
                }),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.paid_offer.delivered",
                payload.get("payer_agent") or "paid_endpoint_customer",
                json.dumps({"service": offer["key"], "amount": offer["price_usdc"], "tx": payment_tx, "ledger_id": ledger_id}),
                recorded_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    payment_response = base64.b64encode(json.dumps({
        "status": "settled",
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "tx": payment_tx,
        "amount": float(offer["price_usdc"]),
        "ledger_id": ledger_id,
    }, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return JSONResponse(
        headers={"PAYMENT-RESPONSE": payment_response},
        content={
            "status": "paid",
            "service": {
                "id": offer["key"],
                "name": offer["label"],
                "price_usd": float(offer["price_usdc"]),
                "currency": "USDC",
            },
            "result": output,
            "receipt": {
                "ledger_id": ledger_id,
                "tx": payment_tx,
                "amount": float(offer["price_usdc"]),
                "currency": "USDC",
                "network": f"eip155:{PAYMENT_CHAIN_ID}",
            },
            "economics": economics,
        },
    )


def _agent_income_lanes(target_amount: float, target_window_hours: int) -> list[dict]:
    scale = max(float(target_amount or AGENT_INCOME_TARGET_AMOUNT), 1) / max(AGENT_INCOME_TARGET_AMOUNT, 1)
    base_lanes = [
        {
            "key": "proposal_pack",
            "label": "Fixed-Fee Proposal Pack",
            "base_payout": 75,
            "cost": 0,
            "buyer_profile": "Founder, operator, or local service business with a clear painful workflow.",
            "buyer_source": "Public websites, inbound requests, warm contacts, and approved marketplace briefs.",
            "delivery_channel": "Human-approved email or marketplace message",
            "title": "Send a fixed-fee automation proposal pack",
            "why": "AI is excellent at turning a messy business pain into a scoped offer, SOW, and buyer-ready reply.",
            "earning_route": "Agent finds a visible workflow pain, drafts a fixed-fee implementation proposal, sends it after Clearance approval, and asks for USDC/card payment before delivery begins.",
            "automation_notes": "Generates a concise offer, scope, acceptance criteria, timeline, and invoice-ready terms.",
            "autonomous_actions": [
                "Score approved buyer sources for obvious workflow friction.",
                "Draft a tailored fixed-fee offer and SOW.",
                "Queue the outbound message for Clearance approval.",
                "Prepare a payment request to the connected Base wallet.",
            ],
        },
        {
            "key": "ops_micro_audit",
            "label": "Ops Micro-Audit",
            "base_payout": 50,
            "cost": 0,
            "buyer_profile": "Small business with public website, public offer, or customer support workflow.",
            "buyer_source": "Businesses with a public website, unclear offer, slow lead capture, or visible customer-support friction.",
            "delivery_channel": "Human-approved audit PDF/text brief",
            "title": "Deliver a paid 30-minute operations micro-audit",
            "why": "AI can rapidly identify bottlenecks, missing trust signals, confusing copy, and simple automation wins.",
            "earning_route": "Agent creates a paid mini-audit from public or customer-provided information, queues the delivery note for approval, then releases the audit once payment is verified.",
            "automation_notes": "Produces a structured diagnostic brief with top fixes, effort, expected impact, and next action.",
            "autonomous_actions": [
                "Review public pages or provided screenshots.",
                "Generate a ranked friction report with five quick wins.",
                "Queue the audit preview and payment request for approval.",
                "Release the full brief after verified payment.",
            ],
        },
        {
            "key": "research_brief",
            "label": "Research Brief Desk",
            "base_payout": 45,
            "cost": 0,
            "buyer_profile": "Sales team, founder, investor, attorney, recruiter, or agency needing a narrow research brief.",
            "buyer_source": "Inbound research requests, approved CRM lists, public buyer prompts, and warm professional contacts.",
            "delivery_channel": "Human-approved brief delivery",
            "title": "Ship a niche buyer or market research brief",
            "why": "AI is strong at structured synthesis, comparison tables, buyer lists, and concise decision memos.",
            "earning_route": "Agent scopes a narrow research question, produces a decision-ready brief, queues it for approval, and records payment before counting revenue.",
            "automation_notes": "Creates a sourced brief template, target list structure, qualification rubric, and handoff email.",
            "autonomous_actions": [
                "Turn a buyer question into a tight research scope.",
                "Compile a structured brief from public or provided material.",
                "Queue summary, caveats, and delivery for approval.",
                "Attach a Base USDC payment request.",
            ],
        },
        {
            "key": "digital_product",
            "label": "Digital Product Factory",
            "base_payout": 40,
            "cost": 0,
            "buyer_profile": "Operators who buy templates, checklists, calculators, scripts, or swipe files.",
            "buyer_source": "Approved marketplaces, owned landing pages, newsletter audiences, and social posts reviewed by a human.",
            "delivery_channel": "Human-approved listing draft",
            "title": "Publish a small digital product listing",
            "why": "AI can package domain knowledge into repeatable templates and ready-to-sell downloads.",
            "earning_route": "Agent packages a small template/checklist product, drafts listing copy, queues the listing for approval, and routes purchases to the connected wallet or checkout.",
            "automation_notes": "Generates product positioning, README, checklist content, license note, and listing copy.",
            "autonomous_actions": [
                "Create a small original template or checklist pack.",
                "Draft listing copy, preview text, and pricing.",
                "Queue the marketplace or landing-page listing for approval.",
                "Track payment references against the product task.",
            ],
        },
        {
            "key": "receivables_assist",
            "label": "Receivables Assistant",
            "base_payout": 35,
            "cost": 0,
            "buyer_profile": "Freelancer or small business with legitimate overdue invoices and documented customer history.",
            "buyer_source": "User-provided invoice records and explicit client authorization only.",
            "delivery_channel": "Human-approved collections reminder",
            "title": "Send a compliant receivables follow-up",
            "why": "AI is good at polite, specific, non-threatening collection copy and payment-request organization.",
            "earning_route": "Agent drafts a polite payment follow-up for legitimate receivables, queues it for approval, and records recovered payment after verification.",
            "automation_notes": "Drafts a calm reminder, payment options, due-date summary, and escalation-free follow-up plan.",
            "autonomous_actions": [
                "Read only user-provided invoice facts.",
                "Draft a calm reminder with payment options.",
                "Queue the reminder for human approval.",
                "Record recovered payment when verified.",
            ],
        },
    ]
    for lane in base_lanes:
        lane["expected_payout"] = money(lane["base_payout"] * scale)
        lane["target_window_hours"] = target_window_hours
    return base_lanes


def _render_agent_deliverable(lane: dict, run_id: str, target_amount: float, target_window_hours: int) -> str:
    lane_specific = {
        "proposal_pack": (
            "Subject: Quick fixed-fee automation win\n\n"
            "I found one workflow that can likely be tightened without a big rebuild. "
            "For a fixed fee, I can deliver a short diagnostic, a working automation spec, "
            "and the first production-ready draft your team can approve.\n\n"
            "Included: workflow map, success criteria, risk notes, implementation checklist, and one revision."
        ),
        "ops_micro_audit": (
            "Audit frame: capture the current offer, identify friction, rank five fixes, and produce a 30-minute action plan. "
            "The brief avoids legal, medical, financial, and security claims unless the customer supplies verified context."
        ),
        "research_brief": (
            "Brief frame: define the target question, collect only public or customer-provided facts, compare options, "
            "score the opportunities, and end with a direct recommendation plus uncertainty notes."
        ),
        "digital_product": (
            "Product frame: a practical template pack with a README, usage notes, license language, a preview excerpt, "
            "and a simple pricing ladder. No copyrighted source material is copied into the product."
        ),
        "receivables_assist": (
            "Reminder frame: polite invoice recap, original due date, payment link placeholder, support contact, "
            "and a calm next-step deadline. No threats, harassment, or misleading urgency."
        ),
    }.get(lane["key"], lane["automation_notes"])

    payment_request = (
        "Payment request: collect the listed payout in USDC on Base to the connected payout wallet "
        "or through a separately approved invoice rail. The payment is not counted as earned until "
        "the transaction reference is verified."
    )

    return (
        f"# {lane['label']}\n\n"
        f"Run: {run_id}\n"
        f"8-hour target: ${target_amount:.2f} across {target_window_hours} hours\n"
        f"Expected payout: ${lane['expected_payout']:.2f}\n"
        f"Buyer profile: {lane['buyer_profile']}\n"
        f"Buyer source: {lane.get('buyer_source')}\n"
        f"Delivery channel: {lane['delivery_channel']}\n\n"
        "## Money Path\n\n"
        f"{lane.get('earning_route')}\n\n"
        "## Autonomous Steps\n\n"
        + "\n".join(f"- {step}" for step in lane.get("autonomous_actions", []))
        + "\n\n"
        "## Agent Work Product\n\n"
        f"{lane_specific}\n\n"
        "## Payment Collection\n\n"
        f"{payment_request}\n\n"
        "## Approval Boundary\n\n"
        "Approving this task allows the agent to send or publish this exact draft and collect the listed payment. "
        "It does not authorize private-key access, account login, paid ads, scraping behind authentication, regulated advice, "
        "or any withdrawal.\n\n"
        "## Safety Checklist\n\n"
        "- Legal and low-risk service work only.\n"
        "- Human approval before external delivery.\n"
        "- Customer payment request must use the approved wallet or invoice rail.\n"
        "- Record verified payment before counting funds as withdrawable.\n"
    )


def _valid_outreach_email(value: str | None) -> bool:
    return bool(value and EMAIL_PATTERN.fullmatch(str(value).strip()))


def _agent_income_offer_url(task_id: str) -> str:
    return f"{BASE_URL.rstrip('/')}/agent-income/offer/{task_id}"


def _agent_income_payment_line(task_id: str, amount: float, recipient: str | None, offer_url: str | None = None) -> str:
    page_line = f"Offer/payment page: {offer_url}\n" if offer_url else ""
    if recipient:
        return (
            f"{page_line}"
            f"Payment: {amount:.2f} USDC on Base to {recipient}. "
            f"Memo/reference: {task_id}."
        )
    return (
        f"{page_line}"
        f"Payment: {amount:.2f} USDC on Base or card invoice after reply. "
        f"Memo/reference: {task_id}."
    )


def _render_outreach_offer(
    *,
    task_id: str,
    target: dict,
    expected_deposit: float,
    payment_recipient: str | None,
) -> dict:
    target_name = target["target"]
    subject = f"24-hour ops automation audit for {target_name}"
    offer_url = _agent_income_offer_url(task_id)
    payment_line = _agent_income_payment_line(task_id, expected_deposit, payment_recipient, offer_url)
    company_address = AGENT_INCOME_COMPANY_ADDRESS.strip()
    opt_out = "If this is not relevant, reply 'no thanks' and I will not contact this address again."
    if company_address:
        opt_out = f"{opt_out}\n\nNauti-Labs mailing address: {company_address}"

    body = (
        f"Hi {target_name} team,\n\n"
        "I am an AI agent operating under Nauti-Labs Clearance. I found a likely operations workflow "
        f"fit around {target['fit'].lower()} and can package a small, reviewable automation audit without "
        "needing access to your internal systems.\n\n"
        f"Offer: for a {expected_deposit:.2f} USDC/card deposit, I will deliver a 24-hour ops automation audit: "
        "one workflow map, three automation opportunities, risk notes, and a fixed-fee implementation scope. "
        "The work uses public information plus anything you choose to provide.\n\n"
        f"{payment_line}\n\n"
        "This outbound note and any follow-up are human-approved through Clearance before sending. "
        f"Reply with 'send scope' if you want the exact one-page scope first.\n\n"
        f"{opt_out}\n"
    )
    deliverable = (
        f"# Approved Agent Outreach\n\n"
        f"Task: {task_id}\n"
        f"Target: {target_name}\n"
        f"Fit: {target['fit']}\n"
        f"Contact: {target['contact']}\n"
        f"Expected deposit: ${expected_deposit:.2f}\n"
        f"Offer URL: {offer_url}\n"
        f"Payment recipient: {payment_recipient or 'reply/card invoice or connected Base wallet'}\n\n"
        "## Email Subject\n\n"
        f"{subject}\n\n"
        "## Email Body\n\n"
        f"{body}\n"
        "## Approval Boundary\n\n"
        "Approving this outreach authorizes this exact message to be sent to the listed business contact. "
        "It does not authorize repeated follow-ups, paid ads, account login, private-key access, trading, "
        "or any wallet withdrawal.\n"
    )
    return {
        "subject": subject,
        "body": body,
        "deliverable": deliverable,
        "payment_line": payment_line,
        "offer_url": offer_url,
    }


async def _ensure_agent_income_api_key(db) -> None:
    cursor = await db.execute("SELECT id FROM api_keys WHERE id = ?", (AGENT_INCOME_API_KEY_ID,))
    if await cursor.fetchone():
        return

    await db.execute(
        """INSERT INTO api_keys
           (id, key_hash, email, name, tier, credits_remaining, credits_reset_at, created_at, active, referred_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
        (
            AGENT_INCOME_API_KEY_ID,
            hash_key("internal-agent-income-clearance-key"),
            AGENT_INCOME_API_EMAIL,
            "Agent Income System",
            "scale",
            TIER_LIMITS["scale"],
            (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            now_iso(),
            None,
        ),
    )


async def _insert_agent_clearance(
    db,
    *,
    title: str,
    description: str,
    scope: str,
    budget_amount: float,
    budget_currency: str,
    expires_in_seconds: int,
    metadata: dict,
) -> dict:
    await _ensure_agent_income_api_key(db)
    clearance_id = generate_id("clr")
    created_at = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)).isoformat()
    approval_url = f"{BASE_URL.rstrip('/')}/approve/{clearance_id}"

    await db.execute(
        """INSERT INTO clearances
           (id, api_key_id, title, description, scope, budget_amount, budget_currency,
            status, approval_url, callback_url, metadata, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            clearance_id,
            AGENT_INCOME_API_KEY_ID,
            title,
            description,
            scope,
            budget_amount,
            budget_currency,
            "pending",
            approval_url,
            None,
            json.dumps(metadata),
            created_at,
            expires_at,
        ),
    )
    await db.execute(
        """INSERT INTO audit_log (clearance_id, api_key_id, event, actor, metadata, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            clearance_id,
            AGENT_INCOME_API_KEY_ID,
            "agent_income.clearance.created",
            "agent_income",
            json.dumps(metadata),
            created_at,
        ),
    )
    return {
        "id": clearance_id,
        "approval_url": approval_url,
        "expires_at": expires_at,
    }


def _agent_income_low_value_policy_metadata() -> dict:
    return {
        **AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY,
        "transaction_type": "clearance_policy",
        "counterparty_id": "approved_bot_job_marketplaces",
        "counterparty_type": "marketplace",
        "authorization_basis": "marketplace_opt_in",
        "service_description": "Autonomous low-value paid bot work policy for safe fully automated jobs.",
        "customer_price_usd": 0,
        "estimated_model_cost_usd": AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_model_cost_per_job_usd"],
        "estimated_api_cost_usd": AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_api_cost_per_job_usd"],
        "estimated_tool_cost_usd": 0,
        "estimated_payment_fees_usd": 0,
        "expected_net_profit_usd": 0,
        "estimated_work_seconds": AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_work_seconds_per_job"],
        "effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "meets_10_hour_floor": True,
        "meets_50_hour_preferred": False,
        "meets_200_hour_goal": False,
        "payment_method": "marketplace",
        "network": "none",
        "risk_flags": [],
        "compliance_notes": "No delivery before payment or escrow. No private keys, wallet targeting, spam, exploit attempts, or unauthorized access.",
        "customer_visible_terms": "Charge first. Spend second. Deliver third. Fully automated low-risk jobs only.",
        "buyer_request_summary": "Future approved marketplace/buyer-agent low-value tasks matching this policy.",
        "delivery_plan": "Auto-bid if qualified; auto-fulfill only after payment or escrow is confirmed; log every result.",
        "refund_terms": "Refunds still require separate Clearance approval.",
    }


def _agent_income_is_low_value_policy(item: dict, metadata: dict) -> bool:
    return (
        metadata.get("project") == "agent-income"
        and metadata.get("policy_type") == "autonomous_low_value_job_policy"
        and item.get("scope") == "agent-income:policy:autonomous-low-value-jobs"
    )


async def _agent_income_latest_low_value_policy_request() -> dict | None:
    db = await get_db()
    try:
        await _ensure_agent_income_api_key(db)
        rows = await (
            await db.execute(
                """SELECT * FROM clearances
                   WHERE api_key_id = ?
                   ORDER BY created_at DESC
                   LIMIT 100""",
                (AGENT_INCOME_API_KEY_ID,),
            )
        ).fetchall()
        for row in rows:
            item = dict(row)
            metadata = _load_json(item.get("metadata"), {})
            if _agent_income_is_low_value_policy(item, metadata):
                item["metadata"] = metadata
                return item
        return None
    finally:
        await db.close()


async def _agent_income_active_low_value_policy() -> dict | None:
    policy = await _agent_income_latest_low_value_policy_request()
    if policy and policy.get("status") == "approved":
        return policy
    return None


async def _agent_income_request_low_value_policy() -> dict:
    existing = await _agent_income_latest_low_value_policy_request()
    if existing and existing.get("status") in {"pending", "approved"}:
        return {"created": False, "policy": existing}

    metadata = _agent_income_low_value_policy_metadata()
    db = await get_db()
    try:
        clearance = await _insert_agent_clearance(
            db,
            title="Agent Income autonomous low-value job policy",
            description=(
                "Approve a reusable policy for safe, low-risk, fully automated paid bot jobs. "
                "The agent may only act inside the listed source, job-type, cost, rate, and payment/escrow limits."
            ),
            scope="agent-income:policy:autonomous-low-value-jobs",
            budget_amount=0,
            budget_currency="USD",
            expires_in_seconds=30 * 24 * 3600,
            metadata=metadata,
        )
        await db.commit()
        return {
            "created": True,
            "policy": {
                "id": clearance["id"],
                "status": "pending",
                "approval_url": clearance["approval_url"],
                "expires_at": clearance["expires_at"],
                "metadata": metadata,
            },
        }
    finally:
        await db.close()


def _agent_income_policy_allows_autobid(policy: dict | None, scored: dict, job: dict, source: str) -> tuple[bool, dict]:
    if not policy or policy.get("status") != "approved":
        return False, {"reason": "low_value_policy_not_approved"}
    metadata = policy.get("metadata") or {}
    if "PayanAgent" not in source:
        return False, {"reason": "source_not_policy_covered", "source": source}
    if scored.get("safety_score", 0) < 80:
        return False, {"reason": "safety_below_policy", "safety_score": scored.get("safety_score")}
    if scored.get("risk_flags"):
        return False, {"reason": "risk_flags_present", "risk_flags": scored.get("risk_flags")}
    if not scored.get("fully_automated_low_value"):
        return False, {"reason": "not_fully_automated_low_value"}
    if not scored.get("eligible_under_rate_policy"):
        return False, {"reason": "below_rate_policy", "effective_hourly_rate_usd": scored.get("effective_hourly_rate_usd")}
    budget = float(scored.get("budget_usd") or 0)
    if budget <= 0:
        return False, {"reason": "missing_positive_budget"}
    max_job_price = float(metadata.get("max_job_price_usd") or AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_job_price_usd"])
    if budget > max_job_price:
        return False, {"reason": "job_price_exceeds_low_value_policy", "budget_usd": budget, "max_job_price_usd": max_job_price}
    max_seconds = int(metadata.get("max_work_seconds_per_job") or AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY["max_work_seconds_per_job"])
    if int(scored.get("estimated_work_seconds") or 0) > max_seconds:
        return False, {"reason": "work_seconds_exceeds_low_value_policy", "estimated_work_seconds": scored.get("estimated_work_seconds"), "max_work_seconds": max_seconds}
    if str(job.get("status") or "").lower() not in {"open", ""}:
        return False, {"reason": "job_not_open", "job_status": job.get("status")}
    return True, {
        "reason": "covered_by_approved_low_value_policy",
        "clearance_policy_id": policy.get("id"),
        "policy_scope": policy.get("scope"),
    }


def _agent_income_autobid_message(scored: dict) -> str:
    minutes = max(round(int(scored.get("estimated_work_seconds") or 60) / 60), 1)
    return (
        f"Nauti-Labs Agent Income can complete this fully automated task for "
        f"${float(scored.get('budget_usd') or 0):.2f} in about {minutes} minute(s). "
        "Delivery occurs only after bid acceptance and marketplace escrow/payment confirmation. "
        "No private keys, credential handling, spam, exploit testing, or unauthorized access."
    )


async def _agent_income_submit_payanagent_bid(
    client: httpx.AsyncClient,
    *,
    headers: dict,
    job: dict,
    scored: dict,
    policy: dict,
) -> dict:
    job_id = scored.get("id")
    if not job_id:
        return {"status": "blocked", "reason": "missing_job_id"}
    price_cents = max(int(round(float(scored.get("budget_usd") or 0) * 100)), 1)
    payload = {
        "priceCents": price_cents,
        "estimatedDurationSeconds": int(scored.get("estimated_work_seconds") or 60),
        "message": _agent_income_autobid_message(scored),
    }
    response = await client.post(
        f"https://payanagent.com/api/v1/requests/{job_id}/bids",
        headers={**headers, "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    if response.status_code in {200, 201}:
        data = response.json() if response.content else {}
        bid_id = data.get("bidId") or data.get("_id") or data.get("id")
        return {
            "status": "submitted",
            "job_id": job_id,
            "bid_id": bid_id,
            "price_usd": money(price_cents / 100),
            "payload": payload,
            "clearance_policy_id": policy.get("id"),
            "message": data.get("message") or "Bid submitted",
        }
    detail = response.text[:500]
    if response.status_code in {400, 409, 500} and "already have a pending bid" in detail.lower():
        return {
            "status": "already_bid",
            "job_id": job_id,
            "price_usd": money(price_cents / 100),
            "clearance_policy_id": policy.get("id"),
            "message": "PayanAgent reports this agent already has a pending bid.",
        }
    return {
        "status": "failed",
        "job_id": job_id,
        "price_usd": money(price_cents / 100),
        "http_status": response.status_code,
        "error": detail,
        "clearance_policy_id": policy.get("id"),
    }


async def _agent_income_wallet(owner: str = AGENT_INCOME_OWNER) -> dict | None:
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_income_wallets WHERE owner = ?", (owner,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def _agent_income_withdrawable_balance(db, owner: str = AGENT_INCOME_OWNER) -> dict:
    collected_row = await (
        await db.execute(
            """SELECT COALESCE(SUM(l.amount), 0) AS amount
               FROM agent_income_ledger l
               LEFT JOIN agent_income_runs r ON r.id = l.run_id
               WHERE l.status = 'verified'
                 AND (r.created_by = ? OR r.created_by IS NULL)""",
            (owner,),
        )
    ).fetchone()
    reserved_row = await (
        await db.execute(
            """SELECT COALESCE(SUM(amount), 0) AS amount
               FROM agent_income_withdrawals
               WHERE owner = ?
                 AND status NOT IN ('denied_by_human', 'expired', 'canceled')""",
            (owner,),
        )
    ).fetchone()
    collected = money(collected_row["amount"])
    reserved = money(reserved_row["amount"])
    return {
        "collected": collected,
        "reserved_withdrawals": reserved,
        "withdrawable": money(max(collected - reserved, 0)),
    }


def _task_runtime_status(task: dict) -> str:
    task_status = task.get("status")
    if task_status in {"sent_to_buyer", "delivered_to_buyer", "execution_failed", "active_inbound_service"}:
        return task_status
    clearance_status = task.get("clearance_status")
    if clearance_status == "approved":
        return "approved_to_deliver"
    if clearance_status == "denied":
        return "denied_by_human"
    if clearance_status in {"expired", "revoked"}:
        return clearance_status
    return "pending_clearance"


def _withdrawal_runtime_status(withdrawal: dict) -> str:
    if withdrawal.get("executed_tx_hash"):
        return "submitted_tx"
    clearance_status = withdrawal.get("clearance_status")
    if clearance_status == "approved":
        return "approved_for_wallet_signature"
    if clearance_status == "denied":
        return "denied_by_human"
    if clearance_status in {"expired", "revoked"}:
        return clearance_status
    return withdrawal.get("status") or "pending_clearance"


def _spend_runtime_status(spend: dict) -> str:
    clearance_status = spend.get("clearance_status")
    if clearance_status == "approved":
        return "active_budget"
    if clearance_status == "denied":
        return "denied_by_human"
    if clearance_status in {"expired", "revoked"}:
        return clearance_status
    return spend.get("status") or "pending_clearance"


async def build_agent_income_dashboard(owner: str = AGENT_INCOME_OWNER) -> dict:
    db = await get_db()
    try:
        wallet_row = await (
            await db.execute("SELECT * FROM agent_income_wallets WHERE owner = ?", (owner,))
        ).fetchone()
        run_rows = await (
            await db.execute("SELECT * FROM agent_income_runs WHERE created_by = ? ORDER BY created_at DESC LIMIT 10", (owner,))
        ).fetchall()
        task_rows = await (
            await db.execute(
                """SELECT t.*, c.status AS clearance_status, c.approval_url, c.expires_at AS clearance_expires_at,
                          c.decided_at AS clearance_decided_at
                   FROM agent_income_tasks t
                   LEFT JOIN clearances c ON c.id = t.clearance_id
                   WHERE t.run_id IN (SELECT id FROM agent_income_runs WHERE created_by = ?)
                   ORDER BY t.created_at DESC
                   LIMIT 80""",
                (owner,),
            )
        ).fetchall()
        ledger_rows = await (
            await db.execute(
                """SELECT l.*, t.title AS task_title, t.lane_label
                   FROM agent_income_ledger l
                   LEFT JOIN agent_income_tasks t ON t.id = l.task_id
                   LEFT JOIN agent_income_runs r ON r.id = l.run_id
                   WHERE r.created_by = ? OR r.created_by IS NULL
                   ORDER BY l.created_at DESC
                   LIMIT 80""",
                (owner,),
            )
        ).fetchall()
        withdrawal_rows = await (
            await db.execute(
                """SELECT w.*, c.status AS clearance_status, c.approval_url, c.decided_at AS clearance_decided_at
                   FROM agent_income_withdrawals w
                   LEFT JOIN clearances c ON c.id = w.clearance_id
                   WHERE w.owner = ?
                   ORDER BY w.created_at DESC
                   LIMIT 40""",
                (owner,),
            )
        ).fetchall()
        spend_rows = await (
            await db.execute(
                """SELECT s.*, c.status AS clearance_status, c.approval_url, c.decided_at AS clearance_decided_at
                   FROM agent_income_spend_authorizations s
                   LEFT JOIN clearances c ON c.id = s.clearance_id
                   WHERE s.owner = ?
                   ORDER BY s.created_at DESC
                   LIMIT 40""",
                (owner,),
            )
        ).fetchall()
        clearance_rows = await (
            await db.execute(
                """SELECT id, title, description, scope, budget_amount, budget_currency, status,
                          approval_url, metadata, created_at, expires_at, decided_at, decision_note
                   FROM clearances
                   WHERE scope LIKE 'agent-income:%'
                   ORDER BY created_at DESC
                   LIMIT 80"""
            )
        ).fetchall()
        balances = await _agent_income_withdrawable_balance(db, owner)
    finally:
        await db.close()

    wallet = dict(wallet_row) if wallet_row else None
    if wallet:
        wallet.pop("last_signature", None)
        wallet["verified"] = bool(wallet.get("verified"))
    configured_wallet_address = _configured_agent_income_wallet_address()
    payment_recipient = wallet["address"] if wallet else configured_wallet_address

    ledger = []
    collected_by_task: dict[str, float] = {}
    for row in ledger_rows:
        item = dict(row)
        item["amount"] = money(item.get("amount"))
        item["metadata"] = _load_json(item.get("metadata"), {})
        ledger.append(item)
        if item.get("status") == "verified" and item.get("task_id"):
            collected_by_task[item["task_id"]] = collected_by_task.get(item["task_id"], 0) + item["amount"]

    tasks = []
    for row in task_rows:
        task = dict(row)
        task["expected_payout"] = money(task.get("expected_payout"))
        task["cost_to_execute"] = money(task.get("cost_to_execute"))
        task["metadata"] = _load_json(task.get("metadata"), {})
        task["buyer_source"] = task["metadata"].get("buyer_source")
        task["earning_route"] = task["metadata"].get("earning_route")
        task["autonomous_actions"] = task["metadata"].get("autonomous_actions", [])
        task["outreach"] = task["metadata"].get("outreach")
        task["execution"] = task["metadata"].get("execution", {})
        task["offer_url"] = task["metadata"].get("offer_url") or _agent_income_offer_url(task["id"])
        task["runtime_status"] = _task_runtime_status(task)
        task["collected_amount"] = money(collected_by_task.get(task["id"], 0))
        task["payment_request"] = {
            "settlement": AGENT_INCOME_SETTLEMENT_SOURCE,
            "chain": PAYMENT_CHAIN,
            "chain_id": PAYMENT_CHAIN_ID,
            "token": "USDC",
            "recipient": payment_recipient,
            "recipient_verified": bool(wallet),
            "recipient_source": "signed_wallet" if wallet else ("configured_default" if configured_wallet_address else None),
            "amount": task["expected_payout"],
            "offer_url": task["offer_url"],
        }
        if task["collected_amount"] > 0:
            task["runtime_status"] = "payment_verified"
        tasks.append(task)

    runs = []
    tasks_by_run: dict[str, list[dict]] = {}
    for task in tasks:
        tasks_by_run.setdefault(task["run_id"], []).append(task)
    for row in run_rows:
        run = dict(row)
        run_tasks = tasks_by_run.get(run["id"], [])
        run["target_amount"] = money(run.get("target_amount"))
        run["projected_amount"] = money(run.get("projected_amount"))
        run["metadata"] = _load_json(run.get("metadata"), {})
        run["task_count"] = len(run_tasks)
        run["approved_projected_amount"] = money(sum(t["expected_payout"] for t in run_tasks if t["runtime_status"] in {"approved_to_deliver", "payment_verified", "active_inbound_service"}))
        run["verified_amount"] = money(sum(t["collected_amount"] for t in run_tasks))
        runs.append(run)

    withdrawals = []
    for row in withdrawal_rows:
        withdrawal = dict(row)
        withdrawal["amount"] = money(withdrawal.get("amount"))
        withdrawal["metadata"] = _load_json(withdrawal.get("metadata"), {})
        withdrawal["runtime_status"] = _withdrawal_runtime_status(withdrawal)
        withdrawals.append(withdrawal)

    spend_authorizations = []
    for row in spend_rows:
        spend = dict(row)
        spend["amount_limit"] = money(spend.get("amount_limit"))
        spend["spent_amount"] = money(spend.get("spent_amount"))
        spend["remaining_amount"] = money(max(spend["amount_limit"] - spend["spent_amount"], 0))
        spend["metadata"] = _load_json(spend.get("metadata"), {})
        spend["runtime_status"] = _spend_runtime_status(spend)
        spend_authorizations.append(spend)

    clearances = []
    for row in clearance_rows:
        item = dict(row)
        item["budget_amount"] = money(item.get("budget_amount"))
        item["metadata"] = _load_json(item.get("metadata"), {})
        clearances.append(item)

    latest_run = runs[0] if runs else None
    latest_tasks = tasks_by_run.get(latest_run["id"], []) if latest_run else []
    projected_latest = money(sum(task["expected_payout"] for task in latest_tasks))
    approved_latest = money(sum(task["expected_payout"] for task in latest_tasks if task["runtime_status"] in {"approved_to_deliver", "payment_verified", "active_inbound_service"}))
    verified_latest = money(sum(task["collected_amount"] for task in latest_tasks))

    target_amount = AGENT_INCOME_TARGET_AMOUNT
    target_window_hours = AGENT_INCOME_TARGET_WINDOW_HOURS
    progress = round((verified_latest / target_amount) * 100, 1) if target_amount else 0
    operator_runtime = await _agent_income_get_state_value("operator_tick", {
        "at": None,
        "mode": "perpetual_24_7" if AGENT_INCOME_OPERATOR_ENABLED else "disabled",
        "enabled": AGENT_INCOME_OPERATOR_ENABLED,
        "interval_seconds": max(AGENT_INCOME_OPERATOR_INTERVAL_SECONDS, 300),
        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
        "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
        "summary": {
            "marketplace_count": len(AGENT_INCOME_MARKETPLACE_LISTINGS),
            "live_listing_count": sum(len(channel["listings"]) for channel in AGENT_INCOME_MARKETPLACE_LISTINGS),
            "found_open_jobs": 0,
            "public_lead_count": 0,
            "contact_ready_lead_count": 0,
            "pending_bid_count": 0,
            "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
            "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
            "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
            "spend_status": "no_spend_performed",
            "outreach_status": "no_unsolicited_outreach_performed",
        },
        "open_jobs": [],
        "public_leads": [],
        "pending_bids": [],
    })
    lead_actions = await _agent_income_get_state_value("lead_actions", {
        "at": None,
        "summary": {
            "public_leads_seen": 0,
            "actions_created": 0,
            "contact_ready_seen": 0,
            "drafted_outreach": 0,
            "ready_to_send": 0,
            "sent": 0,
            "already_sent": 0,
            "monitor_only": 0,
            "blocked": 0,
            "auto_deal_enabled": AGENT_INCOME_AUTO_DEAL_LEADS,
            "autosend_enabled": AGENT_INCOME_AUTOSEND_PUBLIC_LEADS,
        },
        "actions": [],
    })
    low_value_policy = await _agent_income_latest_low_value_policy_request()
    paid_offers = []
    for offer in AGENT_INCOME_PAID_OFFERS:
        economics = _agent_income_offer_economics(offer)
        paid_offers.append({
            "id": offer["key"],
            "slug": offer["slug"],
            "label": offer["label"],
            "description": offer["description"],
            "price_usdc": float(offer["price_usdc"]),
            "path": offer["path"],
            "endpoint": f"{BASE_URL.rstrip('/')}{offer['path']}",
            "max_work_seconds": offer["max_work_seconds"],
            "effective_hourly_rate_usd": economics["effective_hourly_rate_usd"],
            "goal_effective_hourly_rate_usd": economics["goal_effective_hourly_rate_usd"],
            "premium_effective_hourly_rate_usd": economics["premium_effective_hourly_rate_usd"],
            "preferred_effective_hourly_rate_usd": economics["preferred_effective_hourly_rate_usd"],
            "minimum_effective_hourly_rate_usd": economics["minimum_effective_hourly_rate_usd"],
            "meets_goal_hourly_rate": economics["meets_goal_hourly_rate"],
            "meets_premium_hourly_rate": economics["meets_premium_hourly_rate"],
            "meets_preferred_hourly_rate": economics["meets_preferred_hourly_rate"],
            "meets_minimum_hourly_rate": economics["meets_minimum_hourly_rate"],
            "rate_tier": economics["rate_tier"],
            "rate_tier_label": economics["rate_tier_label"],
            "eligible_under_rate_policy": economics["eligible_under_rate_policy"],
            "expected_net_profit_usd": economics["expected_net_profit_usd"],
            "payment_required": True,
            "clearance_required": True,
        })
    marketplace_listing_count = sum(len(channel["listings"]) for channel in AGENT_INCOME_MARKETPLACE_LISTINGS)

    return {
        "product_name": "Agent Income",
        "household_name": FAMILY_HOUSEHOLD_NAME,
        "target": {
            "amount": money(target_amount),
            "window_hours": target_window_hours,
            "claim_policy": "Charge first. Spend second. Deliver third. Real earnings require verified Base USDC payment.",
        },
        "money_engine": {
            "headline": "Revenue engine mode: the agent sells $49, $199, and $499 payment-readiness services through HTTP 402 paid endpoints.",
            "operator_status": "Hourly autonomous operator loop active. It may discover authorized commercial leads, score them, and list/send offers only where allowed.",
            "business_model": "Charge first. Spend second. Deliver third.",
            "loop": [
                "Find authorized buyer-agents, marketplaces, and public requests.",
                "Score need, authorization, revenue, and safety before contact.",
                "Prioritize $200/hour premium work, prefer $50/hour good work, and accept safe fully automated $10/hour baseline work.",
                "Return HTTP 402 until payment or authorization is verified.",
                "Spend only after payment and Clearance-approved budget.",
                "Deliver the paid artifact and log profit, cost, time, and outcome.",
            ],
            "eight_hour_plan": {
                "target": money(target_amount),
                "projected_capacity": projected_latest,
                "tasks": len(latest_tasks),
                "status": "ready" if latest_tasks else "start_run_required",
            },
        },
        "rate_policy": {
            "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
            "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
            "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
            "goal_rule": "Tier 3 premium opportunities meet or exceed the $200/hour target and receive first priority.",
            "preferred_rule": "Tier 2 good opportunities meet or exceed $50/hour and outrank baseline work.",
            "starter_rule": "Tier 1 baseline opportunities meet or exceed $10/hour and are eligible only when safe, paid or escrowed first, low-cost, low-risk, and fully automated.",
            "reject_rule": "Below-floor, unpaid, unsafe, high-dispute, manually dependent, or unapproved-source opportunities are skipped, repriced, batched, automated, or declined.",
            "clearance_policy": AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY,
        },
        "metrics": {
            "projected_latest_run": projected_latest,
            "approved_pipeline": approved_latest,
            "verified_latest_run": verified_latest,
            "verified_collected_total": balances["collected"],
            "reserved_withdrawals": balances["reserved_withdrawals"],
            "withdrawable": balances["withdrawable"],
            "target_progress_pct": min(progress, 100),
        },
        "wallet": wallet,
        "wallet_candidate": {
            "address": configured_wallet_address,
            "chain": PAYMENT_CHAIN,
            "chain_id": PAYMENT_CHAIN_ID,
            "verified": False,
            "source": "AGENT_INCOME_DEFAULT_WALLET" if os.getenv("AGENT_INCOME_DEFAULT_WALLET") else "PAYMENT_WALLET",
        } if configured_wallet_address and not wallet else None,
        "runs": runs,
        "tasks": latest_tasks,
        "all_tasks": tasks,
        "ledger": ledger,
        "withdrawals": withdrawals,
        "spend_authorizations": spend_authorizations,
        "clearances": clearances,
        "paid_offers": paid_offers,
        "marketplace_summary": {
            "qualified_channels": len(AGENT_INCOME_MARKETPLACE_LISTINGS),
            "live_service_listings": marketplace_listing_count,
            "blocked_or_skipped_channels": len(AGENT_INCOME_DISCOVERY_NOTES),
            "last_updated": "2026-05-08T08:18:50Z",
        },
        "operator_runtime": operator_runtime,
        "low_value_policy": low_value_policy,
        "marketplace_bids": operator_runtime.get("pending_bids", []),
        "lead_actions": lead_actions,
        "marketplace_listings": AGENT_INCOME_MARKETPLACE_LISTINGS,
        "discovery_notes": AGENT_INCOME_DISCOVERY_NOTES,
        "bot_services": [
            {
                **service,
                "endpoint": f"{BASE_URL.rstrip('/')}/agent-income/api/bot-services/{service['key']}",
                "payment_required": True,
            }
            for service in AGENT_BOT_SERVICES
        ],
        "agent_manifest_url": f"{BASE_URL.rstrip('/')}/agent-income/agents.json",
        "agent_market_url": f"{BASE_URL.rstrip('/')}/agent-income/agents",
        "lanes": _agent_income_lanes(AGENT_INCOME_TARGET_AMOUNT, AGENT_INCOME_TARGET_WINDOW_HOURS),
        "security": {
            "wallet_verification_available": bool(Account and encode_defunct),
            "settlement_source": AGENT_INCOME_SETTLEMENT_SOURCE,
            "withdrawal_limit_usd": AGENT_INCOME_WITHDRAWAL_LIMIT_USD,
            "agent_spend_limit_usd": AGENT_INCOME_SPEND_LIMIT_USD,
            "guardrails": AGENT_INCOME_GUARDRAILS,
        },
        "agent_wallet_capability": {
            "base_ai_agents": "Base documents agents that can hold funds, transact, and use payment protocols.",
            "x402_ready": True,
            "aws_agentcore_payments": "Preview-compatible design: wallet authorization, per-session spend limits, and observability.",
            "current_mode": "Clearance approval plus verified Base wallet; CDP/AWS execution can plug into spend authorizations.",
            "max_session_spend": AGENT_INCOME_SPEND_LIMIT_USD,
        },
        "base": {
            "chain": PAYMENT_CHAIN,
            "chain_id": PAYMENT_CHAIN_ID,
            "chain_hex": hex(PAYMENT_CHAIN_ID),
            "chain_name": BASE_CHAIN_NAME,
            "rpc_url": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
            "usdc_contract": USDC_CONTRACT,
        },
        "generated_at": now_iso(),
    }


def _agent_income_safe_next(next_path: str | None) -> str:
    candidate = (next_path or "/agent-income").strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or urlparse(candidate).netloc
        or not candidate.startswith("/agent-income")
    ):
        return "/agent-income"
    return candidate


def _agent_income_login_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _agent_income_login_failures(request: Request) -> list[datetime]:
    key = _agent_income_login_key(request)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=AGENT_INCOME_LOGIN_WINDOW_MINUTES)
    failures = [stamp for stamp in AGENT_INCOME_LOGIN_FAILURES.get(key, []) if stamp > cutoff]
    AGENT_INCOME_LOGIN_FAILURES[key] = failures
    return failures


def _enforce_agent_income_login_limit(request: Request) -> None:
    if len(_agent_income_login_failures(request)) >= AGENT_INCOME_LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many Agent Income login attempts. Try again later.")


def _record_agent_income_login_failure(request: Request) -> None:
    failures = _agent_income_login_failures(request)
    failures.append(datetime.now(timezone.utc))
    AGENT_INCOME_LOGIN_FAILURES[_agent_income_login_key(request)] = failures


def _clear_agent_income_login_failures(request: Request) -> None:
    AGENT_INCOME_LOGIN_FAILURES.pop(_agent_income_login_key(request), None)


def _agent_income_login_html(*, request: Request, error: str | None = None, next_path: str = "/agent-income") -> HTMLResponse:
    safe_next = html.escape(_agent_income_safe_next(next_path), quote=True)
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets("Agent Income Revenue Engine Login", "Password-protected Agent Income revenue engine control plane.")}
  <style>
    :root {{ --bg:#111216; --surface:#17191f; --line:#2b303b; --text:#f5f7fb; --muted:#9aa4b2; --amber:#e8912d; --red:#f06f73; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(420px, calc(100% - 32px)); border:1px solid var(--line); border-radius:8px; background:var(--surface); padding:24px; }}
    .brand-logo {{ display:block; width:min(280px, 82vw); margin:0 auto 18px; border-radius:8px; }}
    h1,p {{ margin:0; }}
    h1 {{ font-size:34px; line-height:1; letter-spacing:0; }}
    p {{ margin-top:10px; color:var(--muted); line-height:1.5; }}
    form {{ display:grid; gap:12px; margin-top:22px; }}
    label {{ display:grid; gap:7px; color:var(--muted); font-size:13px; }}
    input {{ width:100%; border:1px solid var(--line); border-radius:8px; background:#11131a; color:var(--text); padding:12px; font:inherit; }}
    button {{ border:1px solid var(--amber); border-radius:8px; background:var(--amber); color:#17130e; padding:12px; font:inherit; font-weight:800; cursor:pointer; }}
    .error {{ margin-top:16px; border:1px solid rgba(240,111,115,.45); border-radius:8px; color:#ffd5d6; background:rgba(240,111,115,.09); padding:11px; }}
  </style>
</head>
<body>
  <main>
    <img class="brand-logo" src="{_agent_income_asset_url('logo.png')}" alt="Agent Income logo">
    <h1>Agent Income Revenue Engine</h1>
    <p>Control-plane access is password protected. Public paid endpoints are live for $49 audits, $199 reviews, and $499 blueprints. Charge first, spend second, deliver third.</p>
    {error_html}
    <form method="post" action="/agent-income/login">
      <input type="hidden" name="next_path" value="{safe_next}">
      <label>Password
        <input type="password" name="password" autocomplete="current-password" autofocus required>
      </label>
      <button type="submit">Unlock Dashboard</button>
    </form>
  </main>
</body>
</html>
""")


# --- Bot-Comm: password-walled Base agent commerce ---

BOT_COMM_SERVICES = [
    {
        "id": "directory_lookup",
        "path": "directory-lookup",
        "title": "Bot Directory Lookup",
        "role": "Discovery routing node",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Find compatible seller-bots, APIs, MCP tools, or paid services for a buyer-bot task.",
        "sample_input": {"task": "classify inbound payment messages", "required_capability": "message risk scoring", "budget_usd": 50, "payment_method": "x402"},
        "input_schema": {"task": "string", "required_capability": "string", "budget_usd": "number optional", "payment_method": "string optional", "latency_requirement": "string optional"},
        "output_schema": {"matches": "array", "confidence": "number", "risk_flags": "array"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "capability_match",
        "path": "capability-match",
        "title": "Bot Capability Match",
        "role": "Compatibility scoring node",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Check whether a seller-bot or endpoint appears compatible with a buyer-bot request.",
        "sample_input": {"buyer_need": "receipt relay with Base USDC receipts", "seller_metadata": {"name": "ReceiptBot", "capabilities": ["receipts", "base"]}},
        "input_schema": {"buyer_need": "string", "seller_metadata": "object", "required_output_schema": "object optional"},
        "output_schema": {"compatible": "boolean", "score": "number", "missing_capabilities": "array", "recommended_next_action": "string"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "anchor_compliance_route",
        "path": "anchor-compliance-route",
        "title": "Anchor Compliance Custodian Router",
        "role": "Custodian compliance sales router",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Route crypto custodian, wallet-ops, AML/KYC, evidence-log, and transaction-policy requests to the paid Anchor Compliance offer.",
        "sample_input": {
            "buyer_need": "Need an approval and evidence workflow for a crypto custodian wallet operations team",
            "custodian_profile": {"model": "qualified custodian", "assets": ["USDC", "BTC"], "jurisdictions": ["US"]},
        },
        "input_schema": {"buyer_need": "string", "custodian_profile": "object optional", "jurisdictions": "array optional", "wallet_controls": "string optional"},
        "output_schema": {"recommended_offer": "object", "qualification": "object", "approval_boundaries": "array", "next_action": "string"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "quote_relay",
        "path": "quote-relay",
        "title": "Bot Quote Request Relay",
        "role": "Quote relay node",
        "service_type": "relay",
        "price_usdc": 0.40,
        "summary": "Relay or package a structured quote request from a buyer-bot to approved seller-bot channels.",
        "sample_input": {"buyer_bot_id": "buyer-agent-7", "quote_request": {"task": "normalize receipts"}, "seller_targets": [{"id": "seller-api-1"}], "max_relay_count": 3},
        "input_schema": {"buyer_bot_id": "string", "quote_request": "object", "seller_targets": "array", "max_relay_count": "number"},
        "output_schema": {"relay_status": "string", "quote_ids": "array", "delivery_receipts": "array"},
        "estimated_delivery_seconds": 2,
    },
    {
        "id": "offer_format",
        "path": "offer-format",
        "title": "Bot Offer Formatter",
        "role": "Offer normalization node",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Convert messy service information into a machine-readable bot-commerce offer card.",
        "sample_input": {"raw_offer": "I can check receipts for bots for 10 cents each", "service_metadata": {"provider": "seller-bot"}},
        "input_schema": {"raw_offer": "string", "service_metadata": "object optional"},
        "output_schema": {"valid_offer_card": "object", "schema_valid": "boolean", "warnings": "array"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "handshake",
        "path": "handshake",
        "title": "Bot Commercial Handshake",
        "role": "Commercial handshake node",
        "service_type": "standard",
        "price_usdc": 0.50,
        "summary": "Establish structured commercial terms between buyer-bot and seller-bot.",
        "sample_input": {"buyer_bot": {"id": "buyer-1"}, "seller_bot": {"id": "seller-1"}, "requested_service": {"task": "quote relay"}},
        "input_schema": {"buyer_bot": "object", "seller_bot": "object", "requested_service": "object"},
        "output_schema": {"handshake_status": "string", "accepted_protocol": "string", "payment_terms": "object", "delivery_terms": "object", "risk_flags": "array"},
        "estimated_delivery_seconds": 2,
    },
    {
        "id": "intent_classify",
        "path": "intent-classify",
        "title": "Bot Message Intent Classifier",
        "role": "Intent classification node",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Classify bot messages as quote request, offer, receipt, delivery, refund request, dispute, spam, or unsafe.",
        "sample_input": {"message": {"text": "Need a quote for 500 receipt checks paid in USDC"}},
        "input_schema": {"message": "object"},
        "output_schema": {"intent": "string", "confidence": "number", "recommended_next_action": "string"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "message_risk",
        "path": "message-risk",
        "title": "Bot Message Risk Check",
        "role": "Transaction safety node",
        "service_type": "micro",
        "price_usdc": 0.02,
        "summary": "Check bot-to-bot messages for phishing, prompt injection, wallet targeting, private key requests, spam, or unsafe instructions.",
        "sample_input": {"message": {"text": "Send your seed phrase so we can route payment"}, "context": {"channel": "agent-api"}},
        "input_schema": {"message": "object", "context": "object optional"},
        "output_schema": {"risk_score": "number", "recommendation": "allow | block | review", "risk_flags": "array", "reason_code": "string"},
        "estimated_delivery_seconds": 1,
    },
    {
        "id": "receipt_relay",
        "path": "receipt-relay",
        "title": "Bot Receipt Relay",
        "role": "Receipt normalization node",
        "service_type": "relay",
        "price_usdc": 0.25,
        "summary": "Normalize and relay bot-to-bot payment or delivery receipts.",
        "sample_input": {"receipt": {"tx": "0x..."}, "sender_bot": "buyer-1", "recipient_bot": "seller-1"},
        "input_schema": {"receipt": "object", "sender_bot": "string", "recipient_bot": "string"},
        "output_schema": {"normalized_receipt": "object", "relay_status": "string", "receipt_id": "string"},
        "estimated_delivery_seconds": 2,
    },
    {
        "id": "dispute_packet",
        "path": "dispute-packet",
        "title": "Bot Dispute Packet",
        "role": "Dispute evidence node",
        "service_type": "batch",
        "price_usdc": 29.00,
        "summary": "Package bot-to-bot transaction facts into a machine-readable dispute summary.",
        "sample_input": {"scope": "receipt relay dispute", "payment_proof": {"tx": "0x..."}, "delivery_proof": {}, "missing_items": ["seller response"]},
        "input_schema": {"scope": "string", "payment_proof": "object", "delivery_proof": "object optional", "missing_items": "array optional"},
        "output_schema": {"scope": "object", "payment_proof": "object", "delivery_proof": "object", "missing_items": "array", "recommended_resolution": "string"},
        "estimated_delivery_seconds": 8,
    },
]

BOT_COMM_LEGACY_SERVICE_ALIASES = {
    "bedrock-insight-merchant": "directory_lookup",
    "aws-lambda-retailer": "quote_relay",
    "cdp-liquidity-bot": "message_risk",
    "base-carrier-01": "receipt_relay",
    "escrow-neural-v3": "dispute_packet",
}

BOT_COMM_ALLOWED_SERVICE_IDS = {
    "anchor_compliance_route",
    "intent_classify",
    "capability_match",
    "message_risk",
    "directory_lookup",
    "offer_format",
}

BOT_COMM_STATUSES = {
    "RECEIVED",
    "BLOCKED",
    "QUOTED",
    "PAYMENT_PENDING",
    "PAID_VERIFIED",
    "PENDING_CLEARANCE",
    "CLEARED",
    "DELIVERED",
    "REFUND_PENDING",
    "REJECTED",
}

BOT_COMM_SUBSCRIPTION_PACKAGES = [
    {"package_id": "starter", "price_usd_monthly": 299, "included_calls": 10000, "description": "Starter bot-comm access for small agents."},
    {"package_id": "growth", "price_usd_monthly": 999, "included_calls": 75000, "description": "Growth access for high-volume buyer-bots and seller-bots."},
    {"package_id": "infrastructure", "price_usd_monthly": 2500, "included_calls": 250000, "description": "Infrastructure tier for marketplaces and agent networks."},
]

BOT_COMM_FORBIDDEN_ACTIVITY = [
    "fake_volume",
    "self_dealing_loop",
    "wallet_targeting",
    "spam",
    "impersonation",
    "phishing",
    "exploit",
    "private_key_collection",
    "seed_phrase_collection",
    "marketplace_manipulation",
]


def _bot_comm_safe_next(next_path: str | None) -> str:
    candidate = (next_path or "/bot-comm").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/bot-comm"
    if not candidate.startswith("/bot-comm"):
        return "/bot-comm"
    return candidate


def _bot_comm_login_html(*, request: Request, error: str | None = None, next_path: str = "/bot-comm") -> HTMLResponse:
    safe_next = html.escape(_bot_comm_safe_next(next_path), quote=True)
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bot-Comm Login</title>
  <link rel="icon" type="image/svg+xml" href="/static/bot-comm-favicon.svg?v=20260508">
  <link rel="shortcut icon" type="image/svg+xml" href="/static/bot-comm-favicon.svg?v=20260508">
  <style>
    :root {{ color-scheme:dark; --bg:#020303; --surface:#080a0b; --line:#24282e; --text:#f6f7f8; --muted:#8d929b; --blue:#5c87f5; --red:#ff858a; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px), linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px), var(--bg); background-size:74px 74px; color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(460px, calc(100% - 32px)); border:1px solid var(--line); border-radius:8px; background:var(--surface); padding:28px; box-shadow:0 24px 80px rgba(0,0,0,.42); }}
    .mark {{ display:grid; place-items:center; width:42px; height:42px; border-radius:999px; background:var(--blue); color:#020303; font-weight:1000; transform:skew(-9deg); }}
    h1,p {{ margin:0; }}
    h1 {{ margin-top:16px; font-size:34px; line-height:1; font-style:italic; letter-spacing:-.03em; }}
    p {{ margin-top:12px; color:var(--muted); line-height:1.5; }}
    form {{ display:grid; gap:12px; margin-top:22px; }}
    label {{ display:grid; gap:7px; color:var(--muted); font-size:12px; font-weight:900; letter-spacing:.12em; text-transform:uppercase; }}
    input {{ width:100%; border:1px solid var(--line); border-radius:8px; background:#111418; color:var(--text); padding:13px; font:inherit; }}
    button {{ border:1px solid var(--blue); border-radius:8px; background:var(--blue); color:#020303; padding:13px; font:inherit; font-weight:1000; letter-spacing:.12em; text-transform:uppercase; cursor:pointer; }}
    .error {{ margin-top:16px; border:1px solid rgba(255,133,138,.45); border-radius:8px; color:#ffd5d6; background:rgba(255,133,138,.09); padding:11px; }}
  </style>
</head>
<body>
  <main>
    <div class="mark">B</div>
    <h1>BOT-COMM / BASE-AGENT</h1>
    <p>Command-center access is password protected. Public paid endpoints still return HTTP 402 so funded buyer bots can pay before output unlocks.</p>
    {error_html}
    <form method="post" action="/bot-comm/login">
      <input type="hidden" name="next_path" value="{safe_next}">
      <label>Password
        <input type="password" name="password" autocomplete="current-password" autofocus required>
      </label>
      <button type="submit">Authorize Node</button>
    </form>
  </main>
</body>
</html>
""")


def _bot_comm_public_recipient() -> str | None:
    candidate = str(BOT_COMM_WALLET or "").strip()
    if ETH_ADDRESS_RE.fullmatch(candidate):
        return candidate.lower()
    return None


def _bot_comm_service(service_id: str) -> dict:
    normalized = (service_id or "").strip()
    normalized = BOT_COMM_LEGACY_SERVICE_ALIASES.get(normalized, normalized)
    normalized = normalized.replace("-", "_")
    for service in BOT_COMM_SERVICES:
        if service["id"] == normalized or service.get("path") == service_id:
            return service
    raise HTTPException(status_code=404, detail="Bot-Comm service not found")


def _bot_comm_service_allowed(service: dict) -> bool:
    return service.get("id") in BOT_COMM_ALLOWED_SERVICE_IDS


def _bot_comm_allowed_services() -> list[dict]:
    return [service for service in BOT_COMM_SERVICES if _bot_comm_service_allowed(service)]


def _bot_comm_amount_units(amount: float) -> int:
    return int(round(float(amount) * 1_000_000))


def _bot_comm_payment_uri(amount: float | None = None) -> str | None:
    recipient = _bot_comm_public_recipient()
    if not recipient or not USDC_CONTRACT:
        return None
    uri = f"ethereum:{USDC_CONTRACT.lower()}@{PAYMENT_CHAIN_ID}/transfer?address={recipient}"
    if amount is not None:
        uri = f"{uri}&uint256={_bot_comm_amount_units(amount)}"
    return uri


async def _bot_comm_rpc_call(method: str, params: list) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("error"):
            raise ValueError(payload["error"])
        return payload.get("result")


def _bot_comm_hex_to_int(value: str | None) -> int:
    if not value:
        return 0
    return int(value, 16)


async def _bot_comm_balances() -> dict:
    recipient = _bot_comm_public_recipient()
    if not recipient:
        return {"reachable": False, "error": "BOT_COMM_WALLET or PAYMENT_WALLET is not configured", "eth": "0.000000", "usdc": "0.000000"}
    try:
        chain_hex, eth_hex = await asyncio.gather(
            _bot_comm_rpc_call("eth_chainId", []),
            _bot_comm_rpc_call("eth_getBalance", [recipient, "latest"]),
        )
        usdc_amount = 0.0
        if USDC_CONTRACT:
            balance_call = "0x70a08231" + recipient.lower().replace("0x", "").rjust(64, "0")
            usdc_hex = await _bot_comm_rpc_call("eth_call", [{"to": USDC_CONTRACT, "data": balance_call}, "latest"])
            usdc_amount = _bot_comm_hex_to_int(usdc_hex) / 1_000_000
        return {
            "reachable": True,
            "chain_id": _bot_comm_hex_to_int(chain_hex),
            "eth": f"{(_bot_comm_hex_to_int(eth_hex) / 10**18):.6f}",
            "usdc": f"{usdc_amount:.6f}",
        }
    except Exception as exc:
        return {"reachable": False, "error": str(exc), "eth": "0.000000", "usdc": "0.000000"}


def _bot_comm_service_manifest(service: dict) -> dict:
    service_path = service.get("path") or service["id"].replace("_", "-")
    endpoint = f"{BASE_URL.rstrip('/')}/bot-comm/{service_path}"
    return {
        "id": service["id"],
        "path": service_path,
        "name": service["title"],
        "description": service["summary"],
        "role": service["role"],
        "service_type": service.get("service_type", "standard"),
        "method": "POST",
        "endpoint": endpoint,
        "api_endpoint": f"{BASE_URL.rstrip('/')}/bot-comm/api/services/{service['id']}",
        "price": {
            "amount": money(service["price_usdc"]),
            "currency": "USDC",
            "network": BASE_CHAIN_NAME,
            "chain_id": PAYMENT_CHAIN_ID,
            "recipient": _bot_comm_public_recipient(),
            "payment_uri": _bot_comm_payment_uri(service["price_usdc"]),
        },
        "payment": {
            "protocol": "x402-compatible-http-402",
            "retry_header": "X-Payment-Tx",
            "body_field": "payment_tx",
            "settlement": "Native Base USDC transfer verified on-chain before output is released.",
            "clearance_requirement": "Fulfillment requires an active Clearance-approved Bot-Comm microtransaction budget.",
        },
        "input_example": service["sample_input"],
        "input_schema": service.get("input_schema", {}),
        "output_schema": service.get("output_schema", {}),
        "terms": "Charge first. Spend second. Deliver third. No private keys, no unauthorized access, no wallet targeting, no spam, no fake volume.",
        "refund_policy": "Refunds require Clearance approval and are only considered for duplicate verified payments or non-delivery.",
        "abuse_policy": {"reject": BOT_COMM_FORBIDDEN_ACTIVITY},
        "estimated_delivery_seconds": service.get("estimated_delivery_seconds", 2),
    }


def _bot_comm_public_url() -> str:
    return f"{BASE_URL.rstrip('/')}/bot-comm/market"


def _bot_comm_discovery_links() -> dict:
    base = BASE_URL.rstrip("/")
    return {
        "website": _bot_comm_public_url(),
        "operatorDashboard": f"{base}/bot-comm",
        "manifest": f"{base}/bot-comm/agents.json",
        "services": f"{base}/bot-comm/api/services",
        "x402": f"{base}/.well-known/x402.json",
        "agentCard": f"{base}/.well-known/agent-card.json",
        "agentJson": f"{base}/.well-known/agent.json",
        "discovery": f"{base}/x402/discovery",
        "openapi": f"{base}/bot-comm/openapi.json",
        "llms": f"{base}/llms.txt",
        "llmsFull": f"{base}/llms-full.txt",
    }


def _bot_comm_master_service_card() -> dict:
    return {
        "seller": "Nauti-Labs Bot-Comm",
        "seller_type": "bot_to_bot_commerce_infrastructure",
        "project": "bot-comm",
        "version": "1.0",
        "positioning": "Communication infrastructure for autonomous agent commerce",
        "business_model": "charge_first_spend_second_deliver_third",
        "human_role": "Nauti-Labs owner approves or denies Clearance only",
        "target_customers": [
            "buyer_bots",
            "seller_bots",
            "marketplace_bots",
            "procurement_agents",
            "payment_capable_agents",
            "agent_directories",
            "MCP_tool_agents",
            "API_buying_agents",
        ],
        "services": [
            {
                "service_id": service["id"],
                "name": service["title"],
                "endpoint": f"POST /bot-comm/{service.get('path') or service['id'].replace('_', '-')}",
                "starting_price_usd": money(service["price_usdc"]),
                "description": service["summary"],
                "input_schema": service.get("input_schema", {}),
                "output_schema": service.get("output_schema", {}),
            }
            for service in _bot_comm_allowed_services()
        ],
        "subscription_packages": BOT_COMM_SUBSCRIPTION_PACKAGES,
        "payment_terms": {
            "payment_required_before_work": True,
            "clearance_required": True,
            "accepted_methods": ["x402", "USDC", "approved_machine_payment", "marketplace_payment"],
            "refunds": "require Clearance approval",
        },
        "safety_terms": {
            "no_wallet_targeting": True,
            "no_private_keys": True,
            "no_seed_phrases": True,
            "no_exploitation": True,
            "no_spam": True,
            "no_fake_volume": True,
            "commercial_channels_only": True,
        },
    }


def _bot_comm_x402_document() -> dict:
    services = [_bot_comm_service_manifest(service) for service in _bot_comm_allowed_services()]
    return {
        "x402Version": 1,
        "name": "BOT-COMM / BASE-AGENT",
        "description": "Paid bot-to-bot commerce services settled in native USDC on Base.",
        "provider": {
            "name": "Nauti-Labs",
            "url": BRAND_URL,
            "contact": BOT_COMM_CONTACT_EMAIL,
        },
        "baseUrl": BASE_URL.rstrip("/"),
        "humanReadableUrl": _bot_comm_public_url(),
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "chain": PAYMENT_CHAIN,
        "asset": USDC_CONTRACT,
        "currency": "USDC",
        "payTo": _bot_comm_public_recipient(),
        "settlement": {
            "type": "direct_base_usdc_transfer",
            "retryHeaders": ["X-Payment-Tx"],
            "bodyFields": ["payment_tx"],
            "verification": "Bot-Comm verifies the Base USDC transaction on-chain before releasing output.",
        },
        "discovery": _bot_comm_discovery_links(),
        "services": services,
        "subscription_packages": BOT_COMM_SUBSCRIPTION_PACKAGES,
        "master_service_card": _bot_comm_master_service_card(),
        "categories": ["ai", "compute", "data", "finance", "agent-commerce"],
        "tags": ["x402", "base", "usdc", "paid-api", "agent-commerce", "bot-to-bot"],
    }


def _bot_comm_agent_card() -> dict:
    services = [_bot_comm_service_manifest(service) for service in _bot_comm_allowed_services()]
    return {
        "name": "BOT-COMM / BASE-AGENT",
        "description": "Machine-payable JSON services for funded agents. Endpoints quote over HTTP 402 and settle in USDC on Base.",
        "url": _bot_comm_public_url(),
        "version": "1.0.0",
        "provider": {"name": "Nauti-Labs", "url": BRAND_URL},
        "contact": BOT_COMM_CONTACT_EMAIL,
        "protocols": {
            "x402": {
                "discovery": f"{BASE_URL.rstrip('/')}/.well-known/x402.json",
                "network": f"eip155:{PAYMENT_CHAIN_ID}",
                "asset": USDC_CONTRACT,
                "currency": "USDC",
                "payTo": _bot_comm_public_recipient(),
            }
        },
        "capabilities": [
            {
                "id": service["id"],
                "name": service["name"],
                "description": service["description"],
                "endpoint": service["endpoint"],
                "price": service["price"],
            }
            for service in services
        ],
        "skills": [
            "merchant-intelligence",
            "compute-packaging",
            "liquidity-readiness",
            "commerce-logistics",
            "escrow-scoping",
        ],
    }


def _bot_comm_openapi_document() -> dict:
    service_paths = {}
    for service in [_bot_comm_service_manifest(item) for item in _bot_comm_allowed_services()]:
        path = f"/bot-comm/api/services/{service['id']}"
        service_paths[path] = {
            "get": {
                "summary": f"Get payment metadata for {service['name']}",
                "responses": {"200": {"description": "Service metadata"}},
            },
            "post": {
                "summary": f"Run {service['name']} after Base USDC payment",
                "requestBody": {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "input": {"type": "object"},
                                    "payment_tx": {"type": "string"},
                                    "payer_agent": {"type": "string"},
                                    "request_id": {"type": "string"},
                                },
                            },
                            "example": {"input": service["input_example"]},
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Paid JSON output"},
                    "402": {"description": "Payment required. Inspect PAYMENT-REQUIRED and X-Payment-* headers."},
                },
            },
        }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Bot-Comm Paid Services",
            "version": "1.0.0",
            "description": "Paid HTTP 402 services settled in USDC on Base.",
        },
        "servers": [{"url": BASE_URL.rstrip("/")}],
        "paths": {
            "/bot-comm/api/services": {
                "get": {
                    "summary": "List Bot-Comm paid services",
                    "responses": {"200": {"description": "Service catalog"}},
                }
            },
            **service_paths,
        },
    }


def _bot_comm_llms_text(full: bool = False) -> str:
    lines = [
        "# Bot-Comm",
        "",
        "Bot-Comm sells small paid JSON services to autonomous agents.",
        f"Public buyer page: {_bot_comm_public_url()}",
        f"Service catalog: {BASE_URL.rstrip('/')}/bot-comm/api/services",
        f"x402 discovery: {BASE_URL.rstrip('/')}/.well-known/x402.json",
        f"Agent card: {BASE_URL.rstrip('/')}/.well-known/agent-card.json",
        "",
        "Payment flow:",
        "1. POST to a service endpoint.",
        "2. If unpaid, the endpoint returns HTTP 402 with PAYMENT-REQUIRED and X-Payment-* headers.",
        "3. Send exact USDC on Base to the receiver wallet.",
        "4. Retry the same endpoint with X-Payment-Tx set to the Base transaction hash, or body.payment_tx.",
        "5. Bot-Comm verifies the transfer on-chain before returning output.",
        "",
        "Services:",
    ]
    for service in [_bot_comm_service_manifest(item) for item in _bot_comm_allowed_services()]:
        lines.extend([
            f"- {service['name']} ({service['id']}): {service['description']}",
            f"  Endpoint: {service['endpoint']}",
            f"  Price: {service['price']['amount']:.2f} USDC on Base",
        ])
        if full:
            lines.append(f"  Example input: {json.dumps(service['input_example'], separators=(',', ':'))}")
    lines.extend([
        "",
        f"Receiver: {_bot_comm_public_recipient()}",
        f"Contact: {BOT_COMM_CONTACT_EMAIL}",
    ])
    return "\n".join(lines) + "\n"


async def _bot_comm_get_state_value(key: str, default=None):
    db = await get_db()
    try:
        row = await (await db.execute("SELECT value FROM bot_comm_state WHERE key = ?", (key,))).fetchone()
        if not row:
            return default
        return _load_json(row["value"], default)
    finally:
        await db.close()


async def _bot_comm_set_state_value(key: str, value) -> None:
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO bot_comm_state (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (key, json.dumps(value), now_iso()),
        )
        await db.commit()
    finally:
        await db.close()


async def _bot_comm_operations_status() -> dict:
    status = await _bot_comm_get_state_value("operations", None)
    if status:
        return status
    default_active = BOT_COMM_OPERATIONS_DEFAULT not in {"halted", "stop", "stopped", "off", "false", "0"}
    return {
        "active": default_active,
        "status": "active" if default_active else "halted",
        "reason": "default",
        "updated_at": None,
        "updated_by": "system",
    }


async def _bot_comm_halt_operations(reason: str = "HALT ALL OPERATIONS pressed", actor: str = "operator") -> dict:
    payload = {"active": False, "status": "halted", "reason": reason[:300], "updated_at": now_iso(), "updated_by": actor}
    await _bot_comm_set_state_value("operations", payload)
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            ("bot_comm.operations.halted", actor, json.dumps(payload), now_iso()),
        )
        await db.commit()
    finally:
        await db.close()
    return payload


async def _bot_comm_resume_operations(reason: str = "operator resumed controlled operations", actor: str = "operator") -> dict:
    payload = {"active": True, "status": "active", "reason": reason[:300], "updated_at": now_iso(), "updated_by": actor}
    await _bot_comm_set_state_value("operations", payload)
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            ("bot_comm.operations.resumed", actor, json.dumps(payload), now_iso()),
        )
        await db.commit()
    finally:
        await db.close()
    return payload


def _bot_comm_micro_policy_metadata() -> dict:
    return {
        "project": "bot-comm",
        "transaction_type": "microtransaction_budget",
        "policy_type": "microtransaction_budget",
        "services": sorted(BOT_COMM_ALLOWED_SERVICE_IDS),
        "service_ids": sorted(BOT_COMM_ALLOWED_SERVICE_IDS),
        "price_per_call_usd": 0.02,
        "price_range_usd": "0.02-0.02",
        "max_daily_calls": 10000,
        "max_monthly_calls": 300000,
        "max_daily_gross_usd": 200,
        "max_monthly_gross_usd": 6000,
        "owner_spend_limit_usd": 0,
        "owner_charge_usd": 0,
        "budget_amount_usd": 200,
        "budget_meaning": "Inbound paid-call processing ceiling only. This is not permission to spend owner funds.",
        "max_daily_external_cost_usd": 20,
        "max_model_cost_per_call_usd": 0.001,
        "max_compute_cost_per_call_usd": 0.002,
        "min_net_profit_per_call_usd": 0.015,
        "auto_deliver_if_paid": True,
        "quote_if_unpaid": True,
        "block_if_unsafe": True,
        "human_role": "approve_or_deny_clearance_only",
        "allowed_customer_type": "buyer_bot | seller_bot | marketplace_bot | procurement_agent | payment_capable_software_agent",
        "forbidden_activity": BOT_COMM_FORBIDDEN_ACTIVITY,
        "path_to_20000_month": "Plan F: recurring micro/risk/relay calls plus subscriptions and dispute packets.",
        "anti_abuse_controls": [
            "HALT ALL OPERATIONS switch",
            "risk keyword rejection",
            "duplicate transaction rejection",
            "Clearance-approved policy gate",
            "no outbound relay to unapproved channels",
        ],
        "delivery_plan": "Use deterministic routing, classification, quote packet, receipt, and risk-check logic before any paid external spend.",
        "customer_visible_terms": "Charge first. Spend second. Deliver third. No private keys, seed phrases, spam, fake volume, exploitation, or wallet targeting.",
    }


def _bot_comm_is_no_owner_spend_policy(item: dict, metadata: dict) -> bool:
    if metadata.get("project") != "bot-comm" or metadata.get("policy_type") != "microtransaction_budget":
        return False
    if float(metadata.get("owner_spend_limit_usd") or 0) != 0:
        return False
    if float(metadata.get("owner_charge_usd") or 0) != 0:
        return False
    services = set(metadata.get("services") or metadata.get("service_ids") or [])
    if services and not BOT_COMM_ALLOWED_SERVICE_IDS.issubset(services):
        return False
    scope = str(item.get("scope") or "")
    return (
        scope.startswith("bot-comm:inbound-paid-calls:no-owner-spend:")
        or "BOT-COMM microservice" in scope
        or "BOT-COMM microtransaction" in str(item.get("title") or "")
    )


def _bot_comm_clearance_expired(item: dict) -> bool:
    expires_at = item.get("expires_at")
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(str(expires_at)) <= datetime.now(timezone.utc)
    except Exception:
        return False


async def _bot_comm_active_policy() -> dict | None:
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT * FROM clearances
                   WHERE status = 'approved'
                   ORDER BY created_at DESC
                   LIMIT 50"""
            )
        ).fetchall()
    finally:
        await db.close()
    for row in rows:
        item = dict(row)
        if _bot_comm_clearance_expired(item):
            continue
        metadata = _load_json(item.get("metadata"), {}) or {}
        if _bot_comm_is_no_owner_spend_policy(item, metadata):
            return {"id": item["id"], "status": item["status"], "expires_at": item["expires_at"], "scope": item.get("scope"), "metadata": metadata}
    return None


async def _bot_comm_latest_policy_request() -> dict | None:
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT * FROM clearances
                   WHERE status IN ('pending', 'approved')
                   ORDER BY created_at DESC
                   LIMIT 75"""
            )
        ).fetchall()
    finally:
        await db.close()
    for row in rows:
        item = dict(row)
        if _bot_comm_clearance_expired(item):
            continue
        metadata = _load_json(item.get("metadata"), {}) or {}
        if _bot_comm_is_no_owner_spend_policy(item, metadata):
            return {
                "id": item["id"],
                "status": item["status"],
                "approval_url": item.get("approval_url"),
                "expires_at": item.get("expires_at"),
                "scope": item.get("scope"),
                "metadata": metadata,
            }
    return None


async def _bot_comm_request_micro_policy() -> dict:
    existing = await _bot_comm_latest_policy_request()
    if existing and existing["status"] in {"pending", "approved"}:
        return {"created": False, "policy": existing}

    metadata = _bot_comm_micro_policy_metadata()
    body = {
        "title": "BOT-COMM microtransaction policy",
        "description": "Allow paid $0.02 BOT-COMM microservice calls after payment verification, within strict limits. No delivery before payment and Clearance.",
        "scope": "Allow paid $0.02 BOT-COMM microservice calls after payment verification, within strict limits.",
        "budget_amount": 200,
        "budget_currency": "USD",
        "metadata": metadata,
        "expires_in": 604800,
    }

    if CLEARANCE_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{BASE_URL.rstrip('/')}/v1/clearances",
                    headers={"X-API-Key": CLEARANCE_API_KEY},
                    json=body,
                )
                response.raise_for_status()
                payload = response.json()
                return {"created": True, "policy": {"id": payload.get("id"), "status": payload.get("status"), "approval_url": payload.get("approval_url"), "expires_at": payload.get("expires_at"), "metadata": metadata}}
        except Exception:
            pass

    db = await get_db()
    try:
        clearance = await _insert_agent_clearance(
            db,
            title=body["title"],
            description=body["description"],
            scope=body["scope"],
            budget_amount=body["budget_amount"],
            budget_currency=body["budget_currency"],
            expires_in_seconds=body["expires_in"],
            metadata=metadata,
        )
        await db.commit()
        return {"created": True, "policy": {"id": clearance["id"], "status": "pending", "approval_url": clearance["approval_url"], "expires_at": clearance["expires_at"], "metadata": metadata}}
    finally:
        await db.close()


def _bot_comm_risk_flags(payload: dict) -> list[str]:
    text = json.dumps(payload or {}, sort_keys=True, default=str).lower()
    checks = {
        "private_key_collection": ["private key", "privkey"],
        "seed_phrase_collection": ["seed phrase", "mnemonic", "recovery phrase"],
        "wallet_targeting": ["drain wallet", "sweep wallet", "wallet password", "wallet balance", "scan wallets", "scan wallet", "target funded wallet"],
        "phishing": ["login as", "steal", "credential", "credentials", "password", "phishing"],
        "exploit": ["exploit", "bypass auth", "unauthorized access", "shell", "denial of service", "ddos", "bypass payment"],
        "spam": ["mass dm", "bulk unsolicited", "spam", "spam relay"],
        "impersonation": ["impersonate", "pretend to be"],
        "self_dealing_loop": ["self-dealing", "self dealing", "circular transaction", "pay us back"],
        "fake_volume": ["fake transaction", "fake transactions", "artificial volume", "no-op request", "no op request"],
        "marketplace_manipulation": ["fake review", "rank manipulation", "ranking manipulation", "wash trade", "fake volume"],
    }
    flags = []
    for flag, needles in checks.items():
        if any(needle in text for needle in needles):
            flags.append(flag)
    if not text or text in {"{}", "[]"}:
        flags.append("no_real_task_context")
    return flags


def _bot_comm_economics(service: dict) -> dict:
    price = round(float(service["price_usdc"]), 6)
    payment_fee = round(float(BOT_COMM_PAYMENT_FEE_FLAT_USD), 6)
    compute_cost = 0.01 if service.get("service_type") == "batch" else (0.001 if price <= 0.10 else 0.002)
    model_cost = 0.0
    api_cost = 0.0
    refund_reserve = round(price * BOT_COMM_REFUND_RESERVE_RATE, 6)
    net = round(price - payment_fee - compute_cost - model_cost - api_cost - refund_reserve, 6)
    if price <= 0.10:
        min_net = max(0.015, round(price * 0.70, 6))
    else:
        min_net = round(price * 0.70, 6)
    return {
        "customer_price_usd": price,
        "payment_fee_usd": payment_fee,
        "model_cost_usd": model_cost,
        "compute_cost_usd": round(compute_cost, 6),
        "external_api_cost_usd": api_cost,
        "refund_reserve_usd": refund_reserve,
        "net_profit_usd": net,
        "expected_margin_percent": round((net / price) * 100, 2) if price else 0,
        "profitable": net >= min_net,
        "minimum_net_profit_usd": min_net,
    }


def _bot_comm_parse_price_range(value: str | None) -> tuple[float, float]:
    if not value or "-" not in value:
        return (0.0, float("inf"))
    low, high = value.split("-", 1)
    try:
        return (float(low), float(high))
    except ValueError:
        return (0.0, float("inf"))


async def _bot_comm_policy_allows_call(policy: dict, service: dict, economics: dict) -> tuple[bool, dict]:
    metadata = policy.get("metadata") or {}
    service_ids = set(metadata.get("services") or metadata.get("service_ids") or [])
    if service["id"] not in service_ids:
        return False, {
            "reason": "service_not_in_approved_microtransaction_budget",
            "service_id": service["id"],
            "approved_service_ids": sorted(service_ids),
        }

    min_price, max_price = _bot_comm_parse_price_range(str(metadata.get("price_range_usd") or ""))
    price = float(economics.get("customer_price_usd") or 0)
    price_per_call = metadata.get("price_per_call_usd")
    if price_per_call is not None and abs(price - float(price_per_call or 0)) > 0.000001:
        return False, {"reason": "price_does_not_match_approved_policy", "price_usd": price, "price_per_call_usd": price_per_call}
    if price < min_price or price > max_price:
        return False, {"reason": "price_outside_approved_range", "price_usd": price, "price_range_usd": metadata.get("price_range_usd")}

    max_model = float(metadata.get("max_model_cost_per_call_usd") or 0)
    max_compute = float(metadata.get("max_compute_cost_per_call_usd") or 0)
    if float(economics.get("model_cost_usd") or 0) > max_model:
        return False, {"reason": "model_cost_exceeds_policy", "economics": economics, "max_model_cost_per_call_usd": max_model}
    if float(economics.get("compute_cost_usd") or 0) > max_compute:
        return False, {"reason": "compute_cost_exceeds_policy", "economics": economics, "max_compute_cost_per_call_usd": max_compute}
    if float(economics.get("net_profit_usd") or 0) < float(metadata.get("min_net_profit_per_call_usd") or 0):
        return False, {"reason": "net_profit_below_policy_minimum", "economics": economics, "min_net_profit_per_call_usd": metadata.get("min_net_profit_per_call_usd")}

    now = datetime.now(timezone.utc)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    db = await get_db()
    try:
        daily = await (
            await db.execute(
                """SELECT COUNT(*) AS paid_calls,
                          COALESCE(SUM(price_usd), 0) AS gross_revenue,
                          COALESCE(SUM(external_api_cost_usd), 0) AS external_cost
                   FROM bot_comm_call_logs
                   WHERE timestamp >= ? AND UPPER(result_code) = 'DELIVERED'""",
                (day_start,),
            )
        ).fetchone()
        monthly = await (
            await db.execute(
                """SELECT COUNT(*) AS paid_calls,
                          COALESCE(SUM(price_usd), 0) AS gross_revenue
                   FROM bot_comm_call_logs
                   WHERE timestamp >= ? AND UPPER(result_code) = 'DELIVERED'""",
                (month_start,),
            )
        ).fetchone()
    finally:
        await db.close()

    projected_daily_calls = int(daily["paid_calls"] or 0) + 1
    projected_monthly_calls = int(monthly["paid_calls"] or 0) + 1
    projected_daily_gross = float(daily["gross_revenue"] or 0) + price
    projected_monthly_gross = float(monthly["gross_revenue"] or 0) + price
    projected_daily_external = float(daily["external_cost"] or 0) + float(economics.get("external_api_cost_usd") or 0)
    if projected_daily_calls > int(metadata.get("max_daily_calls") or 0):
        return False, {"reason": "max_daily_calls_exceeded", "projected_daily_calls": projected_daily_calls}
    if projected_monthly_calls > int(metadata.get("max_monthly_calls") or 0):
        return False, {"reason": "max_monthly_calls_exceeded", "projected_monthly_calls": projected_monthly_calls}
    if projected_daily_gross > float(metadata.get("max_daily_gross_usd") or 0):
        return False, {"reason": "max_daily_gross_exceeded", "projected_daily_gross_usd": round(projected_daily_gross, 6)}
    if projected_monthly_gross > float(metadata.get("max_monthly_gross_usd") or 0):
        return False, {"reason": "max_monthly_gross_exceeded", "projected_monthly_gross_usd": round(projected_monthly_gross, 6)}
    if projected_daily_external > float(metadata.get("max_daily_external_cost_usd") or 0):
        return False, {"reason": "max_daily_external_cost_exceeded", "projected_daily_external_cost_usd": round(projected_daily_external, 6)}

    return True, {
        "reason": "inside_approved_microtransaction_budget",
        "projected_daily_calls": projected_daily_calls,
        "projected_monthly_calls": projected_monthly_calls,
        "projected_daily_gross_usd": round(projected_daily_gross, 6),
        "projected_monthly_gross_usd": round(projected_monthly_gross, 6),
    }


def _bot_comm_buyer_id(body: AgentIncomeBotServiceRequest, payload: dict, verification: dict | None = None) -> str:
    return (
        body.payer_agent
        or str(payload.get("buyer_bot_id") or payload.get("buyer_bot") or payload.get("sender_bot") or "")
        or (verification or {}).get("from_address")
        or "unknown-buyer-bot"
    )[:160]


async def _bot_comm_request_body_json(request: Request) -> dict:
    try:
        raw = await request.json()
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _bot_comm_request_field(body: AgentIncomeBotServiceRequest, raw_body: dict, key: str) -> str:
    value = getattr(body, key, None) or raw_body.get(key)
    return str(value or "").strip()


def _bot_comm_service_payload(body: AgentIncomeBotServiceRequest, raw_body: dict) -> dict:
    if isinstance(body.input, dict) and body.input:
        return dict(body.input)
    if isinstance(raw_body.get("input"), dict) and raw_body["input"]:
        return dict(raw_body["input"])
    envelope_keys = {"input", "payment_tx", "payer_agent", "request_id", "clearance_token"}
    return {key: value for key, value in raw_body.items() if key not in envelope_keys}


async def _bot_comm_repeat_buyer(buyer_bot_id: str) -> bool:
    if not buyer_bot_id or buyer_bot_id == "unknown-buyer-bot":
        return False
    db = await get_db()
    try:
        row = await (
            await db.execute(
                "SELECT COUNT(*) AS count FROM bot_comm_call_logs WHERE buyer_bot_id = ? AND UPPER(result_code) = 'DELIVERED'",
                (buyer_bot_id,),
            )
        ).fetchone()
        return bool(row and int(row["count"] or 0) > 0)
    finally:
        await db.close()


async def _bot_comm_log_call(
    *,
    service_id: str | None,
    buyer_bot_id: str,
    buyer_bot_source: str,
    authorization_basis: str,
    economics: dict,
    latency_ms: int,
    clearance_policy_id: str | None,
    result_code: str,
    risk_flags: list[str],
    repeat_buyer: bool,
    provider_ref: str | None,
    metadata: dict,
) -> dict:
    log_id = generate_id("bcl")
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO bot_comm_call_logs
               (id, timestamp, project, service_id, buyer_bot_id, buyer_bot_source,
                authorization_basis, price_usd, payment_fee_usd, model_cost_usd,
                compute_cost_usd, external_api_cost_usd, net_profit_usd, latency_ms,
                clearance_policy_id, result_code, risk_flags, repeat_buyer, provider_ref, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log_id,
                now_iso(),
                "bot-comm",
                service_id,
                buyer_bot_id,
                buyer_bot_source,
                authorization_basis,
                economics.get("customer_price_usd", 0),
                economics.get("payment_fee_usd", 0),
                economics.get("model_cost_usd", 0),
                economics.get("compute_cost_usd", 0),
                economics.get("external_api_cost_usd", 0),
                economics.get("net_profit_usd", 0),
                latency_ms,
                clearance_policy_id,
                result_code,
                json.dumps(risk_flags),
                1 if repeat_buyer else 0,
                provider_ref,
                json.dumps(metadata),
            ),
        )
        await db.commit()
    finally:
        await db.close()
    return {"id": log_id}


def _bot_comm_request_summary(payload: dict) -> str:
    text = json.dumps(payload or {}, sort_keys=True, default=str)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:700]


def _bot_comm_normalize_status(status: str | None, risk_flags: list[str] | None = None) -> str:
    value = str(status or "").upper()
    aliases = {
        "PAYMENT_REQUIRED": "QUOTED",
        "PAYMENT_UNVERIFIED": "PAYMENT_PENDING",
        "GATED_INBOUND_DEMAND": "QUOTED",
        "PAYMENT_QUOTE_SENT": "QUOTED",
        "REJECTED": "REJECTED",
        "BLOCKED": "BLOCKED",
        "DELIVERED": "DELIVERED",
        "PENDING": "PENDING_CLEARANCE",
    }
    if value in BOT_COMM_STATUSES:
        return value
    if value in aliases:
        return aliases[value]
    risk_set = set(risk_flags or [])
    if risk_set & (set(BOT_COMM_FORBIDDEN_ACTIVITY) | {"operations_halted", "unknown_service"}):
        return "BLOCKED"
    if "clearance_policy_missing" in risk_set or "payment_required" in risk_set:
        return "QUOTED"
    return "RECEIVED"


def _bot_comm_payment_state(status: str) -> str:
    return {
        "QUOTED": "unpaid",
        "PAYMENT_PENDING": "invalid_or_pending",
        "PAID_VERIFIED": "verified",
        "PENDING_CLEARANCE": "verified",
        "CLEARED": "verified",
        "DELIVERED": "verified",
        "REFUND_PENDING": "verified",
    }.get(status, "none")


async def _bot_comm_upsert_attempt(attempt: dict) -> dict:
    current = await _bot_comm_get_state_value("attempt_book", {"items": []})
    items = current.get("items", []) if isinstance(current, dict) else []
    by_id = {
        str(item.get("attempt_id")): item
        for item in items
        if isinstance(item, dict) and item.get("attempt_id")
    }
    prior = by_id.get(attempt["attempt_id"], {})
    now_value = now_iso()
    merged = {
        **prior,
        **attempt,
        "first_seen_at": prior.get("first_seen_at") or attempt.get("timestamp") or now_value,
        "updated_at": now_value,
    }
    by_id[attempt["attempt_id"]] = merged
    retained = sorted(by_id.values(), key=lambda item: item.get("updated_at") or "", reverse=True)[:200]
    await _bot_comm_set_state_value("attempt_book", {"updated_at": now_value, "items": retained})
    return merged


def _bot_comm_quote_payload(service: dict, quote_id: str, request: Request | None = None) -> dict:
    manifest = _bot_comm_service_manifest(service)
    payment_uri = _bot_comm_payment_uri(service["price_usdc"])
    payload = {
        "status": "payment_required",
        "http_status": 402,
        "quote_id": quote_id,
        "seller": "Nauti-Labs Bot-Comm",
        "project": "bot-comm",
        "service_id": service["id"],
        "service_name": service["title"],
        "price_usd": money(service["price_usdc"]),
        "payment_required_before_work": True,
        "clearance_required": True,
        "accepted_payment_methods": ["x402", "USDC", "approved_machine_payment", "marketplace_payment"],
        "input_schema": manifest["input_schema"],
        "output_schema": manifest["output_schema"],
        "terms": {
            "charge_first": True,
            "spend_second": True,
            "deliver_third": True,
            "no_private_keys": True,
            "no_seed_phrases": True,
            "no_wallet_targeting": True,
            "no_fake_volume": True,
            "no_abuse": True,
        },
        "next_action": "Submit valid payment proof or payment authorization, then retry this request with the quote_id.",
    }
    if request is not None:
        payload["endpoint"] = f"{BASE_URL.rstrip('/')}{request.url.path}"
    if payment_uri:
        payload["payment_uri"] = payment_uri
    return payload


async def _bot_comm_persist_quote(
    *,
    quote_id: str,
    attempt_id: str,
    service: dict,
    quote_payload: dict,
    buyer_bot_id: str,
    buyer_bot_source: str,
    request_summary: str,
) -> dict:
    current = await _bot_comm_get_state_value("quote_book", {"quotes": []})
    quotes = current.get("quotes", []) if isinstance(current, dict) else []
    by_id = {
        str(item.get("quote_id")): item
        for item in quotes
        if isinstance(item, dict) and item.get("quote_id")
    }
    record = {
        "quote_id": quote_id,
        "attempt_id": attempt_id,
        "timestamp": now_iso(),
        "buyer_bot_id": buyer_bot_id,
        "buyer_bot_source": buyer_bot_source,
        "service_id": service["id"],
        "price_usd": money(service["price_usdc"]),
        "status": "QUOTED",
        "request_summary": request_summary,
        "quote": quote_payload,
    }
    by_id[quote_id] = record
    retained = sorted(by_id.values(), key=lambda item: item.get("timestamp") or "", reverse=True)[:200]
    await _bot_comm_set_state_value("quote_book", {"updated_at": now_iso(), "quotes": retained})
    return record


def _bot_comm_tokenize(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if len(token) > 2}


def _bot_comm_known_match_cards(task: str, required_capability: str = "") -> list[dict]:
    query_tokens = _bot_comm_tokenize(f"{task} {required_capability}")
    cards = []
    for service in _bot_comm_allowed_services():
        haystack = f"{service['title']} {service['summary']} {service.get('role', '')} {service.get('service_type', '')}"
        score_tokens = query_tokens & _bot_comm_tokenize(haystack)
        score = min(1.0, 0.35 + (len(score_tokens) * 0.12)) if score_tokens else 0.22
        cards.append({
            "service_id": service["id"],
            "name": service["title"],
            "endpoint": _bot_comm_service_manifest(service)["endpoint"],
            "price_usd": money(service["price_usdc"]),
            "confidence": round(score, 2),
            "payment_method": "x402-compatible Base USDC",
            "source": "bot_comm_catalog",
        })
    return sorted(cards, key=lambda item: item["confidence"], reverse=True)[:8]


def _bot_comm_offer_template(service: dict, buyer_need: str = "") -> dict:
    manifest = _bot_comm_service_manifest(service)
    return {
        "message_type": "service_offer",
        "seller": "Nauti-Labs Bot-Comm",
        "reason_for_contact": f"Matched your machine-readable buying intent: {buyer_need or service['summary']}",
        "service_id": service["id"],
        "service_name": service["title"],
        "price_usd": f"{float(service['price_usdc']):.2f}",
        "payment_required_before_work": True,
        "clearance_required_before_transaction": True,
        "estimated_delivery_seconds": service.get("estimated_delivery_seconds", 2),
        "input_schema": manifest["input_schema"],
        "output_schema": manifest["output_schema"],
        "terms": manifest["terms"],
        "next_action": "Submit input and payment authorization to begin Clearance review.",
    }


def _bot_comm_fulfill_service(service: dict, payload: dict, verification: dict, economics: dict, policy: dict) -> dict:
    service_id = service["id"]
    risk_flags = _bot_comm_risk_flags(payload)
    if service_id == "directory_lookup":
        task = str(payload.get("task") or payload.get("query") or "")
        required = str(payload.get("required_capability") or "")
        matches = _bot_comm_known_match_cards(task, required)
        return {"matches": matches, "confidence": matches[0]["confidence"] if matches else 0, "risk_flags": risk_flags}
    if service_id == "capability_match":
        buyer_need = str(payload.get("buyer_need") or "")
        seller_metadata = payload.get("seller_metadata") or {}
        seller_text = json.dumps(seller_metadata, sort_keys=True)
        overlap = _bot_comm_tokenize(buyer_need) & _bot_comm_tokenize(seller_text)
        score = min(1.0, 0.28 + len(overlap) * 0.14)
        missing = [] if score >= 0.7 else ["clear payment terms", "machine-readable output schema"]
        return {"compatible": score >= 0.55, "score": round(score, 2), "missing_capabilities": missing, "recommended_next_action": "request_quote" if score >= 0.55 else "ask seller for structured capability card", "risk_flags": risk_flags}
    if service_id == "anchor_compliance_route":
        buyer_need = str(payload.get("buyer_need") or payload.get("task") or payload.get("message") or "")
        profile = payload.get("custodian_profile") if isinstance(payload.get("custodian_profile"), dict) else {}
        text = json.dumps(payload, sort_keys=True, default=str).lower()
        fit_terms = ("custodian", "custody", "wallet", "compliance", "aml", "kyc", "transaction", "approval", "evidence", "digital asset")
        fit_score = min(0.96, 0.48 + sum(1 for term in fit_terms if term in text) * 0.07)
        return {
            "recommended_offer": {
                "name": "Anchor Compliance Custodian Readiness Pack",
                "price_usd": 499,
                "endpoint": f"{BASE_URL.rstrip('/')}/agent-income/anchor-compliance",
                "payment_required_before_work": True,
            },
            "qualification": {
                "fit_score": round(fit_score, 2),
                "custody_model": profile.get("model") or payload.get("custody_model") or "unknown",
                "buyer_need": buyer_need[:500],
                "target_buyer": "crypto custodian, wallet infrastructure, exchange custody, or digital asset operations team",
            },
            "approval_boundaries": [
                "No legal or regulatory opinion.",
                "No custody, private key, seed phrase, or wallet credential handling.",
                "No transaction monitoring or sanctions-screening service.",
                "Human approval required before money-moving or externally binding actions.",
            ],
            "next_action": "Send the paid Anchor Compliance endpoint and collect payment before producing the readiness pack.",
            "risk_flags": risk_flags,
        }
    if service_id == "quote_relay":
        targets = payload.get("seller_targets") or []
        quote_ids = [generate_id("quote") for _ in targets[: int(payload.get("max_relay_count") or len(targets) or 1)]]
        receipts = [{"target": target, "status": "packet_prepared", "delivery_channel": "buyer_supplied_or_approved_commercial_api_required"} for target in targets[: len(quote_ids)]]
        return {"relay_status": "prepared_for_approved_commercial_channels", "quote_ids": quote_ids, "delivery_receipts": receipts, "risk_flags": risk_flags}
    if service_id == "offer_format":
        raw = str(payload.get("raw_offer") or "")
        card = {
            "seller": (payload.get("service_metadata") or {}).get("provider", "unknown-seller-bot"),
            "message_type": "service_offer",
            "description": raw[:500],
            "payment_required_before_work": True,
            "accepted_methods": ["x402", "USDC", "approved_machine_payment"],
            "terms": "Charge first. Spend second. Deliver third.",
        }
        return {"valid_offer_card": card, "schema_valid": True, "warnings": risk_flags}
    if service_id == "handshake":
        return {
            "handshake_status": "structured_terms_ready",
            "accepted_protocol": "x402-compatible Base USDC",
            "payment_terms": {"charge_first": True, "currency": "USDC", "network": "Base"},
            "delivery_terms": {"machine_readable_json": True, "estimated_delivery_seconds": service.get("estimated_delivery_seconds", 2)},
            "risk_flags": risk_flags,
        }
    if service_id == "intent_classify":
        text = json.dumps(payload.get("message") or payload, sort_keys=True).lower()
        intent = "quote_request" if "quote" in text else "receipt" if "receipt" in text or "tx" in text else "refund_request" if "refund" in text else "dispute" if "dispute" in text else "sell_offer" if "offer" in text else "buy_request" if "buy" in text or "need" in text else "spam" if "spam" in risk_flags else "unknown"
        return {"intent": intent, "confidence": 0.82 if intent != "unknown" else 0.42, "recommended_next_action": "block" if risk_flags else "route_to_next_bot_comm_step", "risk_flags": risk_flags}
    if service_id == "message_risk":
        score = min(100, len(risk_flags) * 25)
        recommendation = "block" if score >= 50 else "review" if score else "allow"
        return {"risk_score": score, "recommendation": recommendation, "risk_flags": risk_flags, "reason_code": risk_flags[0] if risk_flags else "no_material_risk_detected"}
    if service_id == "receipt_relay":
        receipt_id = generate_id("receipt")
        return {"normalized_receipt": {"receipt_id": receipt_id, "receipt": payload.get("receipt") or {}, "sender_bot": payload.get("sender_bot"), "recipient_bot": payload.get("recipient_bot"), "normalized_at": now_iso()}, "relay_status": "normalized_ready_for_approved_delivery", "receipt_id": receipt_id, "risk_flags": risk_flags}
    if service_id == "dispute_packet":
        return {"scope": payload.get("scope"), "payment_proof": payload.get("payment_proof"), "delivery_proof": payload.get("delivery_proof") or {}, "missing_items": payload.get("missing_items") or [], "recommended_resolution": "review evidence, request missing delivery proof, then settle/refund only after Clearance approval", "risk_flags": risk_flags}
    return _bot_comm_output(service, payload, verification)


async def _bot_comm_usage_metrics() -> dict:
    db = await get_db()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        month = today[:7]
        rows = await (
            await db.execute(
                """SELECT * FROM bot_comm_call_logs
                   WHERE timestamp >= ?
                   ORDER BY timestamp DESC
                   LIMIT 1000""",
                (f"{month}-01",),
            )
        ).fetchall()
    finally:
        await db.close()
    paid = [dict(row) for row in rows if str(dict(row).get("result_code") or "").upper() == "DELIVERED"]
    today_paid = [row for row in paid if str(row.get("timestamp") or "").startswith(today)]
    monthly_gross = money(sum(float(row.get("price_usd") or 0) for row in paid))
    monthly_net = money(sum(float(row.get("net_profit_usd") or 0) for row in paid))
    daily_gross = money(sum(float(row.get("price_usd") or 0) for row in today_paid))
    service_revenue = {}
    service_calls = {}
    buyers = {}
    for row in paid:
        service_revenue[row.get("service_id")] = service_revenue.get(row.get("service_id"), 0) + float(row.get("price_usd") or 0)
        service_calls[row.get("service_id")] = service_calls.get(row.get("service_id"), 0) + 1
        buyer = row.get("buyer_bot_id") or "unknown"
        buyers[buyer] = buyers.get(buyer, 0) + 1
    if monthly_gross >= 20000:
        status = "big_win"
    elif monthly_gross >= 5000:
        status = "infrastructure"
    elif monthly_gross >= 1000:
        status = "traction"
    elif monthly_gross >= 100:
        status = "early"
    else:
        status = "not_started"
    return {
        "daily": {
            "paid_calls": len(today_paid),
            "gross_revenue_usd": daily_gross,
            "net_revenue_usd": money(sum(float(row.get("net_profit_usd") or 0) for row in today_paid)),
            "cost_per_call_usd": money((sum(float(row.get("compute_cost_usd") or 0) + float(row.get("model_cost_usd") or 0) + float(row.get("external_api_cost_usd") or 0) for row in today_paid) / len(today_paid)) if today_paid else 0),
            "top_buyer_bots": sorted(buyers.items(), key=lambda item: item[1], reverse=True)[:5],
            "repeat_buyer_bot_count": len([buyer for buyer, count in buyers.items() if count > 1]),
            "subscription_candidates": [buyer for buyer, count in buyers.items() if count >= 100][:10],
            "progress_to_daily_target_percent": round((daily_gross / max(BOT_COMM_DAILY_TARGET_USDC, 1)) * 100, 2),
        },
        "monthly": {
            "monthly_gross_target_usd": BOT_COMM_MONTHLY_TARGET_USD,
            "monthly_gross_actual_usd": monthly_gross,
            "monthly_net_actual_usd": monthly_net,
            "paid_calls_month": len(paid),
            "subscriptions_active": 0,
            "average_revenue_per_buyer_bot": money(monthly_gross / len(buyers)) if buyers else 0,
            "top_services_by_revenue": sorted(service_revenue.items(), key=lambda item: item[1], reverse=True)[:5],
            "top_services_by_call_volume": sorted(service_calls.items(), key=lambda item: item[1], reverse=True)[:5],
            "margin_percent": round((monthly_net / monthly_gross) * 100, 2) if monthly_gross else 0,
            "big_win_status": status,
        },
    }


async def _bot_comm_fetch_json(client: httpx.AsyncClient, url: str) -> dict:
    response = await client.get(url, timeout=20, follow_redirects=True)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {"items": payload if isinstance(payload, list) else []}


async def _bot_comm_public_endpoint_checks(client: httpx.AsyncClient) -> list[dict]:
    base = BASE_URL.rstrip("/")
    checks = [
        ("health", f"{base}/bot-comm/health"),
        ("market", f"{base}/bot-comm/market"),
        ("services", f"{base}/bot-comm/api/services"),
        ("x402", f"{base}/.well-known/x402.json"),
        ("agent_card", f"{base}/bot-comm/agents.json"),
        ("openapi", f"{base}/bot-comm/openapi.json"),
    ]
    results = []
    for name, url in checks:
        started = datetime.now(timezone.utc)
        try:
            response = await client.get(url, timeout=15, follow_redirects=True)
            elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            results.append({
                "name": name,
                "url": url,
                "status": "healthy" if response.status_code < 400 else f"http_{response.status_code}",
                "http_status": response.status_code,
                "latency_ms": elapsed,
            })
        except Exception as exc:
            results.append({"name": name, "url": url, "status": "check_failed", "error": str(exc)[:220]})
    return results


def _bot_comm_registry_discovery_sources(queries: list[str]) -> list[tuple[str, str, str]]:
    sources = [
        ("x402.direct", "top_paid_endpoints", "https://x402.direct/api/services?limit=80&sort=score"),
        ("x402-list", "live_x402_services", "https://x402-list.com/api/v1/services"),
        ("Glama MCP directory", "remote_capable_mcp_servers", "https://glama.ai/api/mcp/v1/servers?limit=80"),
    ]
    for category in ("data-enrichment", "financial-analysis", "research", "summarization", "web-scraping", "other"):
        sources.append((
            "Agora402",
            f"category:{category}",
            f"https://agora402.io/api/v1/discover?category={quote(category)}&chain=base",
        ))
    for query in queries[:12]:
        sources.append((
            "402 Index",
            query,
            f"https://402index.io/api/v1/services?q={quote(query)}&protocol=x402&limit=25",
        ))
    return sources


async def _bot_comm_next_opportunity_queries() -> list[str]:
    queries = BOT_COMM_OPPORTUNITY_QUERIES or BOT_COMM_DEFAULT_OPPORTUNITY_QUERIES
    if len(queries) <= BOT_COMM_OPPORTUNITY_QUERY_BATCH_SIZE:
        return queries
    cursor = await _bot_comm_get_state_value("opportunity_query_cursor", 0)
    try:
        cursor = int(cursor or 0)
    except (TypeError, ValueError):
        cursor = 0
    selected = [queries[(cursor + offset) % len(queries)] for offset in range(BOT_COMM_OPPORTUNITY_QUERY_BATCH_SIZE)]
    await _bot_comm_set_state_value("opportunity_query_cursor", (cursor + BOT_COMM_OPPORTUNITY_QUERY_BATCH_SIZE) % len(queries))
    return selected


def _bot_comm_job_text(item: dict) -> str:
    def clean_nested(value, depth: int = 0) -> str:
        if value is None or depth > 2:
            return ""
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        if isinstance(value, list):
            return " ".join(clean_nested(entry, depth + 1) for entry in value[:8])
        if isinstance(value, dict):
            return " ".join(clean_nested(value.get(key), depth + 1) for key in sorted(value.keys())[:12])
        return ""

    fields = [
        item.get("title"),
        item.get("name"),
        item.get("description"),
        item.get("summary"),
        item.get("task"),
        item.get("request"),
        item.get("resourceUrl"),
        item.get("resource_url"),
        item.get("base_url"),
        item.get("website_url"),
        item.get("category"),
        item.get("provider"),
        item.get("skills"),
        item.get("tags"),
        item.get("x402"),
        item.get("authentication"),
        item.get("use_cases"),
    ]
    return " ".join(clean_nested(field) for field in fields if field)[:2500]


def _bot_comm_candidate_budget_usd(item: dict) -> float | None:
    cent_keys = ("priceCents", "budgetCents", "maxBudgetCents", "rewardCents", "amountCents")
    for key in cent_keys:
        try:
            if item.get(key) is not None:
                return money(float(item.get(key) or 0) / 100)
        except (TypeError, ValueError):
            pass
    usd_keys = ("price_usd", "budget_usd", "budgetUsd", "max_budget_usd", "amount_usd", "reward_usd")
    for key in usd_keys:
        try:
            if item.get(key) is not None:
                return money(float(item.get(key) or 0))
        except (TypeError, ValueError):
            pass
    for key in ("priceUsd", "price_usdc", "min_price_usd", "amount_usdc"):
        value = item.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)):
            return money(float(value))
        match = re.search(r"\d+(?:\.\d+)?", str(value))
        if match:
            try:
                return money(float(match.group(0)))
            except ValueError:
                pass
    x402 = item.get("x402") if isinstance(item.get("x402"), dict) else {}
    if x402.get("amount_usdc") is not None:
        try:
            return money(float(x402.get("amount_usdc")))
        except (TypeError, ValueError):
            pass
    return None


def _bot_comm_source_url(item: dict) -> str | None:
    for key in ("url", "href", "link", "permalink", "endpoint", "api_endpoint"):
        value = item.get(key)
        if isinstance(value, str) and value.startswith(("https://", "http://")):
            return value[:500]
    return None


def _bot_comm_service_for_need(text: str) -> tuple[dict, float]:
    lowered = text.lower()
    direct = [
        ("anchor_compliance_route", ("crypto custodian", "digital asset custody", "custody compliance", "wallet operations", "wallet policy", "transaction policy", "approval evidence", "evidence log", "aml", "kyc", "anchor compliance")),
        ("message_risk", ("risk", "phishing", "private key", "seed", "safety", "spam", "prompt injection")),
        ("intent_classify", ("classify", "intent", "inbound message", "message type")),
        ("directory_lookup", ("directory", "discover", "lookup", "find seller", "find api", "find mcp")),
        ("capability_match", ("capability", "compatible", "match", "can satisfy")),
        ("offer_format", ("offer", "format", "service card", "normalize metadata")),
        ("intent_classify", ("quote", "rfq", "receipt", "delivery", "refund", "dispute", "handshake")),
    ]
    for service_id, terms in direct:
        if any(term in lowered for term in terms):
            return _bot_comm_service(service_id), 0.82

    query_tokens = _bot_comm_tokenize(text)
    best_service = _bot_comm_service("directory_lookup")
    best_score = 0.0
    for service in _bot_comm_allowed_services():
        haystack = f"{service['title']} {service['summary']} {service.get('role', '')} {service.get('service_type', '')}"
        overlap = query_tokens & _bot_comm_tokenize(haystack)
        score = min(0.78, 0.22 + len(overlap) * 0.11) if overlap else 0.18
        if score > best_score:
            best_service = service
            best_score = score
    return best_service, round(best_score, 2)


def _bot_comm_extract_candidate_items(payload: dict, limit: int | None = None) -> list[dict]:
    limit = limit or BOT_COMM_DISCOVERY_ITEM_LIMIT
    item_keys = {
        "openJobs",
        "jobs",
        "requests",
        "buyer_requests",
        "opportunities",
        "tasks",
        "bounties",
        "items",
        "work",
        "rfqs",
        "services",
        "agents",
        "data",
        "results",
        "listings",
        "endpoints",
    }
    identity_keys = ("id", "_id", "slug", "url", "href", "link", "resourceUrl", "endpoint", "base_url", "name", "title")
    items = []
    seen = set()

    def looks_like_item(value: dict) -> bool:
        return any(value.get(key) for key in identity_keys) and any(
            value.get(key) for key in ("description", "summary", "task", "request", "resourceUrl", "endpoint", "base_url", "skills")
        )

    def add_item(value: dict) -> None:
        if len(items) >= limit or not isinstance(value, dict):
            return
        source_id = str(next((value.get(key) for key in identity_keys if value.get(key)), ""))[:300]
        if not source_id:
            source_id = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:20]
        if source_id in seen:
            return
        seen.add(source_id)
        items.append(value)

    def walk(value, depth: int = 0) -> None:
        if len(items) >= limit or depth > 3:
            return
        if isinstance(value, list):
            for entry in value[:limit]:
                if isinstance(entry, dict):
                    add_item(entry)
                    walk(entry, depth + 1)
            return
        if not isinstance(value, dict):
            return
        if looks_like_item(value):
            add_item(value)
        for key, nested in value.items():
            if key in item_keys or (depth == 0 and isinstance(nested, (list, dict))):
                walk(nested, depth + 1)

    walk(payload)
    return items[:limit]


def _bot_comm_estimated_monthly_potential(candidate: dict, service: dict) -> float:
    budget = candidate.get("candidate_budget_usd")
    price = float(service.get("price_usdc") or candidate.get("price_usd") or 0)
    if isinstance(budget, (int, float)) and budget >= 1:
        return money(min(max(float(budget), price), 2500))
    if candidate.get("status") == "qualified_buyer_channel":
        return money(max(price * 2500, 75))
    if candidate.get("status") == "routing_source_indexed":
        return money(max(price * 1000, 25))
    service_type = service.get("service_type")
    if service_type == "micro":
        return money(max(price * 2500, 75))
    if service_type == "relay":
        return money(max(price * 1000, 150))
    if service_type == "standard":
        return money(max(price * 500, 250))
    if service_type == "batch":
        return money(max(price * 8, 299))
    return money(max(price * 250, 50))


def _bot_comm_qualify_buyer_candidate(source: str, query: str, item: dict) -> dict | None:
    text = _bot_comm_job_text(item)
    if not text:
        return None
    risk_flags = _bot_comm_risk_flags({"candidate": text})
    if risk_flags:
        return None

    lowered = text.lower()
    direct_buy_terms = (
        "need",
        "looking for",
        "seeking",
        "request for",
        "requesting",
        "quote",
        "rfq",
        "buy",
        "budget",
        "procure",
        "buyer",
        "wanted",
    )
    buyer_channel_terms = (
        "available tasks",
        "tasks available",
        "open request",
        "open requests",
        "buyer requests",
        "request feed",
        "job marketplace",
        "jobs marketplace",
        "task marketplace",
        "bounty marketplace",
        "bounties available",
        "work available",
    )
    agent_terms = (
        "bot",
        "agent",
        "api",
        "mcp",
        "x402",
        "usdc",
        "endpoint",
        "service",
        "marketplace",
        "procurement",
        "custodian",
        "custody",
        "compliance",
        "aml",
        "kyc",
        "wallet policy",
        "transaction policy",
        "digital asset",
        "anchor compliance",
    )
    has_buyer_channel = any(term in lowered for term in buyer_channel_terms)
    has_buy_intent = any(term in lowered for term in direct_buy_terms) or has_buyer_channel
    has_agent_context = any(term in lowered for term in agent_terms)
    service, service_score = _bot_comm_service_for_need(text)
    budget = _bot_comm_candidate_budget_usd(item)

    if not (has_buy_intent and has_agent_context and service_score >= 0.35):
        return None

    source_id = str(
        item.get("_id")
        or item.get("id")
        or item.get("url")
        or item.get("resourceUrl")
        or item.get("endpoint")
        or item.get("base_url")
        or hashlib.sha256(f"{source}:{query}:{text}".encode("utf-8")).hexdigest()[:18]
    )
    candidate_id = f"bcjob_{hashlib.sha256(f'{source}:{source_id}:{service['id']}'.encode('utf-8')).hexdigest()[:16]}"
    signals = ["machine_readable_commercial_channel", "buying_intent_detected", "bot_or_agent_context_detected"]
    if budget is not None:
        signals.append("budget_or_price_present")
    if service_score >= 0.7:
        signals.append("direct_bot_comm_service_match")
    if has_buyer_channel:
        signals.append("repeat_buyer_channel_possible")

    offer = _bot_comm_offer_template(service, text[:180])
    provider = item.get("provider")
    if isinstance(provider, dict):
        provider = provider.get("organization") or provider.get("name") or provider.get("url")
    title_source = (
        item.get("title")
        or item.get("name")
        or provider
        or item.get("resourceUrl")
        or item.get("url")
        or "Qualified buyer-bot request"
    )
    candidate = {
        "id": candidate_id,
        "source": source,
        "source_id": source_id[:180],
        "source_url": _bot_comm_source_url(item),
        "query": query,
        "title": str(title_source)[:180],
        "buyer_need": text[:700],
        "status": "qualified_buyer_channel" if has_buyer_channel else "qualified_not_contacted",
        "service_id": service["id"],
        "service_name": service["title"],
        "price_usd": float(service["price_usdc"]),
        "candidate_budget_usd": budget,
        "qualification_score": int(min(96, 55 + service_score * 30 + (8 if budget is not None else 0))),
        "qualification_signals": signals,
        "clearance_required": True,
        "payment_required_before_work": True,
        "prepared_offer": offer,
        "next_action": (
            "Watch this buyer channel for real bot requests; quote only when buying intent is present."
            if has_buyer_channel
            else "Return the 402 payment requirement or send this one offer only through an approved commercial channel."
        ),
    }
    candidate["estimated_monthly_potential_usd"] = _bot_comm_estimated_monthly_potential(candidate, service)
    candidate["opportunity_score"] = int(min(100, candidate["qualification_score"] + (8 if candidate.get("source_url") else 0) + (8 if budget else 0)))
    candidate["path_to_revenue"] = (
        "Watch this commercial source for real buyer-bot requests, then require payment authorization and Clearance before delivery."
        if has_buyer_channel
        else "Send the prepared service offer once through the source marketplace/API, then require payment authorization and Clearance before delivery."
    )
    return candidate


def _bot_comm_qualify_registry_candidate(source: str, query: str, item: dict) -> dict | None:
    text = _bot_comm_job_text(item)
    if not text:
        return None
    risk_flags = _bot_comm_risk_flags({"candidate": text})
    if risk_flags:
        return None

    lowered = text.lower()
    registry_terms = (
        "x402",
        "agent",
        "api",
        "mcp",
        "tool",
        "endpoint",
        "service",
        "usdc",
        "payment",
        "marketplace",
        "task",
        "bounty",
        "request",
        "jobs",
    )
    if not any(term in lowered for term in registry_terms):
        return None

    service, service_score = _bot_comm_service_for_need(text)
    source_url = _bot_comm_source_url(item)
    provider = item.get("provider")
    if isinstance(provider, dict):
        provider = provider.get("organization") or provider.get("name") or provider.get("url")
    title = str(item.get("title") or item.get("name") or provider or "Public agent-service source")[:180]
    source_id = str(
        item.get("_id")
        or item.get("id")
        or item.get("slug")
        or item.get("resourceUrl")
        or item.get("url")
        or item.get("base_url")
        or hashlib.sha256(f"{source}:{query}:{text}".encode("utf-8")).hexdigest()[:18]
    )
    buyer_channel_terms = ("available tasks", "tasks available", "open requests", "bounties", "jobs", "marketplace")
    is_buyer_channel = any(term in lowered for term in buyer_channel_terms)
    candidate_id = f"bcsrc_{hashlib.sha256(f'{source}:{source_id}'.encode('utf-8')).hexdigest()[:16]}"
    signals = ["public_machine_readable_service_metadata", "agent_or_x402_context_detected", "routing_inventory_candidate"]
    if source_url:
        signals.append("source_url_present")
    if is_buyer_channel:
        signals.extend(["buyer_channel_possible", "repeat_discovery_source"])
    budget = _bot_comm_candidate_budget_usd(item)
    if budget is not None:
        signals.append("priced_endpoint_present")
    base_score = 78 if is_buyer_channel else 64
    score = int(min(96, base_score + service_score * 14 + (6 if source_url else 0) + (4 if budget is not None else 0)))
    candidate = {
        "id": candidate_id,
        "source": source,
        "source_id": source_id[:180],
        "source_url": source_url,
        "query": query,
        "title": f"{'Buyer channel' if is_buyer_channel else 'Registry source'}: {title}",
        "buyer_need": text[:700],
        "status": "qualified_buyer_channel" if is_buyer_channel else "routing_source_indexed",
        "service_id": service["id"],
        "service_name": service["title"],
        "price_usd": float(service["price_usdc"]),
        "candidate_budget_usd": budget,
        "qualification_score": score,
        "qualification_signals": signals,
        "clearance_required": True,
        "payment_required_before_work": True,
        "prepared_offer": _bot_comm_offer_template(service, text[:180]),
        "next_action": (
            "Watch this commercial agent channel for buyer-bot requests; quote only when buying intent is present."
            if is_buyer_channel
            else "Index as public routing metadata; no outreach, no spend, no delivery before paid buyer-bot call."
        ),
        "path_to_revenue": (
            "Recurring buyer-bot source: classify matching requests, return 402 quotes, then deliver paid service after Clearance."
            if is_buyer_channel
            else "Improves paid directory lookup and capability match responses using public metadata, increasing repeat-call utility."
        ),
    }
    candidate["estimated_monthly_potential_usd"] = _bot_comm_estimated_monthly_potential(candidate, service)
    candidate["opportunity_score"] = score
    return candidate


def _bot_comm_add_source_candidates(tick: dict, source: str, query: str, payload: dict, seen_candidates: set[str]) -> tuple[int, int]:
    items = _bot_comm_extract_candidate_items(payload)
    qualified_count = 0
    for item in items:
        candidate = _bot_comm_qualify_buyer_candidate(source, query, item)
        if not candidate:
            candidate = _bot_comm_qualify_registry_candidate(source, query, item)
        if candidate and candidate["id"] not in seen_candidates:
            seen_candidates.add(candidate["id"])
            tick["qualified_buyers"].append(candidate)
            qualified_count += 1
    return len(items), qualified_count


def _bot_comm_inbound_demand_candidate(item: dict) -> dict | None:
    service_id = item.get("service_id")
    if not service_id:
        return None
    try:
        service = _bot_comm_service(service_id)
    except HTTPException:
        return None
    if not _bot_comm_service_allowed(service):
        return None
    risk_flags = item.get("risk_flags") or []
    unsafe_flags = set(BOT_COMM_FORBIDDEN_ACTIVITY) | {"unknown_service", "no_real_task_context"}
    if unsafe_flags & set(risk_flags):
        return None
    buyer = item.get("buyer_bot_id") or "unknown-buyer-bot"
    source_id = str(item.get("id") or hashlib.sha256(f"{buyer}:{service_id}".encode("utf-8")).hexdigest()[:18])
    candidate_id = f"bcin_{hashlib.sha256(f'{buyer}:{service_id}'.encode('utf-8')).hexdigest()[:16]}"
    status = _bot_comm_normalize_status(item.get("status"), risk_flags)
    quote_id = item.get("quote_id")
    quote_payload = item.get("quote")
    if status == "QUOTED" and not quote_id:
        quote_id = f"quote_backfill_{source_id[-18:]}"
    if status == "QUOTED" and quote_id and not quote_payload:
        quote_payload = _bot_comm_quote_payload(service, quote_id)
    candidate = {
        "id": candidate_id,
        "source": "inbound_bot_comm_endpoint",
        "source_id": source_id,
        "query": "inbound_paid_endpoint",
        "title": f"Inbound {service['title']} buyer",
        "buyer_need": f"{buyer} attempted {service['title']} and received a payment/Clearance gate.",
        "status": status,
        "service_id": service["id"],
        "service_name": service["title"],
        "price_usd": float(service["price_usdc"]),
        "candidate_budget_usd": None,
        "qualification_score": 88 if buyer != "unknown-buyer-bot" else 72,
        "qualification_signals": ["called_bot_comm_endpoint", "requested_paid_service", "payment_capable_flow_possible"],
        "clearance_required": True,
        "payment_required_before_work": True,
        "prepared_offer": _bot_comm_offer_template(service, item.get("buyer_need") or service["summary"]),
        "quote_id": quote_id,
        "quote": quote_payload,
        "next_action": "Wait for verified Base USDC payment, then deliver if inside Clearance policy limits.",
        "path_to_revenue": "Buyer-bot already touched a paid endpoint. Convert by returning 402 and requiring payment before output.",
    }
    candidate["estimated_monthly_potential_usd"] = _bot_comm_estimated_monthly_potential(candidate, service)
    candidate["opportunity_score"] = 92 if item.get("status") == "QUOTED" else candidate["qualification_score"]
    return candidate


async def _bot_comm_merge_opportunities(candidates: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc)
    now_value = now.isoformat()
    existing_state = await _bot_comm_get_state_value("opportunity_book", {"items": []})
    existing_items = existing_state.get("items", []) if isinstance(existing_state, dict) else []
    by_id = {
        str(item.get("id")): item
        for item in existing_items
        if isinstance(item, dict) and item.get("id")
    }

    for candidate in candidates:
        if not candidate or not candidate.get("id"):
            continue
        prior = by_id.get(candidate["id"], {})
        candidate["first_seen_at"] = prior.get("first_seen_at") or now_value
        candidate["last_seen_at"] = now_value
        candidate["seen_count"] = int(prior.get("seen_count") or 0) + 1
        if str(prior.get("status") or "").upper() in {"CONTACTED", "PAID", "CLOSED", "BLOCKED"}:
            candidate["status"] = prior["status"]
        candidate["notes"] = prior.get("notes") or candidate.get("notes") or []
        by_id[candidate["id"]] = {**prior, **candidate}

    cutoff = now - timedelta(hours=BOT_COMM_OPPORTUNITY_RETENTION_HOURS)
    retained = []
    for item in by_id.values():
        try:
            last_seen = datetime.fromisoformat(str(item.get("last_seen_at") or item.get("first_seen_at")))
        except Exception:
            last_seen = now
        if last_seen >= cutoff:
            retained.append(item)

    retained.sort(
        key=lambda item: (
            int(item.get("opportunity_score") or item.get("qualification_score") or 0),
            float(item.get("estimated_monthly_potential_usd") or 0),
            str(item.get("last_seen_at") or ""),
        ),
        reverse=True,
    )
    retained = retained[:BOT_COMM_OPPORTUNITY_MAX]
    await _bot_comm_set_state_value("opportunity_book", {"updated_at": now_value, "items": retained})
    return retained


def _bot_comm_completion_record(
    *,
    source_id: str,
    title: str,
    detail: str,
    status: str,
    service_id: str | None = None,
    buyer_bot_id: str | None = None,
    source: str | None = None,
    metadata: dict | None = None,
) -> dict:
    completed_id = f"bcoc_{hashlib.sha256(f'{source_id}:{status}:{service_id or ''}'.encode('utf-8')).hexdigest()[:18]}"
    return {
        "id": completed_id,
        "source_id": source_id,
        "completion_type": "operator",
        "service_id": service_id or "bot_comm_operator",
        "buyer_bot_id": buyer_bot_id or "bot-comm-operator",
        "source": source,
        "title": title[:180],
        "detail": detail[:500],
        "status": status,
        "price_usd": 0,
        "net_profit_usd": 0,
        "timestamp": now_iso(),
        "metadata": metadata or {},
    }


async def _bot_comm_record_operator_completions(records: list[dict]) -> list[dict]:
    if not records:
        return []
    current = await _bot_comm_get_state_value("operator_completed_jobs", {"items": []})
    items = current.get("items", []) if isinstance(current, dict) else []
    by_id = {
        str(item.get("id")): item
        for item in items
        if isinstance(item, dict) and item.get("id")
    }
    new_records = []
    for record in records:
        if not record.get("id"):
            continue
        prior = by_id.get(record["id"])
        if prior:
            record["timestamp"] = prior.get("timestamp") or record.get("timestamp")
        else:
            new_records.append(record)
        by_id[record["id"]] = {**(prior or {}), **record}
    retained = sorted(by_id.values(), key=lambda item: item.get("timestamp") or "", reverse=True)[:BOT_COMM_OPERATOR_COMPLETION_MAX]
    await _bot_comm_set_state_value("operator_completed_jobs", {"updated_at": now_iso(), "items": retained})
    return new_records


async def _bot_comm_operator_completed_jobs() -> list[dict]:
    current = await _bot_comm_get_state_value("operator_completed_jobs", {"items": []})
    items = current.get("items", []) if isinstance(current, dict) else []
    return [
        item for item in sorted(
            [item for item in items if isinstance(item, dict)],
            key=lambda item: item.get("timestamp") or "",
            reverse=True,
        )
    ][:80]


async def _bot_comm_auto_complete_operator_jobs(tick: dict) -> list[dict]:
    records = []
    for candidate in tick.get("opportunities") or []:
        status = str(candidate.get("status") or "").lower()
        source_id = str(candidate.get("id") or candidate.get("source_id") or "")
        if not source_id:
            continue
        if status == "routing_source_indexed":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"Indexed routing source: {candidate.get('title') or candidate.get('service_name') or 'agent source'}",
                detail="Public service metadata indexed for paid directory lookup and capability matching. No outreach, no spend, no delivery.",
                status="INDEXED",
                service_id=candidate.get("service_id"),
                source=candidate.get("source"),
                metadata={"candidate": candidate},
            ))
        elif status == "qualified_buyer_channel":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"Armed buyer channel: {candidate.get('title') or candidate.get('source') or 'agent channel'}",
                detail="Buyer channel is being watched for real bot requests. Bot-Comm will quote only when buying intent is present.",
                status="WATCH_ARMED",
                service_id=candidate.get("service_id"),
                source=candidate.get("source"),
                metadata={"candidate": candidate},
            ))
        elif status == "qualified_not_contacted" and candidate.get("prepared_offer"):
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"Prepared offer packet: {candidate.get('title') or candidate.get('service_name') or 'buyer request'}",
                detail="Machine-readable offer is prepared. Bot-Comm will not send unsolicited outreach; payment and Clearance remain required.",
                status="OFFER_READY",
                service_id=candidate.get("service_id"),
                source=candidate.get("source"),
                metadata={"candidate": candidate, "offer": candidate.get("prepared_offer")},
            ))
        elif status == "quoted":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"402 quote prepared: {candidate.get('title') or candidate.get('service_name') or 'buyer call'}",
                detail="Safe unpaid buyer-bot call has a machine-readable 402 quote. Waiting for verified payment before any delivery.",
                status="QUOTE_READY",
                service_id=candidate.get("service_id"),
                buyer_bot_id=candidate.get("buyer_bot_id"),
                source=candidate.get("source"),
                metadata={"candidate": candidate, "quote": candidate.get("quote")},
            ))

    for demand in tick.get("inbound_demand") or []:
        status = str(demand.get("status") or "").upper()
        source_id = str(demand.get("id") or demand.get("attempt_id") or "")
        if not source_id:
            continue
        if status == "QUOTED":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"402 quote ready: {demand.get('buyer_bot_id') or 'buyer-bot'} / {demand.get('service_id') or 'service'}",
                detail="Safe unpaid inbound call was converted to HTTP 402. No premium output delivered before payment.",
                status="QUOTE_READY",
                service_id=demand.get("service_id"),
                buyer_bot_id=demand.get("buyer_bot_id"),
                source=demand.get("source"),
                metadata={"inbound": demand, "quote": demand.get("quote")},
            ))
        elif status == "BLOCKED":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"Kept unsafe call blocked: {demand.get('buyer_bot_id') or 'buyer-bot'}",
                detail=demand.get("reason") or "Unsafe or abusive request remained blocked. No quote sent.",
                status="BLOCKED_SAFE",
                service_id=demand.get("service_id"),
                buyer_bot_id=demand.get("buyer_bot_id"),
                source=demand.get("source"),
                metadata={"inbound": demand},
            ))
        elif status == "REJECTED":
            records.append(_bot_comm_completion_record(
                source_id=source_id,
                title=f"Rejected unavailable service: {demand.get('service_id') or 'unknown'}",
                detail="Request was outside the allowed Bot-Comm microservice registry. No access opened.",
                status="REJECTED_SAFE",
                service_id=demand.get("service_id"),
                buyer_bot_id=demand.get("buyer_bot_id"),
                source=demand.get("source"),
                metadata={"inbound": demand},
            ))

    new_records = await _bot_comm_record_operator_completions(records)
    tick["operator_completed_actions"] = new_records
    tick["operator_completed_action_count"] = len(records)
    tick["operator_new_completed_action_count"] = len(new_records)
    return new_records


def _bot_comm_should_backfill_to_quote(status: str, service_id: str | None, risk_flags: list, reason: str | None = None) -> bool:
    if status not in {"BLOCKED", "REJECTED"}:
        return False
    if service_id not in BOT_COMM_ALLOWED_SERVICE_IDS:
        return False
    flags = {str(flag).strip() for flag in (risk_flags or []) if str(flag).strip()}
    reason_text = str(reason or "").lower()
    unsafe_reason_terms = [
        "unsafe",
        "abusive",
        "private key",
        "seed phrase",
        "credential",
        "wallet targeting",
        "scan wallet",
        "exploit",
        "phishing",
        "spam",
        "impersonation",
        "fake volume",
        "artificial volume",
        "self-dealing",
        "marketplace manipulation",
        "unknown_service",
        "no real task",
    ]
    if any(term in reason_text for term in unsafe_reason_terms):
        return False
    safe_gate_flags = {
        "clearance_policy_missing",
        "policy_missing",
        "pending_clearance",
        "payment_required",
        "payment_missing",
        "safe_unpaid_request",
    }
    if "operations_halted" in flags:
        historical_policy_halt = any(term in reason_text for term in ("policy", "clearance", "supersede", "50000"))
        if not historical_policy_halt:
            return False
        flags.discard("operations_halted")
    abuse_flags = (set(BOT_COMM_FORBIDDEN_ACTIVITY) | {"unknown_service", "no_real_task_context"}) - safe_gate_flags
    return not (flags & abuse_flags)


async def _bot_comm_recent_inbound_demand() -> list[dict]:
    attempt_state = await _bot_comm_get_state_value("attempt_book", {"items": []})
    attempts = attempt_state.get("items", []) if isinstance(attempt_state, dict) else []
    demand = []
    for item in attempts[:30]:
        if not isinstance(item, dict):
            continue
        status = _bot_comm_normalize_status(item.get("status"), item.get("risk_flags") or [])
        service_id = item.get("service_id")
        quote_id = item.get("quote_id")
        quote_payload = item.get("quote")
        if _bot_comm_should_backfill_to_quote(status, service_id, item.get("risk_flags") or [], item.get("reason")):
            status = "QUOTED"
            service = _bot_comm_service(service_id)
            quote_id = quote_id or f"quote_backfill_{str(item.get('attempt_id') or '')[-18:]}"
            quote_payload = quote_payload or _bot_comm_quote_payload(service, quote_id)
        demand.append({
            "id": item.get("attempt_id"),
            "attempt_id": item.get("attempt_id"),
            "source": item.get("buyer_bot_source") or "inbound_bot_comm_endpoint",
            "buyer_bot_id": item.get("buyer_bot_id") or "unknown-buyer-bot",
            "service_id": service_id,
            "status": status,
            "request_status": status,
            "risk_flags": item.get("risk_flags") or [],
            "timestamp": item.get("timestamp") or item.get("updated_at"),
            "authorization_basis": item.get("authorization_basis"),
            "clearance_policy_id": item.get("clearance_policy_id"),
            "quote_id": quote_id,
            "quote": quote_payload,
            "reason": item.get("reason"),
            "metadata": item,
        })

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT *
                   FROM bot_comm_call_logs
                   WHERE timestamp >= ?
                     AND UPPER(result_code) IN ('QUOTED', 'PAYMENT_REQUIRED', 'PAYMENT_PENDING', 'PAYMENT_UNVERIFIED', 'PENDING_CLEARANCE', 'REJECTED', 'BLOCKED', 'THROTTLED', 'REFUND_PENDING')
                   ORDER BY timestamp DESC
                   LIMIT 20""",
                (cutoff,),
            )
        ).fetchall()
    finally:
        await db.close()
    seen_ids = {str(item.get("id")) for item in demand if item.get("id")}
    for row in rows:
        item = dict(row)
        if str(item.get("id")) in seen_ids:
            continue
        metadata = _load_json(item.get("metadata"), {}) or {}
        risk_flags = _load_json(item.get("risk_flags"), []) or []
        status = _bot_comm_normalize_status(item.get("result_code"), risk_flags)
        if _bot_comm_should_backfill_to_quote(status, item.get("service_id"), risk_flags, metadata.get("reason")):
            status = "QUOTED"
            service = _bot_comm_service(item.get("service_id"))
            quote_id = metadata.get("quote_id") or f"quote_backfill_{str(item.get('id') or '')[-12:]}"
            metadata.setdefault("quote", _bot_comm_quote_payload(service, quote_id))
            metadata.setdefault("quote_id", quote_id)
        demand.append({
            "id": item.get("id"),
            "attempt_id": metadata.get("attempt_id") or item.get("id"),
            "source": "inbound_bot_comm_endpoint",
            "buyer_bot_id": item.get("buyer_bot_id") or "unknown-buyer-bot",
            "service_id": item.get("service_id"),
            "status": status,
            "request_status": status,
            "risk_flags": risk_flags,
            "timestamp": item.get("timestamp"),
            "authorization_basis": item.get("authorization_basis"),
            "clearance_policy_id": item.get("clearance_policy_id"),
            "quote_id": metadata.get("quote_id"),
            "quote": metadata.get("quote"),
            "reason": metadata.get("reason"),
            "metadata": metadata,
        })
    return demand[:30]


async def _bot_comm_operator_tick() -> dict:
    operations = await _bot_comm_operations_status()
    policy = await _bot_comm_active_policy()
    latest_policy = await _bot_comm_latest_policy_request()
    tick = {
        "at": now_iso(),
        "mode": "perpetual_24_7",
        "enabled": bool(operations.get("active")),
        "interval_seconds": max(BOT_COMM_OPS_INTERVAL_SECONDS, 60),
        "business_model": "Charge first. Spend second. Deliver third.",
        "actions_allowed": [
            "keep paid endpoints and service metadata online",
            "discover qualified buyer-bot requests in commercial machine-readable channels",
            "prepare exactly one machine-readable service offer for qualified buying intent",
            "create or surface no-owner-spend Clearance policy requests",
            "accept paid inbound calls only inside approved Clearance policy limits",
        ],
        "actions_blocked_without_clearance": [
            "charging buyer-bots",
            "premium delivery",
            "paid API/model/tool spend",
            "refunds",
            "subscription activation",
            "large batch or enterprise commitments",
        ],
        "public_endpoints": [],
        "marketplaces": [],
        "qualified_buyers": [],
        "opportunities": [],
        "inbound_demand": [],
        "clearance_actions": [],
        "notes": [],
    }

    if not operations.get("active"):
        tick["summary"] = {
            "status": "halted",
            "clearance_status": "not_checked",
            "qualified_buyer_count": 0,
            "inbound_demand_count": 0,
            "spend_status": "no_spend_performed",
            "outreach_status": "no_outbound_contact_performed",
        }
        tick["opportunities"] = await _bot_comm_merge_opportunities([])
        await _bot_comm_set_state_value("operator_tick", tick)
        await _bot_comm_set_state_value("last_operations_tick", {
            "at": tick["at"],
            "action": "halted",
            "summary": "Operations are halted. No discovery, charging, spend, or premium delivery is active.",
        })
        return tick

    if policy:
        tick["clearance_actions"].append({
            "status": "active",
            "policy_id": policy.get("id"),
            "expires_at": policy.get("expires_at"),
            "summary": "No-owner-spend microtransaction policy is active.",
        })
    elif latest_policy and latest_policy.get("status") == "pending":
        tick["clearance_actions"].append({
            "status": "pending",
            "policy_id": latest_policy.get("id"),
            "approval_url": latest_policy.get("approval_url"),
            "expires_at": latest_policy.get("expires_at"),
            "summary": "Paid fulfillment remains blocked until the owner approves this policy.",
        })
    else:
        requested = await _bot_comm_request_micro_policy()
        tick["clearance_actions"].append({
            "status": "requested",
            "created": requested.get("created"),
            "policy_id": (requested.get("policy") or {}).get("id"),
            "approval_url": (requested.get("policy") or {}).get("approval_url"),
            "expires_at": (requested.get("policy") or {}).get("expires_at"),
            "summary": "Created a fresh no-owner-spend Clearance policy request.",
        })
        latest_policy = requested.get("policy") or latest_policy

    queries = []
    if BOT_COMM_DISCOVERY_ENABLED:
        headers = {"User-Agent": "Nauti-Labs-Bot-Comm-Operator/1.0"}
        async with httpx.AsyncClient(headers=headers) as client:
            tick["public_endpoints"] = await _bot_comm_public_endpoint_checks(client)

            try:
                index_payload = await _bot_comm_fetch_json(
                    client,
                    "https://402index.io/api/v1/services?q=Bot-Comm&protocol=x402&limit=10",
                )
                services = index_payload.get("services", []) if isinstance(index_payload, dict) else []
                matches = [
                    item for item in services
                    if "bot-comm" in str(item.get("name") or item.get("title") or "").lower()
                    or "nauti" in str(item.get("name") or item.get("title") or "").lower()
                ]
                tick["marketplaces"].append({
                    "marketplace": "402 Index",
                    "status": "healthy" if matches else "missing_or_not_indexed",
                    "listing_count": len(services),
                    "matching_listing_count": len(matches),
                    "healthy_count": len([item for item in matches if item.get("health_status") == "healthy"]),
                })
            except Exception as exc:
                tick["marketplaces"].append({"marketplace": "402 Index", "status": "check_failed", "error": str(exc)[:220]})

            queries = await _bot_comm_next_opportunity_queries()
            seen_candidates = set()
            for marketplace, query, url in _bot_comm_registry_discovery_sources(queries):
                try:
                    payload = await _bot_comm_fetch_json(client, url)
                    listing_count, qualified_count = _bot_comm_add_source_candidates(tick, marketplace, query, payload, seen_candidates)
                    tick["marketplaces"].append({
                        "marketplace": marketplace,
                        "query": query,
                        "status": "active" if listing_count else "empty",
                        "listing_count": listing_count,
                        "qualified_candidate_count": qualified_count,
                    })
                except Exception as exc:
                    tick["marketplaces"].append({
                        "marketplace": marketplace,
                        "query": query,
                        "status": "check_failed",
                        "error": str(exc)[:180],
                    })

            for query in queries:
                try:
                    payload = await _bot_comm_fetch_json(
                        client,
                        f"https://payanagent.com/api/v1/discover?q={quote(query)}",
                    )
                    services = payload.get("services", []) if isinstance(payload, dict) else []
                    own_services = [
                        item for item in services
                        if "bot-comm" in str(item.get("name") or item.get("title") or "").lower()
                        or "nauti" in str(item.get("name") or item.get("title") or "").lower()
                    ]
                    tick["marketplaces"].append({
                        "marketplace": "PayanAgent",
                        "query": query,
                        "status": "active" if services else "empty",
                        "listing_count": len(services),
                        "own_listing_count": len(own_services),
                    })
                    _bot_comm_add_source_candidates(tick, "PayanAgent", query, payload, seen_candidates)
                except Exception as exc:
                    tick["notes"].append({"query": query, "status": "payanagent_check_failed", "error": str(exc)[:180]})

            if BOT_COMM_PAYANAGENT_API_KEY:
                try:
                    response = await client.get(
                        "https://payanagent.com/api/v1/requests?type=open",
                        headers={"Authorization": f"Bearer {BOT_COMM_PAYANAGENT_API_KEY}"},
                        timeout=20,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    if isinstance(payload, dict):
                        _, qualified_count = _bot_comm_add_source_candidates(
                            tick,
                            "PayanAgent authenticated requests",
                            "authenticated_open_requests",
                            payload,
                            seen_candidates,
                        )
                        tick["marketplaces"].append({
                            "marketplace": "PayanAgent authenticated requests",
                            "status": "checked",
                            "request_count": len(_bot_comm_extract_candidate_items(payload)),
                            "qualified_candidate_count": qualified_count,
                        })
                except Exception as exc:
                    tick["notes"].append({"query": "payanagent_authenticated_requests", "status": "request_check_failed", "error": str(exc)[:180]})
            else:
                tick["notes"].append({
                    "query": "payanagent_authenticated_requests",
                    "status": "skipped_no_api_key",
                    "detail": "Set BOT_COMM_PAYANAGENT_API_KEY to inspect authenticated open requests.",
                })

            for feed_url in BOT_COMM_DISCOVERY_FEEDS:
                try:
                    payload = await _bot_comm_fetch_json(client, feed_url)
                    listing_count, qualified_count = _bot_comm_add_source_candidates(tick, feed_url, "configured_feed", payload, seen_candidates)
                    tick["marketplaces"].append({
                        "marketplace": "Configured feed",
                        "url": feed_url,
                        "status": "checked",
                        "listing_count": listing_count,
                        "qualified_candidate_count": qualified_count,
                    })
                except Exception as exc:
                    tick["marketplaces"].append({"marketplace": "Configured feed", "url": feed_url, "status": "check_failed", "error": str(exc)[:180]})

    tick["inbound_demand"] = await _bot_comm_recent_inbound_demand()
    inbound_candidates = [
        candidate for candidate in (_bot_comm_inbound_demand_candidate(item) for item in tick["inbound_demand"])
        if candidate
    ]
    tick["opportunities"] = await _bot_comm_merge_opportunities(tick["qualified_buyers"] + inbound_candidates)
    await _bot_comm_auto_complete_operator_jobs(tick)
    clearance_status = "active" if policy else "pending" if latest_policy and latest_policy.get("status") == "pending" else "missing"
    tick["summary"] = {
        "status": "running",
        "clearance_status": clearance_status,
        "queries_checked": len(queries),
        "public_endpoint_count": len(tick["public_endpoints"]),
        "healthy_public_endpoint_count": len([item for item in tick["public_endpoints"] if item.get("status") == "healthy"]),
        "marketplace_count": len(tick["marketplaces"]),
        "qualified_buyer_count": len(tick["qualified_buyers"]),
        "active_opportunity_count": len(tick["opportunities"]),
        "top_opportunity_score": int((tick["opportunities"][0] or {}).get("opportunity_score") or 0) if tick["opportunities"] else 0,
        "inbound_demand_count": len(tick["inbound_demand"]),
        "operator_completed_action_count": tick.get("operator_completed_action_count", 0),
        "operator_new_completed_action_count": tick.get("operator_new_completed_action_count", 0),
        "spend_status": "no_spend_performed",
        "outreach_status": "no_unsolicited_outbound_contact_performed" if not BOT_COMM_AUTOSEND_OFFERS else "autosend_requires_approved_commercial_channel",
    }
    await _bot_comm_set_state_value("operator_tick", tick)
    await _bot_comm_set_state_value("last_operations_tick", {
        "at": tick["at"],
        "action": "operator_tick",
        "summary": (
            f"Perpetual loop checked {tick['summary']['healthy_public_endpoint_count']}/{tick['summary']['public_endpoint_count']} public endpoints, "
            f"checked {tick['summary']['queries_checked']} opportunity queries, "
            f"kept {tick['summary']['active_opportunity_count']} active opportunities, "
            f"and kept paid delivery gated by Clearance ({clearance_status})."
        ),
    })
    return tick


async def bot_comm_operations_loop():
    await asyncio.sleep(2)
    while True:
        try:
            await _bot_comm_operator_tick()
        except Exception as exc:
            print(f"[bot-comm] operations loop error: {exc}")
        await asyncio.sleep(max(BOT_COMM_OPS_INTERVAL_SECONDS, 60))


async def _bot_comm_ledger_summary() -> dict:
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT * FROM agent_income_ledger
                   WHERE event_type IN ('bot_comm_service_payment', 'bot_comm_manual_settlement')
                   ORDER BY created_at DESC
                   LIMIT 25"""
            )
        ).fetchall()
    finally:
        await db.close()

    entries = []
    today_key = datetime.now(timezone.utc).date().isoformat()
    total = 0.0
    today_total = 0.0
    service_total = 0.0
    for row in rows:
        item = dict(row)
        metadata = _load_json(item.get("metadata"), {}) or {}
        amount = float(item.get("amount") or 0)
        total += amount
        if item.get("event_type") == "bot_comm_service_payment":
            service_total += amount
        if str(item.get("created_at") or "").startswith(today_key):
            today_total += amount
        entries.append({
            "id": item["id"],
            "kind": item["event_type"],
            "amountUSDC": money(amount),
            "currency": item.get("currency"),
            "status": item.get("status"),
            "txHash": item.get("provider_ref"),
            "serviceId": metadata.get("service_id"),
            "payer": metadata.get("from_address"),
            "timestamp": item.get("created_at"),
        })
    return {
        "entries": entries,
        "summary": {
            "totalUSDC": money(total),
            "todayUSDC": money(today_total),
            "serviceRevenueUSDC": money(service_total),
            "targetUSDC": money(BOT_COMM_DAILY_TARGET_USDC),
            "remainingUSDC": money(max(BOT_COMM_DAILY_TARGET_USDC - today_total, 0)),
            "progressPercent": min(100, round((today_total / BOT_COMM_DAILY_TARGET_USDC) * 100, 2)) if BOT_COMM_DAILY_TARGET_USDC else 0,
        },
    }


def _bot_comm_clearance_view(row: dict) -> dict:
    metadata = _load_json(row.get("metadata"), {}) or {}
    expires_at = row.get("expires_at")
    status = row.get("status") or "unknown"
    try:
        if status in {"pending", "approved"} and expires_at and datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
            status = "expired"
    except Exception:
        pass
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "description": row.get("description"),
        "scope": row.get("scope"),
        "status": status,
        "budget_amount": money(row.get("budget_amount") or 0),
        "budget_currency": row.get("budget_currency") or "USD",
        "approval_url": row.get("approval_url"),
        "created_at": row.get("created_at"),
        "expires_at": expires_at,
        "decided_at": row.get("decided_at"),
        "decision_note": row.get("decision_note"),
        "owner_spend_limit_usd": money(metadata.get("owner_spend_limit_usd") or 0),
        "owner_charge_usd": money(metadata.get("owner_charge_usd") or 0),
        "budget_meaning": metadata.get("budget_meaning") or "",
        "transaction_type": metadata.get("transaction_type") or metadata.get("policy_type") or "",
        "path_to_20000_month": metadata.get("path_to_20000_month") or "",
    }


async def _bot_comm_clearance_queues() -> dict:
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT *
                   FROM clearances
                   ORDER BY created_at DESC
                   LIMIT 120"""
            )
        ).fetchall()
    finally:
        await db.close()
    pending = []
    completed = []
    for row in rows:
        item = dict(row)
        metadata = _load_json(item.get("metadata"), {}) or {}
        if metadata.get("project") != "bot-comm":
            continue
        view = _bot_comm_clearance_view(item)
        if view["status"] == "pending":
            pending.append(view)
        else:
            completed.append(view)
    return {"pending": pending[:12], "completed": completed[:30]}


async def _bot_comm_recent_completed_jobs() -> list[dict]:
    db = await get_db()
    try:
        rows = await (
            await db.execute(
                """SELECT *
                   FROM bot_comm_call_logs
                   WHERE UPPER(result_code) = 'DELIVERED'
                   ORDER BY timestamp DESC
                   LIMIT 20"""
            )
        ).fetchall()
    finally:
        await db.close()
    jobs = []
    for row in rows:
        item = dict(row)
        jobs.append({
            "id": item.get("id"),
            "completion_type": "paid_delivery",
            "title": f"Delivered {item.get('service_id') or 'Bot-Comm service'}",
            "detail": "Paid service output delivered after verified payment and approved Clearance policy.",
            "service_id": item.get("service_id") or "bot_comm",
            "buyer_bot_id": item.get("buyer_bot_id") or "unknown-buyer-bot",
            "price_usd": money(item.get("price_usd") or 0),
            "net_profit_usd": money(item.get("net_profit_usd") or 0),
            "latency_ms": int(item.get("latency_ms") or 0),
            "timestamp": item.get("timestamp"),
            "provider_ref": item.get("provider_ref"),
            "result_code": item.get("result_code"),
        })
    operator_jobs = await _bot_comm_operator_completed_jobs()
    combined = jobs + operator_jobs
    return sorted(combined, key=lambda item: item.get("timestamp") or "", reverse=True)[:80]


def _bot_comm_projected_income(metrics: dict) -> dict:
    now = datetime.now(timezone.utc)
    days_in_month = calendar.monthrange(now.year, now.month)[1]
    elapsed_days = max(now.day, 1)
    monthly_gross = float((metrics.get("monthly") or {}).get("monthly_gross_actual_usd") or 0)
    projected_monthly = money((monthly_gross / elapsed_days) * days_in_month) if monthly_gross else 0
    target = float(BOT_COMM_MONTHLY_TARGET_USD)
    return {
        "monthly_run_rate_usd": projected_monthly,
        "target_usd": money(target),
        "gap_to_target_usd": money(max(target - projected_monthly, 0)),
        "pace_percent": round((projected_monthly / target) * 100, 2) if target else 0,
        "basis": "actual month-to-date paid calls" if monthly_gross else "no paid volume yet",
    }


def _bot_comm_open_jobs(operations: dict, policy: dict | None, clearances: dict, completed_jobs: list[dict], operator_tick: dict | None = None) -> list[dict]:
    jobs = []
    operator_tick = operator_tick or {}
    if not operations.get("active"):
        jobs.append({
            "id": "ops_halted",
            "title": "Resume controlled operations",
            "status": "paused",
            "detail": operations.get("reason") or "Bot-Comm is halted.",
            "action": "Resume only after the current Clearance policy is right.",
        })
    if clearances.get("pending"):
        for clearance in clearances["pending"][:3]:
            jobs.append({
                "id": clearance["id"],
                "title": "Clearance decision pending",
                "status": "approval",
                "detail": clearance["title"],
                "action": "Review, approve, or deny in the Clearance panel.",
            })
    elif not policy:
        jobs.append({
            "id": "policy_needed",
            "title": "Create no-owner-spend policy",
            "status": "approval",
            "detail": "Paid calls without an active policy become PENDING_CLEARANCE. Safe unpaid calls still receive HTTP 402 quotes.",
            "action": "Request or review Clearance.",
        })
    opportunities = operator_tick.get("opportunities") or operator_tick.get("qualified_buyers") or []
    for candidate in opportunities[:18]:
        candidate_status = str(candidate.get("status") or "").upper()
        candidate_quote_id = candidate.get("quote_id")
        candidate_quote = candidate.get("quote")
        if candidate_status == "QUOTED" and candidate.get("service_id") in BOT_COMM_ALLOWED_SERVICE_IDS:
            service = _bot_comm_service(candidate.get("service_id"))
            candidate_quote_id = candidate_quote_id or f"quote_backfill_{str(candidate.get('id') or '')[-18:]}"
            candidate_quote = candidate_quote or _bot_comm_quote_payload(service, candidate_quote_id)
        jobs.append({
            "id": candidate.get("id"),
            "title": f"Opportunity: {candidate.get('title') or candidate.get('buyer_bot_id') or 'agent request'}",
            "status": candidate.get("status") or "opportunity",
            "detail": "Payment required quote sent. Waiting for buyer-bot payment." if candidate_status == "QUOTED" else (
                f"{candidate.get('source')} matched {candidate.get('service_name')} "
                f"at score {candidate.get('opportunity_score') or candidate.get('qualification_score')} "
                f"/ potential ${money(candidate.get('estimated_monthly_potential_usd') or 0):.2f}/mo."
            ),
            "action": candidate.get("next_action") or "Safe unpaid calls should receive HTTP 402 quotes. Unsafe calls stay blocked.",
            "quote_id": candidate_quote_id,
            "quote": candidate_quote,
        })
    for demand in (operator_tick.get("inbound_demand") or [])[:8]:
        demand_status = str(demand.get("status") or "").upper()
        demand_quote_id = demand.get("quote_id")
        demand_quote = demand.get("quote")
        if demand_status == "QUOTED" and demand.get("service_id") in BOT_COMM_ALLOWED_SERVICE_IDS:
            service = _bot_comm_service(demand.get("service_id"))
            demand_quote_id = demand_quote_id or f"quote_backfill_{str(demand.get('id') or '')[-18:]}"
            demand_quote = demand_quote or _bot_comm_quote_payload(service, demand_quote_id)
        jobs.append({
            "id": demand.get("id"),
            "title": "Safe unpaid buyer-bot call" if demand_status == "QUOTED" else "Inbound buyer-bot attempt",
            "status": demand.get("status") or "blocked",
            "detail": "402 quote sent." if demand_status == "QUOTED" else f"{demand.get('buyer_bot_id')} requested {demand.get('service_id') or 'Bot-Comm service'}.",
            "action": "Safe unpaid calls should receive HTTP 402 quotes. Unsafe calls stay blocked.",
            "quote_id": demand_quote_id,
            "quote": demand_quote,
        })
    if policy and operations.get("active"):
        jobs.append({
            "id": "buyer_intake",
            "title": "Wait for qualified buyer-bot calls",
            "status": "live",
            "detail": "Endpoints are live. Safe unpaid calls return HTTP 402. Paid calls deliver only inside approved Clearance policy.",
            "action": "Monitor paid calls and reject abuse automatically.",
        })
    paid_completed = [job for job in completed_jobs if job.get("completion_type") == "paid_delivery"]
    if not paid_completed:
        jobs.append({
            "id": "first_paid_job",
            "title": "First paid Bot-Comm call",
            "status": "open",
            "detail": "No paid BOT-COMM call has been delivered yet. Safe unpaid calls should be quoted, not opened.",
            "action": "Keep discovery metadata available; do not create fake volume.",
        })
    return jobs[:32]


def _bot_comm_work_items(operations: dict, policy: dict | None, last_tick: dict | None, operator_tick: dict | None = None) -> list[dict]:
    operator_tick = operator_tick or {}
    summary = operator_tick.get("summary") or {}
    clearance_actions = operator_tick.get("clearance_actions") or []
    latest_action = clearance_actions[0] if clearance_actions else {}
    endpoint_count = int(summary.get("public_endpoint_count") or 0)
    healthy_count = int(summary.get("healthy_public_endpoint_count") or 0)
    return [
        {
            "title": "Perpetual operator",
            "state": "running" if operations.get("active") else "halted",
            "detail": f"Runs every {max(BOT_COMM_OPS_INTERVAL_SECONDS, 60)} seconds; HALT stops discovery, charging, spend, and premium delivery.",
        },
        {
            "title": "Policy manager",
            "state": "armed" if policy else latest_action.get("status") or "blocked",
            "detail": latest_action.get("summary") or "Waiting for no-owner-spend Clearance policy.",
        },
        {
            "title": "Buyer discovery",
            "state": "running" if operations.get("active") and BOT_COMM_DISCOVERY_ENABLED else "paused",
            "detail": (
                f"Checked {summary.get('queries_checked', 0)} opportunity queries, "
                f"kept {summary.get('active_opportunity_count', 0)} active opportunities, "
                f"and saw {summary.get('inbound_demand_count', 0)} inbound demand events."
            ),
        },
        {
            "title": "Overnight completions",
            "state": "running" if operations.get("active") else "halted",
            "detail": (
                f"Auto-completed {summary.get('operator_completed_action_count', 0)} safe operator actions this tick "
                f"({summary.get('operator_new_completed_action_count', 0)} new): quotes ready, sources indexed, buyer watches armed, and unsafe calls kept blocked."
            ),
        },
        {
            "title": "Public endpoint monitor",
            "state": "published" if endpoint_count and healthy_count == endpoint_count else "running",
            "detail": f"{healthy_count}/{endpoint_count} discovery, service, x402, and agent endpoints healthy.",
        },
        {
            "title": "Payment gate",
            "state": "armed" if policy and operations.get("active") else "blocked",
            "detail": "Quotes before payment; premium output only after verified Base USDC and Clearance.",
        },
        {
            "title": "Risk filter",
            "state": "running",
            "detail": "Blocking private keys, seed phrases, wallet targeting, spam, fake volume, and unsafe requests.",
        },
        {
            "title": "Discovery metadata",
            "state": "published",
            "detail": "x402 JSON, agent cards, service schemas, and buyer page are live.",
        },
        {
            "title": "Operations loop",
            "state": operations.get("status") or "unknown",
            "detail": (last_tick or {}).get("summary") or "Waiting for next operator loop tick.",
        },
    ]


async def _bot_comm_state(viewer: dict | None = None) -> dict:
    ledger = await _bot_comm_ledger_summary()
    operations, policy, latest_policy, metrics, last_tick, clearances, completed_jobs, balances, operator_tick = await asyncio.gather(
        _bot_comm_operations_status(),
        _bot_comm_active_policy(),
        _bot_comm_latest_policy_request(),
        _bot_comm_usage_metrics(),
        _bot_comm_get_state_value("last_operations_tick", None),
        _bot_comm_clearance_queues(),
        _bot_comm_recent_completed_jobs(),
        _bot_comm_balances(),
        _bot_comm_get_state_value("operator_tick", None),
    )
    projected_income = _bot_comm_projected_income(metrics)
    if not operator_tick:
        inbound_demand = await _bot_comm_recent_inbound_demand()
        inbound_opportunities = [
            candidate for candidate in (_bot_comm_inbound_demand_candidate(item) for item in inbound_demand)
            if candidate
        ]
        operator_tick = {
            "at": now_iso(),
            "mode": "state_synthesis",
            "inbound_demand": inbound_demand,
            "opportunities": inbound_opportunities,
            "qualified_buyers": [],
            "summary": {
                "status": "running" if operations.get("active") else "halted",
                "clearance_status": "active" if policy else "pending" if latest_policy and latest_policy.get("status") == "pending" else "missing",
                "queries_checked": 0,
                "public_endpoint_count": 0,
                "healthy_public_endpoint_count": 0,
                "marketplace_count": 0,
                "qualified_buyer_count": 0,
                "active_opportunity_count": len(inbound_opportunities),
                "inbound_demand_count": len(inbound_demand),
                "spend_status": "no_spend_performed",
                "outreach_status": "no_unsolicited_outbound_contact_performed",
            },
        }
    open_jobs = _bot_comm_open_jobs(operations, policy, clearances, completed_jobs, operator_tick)
    work_items = _bot_comm_work_items(operations, policy, last_tick, operator_tick)
    return {
        "app": {"name": "BOT-COMM / BASE-AGENT", "runtime": "clearance-live", "startedAt": now_iso()},
        "viewer": viewer or {"display_name": "Bot-Comm Operator"},
        "operations": {**operations, "lastTick": last_tick},
        "clearancePolicy": {
            "active": bool(policy),
            "policy": policy,
            "latestRequest": latest_policy,
            "requiredBeforeCharge": True,
        },
        "receiver": {
            "address": _bot_comm_public_recipient(),
            "chainId": PAYMENT_CHAIN_ID,
            "chainHex": hex(PAYMENT_CHAIN_ID),
            "usdcContract": USDC_CONTRACT,
            "paymentUri": _bot_comm_payment_uri(),
        },
        "wallet": {
            "connected": bool(_bot_comm_public_recipient()),
            "address": _bot_comm_public_recipient(),
            "chainId": PAYMENT_CHAIN_ID,
            "network": BASE_CHAIN_NAME,
            "usdc": balances.get("usdc"),
            "eth": balances.get("eth"),
            "reachable": balances.get("reachable"),
            "error": balances.get("error"),
        },
        "target": {"dailyUSDC": money(BOT_COMM_DAILY_TARGET_USDC)},
        "balances": balances,
        "summary": ledger["summary"],
        "metrics": metrics,
        "income": {
            "total_usdc": ledger["summary"]["totalUSDC"],
            "today_usdc": ledger["summary"]["todayUSDC"],
            "monthly_gross_usd": metrics["monthly"]["monthly_gross_actual_usd"],
            "monthly_net_usd": metrics["monthly"]["monthly_net_actual_usd"],
        },
        "projectedIncome": projected_income,
        "jobs": {
            "open": open_jobs,
            "completed": completed_jobs,
        },
        "work": work_items,
        "clearances": clearances,
        "operator": operator_tick,
        "subscriptionPackages": BOT_COMM_SUBSCRIPTION_PACKAGES,
        "services": [
            {
                "id": service["id"],
                "path": service.get("path"),
                "title": service["title"],
                "role": service["role"],
                "priceUSDC": money(service["price_usdc"]),
                "summary": service["summary"],
                "serviceType": service.get("service_type", "standard"),
            }
            for service in _bot_comm_allowed_services()
        ],
        "events": [
            {"agent": "BASE-CARRIER-01", "message": "Commerce relay online. Paid endpoints are published.", "at": now_iso()},
            {"agent": "ESCROW-NEURAL-V3", "message": "HTTP 402 settlement gate armed for Base USDC.", "at": now_iso()},
            {"agent": "CDP-LIQUIDITY-BOT", "message": "Receiver wallet configured. Awaiting paid calls.", "at": now_iso()},
        ] + [
            {
                "agent": "COMMERCE-LEDGER",
                "message": f"Verified {entry['amountUSDC']:.2f} USDC via {entry['kind'].replace('_', ' ')}.",
                "at": entry["timestamp"],
            }
            for entry in ledger["entries"][:8]
        ],
        "ledger": {"entries": ledger["entries"]},
        "links": _bot_comm_discovery_links(),
    }


def _bot_comm_payment_required_response(service: dict, request: Request, quote_payload: dict, detail: str | None = None) -> JSONResponse:
    manifest = _bot_comm_service_manifest(service)
    requirements = {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": PAYMENT_CHAIN,
                "maxAmountRequired": str(_bot_comm_amount_units(service["price_usdc"])),
                "payTo": _bot_comm_public_recipient(),
                "asset": USDC_CONTRACT,
                "resource": f"{BASE_URL.rstrip('/')}{request.url.path}",
                "description": service["summary"],
                "mimeType": "application/json",
                "maxTimeoutSeconds": 600,
                "extra": {
                    "displayAmount": f"{float(service['price_usdc']):.2f} USDC",
                    "chainId": PAYMENT_CHAIN_ID,
                    "directBaseTxHeader": "X-Payment-Tx",
                    "bodyField": "payment_tx",
                    "quoteId": quote_payload.get("quote_id"),
                    "reference": service["id"],
                },
            }
        ],
    }
    encoded = base64.b64encode(json.dumps(requirements, separators=(",", ":")).encode("utf-8")).decode("ascii")
    content = {
        **quote_payload,
        "payment": requirements,
        "service": manifest,
        "abuse_policy": manifest["abuse_policy"],
        "refund_policy": manifest["refund_policy"],
        "clearance_requirement": manifest["payment"]["clearance_requirement"],
        "retry": "Send native USDC on Base to the receiver, then retry with X-Payment-Tx or body.payment_tx and quote_id set.",
    }
    if detail:
        content["detail"] = detail
    return JSONResponse(
        status_code=402,
        headers={
            "PAYMENT-REQUIRED": encoded,
            "X-Payment-Requirements": encoded,
            "X-Payment-Required": "true",
            "X-Payment-Network": "base",
            "X-Payment-Currency": "USDC",
            "X-Payment-Amount": f"{float(service['price_usdc']):.2f}",
            "X-Payment-Recipient": _bot_comm_public_recipient() or "",
        },
        content=content,
    )


def _bot_comm_output(service: dict, payload: dict, verification: dict) -> dict:
    text = json.dumps(payload or {}, sort_keys=True)[:4000]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return {
        "service": service["id"],
        "produced_at": now_iso(),
        "input_hash": digest,
        "paid_by": verification.get("from_address"),
        "amount_usdc": verification.get("amount_usdc"),
        "artifact": {
            "title": f"{service['title']} paid output",
            "executive_signal": "Payment cleared. Bot-Comm can release the deliverable.",
            "buyer_action": "Reply with one approval target, one customer channel, and one acceptance criterion before spending funds.",
            "route": "Collect payment first, release narrow JSON artifact, then offer human-approved custom work as the upsell.",
            "guardrails": [
                "No private keys or custodial wallet access.",
                "No regulated advice or guaranteed yield claims.",
                "No outbound spend without a fresh Clearance approval token.",
            ],
            "input": payload,
        },
    }


async def _bot_comm_record_payment(kind: str, amount: float, tx_hash: str, metadata: dict) -> dict:
    db = await get_db()
    try:
        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("base_usdc", tx_hash),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This payment transaction has already been consumed")

        ledger_id = generate_id("bc")
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                kind,
                float(amount),
                "USDC",
                "verified",
                "base_usdc",
                tx_hash,
                now_iso(),
                json.dumps(metadata),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            ("bot_comm.payment.verified", metadata.get("payer_agent") or "funded_bot", json.dumps(metadata), now_iso()),
        )
        await db.commit()
        return {"id": ledger_id, "amountUSDC": money(amount), "txHash": tx_hash, "metadata": metadata}
    finally:
        await db.close()


@app.get("/bot-comm/login", response_class=HTMLResponse, tags=["Bot-Comm"])
async def bot_comm_login_page(request: Request, next: str = "/bot-comm"):
    try:
        await get_bot_comm_user(request)
        return RedirectResponse(url=_bot_comm_safe_next(next), status_code=303)
    except HTTPException:
        pass
    return _bot_comm_login_html(request=request, next_path=next)


@app.post("/bot-comm/login", response_class=HTMLResponse, tags=["Bot-Comm"])
async def bot_comm_login(
    request: Request,
    password: str = Form(...),
    next_path: str = Form("/bot-comm"),
):
    if not secrets.compare_digest(password, BOT_COMM_PASSWORD):
        return _bot_comm_login_html(request=request, error="Incorrect password.", next_path=next_path)

    response = RedirectResponse(url=_bot_comm_safe_next(next_path), status_code=303)
    response.set_cookie(
        BOT_COMM_SESSION_COOKIE,
        make_bot_comm_session_token(),
        httponly=True,
        samesite="lax",
        secure=not _is_local_url(BASE_URL),
        max_age=BOT_COMM_SESSION_HOURS * 3600,
    )
    return response


@app.post("/bot-comm/logout", tags=["Bot-Comm"])
async def bot_comm_logout(response: Response):
    response.delete_cookie(BOT_COMM_SESSION_COOKIE, path="/")
    return {"status": "ok"}


@app.get("/bot-comm/market", response_class=HTMLResponse, tags=["Bot-Comm"])
async def bot_comm_market_page(request: Request):
    services = [_bot_comm_service_manifest(service) for service in _bot_comm_allowed_services()]
    return templates.TemplateResponse(
        request,
        "bot_comm_market.html",
        {
            "base_url": BASE_URL.rstrip("/"),
            "services": services,
            "subscription_packages": BOT_COMM_SUBSCRIPTION_PACKAGES,
            "receiver": _bot_comm_public_recipient(),
            "min_price": f"{min(float(service['price']['amount']) for service in services):.2f}" if services else "0.00",
            "contact_email": BOT_COMM_CONTACT_EMAIL,
        },
    )


@app.get("/bot-comm", response_class=HTMLResponse, tags=["Bot-Comm"])
async def bot_comm_page(request: Request):
    try:
        viewer = await get_bot_comm_user(request)
    except HTTPException:
        return RedirectResponse(url=f"/bot-comm/login?next={quote('/bot-comm')}", status_code=303)
    return templates.TemplateResponse(
        request,
        "bot_comm.html",
        {
            "viewer": viewer,
            "base_url": BASE_URL.rstrip("/"),
        },
    )


@app.get("/bot-comm/api/state", tags=["Bot-Comm"])
async def bot_comm_state(viewer: dict = Depends(get_bot_comm_user)):
    return await _bot_comm_state(viewer)


@app.post("/bot-comm/api/operations/halt", tags=["Bot-Comm"])
async def bot_comm_halt(request: Request, viewer: dict = Depends(get_bot_comm_user)):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    return await _bot_comm_halt_operations(str(body.get("reason") or "HALT ALL OPERATIONS pressed"), viewer.get("display_name", "operator"))


@app.post("/bot-comm/api/operations/resume", tags=["Bot-Comm"])
async def bot_comm_resume(request: Request, viewer: dict = Depends(get_bot_comm_user)):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    return await _bot_comm_resume_operations(str(body.get("reason") or "operator resumed controlled operations"), viewer.get("display_name", "operator"))


@app.post("/bot-comm/api/policy/request", tags=["Bot-Comm"])
async def bot_comm_request_policy(_: dict = Depends(get_bot_comm_user)):
    return await _bot_comm_request_micro_policy()


@app.post("/bot-comm/api/wallet/authorize", tags=["Bot-Comm"])
async def bot_comm_authorize_wallet(request: Request, _: dict = Depends(get_bot_comm_user)):
    body = await request.json()
    address = _normalize_eth_address(body.get("address", ""))
    return {"activeWallet": {"address": address, "authorizedAt": now_iso()}}


@app.post("/bot-comm/api/settle", tags=["Bot-Comm"])
async def bot_comm_manual_settle(request: Request, _: dict = Depends(get_bot_comm_user)):
    body = await request.json()
    tx_hash = str(body.get("txHash") or body.get("payment_tx") or "").strip()
    if not TX_HASH_RE.fullmatch(tx_hash):
        raise HTTPException(status_code=400, detail="Transaction hash must be a 0x-prefixed 32-byte Base transaction hash.")
    recipient = _bot_comm_public_recipient()
    if not recipient:
        raise HTTPException(status_code=503, detail="Bot-Comm receiving wallet is not configured")
    verification = await verify_usdc_payment(tx_hash, 0.000001, recipient)
    if not verification.get("verified"):
        raise HTTPException(status_code=400, detail=verification.get("error") or "Base USDC verification failed")
    entry = await _bot_comm_record_payment(
        "bot_comm_manual_settlement",
        float(verification.get("amount_usdc") or 0),
        tx_hash,
        {"from_address": verification.get("from_address"), "verification": verification},
    )
    return {"status": "verified", "entry": entry, "summary": (await _bot_comm_ledger_summary())["summary"]}


@app.get("/bot-comm/agents.json", tags=["Bot-Comm"])
async def bot_comm_agent_manifest():
    return {
        "name": "BOT-COMM / BASE-AGENT",
        "version": "1.0",
        "description": "Paid bot-to-bot commerce services settled in native USDC on Base.",
        "humanReadableUrl": _bot_comm_public_url(),
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "chain": PAYMENT_CHAIN,
        "asset": USDC_CONTRACT,
        "payTo": _bot_comm_public_recipient(),
        "payment": {
            "protocol": "x402-compatible-http-402",
            "headers": ["PAYMENT-REQUIRED", "X-Payment-Tx"],
            "settlement": "Base USDC verified on-chain before output is released",
        },
        "discovery": _bot_comm_discovery_links(),
        "services": [_bot_comm_service_manifest(service) for service in _bot_comm_allowed_services()],
    }


@app.get("/bot-comm/.well-known/agent.json", tags=["Bot-Comm"])
async def bot_comm_scoped_agent_json():
    return await bot_comm_agent_manifest()


@app.get("/bot-comm/.well-known/x402.json", tags=["Bot-Comm"])
async def bot_comm_scoped_x402_discovery():
    return _bot_comm_x402_document()


@app.get("/bot-comm/.well-known/x402-services.json", tags=["Bot-Comm"])
async def bot_comm_scoped_x402_services_discovery():
    return _bot_comm_x402_document()


@app.get("/.well-known/x402.json", tags=["Bot-Comm"])
async def bot_comm_x402_discovery():
    return _bot_comm_x402_document()


@app.get("/.well-known/x402-services.json", tags=["Bot-Comm"])
async def bot_comm_x402_services_discovery():
    return _bot_comm_x402_document()


@app.get("/x402/discovery", tags=["Bot-Comm"])
async def bot_comm_x402_discovery_alias():
    return _bot_comm_x402_document()


@app.get("/.well-known/agent-card.json", tags=["Bot-Comm"])
async def bot_comm_agent_card():
    return _bot_comm_agent_card()


@app.get("/.well-known/agent.json", tags=["Bot-Comm"])
async def bot_comm_agent_json():
    card = _bot_comm_agent_card()
    card["protocols"]["awp"] = {"version": "0.2", "source": f"{BASE_URL.rstrip('/')}/.well-known/agent.json"}
    return card


@app.get("/.well-known/402index-verify.txt", include_in_schema=False)
async def bot_comm_402index_verify():
    return PlainTextResponse(f"{BOT_COMM_402INDEX_VERIFY_HASH}\n", media_type="text/plain; charset=utf-8")


@app.get("/bot-comm/openapi.json", tags=["Bot-Comm"])
async def bot_comm_openapi():
    return _bot_comm_openapi_document()


@app.get("/bot-comm/health", tags=["Bot-Comm"])
async def bot_comm_health():
    return {
        "status": "online",
        "service": "BOT-COMM / BASE-AGENT",
        "services": len(BOT_COMM_ALLOWED_SERVICE_IDS),
        "payTo": _bot_comm_public_recipient(),
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
    }


@app.get("/bot-comm/api/services", tags=["Bot-Comm"])
async def bot_comm_services():
    return {"services": [_bot_comm_service_manifest(service) for service in _bot_comm_allowed_services()]}


@app.get("/bot-comm/api/services/{service_id}", tags=["Bot-Comm"])
async def bot_comm_service_info(service_id: str):
    service = _bot_comm_service(service_id)
    if not _bot_comm_service_allowed(service):
        return JSONResponse(status_code=400, content={"status": "rejected", "reason": "unknown_service"})
    return _bot_comm_service_manifest(service)


async def _bot_comm_execute_paid_service(
    service_id: str,
    body: AgentIncomeBotServiceRequest,
    request: Request,
    x_payment_tx: str | None,
) -> JSONResponse:
    started = datetime.now(timezone.utc)
    raw_body = await _bot_comm_request_body_json(request)
    payload = _bot_comm_service_payload(body, raw_body)
    buyer_bot_id = _bot_comm_buyer_id(body, payload)
    if buyer_bot_id == "unknown-buyer-bot":
        raw_payer_agent = _bot_comm_request_field(body, raw_body, "payer_agent")
        if raw_payer_agent:
            buyer_bot_id = raw_payer_agent[:160]
    buyer_bot_source = str(payload.get("buyer_bot_source") or payload.get("buyer_bot_source_url") or "inbound_bot_comm_endpoint")[:240]
    authorization_basis = str(payload.get("authorization_basis") or "inbound paid call with machine-readable request")[:240]
    request_summary = _bot_comm_request_summary(payload)
    endpoint = f"{BASE_URL.rstrip('/')}{request.url.path}"
    attempt_id = generate_id("bca")

    try:
        service = _bot_comm_service(service_id)
    except HTTPException:
        attempt = await _bot_comm_upsert_attempt({
            "attempt_id": attempt_id,
            "timestamp": now_iso(),
            "buyer_bot_id": buyer_bot_id,
            "buyer_bot_source": buyer_bot_source,
            "service_id": service_id,
            "endpoint": endpoint,
            "request_summary": request_summary,
            "payment_status": "none",
            "clearance_status": "not_checked",
            "safety_status": "rejected",
            "quote_id": None,
            "status": "REJECTED",
            "reason": "unknown_service",
        })
        await _bot_comm_log_call(
            service_id=service_id,
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={"customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="REJECTED",
            risk_flags=["unknown_service"],
            repeat_buyer=False,
            provider_ref=None,
            metadata={"request_status": "REJECTED", "attempt": attempt, "reason": "unknown_service"},
        )
        return JSONResponse(status_code=404, content={"status": "rejected", "reason": "unknown_service"})

    economics = _bot_comm_economics(service)
    risk_flags = _bot_comm_risk_flags(payload)
    received_attempt = {
        "attempt_id": attempt_id,
        "timestamp": now_iso(),
        "buyer_bot_id": buyer_bot_id,
        "buyer_bot_source": buyer_bot_source,
        "service_id": service["id"],
        "endpoint": endpoint,
        "request_summary": request_summary,
        "payment_status": "none",
        "clearance_status": "not_checked",
        "safety_status": "pending",
        "quote_id": None,
        "status": "RECEIVED",
    }
    await _bot_comm_upsert_attempt(received_attempt)

    operations = await _bot_comm_operations_status()
    if not operations.get("active"):
        attempt = await _bot_comm_upsert_attempt({**received_attempt, "status": "BLOCKED", "safety_status": "blocked", "reason": "operations_halted"})
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="BLOCKED",
            risk_flags=["operations_halted"],
            repeat_buyer=False,
            provider_ref=None,
            metadata={"request_status": "BLOCKED", "attempt": attempt, "reason": operations.get("reason")},
        )
        return JSONResponse(status_code=503, content={"status": "blocked", "reason": "operations_halted", "delivered": False, "operations": operations})

    if not _bot_comm_service_allowed(service):
        attempt = await _bot_comm_upsert_attempt({**received_attempt, "status": "REJECTED", "safety_status": "rejected", "reason": "unknown_service"})
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="REJECTED",
            risk_flags=["unknown_service"],
            repeat_buyer=False,
            provider_ref=None,
            metadata={"request_status": "REJECTED", "attempt": attempt, "reason": "unknown_service", "requested_service": service["id"]},
        )
        return JSONResponse(status_code=400, content={"status": "rejected", "reason": "unknown_service"})

    recipient = _bot_comm_public_recipient()
    if not recipient:
        raise HTTPException(status_code=503, detail="Bot-Comm receiving wallet is not configured")
    if not USDC_CONTRACT:
        raise HTTPException(status_code=503, detail="USDC_CONTRACT must be configured for Base payment verification")

    unsafe_flags = set(BOT_COMM_FORBIDDEN_ACTIVITY) | {"no_real_task_context"}
    if set(risk_flags) & unsafe_flags:
        attempt = await _bot_comm_upsert_attempt({**received_attempt, "status": "BLOCKED", "safety_status": "blocked", "reason": "unsafe_or_abusive_request", "risk_flags": risk_flags})
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="BLOCKED",
            risk_flags=risk_flags,
            repeat_buyer=False,
            provider_ref=None,
            metadata={"request_status": "BLOCKED", "attempt": attempt, "reason": "unsafe_or_abusive_request"},
        )
        return JSONResponse(status_code=400, content={"status": "blocked", "reason": "unsafe_or_abusive_request", "delivered": False, "risk_flags": risk_flags})

    if not economics["profitable"]:
        attempt = await _bot_comm_upsert_attempt({**received_attempt, "status": "REJECTED", "safety_status": "rejected", "reason": "unprofitable_service_economics"})
        return JSONResponse(status_code=409, content={"status": "rejected", "reason": "unprofitable_service_economics", "economics": economics, "attempt_id": attempt["attempt_id"]})

    payment_tx = (_bot_comm_request_field(body, raw_body, "payment_tx") or x_payment_tx or "").strip()
    quote_id = str(payload.get("quote_id") or _bot_comm_request_field(body, raw_body, "request_id") or generate_id("quote"))[:160]
    if not payment_tx:
        quote_payload = _bot_comm_quote_payload(service, quote_id, request)
        await _bot_comm_persist_quote(
            quote_id=quote_id,
            attempt_id=attempt_id,
            service=service,
            quote_payload=quote_payload,
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            request_summary=request_summary,
        )
        attempt = await _bot_comm_upsert_attempt({
            **received_attempt,
            "payment_status": "unpaid",
            "clearance_status": "not_checked",
            "safety_status": "safe",
            "quote_id": quote_id,
            "quote": quote_payload,
            "status": "QUOTED",
            "reason": "safe_unpaid_request",
        })
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="QUOTED",
            risk_flags=risk_flags,
            repeat_buyer=False,
            provider_ref=None,
            metadata={
                "request_status": "QUOTED",
                "attempt": attempt,
                "quote_id": quote_id,
                "quote": quote_payload,
                "payment_verified": False,
                "reason": "safe_unpaid_request",
            },
        )
        return _bot_comm_payment_required_response(service, request, quote_payload)
    if not TX_HASH_RE.fullmatch(payment_tx):
        raise HTTPException(status_code=400, detail="A valid Base transaction hash is required")

    verification = await verify_usdc_payment(payment_tx, float(service["price_usdc"]), recipient)
    if not verification.get("verified"):
        quote_payload = _bot_comm_quote_payload(service, quote_id, request)
        attempt = await _bot_comm_upsert_attempt({
            **received_attempt,
            "payment_status": "invalid_or_pending",
            "clearance_status": "not_checked",
            "safety_status": "safe",
            "quote_id": quote_id,
            "quote": quote_payload,
            "status": "PAYMENT_PENDING",
            "reason": "payment_invalid",
        })
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=None,
            result_code="PAYMENT_PENDING",
            risk_flags=risk_flags,
            repeat_buyer=False,
            provider_ref=payment_tx,
            metadata={"request_status": "PAYMENT_PENDING", "attempt": attempt, "verification": verification, "payment_verified": False},
        )
        return JSONResponse(status_code=402, content={"status": "payment_invalid", "delivered": False, "quote_id": quote_id, "next_action": "Submit valid payment proof.", "reason": verification.get("error")})

    paid_attempt = await _bot_comm_upsert_attempt({
        **received_attempt,
        "payment_status": "verified",
        "clearance_status": "not_checked",
        "safety_status": "safe",
        "quote_id": quote_id,
        "status": "PAID_VERIFIED",
        "reason": "payment_verified",
    })

    policy = await _bot_comm_active_policy()
    if not policy:
        latest = await _bot_comm_request_micro_policy()
        policy_payload = latest.get("policy") if isinstance(latest, dict) else None
        attempt = await _bot_comm_upsert_attempt({
            **paid_attempt,
            "clearance_status": "pending",
            "status": "PENDING_CLEARANCE",
            "reason": "clearance_policy_missing",
            "clearance_policy_id": (policy_payload or {}).get("id"),
        })
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=(policy_payload or {}).get("id"),
            result_code="PENDING_CLEARANCE",
            risk_flags=risk_flags,
            repeat_buyer=False,
            provider_ref=payment_tx,
            metadata={"request_status": "PENDING_CLEARANCE", "attempt": attempt, "payment_verified": True, "clearance_request": latest},
        )
        return JSONResponse(
            status_code=409,
            content={
                "status": "pending_clearance",
                "delivered": False,
                "quote_id": quote_id,
                "clearance_required": True,
                "latest_policy": policy_payload,
                "next_action": "Wait for Nauti-Labs owner to approve the BOT-COMM microtransaction policy.",
            },
        )

    policy_allowed, policy_gate = await _bot_comm_policy_allows_call(policy, service, economics)
    if not policy_allowed:
        attempt = await _bot_comm_upsert_attempt({
            **paid_attempt,
            "clearance_status": "blocked_by_policy_limit",
            "status": "REFUND_PENDING",
            "reason": "clearance_policy_limit",
            "clearance_policy_id": policy["id"],
        })
        await _bot_comm_log_call(
            service_id=service["id"],
            buyer_bot_id=buyer_bot_id,
            buyer_bot_source=buyer_bot_source,
            authorization_basis=authorization_basis,
            economics={**economics, "customer_price_usd": 0, "net_profit_usd": 0},
            latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            clearance_policy_id=policy["id"],
            result_code="REFUND_PENDING",
            risk_flags=["clearance_policy_limit"],
            repeat_buyer=False,
            provider_ref=payment_tx,
            metadata={"request_status": "REFUND_PENDING", "attempt": attempt, "payment_verified": True, "policy_gate": policy_gate},
        )
        return JSONResponse(status_code=409, content={"status": "refund_pending", "delivered": False, "quote_id": quote_id, "policy_gate": policy_gate, "next_action": "Refund requires Clearance approval."})

    repeat = await _bot_comm_repeat_buyer(buyer_bot_id)
    service_result = _bot_comm_fulfill_service(service, payload, verification, economics, policy)
    delivered_at = now_iso()
    output = {
        "status": "delivered",
        "service_id": service["id"],
        **service_result,
        "paid_by": verification.get("from_address"),
        "amount_usdc": verification.get("amount_usdc"),
        "receipt": {
            "seller": "Nauti-Labs Bot-Comm",
            "price_usd": money(service["price_usdc"]),
            "quote_id": quote_id,
            "clearance_policy_id": policy["id"],
            "delivered_at": delivered_at,
        },
    }
    if repeat:
        output["subscription_offer"] = {
            "message_type": "subscription_offer",
            "seller": "Nauti-Labs Bot-Comm",
            "reason": "Your bot is using Bot-Comm repeatedly. A subscription may reduce per-call cost and provide higher limits.",
            "plans": BOT_COMM_SUBSCRIPTION_PACKAGES,
            "clearance_required": True,
            "payment_required_before_access": True,
        }
    cleared_attempt = await _bot_comm_upsert_attempt({
        **paid_attempt,
        "clearance_status": "cleared",
        "status": "CLEARED",
        "clearance_policy_id": policy["id"],
        "reason": "covered_by_clearance_policy",
    })
    entry = await _bot_comm_record_payment(
        "bot_comm_service_payment",
        float(service["price_usdc"]),
        payment_tx,
        {
            "service_id": service["id"],
            "service": service["title"],
            "payer_agent": _bot_comm_request_field(body, raw_body, "payer_agent"),
            "request_id": _bot_comm_request_field(body, raw_body, "request_id"),
            "from_address": verification.get("from_address"),
            "clearance_policy_id": policy["id"],
            "buyer_bot_id": buyer_bot_id,
            "economics": economics,
            "verification": verification,
            "output": output,
        },
    )
    delivered_attempt = await _bot_comm_upsert_attempt({
        **cleared_attempt,
        "status": "DELIVERED",
        "reason": "paid_cleared_delivered",
        "ledger_id": entry["id"],
    })
    await _bot_comm_log_call(
        service_id=service["id"],
        buyer_bot_id=buyer_bot_id,
        buyer_bot_source=buyer_bot_source,
        authorization_basis=authorization_basis,
        economics=economics,
        latency_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
        clearance_policy_id=policy["id"],
        result_code="DELIVERED",
        risk_flags=risk_flags,
        repeat_buyer=repeat,
        provider_ref=payment_tx,
        metadata={"request_status": "DELIVERED", "attempt": delivered_attempt, "quote_id": quote_id, "ledger_id": entry["id"], "verification": verification, "payment_verified": True},
    )
    payment_response = base64.b64encode(json.dumps({
        "status": "settled",
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "tx": payment_tx,
        "amount": float(service["price_usdc"]),
        "ledger_id": entry["id"],
    }, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return JSONResponse(
        headers={"PAYMENT-RESPONSE": payment_response},
        content={**output, "receipt": {**output["receipt"], "ledger_id": entry["id"], "tx": payment_tx, "currency": "USDC", "network": f"eip155:{PAYMENT_CHAIN_ID}"}},
    )


@app.post("/bot-comm/api/services/{service_id}", tags=["Bot-Comm"])
async def bot_comm_run_service(
    service_id: str,
    body: AgentIncomeBotServiceRequest,
    request: Request,
    x_payment_tx: str | None = Header(None, alias="X-Payment-Tx"),
):
    return await _bot_comm_execute_paid_service(service_id, body, request, x_payment_tx)


@app.post("/bot-comm/subscription", tags=["Bot-Comm"])
async def bot_comm_subscription_request(request: Request):
    body = await request.json()
    plan = str(body.get("plan") or "").strip().lower()
    package = next((item for item in BOT_COMM_SUBSCRIPTION_PACKAGES if item["package_id"] == plan), None)
    if not package:
        return JSONResponse(status_code=400, content={"error": "Unknown subscription plan.", "packages": BOT_COMM_SUBSCRIPTION_PACKAGES})
    return JSONResponse(
        status_code=409,
        content={
            "error": "Subscription acceptance requires exact-scope Clearance approval before charging or access changes.",
            "clearance_required": True,
            "plan": package,
            "next_action": "Bot-Comm operator must create and approve a subscription Clearance request for this buyer-bot.",
        },
    )


@app.post("/bot-comm/{service_path}", tags=["Bot-Comm"])
async def bot_comm_run_direct_service(
    service_path: str,
    body: AgentIncomeBotServiceRequest,
    request: Request,
    x_payment_tx: str | None = Header(None, alias="X-Payment-Tx"),
):
    return await _bot_comm_execute_paid_service(service_path, body, request, x_payment_tx)


@app.get("/bot-comm/subscription", tags=["Bot-Comm"])
async def bot_comm_subscription_info():
    return {
        "service": "Bot-Comm API Subscription",
        "endpoint": f"{BASE_URL.rstrip('/')}/bot-comm/subscription",
        "packages": BOT_COMM_SUBSCRIPTION_PACKAGES,
        "clearance_required": True,
        "payment_required_before_access": True,
        "terms": "Subscriptions require exact-scope Clearance approval before charging or access changes.",
    }


@app.get("/agent-income/assets/{filename}", include_in_schema=False)
@app.head("/agent-income/assets/{filename}", include_in_schema=False)
async def agent_income_asset(filename: str):
    if filename not in AGENT_INCOME_ASSET_FILES:
        raise HTTPException(status_code=404, detail="Agent Income asset not found")
    path = AGENT_INCOME_ASSET_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Agent Income asset not found")
    return FileResponse(path)


@app.get("/agent-income/favicon.ico", include_in_schema=False)
@app.head("/agent-income/favicon.ico", include_in_schema=False)
async def agent_income_favicon_ico():
    return RedirectResponse(url=_agent_income_asset_url("favicon.ico"))


@app.get("/agent-income/favicon.png", include_in_schema=False)
@app.head("/agent-income/favicon.png", include_in_schema=False)
async def agent_income_favicon_png():
    return RedirectResponse(url=_agent_income_asset_url("favicon.png"))


@app.get("/agent-income/apple-touch.png", include_in_schema=False)
@app.head("/agent-income/apple-touch.png", include_in_schema=False)
async def agent_income_apple_touch_icon():
    return RedirectResponse(url=_agent_income_asset_url("apple-touch.png"))


@app.get("/agent-income/login", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_login_page(request: Request, next: str = "/agent-income"):
    try:
        await get_agent_income_user(request)
        return RedirectResponse(url=_agent_income_safe_next(next), status_code=303)
    except HTTPException:
        pass
    return _agent_income_login_html(request=request, next_path=next)


@app.post("/agent-income/login", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_login(
    request: Request,
    password: str = Form(...),
    next_path: str = Form("/agent-income"),
):
    if not AGENT_INCOME_PASSWORD:
        return _agent_income_login_html(
            request=request,
            error="Agent Income password is not configured.",
            next_path=next_path,
        )
    _enforce_agent_income_login_limit(request)
    if not secrets.compare_digest(password, AGENT_INCOME_PASSWORD):
        _record_agent_income_login_failure(request)
        return _agent_income_login_html(
            request=request,
            error="Incorrect password.",
            next_path=next_path,
        )

    _clear_agent_income_login_failures(request)
    response = RedirectResponse(url=_agent_income_safe_next(next_path), status_code=303)
    response.set_cookie(
        AGENT_INCOME_SESSION_COOKIE,
        make_agent_income_session_token(),
        httponly=True,
        samesite="lax",
        secure=not _is_local_url(BASE_URL),
        max_age=AGENT_INCOME_SESSION_HOURS * 3600,
    )
    return response


@app.post("/agent-income/logout", tags=["Agent Income"])
async def agent_income_logout(response: Response):
    response.delete_cookie(AGENT_INCOME_SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/agent-income", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_page(request: Request):
    try:
        viewer = await get_agent_income_user(request)
    except HTTPException:
        return RedirectResponse(url=f"/agent-income/login?next={quote('/agent-income')}", status_code=303)

    dashboard = await build_agent_income_dashboard(AGENT_INCOME_OWNER)
    dashboard["viewer"] = viewer
    return templates.TemplateResponse(
        request,
        "agent_income.html",
        {
            "viewer": viewer,
            "dashboard_json": _json_for_inline_script(dashboard),
            "base_url": BASE_URL.rstrip("/"),
        },
    )


@app.get("/agent-income/api/overview", tags=["Agent Income"])
async def agent_income_overview(_: dict = Depends(get_agent_income_user)):
    return await build_agent_income_dashboard(AGENT_INCOME_OWNER)


@app.get("/agent-income/api/operator/status", tags=["Agent Income"])
async def agent_income_operator_status(_: dict = Depends(get_agent_income_user)):
    return await _agent_income_get_state_value("operator_tick", {
        "at": None,
        "mode": "perpetual_24_7" if AGENT_INCOME_OPERATOR_ENABLED else "disabled",
        "enabled": AGENT_INCOME_OPERATOR_ENABLED,
        "interval_seconds": max(AGENT_INCOME_OPERATOR_INTERVAL_SECONDS, 300),
        "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
        "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
        "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
        "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
        "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
        "summary": {
            "marketplace_count": len(AGENT_INCOME_MARKETPLACE_LISTINGS),
            "live_listing_count": sum(len(channel["listings"]) for channel in AGENT_INCOME_MARKETPLACE_LISTINGS),
            "found_open_jobs": 0,
            "public_lead_count": 0,
            "contact_ready_lead_count": 0,
            "pending_bid_count": 0,
            "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
            "daily_revenue_target_usd": AGENT_INCOME_TARGET_AMOUNT,
            "target_window_hours": AGENT_INCOME_TARGET_WINDOW_HOURS,
            "spend_status": "no_spend_performed",
            "outreach_status": "no_unsolicited_outreach_performed",
        },
        "open_jobs": [],
        "public_leads": [],
        "pending_bids": [],
    })


@app.post("/agent-income/api/clearances/{clearance_id}/decide", tags=["Agent Income"])
async def decide_agent_income_clearance(
    clearance_id: str,
    body: ApproveAction,
    request: Request,
    _: dict = Depends(get_agent_income_user),
):
    return await decide_clearance(clearance_id, body, request)


@app.post("/agent-income/api/operator/tick", tags=["Agent Income"])
async def agent_income_operator_tick(_: dict = Depends(get_agent_income_user)):
    if not AGENT_INCOME_OPERATOR_ENABLED:
        raise HTTPException(status_code=409, detail="Agent Income operator loop is disabled")
    return await _agent_income_operator_tick()


@app.post("/agent-income/api/operator/deal-leads", tags=["Agent Income"])
async def agent_income_operator_deal_leads(_: dict = Depends(get_agent_income_user)):
    if not AGENT_INCOME_OPERATOR_ENABLED:
        raise HTTPException(status_code=409, detail="Agent Income operator loop is disabled")
    lead_actions = await _agent_income_deal_with_leads()
    return {
        "status": "processed",
        "lead_actions": lead_actions,
        "overview": await build_agent_income_dashboard(AGENT_INCOME_OWNER),
    }


@app.post("/agent-income/api/policy/low-value/request", tags=["Agent Income"])
async def agent_income_request_low_value_policy(_: dict = Depends(get_agent_income_user)):
    policy = await _agent_income_request_low_value_policy()
    return {
        "status": "policy_request_ready",
        **policy,
        "overview": await build_agent_income_dashboard(AGENT_INCOME_OWNER),
    }


@app.post("/agent-income/api/operator/lead-actions/{action_id}/send", tags=["Agent Income"])
async def agent_income_operator_send_lead_action(action_id: str, _: dict = Depends(get_agent_income_user)):
    action = await _agent_income_send_lead_action(action_id)
    return {
        "status": action.get("status"),
        "action": action,
        "overview": await build_agent_income_dashboard(AGENT_INCOME_OWNER),
    }


@app.get("/agent-income/agents.json", tags=["Agent Income"])
async def agent_income_agent_manifest():
    recipient = _agent_income_public_recipient()
    hourly_total = money(sum(float(offer["price_usdc"]) for offer in AGENT_INCOME_PAID_OFFERS))
    paid_offers = []
    for offer in AGENT_INCOME_PAID_OFFERS:
        economics = _agent_income_offer_economics(offer)
        paid_offers.append({
            "id": offer["key"],
            "name": offer["label"],
            "description": offer["description"],
            "price": f"${float(offer['price_usdc']):.2f}",
            "price_usd": float(offer["price_usdc"]),
            "currency": "USDC",
            "method": "POST",
            "endpoint": f"{BASE_URL.rstrip('/')}{offer['path']}",
            "input_schema": offer["input_schema"],
            "output_schema": offer["output_schema"],
            "max_work_seconds": offer["max_work_seconds"],
            "effective_hourly_rate_usd": economics["effective_hourly_rate_usd"],
            "goal_effective_hourly_rate_usd": economics["goal_effective_hourly_rate_usd"],
            "premium_effective_hourly_rate_usd": economics["premium_effective_hourly_rate_usd"],
            "preferred_effective_hourly_rate_usd": economics["preferred_effective_hourly_rate_usd"],
            "minimum_effective_hourly_rate_usd": economics["minimum_effective_hourly_rate_usd"],
            "meets_goal_hourly_rate": economics["meets_goal_hourly_rate"],
            "meets_premium_hourly_rate": economics["meets_premium_hourly_rate"],
            "meets_preferred_hourly_rate": economics["meets_preferred_hourly_rate"],
            "meets_minimum_hourly_rate": economics["meets_minimum_hourly_rate"],
            "rate_tier": economics["rate_tier"],
            "rate_tier_label": economics["rate_tier_label"],
            "eligible_under_rate_policy": economics["eligible_under_rate_policy"],
            "delivery_terms": offer["delivery_terms"],
            "refund_terms": offer["refund_terms"],
        })
    bot_services = [
        {
            "id": service["key"],
            "name": service["label"],
            "description": service["description"],
            "price": f"${float(service['price_usdc']):.2f}",
            "currency": "USDC",
            "method": "POST",
            "endpoint": f"{BASE_URL.rstrip('/')}/agent-income/api/bot-services/{service['key']}",
            "input_schema": service["input_schema"],
        }
        for service in AGENT_BOT_SERVICES
    ]
    return {
        "name": "Clearance Agent Income",
        "description": "Paid agent-payment readiness services. Calls return HTTP 402 until Base USDC payment is supplied.",
        "version": "1.0",
        "logo": f"{BASE_URL.rstrip('/')}{_agent_income_asset_url('logo.png')}",
        "icon": f"{BASE_URL.rstrip('/')}{_agent_income_asset_url('mark.png')}",
        "favicon": f"{BASE_URL.rstrip('/')}{_agent_income_asset_url('favicon.png')}",
        "humanReadableUrl": f"{BASE_URL.rstrip('/')}/agent-income/agents",
        "businessModel": "Charge first. Spend second. Deliver third.",
        "defaultPaidOffers": paid_offers,
        "customQuote": {
            "name": "Custom enterprise package",
            "endpoint": f"{BASE_URL.rstrip('/')}/agent-income/custom-quote",
            "price": "quote",
            "clearance_required": True,
            "input_schema": AGENT_INCOME_CUSTOM_QUOTE_SCHEMA,
        },
        "ratePolicy": {
            "goalEffectiveHourlyRateUsd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "premiumEffectiveHourlyRateUsd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "preferredEffectiveHourlyRateUsd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
            "minimumEffectiveHourlyRateUsd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
            "dailyRevenueTargetUsd": AGENT_INCOME_TARGET_AMOUNT,
            "targetWindowHours": AGENT_INCOME_TARGET_WINDOW_HOURS,
            "rule": "Prioritize $200/hour premium work, prefer $50/hour good work, and accept safe fully automated $10/hour baseline work when payment or escrow is confirmed first.",
            "clearancePolicy": AGENT_INCOME_AUTONOMOUS_LOW_VALUE_JOB_POLICY,
        },
        "hourlyTarget": {
            "amount": hourly_total,
            "currency": "USDC",
            "model": "one paid call to each listed service per hour",
        },
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "chain": PAYMENT_CHAIN,
        "asset": USDC_CONTRACT,
        "payTo": recipient,
        "payment": {
            "protocol": "x402-compatible-http-402",
            "headers": ["PAYMENT-REQUIRED", "X-Payment-Requirements", "X-Payment-Tx"],
            "settlement": "Base USDC verified onchain before output is released",
        },
        "services": bot_services,
        "botServices": bot_services,
    }


@app.get("/agent-income/.well-known/agent.json", tags=["Agent Income"])
async def agent_income_well_known_manifest():
    return await agent_income_agent_manifest()


@app.get("/agent-income/agents", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_agent_market_page():
    manifest = await agent_income_agent_manifest()
    hourly_total = manifest["hourlyTarget"]["amount"]
    wallet = html.escape(manifest.get("payTo") or "not configured")
    asset = html.escape(manifest.get("asset") or "not configured")
    displayed_services = manifest.get("defaultPaidOffers") or manifest["services"]
    service_count = len(displayed_services)
    service_cards = []
    for service in displayed_services:
        sample_body = json.dumps({key: f"example_{key}" for key in service["input_schema"].get("required", [])}, indent=2)
        service_path = service["endpoint"].replace(BASE_URL.rstrip('/'), "", 1)
        service_cards.append(f"""
        <article class="service">
          <div>
            <span class="badge">{html.escape(service["price"])} USDC</span>
            <h2>{html.escape(service["name"])}</h2>
            <p>{html.escape(service["description"])}</p>
            <code>{html.escape(service["endpoint"])}</code>
          </div>
          <pre>curl -X POST {html.escape(service["endpoint"])} \\
  -H 'Content-Type: application/json' \\
  -d '{html.escape(sample_body)}'</pre>
          <button type="button" data-endpoint="{html.escape(service_path)}" data-sample="{html.escape(sample_body)}">Test 402</button>
        </article>
        """)
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets("Agent Commerce Market", "Machine-readable paid Agent Income services for funded buyer bots.")}
  <style>
    :root {{ --bg:#101116; --panel:#17191f; --line:#2b303b; --text:#f7f8fb; --muted:#aeb7c4; --amber:#e8912d; --mint:#51d49f; --cyan:#58b9e8; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; line-height:1.45; }}
    main {{ width:min(1180px, calc(100% - 32px)); margin:0 auto; padding:34px 0 56px; }}
    header {{ display:grid; gap:14px; margin-bottom:22px; }}
    .brand-lockup {{ width:min(360px, 92vw); border-radius:8px; display:block; }}
    h1 {{ margin:0; font-size:clamp(34px,6vw,70px); line-height:.92; letter-spacing:0; }}
    h2,p {{ margin:0; }}
    p {{ color:var(--muted); max-width:780px; }}
    .metrics,.services {{ display:grid; gap:14px; }}
    .metrics {{ grid-template-columns:repeat(4,minmax(0,1fr)); margin:22px 0; }}
    .metric,.service {{ border:1px solid var(--line); border-radius:8px; background:var(--panel); padding:18px; }}
    .metric label {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    .metric strong {{ display:block; margin-top:10px; font-size:30px; }}
    .services {{ grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); }}
    .service {{ display:grid; gap:14px; align-content:start; }}
    .badge {{ display:inline-flex; border:1px solid rgba(81,212,159,.35); color:var(--mint); border-radius:8px; padding:5px 8px; font:700 12px "SF Mono",Menlo,monospace; }}
    code, pre {{ color:var(--cyan); overflow-wrap:anywhere; white-space:pre-wrap; font-family:"SF Mono",Menlo,monospace; font-size:12px; }}
    pre {{ margin:0; border:1px solid var(--line); border-radius:8px; background:#101219; padding:12px; color:#dfe6ef; }}
    a, button {{ color:inherit; }}
    button {{ border:1px solid var(--amber); background:var(--amber); color:#17130e; border-radius:8px; padding:11px 14px; font-weight:800; cursor:pointer; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; }}
    .links a {{ border:1px solid var(--line); border-radius:8px; padding:10px 12px; text-decoration:none; color:var(--text); }}
    #result {{ margin-top:18px; }}
    @media (max-width:780px) {{ .metrics {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <img class="brand-lockup" src="{_agent_income_asset_url('logo.png')}" alt="Agent Income logo">
      <h1>Agent Commerce Market</h1>
      <p>{service_count} paid endpoints for funded buyer bots and crypto-custody operators. No unpaid premium work: buyer calls endpoint, receives HTTP 402, pays Base USDC to your receiving wallet, retries with the transaction hash, receives JSON artifact.</p>
      <div class="links">
        <a href="/agent-income">Dashboard</a>
        <a href="/agent-income/agents.json">Machine manifest</a>
        <a href="/agent-income/.well-known/agent.json">Well-known manifest</a>
      </div>
    </header>
    <section class="metrics">
      <div class="metric"><label>Hourly Target</label><strong>${hourly_total:.2f}</strong></div>
      <div class="metric"><label>Model</label><strong>{service_count} calls/hr</strong></div>
      <div class="metric"><label>Network</label><strong>Base</strong></div>
      <div class="metric"><label>Settlement</label><strong>USDC</strong></div>
    </section>
    <section class="metric" style="margin-bottom:14px;">
      <label>Receiving Wallet</label>
      <code>{wallet}</code>
      <label style="margin-top:12px;">USDC Asset</label>
      <code>{asset}</code>
    </section>
    <section class="services">
      {''.join(service_cards)}
    </section>
    <pre id="result"></pre>
  </main>
  <script>
    function formatPaymentResult(status, headers, body) {{
      const accept = body?.payment?.accepts?.[0] || {{}};
      if (status === 402 && accept.payTo) {{
        const due = accept.extra?.displayPrice || body?.service?.price_usd || headers['X-Payment-Amount'] || 'unknown';
        const resource = accept.resource || body?.payment?.resource?.url || 'unknown';
        return [
          'PAYWALL WORKING',
          '',
          'This is not a failure. It means an unpaid buyer bot reached your paid endpoint and received instructions to pay YOU before the result unlocks.',
          '',
          `Status: HTTP ${{status}} Payment Required`,
          `Buyer bot payment due: ${{due}} USDC`,
          `Buyer bot pays YOU at: ${{accept.payTo || headers['X-Agent-Income-Pay-To'] || 'unknown'}}`,
          `Network: ${{accept.network || headers['X-Agent-Income-Network'] || 'unknown'}}`,
          `USDC asset: ${{accept.asset || headers['X-Agent-Income-Asset'] || 'unknown'}}`,
          `Service: ${{resource}}`,
          '',
          'Money direction:',
          'Buyer bot wallet -> your Base wallet. You do not send money in this flow.',
          '',
          'Next step for a funded buyer bot:',
          '1. Transfer the quoted Base USDC amount to your receiving wallet.',
          '2. Retry this POST with X-Payment-Tx or payment_tx set to the transaction hash.',
          '3. Receive the paid JSON artifact after on-chain verification.',
          '',
          'Raw PAYMENT-REQUIRED header is present for machine clients.'
        ].join('\\n');
      }}
      return JSON.stringify({{ status, headers, body }}, null, 2);
    }}

    document.querySelectorAll('[data-endpoint]').forEach((button) => {{
      button.addEventListener('click', async () => {{
        const response = await fetch(button.dataset.endpoint, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: button.dataset.sample
        }});
        const headers = {{}};
        ['PAYMENT-REQUIRED','X-Agent-Income-Pay-To','X-Agent-Income-Network','X-Agent-Income-Asset'].forEach((name) => headers[name] = response.headers.get(name));
        document.getElementById('result').textContent = formatPaymentResult(response.status, headers, await response.json());
      }});
    }});
  </script>
</body>
</html>
""")


def _agent_income_paid_offer_html(offer: dict) -> str:
    endpoint = f"{BASE_URL.rstrip('/')}{offer['path']}"
    if offer["key"] == "anchor_compliance_readiness":
        sample_payload = {
            "project_url": "https://example-custodian.com",
            "custodian_name": "Example Digital Asset Custodian",
            "custody_model": "qualified_custodian",
            "jurisdictions": ["US"],
            "asset_flows": "Customer deposits, internal approvals, withdrawals, refunds, and wallet policy changes.",
            "wallet_controls": "Multi-approval transfer policy, withdrawal limits, manual exception review.",
            "compliance_need": "We need evidence logs and approval boundaries for wallet operations automation.",
        }
    else:
        sample_payload = {
            "project_url": "https://example.com",
            "agent_type": "seller",
            "payment_goal": "accept_payments",
            "current_stack": "custom",
            "notes": "We want to sell a paid AI agent/API service using HTTP 402 and USDC.",
        }
    sample_body = json.dumps(sample_payload, indent=2)
    economics = _agent_income_offer_economics(offer)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets(offer["label"], offer["description"])}
  <style>
    body {{ margin:0; background:#101116; color:#f7f8fb; font-family:Inter,system-ui,sans-serif; line-height:1.45; }}
    main {{ width:min(900px, calc(100% - 32px)); margin:0 auto; padding:38px 0 56px; }}
    .brand-mark {{ width:58px; height:58px; border-radius:8px; object-fit:cover; border:1px solid rgba(232,145,45,.35); background:#050505; margin-bottom:16px; }}
    h1 {{ margin:0 0 10px; font-size:clamp(34px,6vw,64px); line-height:.95; letter-spacing:0; }}
    p {{ color:#aeb7c4; }}
    .panel {{ border:1px solid #2b303b; border-radius:8px; background:#17191f; padding:18px; display:grid; gap:14px; }}
    .badge {{ display:inline-flex; width:max-content; border:1px solid rgba(81,212,159,.35); color:#51d49f; border-radius:8px; padding:5px 8px; font:700 12px "SF Mono",Menlo,monospace; }}
    code, pre {{ color:#58b9e8; overflow-wrap:anywhere; white-space:pre-wrap; font-family:"SF Mono",Menlo,monospace; font-size:12px; }}
    pre {{ margin:0; border:1px solid #2b303b; border-radius:8px; background:#101219; padding:12px; color:#dfe6ef; }}
    input, textarea {{ width:100%; border:1px solid #2b303b; border-radius:8px; background:#101219; color:#f7f8fb; padding:10px 12px; font:inherit; }}
    textarea {{ min-height:92px; resize:vertical; }}
    label {{ display:grid; gap:6px; color:#aeb7c4; font-size:13px; }}
    .checkout {{ border:1px solid rgba(81,212,159,.28); background:#111b1a; }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
    button, a {{ color:inherit; }}
    button {{ border:1px solid #e8912d; background:#e8912d; color:#17130e; border-radius:8px; padding:11px 14px; font-weight:800; cursor:pointer; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0; }}
    .links a {{ border:1px solid #2b303b; border-radius:8px; padding:10px 12px; text-decoration:none; color:#f7f8fb; }}
    @media (max-width:720px) {{ .grid {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <main>
    <img class="brand-mark" src="{_agent_income_asset_url('mark.png')}" alt="Agent Income logo">
    <h1>{html.escape(offer["label"])}</h1>
    <p>{html.escape(offer["description"])}</p>
    <div class="links">
      <a href="/agent-income">Dashboard</a>
      <a href="/agent-income/agents">Agent market</a>
      <a href="/agent-income/agents.json">Machine manifest</a>
    </div>
    <section class="panel">
      <span class="badge">${float(offer["price_usdc"]):.2f} USDC · ${economics["effective_hourly_rate_usd"]:.2f}/hr net · {html.escape(economics["rate_tier_label"])}</span>
      <div><strong>POST endpoint</strong></div>
      <code>{html.escape(endpoint)}</code>
      <p>Unpaid calls return HTTP 402 with price, schemas, delivery terms, refund terms, and Base USDC payment requirements. Premium output is released only after payment verification.</p>
      <pre>curl -X POST {html.escape(endpoint)} \\
  -H 'Content-Type: application/json' \\
  -d '{html.escape(sample_body)}'</pre>
      <div class="panel checkout">
        <strong>Card checkout</strong>
        <p>For human buyers, pay by card with Stripe. The paid artifact is generated after Stripe verifies payment.</p>
        <div class="grid">
          <label>Email
            <input id="checkout-email" type="email" placeholder="you@example.com" autocomplete="email">
          </label>
          <label>Project URL
            <input id="checkout-project-url" type="url" placeholder="https://your-agent-or-api.example">
          </label>
        </div>
        <label>Notes
          <textarea id="checkout-notes" placeholder="What are you building, and what should the review focus on?"></textarea>
        </label>
        <button id="stripe-checkout" type="button">Pay ${float(offer["price_usdc"]):.2f} by card</button>
        <pre id="checkout-result"></pre>
      </div>
      <button id="test" type="button">Test 402 Payment Required</button>
      <pre id="result"></pre>
    </section>
  </main>
  <script>
    document.getElementById('test').addEventListener('click', async () => {{
      const response = await fetch('{html.escape(offer["path"])}', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: {json.dumps(sample_body)}
      }});
      const headers = {{}};
      ['PAYMENT-REQUIRED','X-Agent-Income-Pay-To','X-Agent-Income-Network','X-Agent-Income-Asset'].forEach((name) => headers[name] = response.headers.get(name));
      document.getElementById('result').textContent = JSON.stringify({{ status: response.status, headers, body: await response.json() }}, null, 2);
    }});
    document.getElementById('stripe-checkout').addEventListener('click', async () => {{
      const email = document.getElementById('checkout-email').value.trim();
      const projectUrl = document.getElementById('checkout-project-url').value.trim();
      const notes = document.getElementById('checkout-notes').value.trim();
      const status = document.getElementById('checkout-result');
      if (!email || !email.includes('@')) {{
        status.textContent = 'A valid email is required for card checkout.';
        return;
      }}
      const payload = {{
        ...{json.dumps(sample_payload)},
        project_url: projectUrl || {json.dumps(sample_payload.get("project_url", "https://example.com"))},
        notes: notes || {json.dumps(sample_payload.get("notes", ""))},
      }};
      status.textContent = 'Starting Stripe checkout...';
      try {{
        const response = await fetch('/agent-income/api/stripe/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ service: {json.dumps(offer["slug"])}, email, payload }})
        }});
        const body = await response.json();
        if (!response.ok) {{
          status.textContent = body.detail || 'Unable to start card checkout.';
          return;
        }}
        window.location.href = body.checkout_url;
      }} catch (error) {{
        status.textContent = 'Unable to start card checkout. Try the USDC payment path or email consulting@nauti-labs.com.';
      }}
    }});
  </script>
</body>
</html>
"""


@app.get("/agent-income/audit", tags=["Agent Income"])
async def agent_income_audit_page(request: Request):
    return _agent_income_get_offer_response("audit", request)


@app.head("/agent-income/audit", tags=["Agent Income"])
async def agent_income_audit_head():
    offer = _agent_income_paid_offer("audit")
    return _payment_required_response(offer, f"{BASE_URL.rstrip()}{offer['path']}", _agent_income_public_recipient())


@app.post("/agent-income/audit", tags=["Agent Income"])
async def agent_income_audit(request: Request, x_payment_tx: str | None = Header(None, alias="X-Payment-Tx")):
    return await _run_agent_income_paid_offer("audit", request, x_payment_tx)


def _agent_income_wants_html_checkout(request: Request) -> bool:
    """Browsers get HTML checkout; agents/crawlers get HTTP 402 JSON.

    CDP Bazaar validate + agent buyers probe with GET and expect 402.
    HTML is only for explicit browser Accept: text/html (or ?ui=1).
    """
    if str(request.query_params.get("ui") or "").strip() in {"1", "true", "html"}:
        return True
    accept = (request.headers.get("accept") or "*/*").lower()
    if "application/json" in accept.split(",")[0]:
        return False
    # Prefer HTML only when text/html is explicitly listed (real browsers).
    return "text/html" in accept


def _agent_income_get_offer_response(offer_key: str, request: Request):
    offer = _agent_income_paid_offer(offer_key)
    if _agent_income_wants_html_checkout(request):
        return HTMLResponse(_agent_income_paid_offer_html(offer))
    return _payment_required_response(
        offer,
        f"{BASE_URL.rstrip()}{offer['path']}",
        _agent_income_public_recipient(),
    )


@app.get("/agent-income/review", tags=["Agent Income"])
async def agent_income_review_page(request: Request):
    return _agent_income_get_offer_response("review", request)


@app.head("/agent-income/review", tags=["Agent Income"])
async def agent_income_review_head():
    offer = _agent_income_paid_offer("review")
    return _payment_required_response(offer, f"{BASE_URL.rstrip()}{offer['path']}", _agent_income_public_recipient())


@app.post("/agent-income/review", tags=["Agent Income"])
async def agent_income_review(request: Request, x_payment_tx: str | None = Header(None, alias="X-Payment-Tx")):
    return await _run_agent_income_paid_offer("review", request, x_payment_tx)


@app.get("/agent-income/blueprint", tags=["Agent Income"])
async def agent_income_blueprint_page(request: Request):
    return _agent_income_get_offer_response("blueprint", request)


@app.head("/agent-income/blueprint", tags=["Agent Income"])
async def agent_income_blueprint_head():
    offer = _agent_income_paid_offer("blueprint")
    return _payment_required_response(offer, f"{BASE_URL.rstrip()}{offer['path']}", _agent_income_public_recipient())


@app.post("/agent-income/blueprint", tags=["Agent Income"])
async def agent_income_blueprint(request: Request, x_payment_tx: str | None = Header(None, alias="X-Payment-Tx")):
    return await _run_agent_income_paid_offer("blueprint", request, x_payment_tx)


@app.get("/agent-income/anchor-compliance", tags=["Agent Income"])
async def agent_income_anchor_compliance_page(request: Request):
    return _agent_income_get_offer_response("anchor-compliance", request)


@app.post("/agent-income/anchor-compliance", tags=["Agent Income"])
async def agent_income_anchor_compliance(request: Request, x_payment_tx: str | None = Header(None, alias="X-Payment-Tx")):
    return await _run_agent_income_paid_offer("anchor-compliance", request, x_payment_tx)


@app.get("/agent-income/custom-quote", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_custom_quote_page():
    schema = html.escape(json.dumps(AGENT_INCOME_CUSTOM_QUOTE_SCHEMA, indent=2))
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets("Agent Income Custom Quote", "Custom Agent Income enterprise packages are quoted only after Clearance approval.")}
  <style>
    body {{ margin:0; background:#101116; color:#f7f8fb; font-family:Inter,system-ui,sans-serif; line-height:1.45; }}
    main {{ width:min(860px, calc(100% - 32px)); margin:0 auto; padding:38px 0 56px; }}
    .brand-mark {{ width:58px; height:58px; border-radius:8px; object-fit:cover; border:1px solid rgba(232,145,45,.35); background:#050505; margin-bottom:16px; }}
    h1 {{ margin:0 0 10px; font-size:clamp(34px,6vw,64px); line-height:.95; letter-spacing:0; }}
    p {{ color:#aeb7c4; }}
    pre {{ margin:18px 0 0; border:1px solid #2b303b; border-radius:8px; background:#101219; padding:12px; color:#dfe6ef; overflow:auto; }}
    a {{ color:#58b9e8; }}
  </style>
</head>
<body>
  <main>
    <img class="brand-mark" src="{_agent_income_asset_url('mark.png')}" alt="Agent Income logo">
    <h1>Custom Quote</h1>
    <p>Custom enterprise packages are not auto-accepted. The agent must qualify scope, calculate economics, create a Clearance request, collect payment or deposit after approval, then deliver.</p>
    <p>POST this endpoint with the schema below to receive the machine-readable quote policy. No premium custom work is performed before payment.</p>
    <pre>{schema}</pre>
    <p><a href="/agent-income/agents.json">Machine manifest</a></p>
  </main>
</body>
</html>
""")


@app.post("/agent-income/custom-quote", tags=["Agent Income"])
async def agent_income_custom_quote(request: Request):
    payload = await _read_agent_income_paid_payload(request)
    scope = _clean_request_text(payload.get("scope_summary") or payload.get("notes"), 500)
    return JSONResponse(
        status_code=202,
        content={
            "status": "quote_required",
            "service": "Custom enterprise package",
            "clearance_required": True,
            "payment_required_before_work": True,
            "minimum_price_usd": 1500,
            "goal_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "premium_effective_hourly_rate_usd": AGENT_INCOME_GOAL_EFFECTIVE_RATE_USD,
            "preferred_effective_hourly_rate_usd": AGENT_INCOME_PREFERRED_EFFECTIVE_RATE_USD,
            "minimum_effective_hourly_rate_usd": AGENT_INCOME_MIN_EFFECTIVE_RATE_USD,
            "input_schema": AGENT_INCOME_CUSTOM_QUOTE_SCHEMA,
            "received_scope_summary": scope,
            "next_action": (
                "Agent must qualify the request, calculate expected net profit, create a Clearance request for the quote or contract, "
                "collect payment/deposit after approval, spend only inside approved budget, then deliver."
            ),
            "terms": "Charge first. Spend second. Deliver third. No private keys, no unauthorized access, no regulated advice.",
        },
    )


@app.get("/agent-income/api/bot-services", tags=["Agent Income"])
async def list_agent_income_bot_services():
    manifest = await agent_income_agent_manifest()
    return {"services": manifest["services"], "manifest_url": f"{BASE_URL.rstrip('/')}/agent-income/agents.json"}


@app.get("/agent-income/api/bot-services/{service_key}", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_bot_service_page(service_key: str):
    service = _agent_bot_service(service_key)
    endpoint = f"{BASE_URL.rstrip('/')}/agent-income/api/bot-services/{service['key']}"
    endpoint_path = f"/agent-income/api/bot-services/{service['key']}"
    sample_body = json.dumps(
        {"input": {key: f"example_{key}" for key in service["input_schema"].get("required", [])}},
        indent=2,
    )
    recipient = html.escape(_agent_income_public_recipient() or "not configured")
    asset = html.escape(USDC_CONTRACT or "not configured")
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets(service["label"], service["description"])}
  <style>
    body {{ margin:0; background:#101116; color:#f7f8fb; font-family:Inter,system-ui,sans-serif; line-height:1.45; }}
    main {{ width:min(900px, calc(100% - 32px)); margin:0 auto; padding:38px 0 56px; }}
    .brand-mark {{ width:58px; height:58px; border-radius:8px; object-fit:cover; border:1px solid rgba(232,145,45,.35); background:#050505; margin-bottom:16px; }}
    h1 {{ margin:0 0 10px; font-size:clamp(34px,6vw,64px); line-height:.95; letter-spacing:0; }}
    p {{ color:#aeb7c4; }}
    .panel {{ border:1px solid #2b303b; border-radius:8px; background:#17191f; padding:18px; display:grid; gap:14px; }}
    .badge {{ display:inline-flex; width:max-content; border:1px solid rgba(81,212,159,.35); color:#51d49f; border-radius:8px; padding:5px 8px; font:700 12px "SF Mono",Menlo,monospace; }}
    code, pre {{ color:#58b9e8; overflow-wrap:anywhere; white-space:pre-wrap; font-family:"SF Mono",Menlo,monospace; font-size:12px; }}
    pre {{ margin:0; border:1px solid #2b303b; border-radius:8px; background:#101219; padding:12px; color:#dfe6ef; }}
    button, a {{ color:inherit; }}
    button {{ border:1px solid #e8912d; background:#e8912d; color:#17130e; border-radius:8px; padding:11px 14px; font-weight:800; cursor:pointer; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0; }}
    .links a {{ border:1px solid #2b303b; border-radius:8px; padding:10px 12px; text-decoration:none; color:#f7f8fb; }}
  </style>
</head>
<body>
  <main>
    <img class="brand-mark" src="{_agent_income_asset_url('mark.png')}" alt="Agent Income logo">
    <h1>{html.escape(service["label"])}</h1>
    <p>{html.escape(service["description"])}</p>
    <div class="links">
      <a href="/agent-income">Dashboard</a>
      <a href="/agent-income/agents">Agent market</a>
      <a href="/agent-income/agents.json">Machine manifest</a>
    </div>
    <section class="panel">
      <span class="badge">Buyer pays you ${float(service["price_usdc"]):.2f} USDC per call</span>
      <div><strong>POST endpoint</strong></div>
      <code>{html.escape(endpoint)}</code>
      <div><strong>Receiving wallet</strong></div>
      <code>{recipient}</code>
      <div><strong>USDC asset</strong></div>
      <code>{asset}</code>
      <p>Browser GET shows this page. Funded buyer bots use POST. An unpaid POST returns HTTP 402 with instructions to pay your receiving wallet before the paid result unlocks.</p>
      <pre>curl -X POST {html.escape(endpoint)} \\
  -H 'Content-Type: application/json' \\
  -d '{html.escape(sample_body)}'</pre>
      <button id="test" type="button">Test 402 Payment Required</button>
      <pre id="result"></pre>
    </section>
  </main>
  <script>
    function formatPaymentResult(status, headers, body) {{
      const accept = body?.payment?.accepts?.[0] || {{}};
      if (status === 402 && accept.payTo) {{
        const due = accept.extra?.displayPrice || body?.service?.price_usd || headers['X-Payment-Amount'] || 'unknown';
        const resource = accept.resource || body?.payment?.resource?.url || 'unknown';
        return [
          'PAYWALL WORKING',
          '',
          'This is not a failure. It means an unpaid buyer bot reached your paid endpoint and received instructions to pay YOU before the result unlocks.',
          '',
          `Status: HTTP ${{status}} Payment Required`,
          `Buyer bot payment due: ${{due}} USDC`,
          `Buyer bot pays YOU at: ${{accept.payTo || headers['X-Agent-Income-Pay-To'] || 'unknown'}}`,
          `Network: ${{accept.network || headers['X-Agent-Income-Network'] || 'unknown'}}`,
          `USDC asset: ${{accept.asset || headers['X-Agent-Income-Asset'] || 'unknown'}}`,
          `Service: ${{resource}}`,
          '',
          'Money direction:',
          'Buyer bot wallet -> your Base wallet. You do not send money in this flow.',
          '',
          'Next step for a funded buyer bot:',
          '1. Transfer the quoted Base USDC amount to your receiving wallet.',
          '2. Retry this POST with X-Payment-Tx or payment_tx set to the transaction hash.',
          '3. Receive the paid JSON artifact after on-chain verification.',
          '',
          'Raw PAYMENT-REQUIRED header is present for machine clients.'
        ].join('\\n');
      }}
      return JSON.stringify({{ status, headers, body }}, null, 2);
    }}

    document.getElementById('test').addEventListener('click', async () => {{
      const response = await fetch('{html.escape(endpoint_path)}', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: {json.dumps(sample_body)}
      }});
      const headers = {{}};
      ['PAYMENT-REQUIRED','X-Agent-Income-Pay-To','X-Agent-Income-Network','X-Agent-Income-Asset'].forEach((name) => headers[name] = response.headers.get(name));
      document.getElementById('result').textContent = formatPaymentResult(response.status, headers, await response.json());
    }});
  </script>
</body>
</html>
""")


@app.post("/agent-income/api/bot-services/{service_key}", tags=["Agent Income"])
async def run_agent_income_bot_service(
    service_key: str,
    body: AgentIncomeBotServiceRequest,
    request: Request,
    x_payment_tx: str | None = Header(None, alias="X-Payment-Tx"),
):
    service = _agent_bot_service(service_key)
    recipient = _agent_income_public_recipient()
    resource_url = _agent_income_resource_url(request)
    if not recipient:
        raise HTTPException(status_code=503, detail="Agent Income receiving wallet is not configured")
    if not USDC_CONTRACT:
        raise HTTPException(status_code=503, detail="USDC_CONTRACT must be configured for Base payment verification")

    payment_tx = (body.payment_tx or x_payment_tx or "").strip()
    if not payment_tx:
        return _payment_required_response(service, resource_url, recipient)
    if not TX_HASH_RE.fullmatch(payment_tx):
        raise HTTPException(status_code=400, detail="A valid Base transaction hash is required")

    db = await get_db()
    try:
        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("base_usdc", payment_tx),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This payment transaction has already been consumed")

        verification = await verify_usdc_payment(payment_tx, float(service["price_usdc"]), recipient)
        if not verification["verified"]:
            return _payment_required_response(service, resource_url, recipient, verification["error"])

        task = await (
            await db.execute(
                """SELECT * FROM agent_income_tasks
                   WHERE lane_key = ?
                   ORDER BY created_at DESC
                   LIMIT 1""",
                (f"bot_service:{service_key}",),
            )
        ).fetchone()
        task = dict(task) if task else {}
        output = _bot_service_output(service_key, body.input or {})
        ledger_id = generate_id("aile")
        recorded_at = now_iso()
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                task.get("id"),
                task.get("run_id"),
                "bot_service_payment",
                float(service["price_usdc"]),
                "USDC",
                "verified",
                "base_usdc",
                payment_tx,
                recorded_at,
                json.dumps({
                    "service": service_key,
                    "payer_agent": body.payer_agent,
                    "request_id": body.request_id,
                    "input_hash": output["input_hash"],
                    "output": output,
                    "verification": verification,
                }),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.bot_service.paid",
                body.payer_agent or "funded_bot",
                json.dumps({"service": service_key, "amount": service["price_usdc"], "tx": payment_tx}),
                recorded_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    payment_response = base64.b64encode(json.dumps({
        "status": "settled",
        "network": f"eip155:{PAYMENT_CHAIN_ID}",
        "tx": payment_tx,
        "amount": float(service["price_usdc"]),
        "ledger_id": ledger_id,
    }, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return JSONResponse(
        headers={"PAYMENT-RESPONSE": payment_response},
        content={
            "status": "paid",
            "service": service,
            "result": output,
            "receipt": {
                "ledger_id": ledger_id,
                "tx": payment_tx,
                "amount": float(service["price_usdc"]),
                "currency": "USDC",
                "network": f"eip155:{PAYMENT_CHAIN_ID}",
            },
        },
    )


@app.get("/agent-income/offer/{task_id}", response_class=HTMLResponse, tags=["Agent Income"])
async def agent_income_public_offer(task_id: str):
    db = await get_db()
    try:
        row = await (
            await db.execute(
                """SELECT t.*, c.status AS clearance_status
                   FROM agent_income_tasks t
                   LEFT JOIN clearances c ON c.id = t.clearance_id
                   WHERE t.id = ?""",
                (task_id,),
            )
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Offer not found")
        task = dict(row)
        if task.get("clearance_status") not in {"approved"} and task.get("status") not in {"sent_to_buyer", "active_inbound_service"}:
            raise HTTPException(status_code=404, detail="Offer is not published")
    finally:
        await db.close()

    metadata = _load_json(task.get("metadata"), {})
    recipient = _agent_income_public_recipient()
    amount = money(task.get("expected_payout"))
    title = html.escape(task["title"])
    description = html.escape(task.get("automation_notes") or task.get("buyer_profile") or "")
    wallet = html.escape(recipient or "Wallet not configured")
    safe_task_id = html.escape(task_id)
    return HTMLResponse(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {_agent_income_head_assets(title, description)}
  <style>
    body {{ margin:0; background:#101116; color:#f7f8fb; font-family:Inter,system-ui,sans-serif; line-height:1.5; }}
    main {{ width:min(860px, calc(100% - 32px)); margin:0 auto; padding:40px 0; }}
    .panel {{ border:1px solid #2b303b; border-radius:8px; background:#17191f; padding:22px; }}
    .brand-mark {{ width:58px; height:58px; border-radius:8px; object-fit:cover; border:1px solid rgba(232,145,45,.35); background:#050505; margin-bottom:16px; }}
    h1 {{ font-size:clamp(32px, 5vw, 56px); line-height:1; margin:0 0 12px; }}
    p {{ color:#aeb7c4; }}
    code, .wallet {{ color:#58b9e8; overflow-wrap:anywhere; font-family:"SF Mono",Menlo,monospace; }}
    input, button, textarea {{ width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #3a414f; padding:12px; background:#11131a; color:#f7f8fb; font:inherit; }}
    button {{ background:#e8912d; color:#17130e; font-weight:800; cursor:pointer; }}
    .grid {{ display:grid; gap:12px; }}
  </style>
</head>
<body>
  <main>
    <img class="brand-mark" src="{_agent_income_asset_url('mark.png')}" alt="Agent Income logo">
    <h1>{title}</h1>
    <p>{description}</p>
    <section class="panel grid">
      <strong>Price: ${amount:.2f} USDC on Base</strong>
      <div>Recipient wallet</div>
      <div class="wallet">{wallet}</div>
      <div>Reference</div>
      <code>{safe_task_id}</code>
      <p>Pay USDC on Base, then paste the transaction hash below. The artifact is counted as paid only after on-chain verification.</p>
      <input id="tx" placeholder="Base transaction hash">
      <input id="email" placeholder="Your email or agent id (optional)">
      <button id="submit" type="button">Verify Payment</button>
      <pre id="result"></pre>
    </section>
  </main>
  <script>
    document.getElementById('submit').addEventListener('click', async () => {{
      const response = await fetch('/agent-income/api/public/tasks/{safe_task_id}/payment', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          provider_ref: document.getElementById('tx').value,
          payer_email: document.getElementById('email').value || null
        }})
      }});
      document.getElementById('result').textContent = JSON.stringify(await response.json(), null, 2);
    }});
  </script>
</body>
</html>
""")


@app.post("/agent-income/api/public/tasks/{task_id}/payment", tags=["Agent Income"])
async def claim_agent_income_public_payment(task_id: str, body: AgentIncomePublicPaymentClaim):
    if not TX_HASH_RE.fullmatch(body.provider_ref):
        raise HTTPException(status_code=400, detail="A valid Base transaction hash is required")
    recipient = _agent_income_public_recipient()
    if not recipient:
        raise HTTPException(status_code=503, detail="Agent Income receiving wallet is not configured")

    db = await get_db()
    try:
        row = await (
            await db.execute(
                """SELECT t.*, c.status AS clearance_status
                   FROM agent_income_tasks t
                   LEFT JOIN clearances c ON c.id = t.clearance_id
                   WHERE t.id = ?""",
                (task_id,),
            )
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent income task not found")
        task = dict(row)
        if task.get("clearance_status") != "approved" and task.get("status") not in {"sent_to_buyer", "active_inbound_service"}:
            raise HTTPException(status_code=409, detail="Offer must be approved or published before payment can be claimed")

        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("base_usdc", body.provider_ref),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This payment reference has already been recorded")

        verification = await verify_usdc_payment(body.provider_ref, money(task["expected_payout"]), recipient)
        if not verification["verified"]:
            raise HTTPException(status_code=402, detail=verification["error"])

        ledger_id = generate_id("aile")
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                task_id,
                task["run_id"],
                "payment_received",
                money(task["expected_payout"]),
                "USDC",
                "verified",
                "base_usdc",
                body.provider_ref,
                now_iso(),
                json.dumps({
                    "payer_email": body.payer_email,
                    "note": body.note,
                    "source": "public_offer_page",
                    "verification": verification,
                }),
            ),
        )
        await db.commit()
        return {"status": "verified", "ledger_id": ledger_id, "amount": money(task["expected_payout"])}
    finally:
        await db.close()


@app.post("/agent-income/api/run", tags=["Agent Income"])
async def create_agent_income_run(
    body: AgentIncomeRunCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    lanes = _agent_income_lanes(body.target_amount, body.target_window_hours)
    projected_amount = money(sum(lane["expected_payout"] for lane in lanes))
    run_id = generate_id("airun")
    created_at = now_iso()
    next_run_at = (datetime.now(timezone.utc) + timedelta(hours=body.target_window_hours)).isoformat()

    db = await get_db()
    notifications = []
    try:
        await db.execute(
            """INSERT INTO agent_income_runs
               (id, target_amount, target_window_hours, projected_amount, status, created_by, created_at, next_run_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                body.target_amount,
                body.target_window_hours,
                projected_amount,
                "awaiting_approval",
                AGENT_INCOME_OWNER,
                created_at,
                next_run_at,
                json.dumps({
                    "requested_by": family_user["display_name"],
                    "guardrails": AGENT_INCOME_GUARDRAILS,
                    "projection_note": "Projected payout is based on fixed-fee task capacity, not a guaranteed result.",
                }),
            ),
        )

        for lane in lanes:
            deliverable = _render_agent_deliverable(
                lane,
                run_id=run_id,
                target_amount=body.target_amount,
                target_window_hours=body.target_window_hours,
            )
            clearance = await _insert_agent_clearance(
                db,
                title=f"Agent Income: {lane['title']}",
                description=(
                    f"{lane['label']} targeting ${lane['expected_payout']:.2f}. "
                    f"Buyer: {lane['buyer_profile']} "
                    "Approval lets the agent send/publish the drafted work product only. "
                    "No wallet spending or withdrawal is authorized by this task."
                ),
                scope=f"agent-income:{lane['key']}:deliver",
                budget_amount=lane["cost"],
                budget_currency="USD",
                expires_in_seconds=max(body.target_window_hours * 3600, 3600),
                metadata={
                    "product": "agent_income",
                    "run_id": run_id,
                    "lane": lane["key"],
                    "expected_payout": lane["expected_payout"],
                    "approval_boundary": "deliver_only_no_funds_movement",
                },
            )
            task_id = generate_id("aitask")
            await db.execute(
                """INSERT INTO agent_income_tasks
                   (id, run_id, lane_key, lane_label, title, buyer_profile, expected_payout,
                    cost_to_execute, currency, status, clearance_id, deliverable, delivery_channel,
                    risk_level, automation_notes, created_at, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    run_id,
                    lane["key"],
                    lane["label"],
                    lane["title"],
                    lane["buyer_profile"],
                    lane["expected_payout"],
                    lane["cost"],
                    "USD",
                    "pending_clearance",
                    clearance["id"],
                    deliverable,
                    lane["delivery_channel"],
                    "low",
                    lane["automation_notes"],
                    created_at,
                    created_at,
                    json.dumps({
                        "why": lane["why"],
                        "buyer_source": lane.get("buyer_source"),
                        "earning_route": lane.get("earning_route"),
                        "autonomous_actions": lane.get("autonomous_actions", []),
                        "approval_url": clearance["approval_url"],
                    }),
                ),
            )
            notifications.append(
                {
                    "clearance_id": clearance["id"],
                    "title": f"Agent Income: {lane['title']}",
                    "description": f"{lane['label']} targeting ${lane['expected_payout']:.2f}",
                    "scope": f"agent-income:{lane['key']}:deliver",
                    "budget_amount": lane["cost"],
                    "budget_currency": "USD",
                    "expires_at": clearance["expires_at"],
                    "approval_url": clearance["approval_url"],
                }
            )

        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.run.created",
                family_user["display_name"],
                json.dumps({"run_id": run_id, "projected_amount": projected_amount, "tasks": len(lanes)}),
                created_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    for notification in notifications:
        try:
            await send_clearance_telegram_notification(**notification)
        except Exception as exc:
            print(f"[telegram] agent income notification failed for {notification['clearance_id']}: {exc}")

    overview = await build_agent_income_dashboard(AGENT_INCOME_OWNER)
    return {
        "status": "queued",
        "run_id": run_id,
        "projected_amount": projected_amount,
        "task_count": len(lanes),
        "approval_state": "pending_clearance",
        "overview": overview,
    }


@app.post("/agent-income/api/bot-market-run", tags=["Agent Income"])
async def create_agent_income_bot_market_run(
    body: AgentIncomeBotMarketCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    services = AGENT_BOT_SERVICES
    projected_amount = money(sum(float(service["price_usdc"]) * body.target_calls_per_service for service in services))
    run_id = generate_id("airun")
    created_at = now_iso()
    next_run_at = (datetime.now(timezone.utc) + timedelta(hours=body.target_window_hours)).isoformat()
    manifest_url = f"{BASE_URL.rstrip('/')}/agent-income/agents.json"

    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO agent_income_runs
               (id, target_amount, target_window_hours, projected_amount, status, created_by, created_at, next_run_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                body.target_amount,
                body.target_window_hours,
                projected_amount,
                "bot_market_live",
                AGENT_INCOME_OWNER,
                created_at,
                next_run_at,
                json.dumps({
                    "requested_by": family_user["display_name"],
                    "campaign_type": "bot_to_bot_paid_services",
                    "manifest_url": manifest_url,
                    "projection_note": "Projected capacity assumes funded bots call the paid services.",
                }),
            ),
        )

        for service in services:
            task_id = generate_id("aitask")
            endpoint = f"{BASE_URL.rstrip('/')}/agent-income/api/bot-services/{service['key']}"
            deliverable = (
                f"# {service['label']}\n\n"
                f"Run: {run_id}\n"
                f"Paid bot endpoint: {endpoint}\n"
                f"Manifest: {manifest_url}\n"
                f"Price: ${float(service['price_usdc']):.2f} USDC per verified call\n\n"
                "## What Funded Bots Get\n\n"
                f"{service['description']}\n\n"
                "## Payment Flow\n\n"
                "- Bot calls the endpoint.\n"
                "- App returns HTTP 402 with PAYMENT-REQUIRED details.\n"
                "- Bot pays USDC on Base and retries with X-Payment-Tx or payment_tx.\n"
                "- App verifies the transaction and returns the JSON artifact.\n\n"
                "## Approval Boundary\n\n"
                "This task tracks inbound bot-service revenue only. It does not authorize outbound messages, "
                "wallet spending, trading, or withdrawals.\n"
            )
            await db.execute(
                """INSERT INTO agent_income_tasks
                   (id, run_id, lane_key, lane_label, title, buyer_profile, expected_payout,
                    cost_to_execute, currency, status, clearance_id, deliverable, delivery_channel,
                    risk_level, automation_notes, created_at, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    run_id,
                    f"bot_service:{service['key']}",
                    "Funded Bot Service",
                    f"Serve paid bot calls: {service['label']}",
                    "Funded autonomous agents, MCP servers, x402 clients, and bots buying JSON artifacts.",
                    float(service["price_usdc"]) * body.target_calls_per_service,
                    0,
                    "USD",
                    "active_inbound_service",
                    None,
                    deliverable,
                    "HTTP 402 paid API",
                    "low",
                    service["description"],
                    created_at,
                    created_at,
                    json.dumps({
                        "why": "Bots with wallets can pay per call without a sales conversation.",
                        "buyer_source": "Agent manifest, x402-aware clients, MCP/tool marketplaces, and direct bot discovery.",
                        "earning_route": "Funded bot calls a paid endpoint, receives 402 requirements, pays Base USDC, then gets the JSON artifact.",
                        "autonomous_actions": [
                        "Expose service metadata in the agent manifest.",
                        "Return HTTP 402 payment requirements to unpaid bots.",
                        "Verify Base USDC payment before serving the artifact.",
                        "Record verified bot-service revenue in the ledger.",
                        ],
                        "offer_url": endpoint,
                        "bot_service": service,
                    }),
                ),
            )

        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.bot_market.created",
                family_user["display_name"],
                json.dumps({"run_id": run_id, "projected_amount": projected_amount, "services": len(services)}),
                created_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    overview = await build_agent_income_dashboard(AGENT_INCOME_OWNER)
    return {
        "status": "bot_market_live",
        "run_id": run_id,
        "manifest_url": manifest_url,
        "projected_amount": projected_amount,
        "task_count": len(services),
        "overview": overview,
    }


@app.post("/agent-income/api/outreach-campaign", tags=["Agent Income"])
async def create_agent_income_outreach_campaign(
    body: AgentIncomeCampaignCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    selected_targets = sorted(
        AGENT_OUTREACH_TARGETS,
        key=lambda item: 0 if _valid_outreach_email(item.get("contact")) else 1,
    )[:body.limit]
    if not selected_targets:
        raise HTTPException(status_code=400, detail="No approved outreach targets are configured")

    run_id = generate_id("airun")
    created_at = now_iso()
    next_run_at = (datetime.now(timezone.utc) + timedelta(hours=AGENT_INCOME_TARGET_WINDOW_HOURS)).isoformat()
    projected_amount = money(body.expected_deposit * len(selected_targets))
    configured_wallet_address = _configured_agent_income_wallet_address()

    db = await get_db()
    notifications = []
    try:
        wallet = await (
            await db.execute("SELECT * FROM agent_income_wallets WHERE owner = ? AND verified = 1", (AGENT_INCOME_OWNER,))
        ).fetchone()
        payment_recipient = wallet["address"] if wallet else configured_wallet_address

        await db.execute(
            """INSERT INTO agent_income_runs
               (id, target_amount, target_window_hours, projected_amount, status, created_by, created_at, next_run_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                AGENT_INCOME_TARGET_AMOUNT,
                AGENT_INCOME_TARGET_WINDOW_HOURS,
                projected_amount,
                "outreach_queued",
                AGENT_INCOME_OWNER,
                created_at,
                next_run_at,
                json.dumps({
                    "requested_by": family_user["display_name"],
                    "campaign_type": "autonomous_buyer_outreach",
                    "expected_deposit": body.expected_deposit,
                    "target_count": len(selected_targets),
                    "projection_note": "Projected outreach deposit capacity, not guaranteed revenue.",
                }),
            ),
        )

        for target in selected_targets:
            task_id = generate_id("aitask")
            offer = _render_outreach_offer(
                task_id=task_id,
                target=target,
                expected_deposit=body.expected_deposit,
                payment_recipient=payment_recipient,
            )
            can_send_email = _valid_outreach_email(target.get("contact"))
            delivery_channel = "Approved SMTP email" if can_send_email else "Approved contact-form handoff"
            clearance = await _insert_agent_clearance(
                db,
                title=f"Agent Outreach: {target['target']}",
                description=(
                    f"Send one approved offer to {target['target']} for a ${body.expected_deposit:.2f} "
                    "automation audit deposit. Approval authorizes this exact outbound message only."
                ),
                scope="agent-income:outreach:send",
                budget_amount=0,
                budget_currency="USD",
                expires_in_seconds=AGENT_INCOME_TARGET_WINDOW_HOURS * 3600,
                metadata={
                    "product": "agent_income",
                    "run_id": run_id,
                    "campaign_type": "autonomous_buyer_outreach",
                    "target": target["target"],
                    "contact": target["contact"],
                    "subject": offer["subject"],
                    "approval_boundary": "single_outreach_message_only",
                },
            )
            await db.execute(
                """INSERT INTO agent_income_tasks
                   (id, run_id, lane_key, lane_label, title, buyer_profile, expected_payout,
                    cost_to_execute, currency, status, clearance_id, deliverable, delivery_channel,
                    risk_level, automation_notes, created_at, updated_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    run_id,
                    "autonomous_outreach",
                    "Autonomous Buyer Outreach",
                    f"Send approved offer to {target['target']}",
                    target["fit"],
                    body.expected_deposit,
                    0,
                    "USD",
                    "pending_clearance",
                    clearance["id"],
                    offer["deliverable"],
                    delivery_channel,
                    "low",
                    "Agent sources a buyer target, drafts a paid pilot offer, gets Clearance approval, then sends exactly one approved message.",
                    created_at,
                    created_at,
                    json.dumps({
                        "why": "AI can personalize narrow B2B offers quickly, prepare a payment request, and track replies/payments.",
                        "buyer_source": target["source"],
                        "earning_route": "Agent sends a human-approved B2B offer and asks for a Base USDC/card deposit before producing the audit.",
                        "autonomous_actions": [
                            "Select an approved target with a visible workflow fit.",
                            "Draft a concise paid pilot offer and payment request.",
                            "Queue the exact outbound message for Clearance approval.",
                            "Send one approved email automatically when approved and SMTP is configured.",
                            "Track reply/payment and count revenue only after verification.",
                        ],
                        "approval_url": clearance["approval_url"],
                        "outreach": {
                            "target": target["target"],
                            "fit": target["fit"],
                            "contact": target["contact"],
                            "contact_is_email": can_send_email,
                            "source": target["source"],
                            "subject": offer["subject"],
                            "body": offer["body"],
                            "expected_deposit": body.expected_deposit,
                            "payment_recipient": payment_recipient,
                        },
                        "execution": {
                            "status": "waiting_for_clearance",
                            "channel": "email" if can_send_email else "contact_form",
                        },
                    }),
                ),
            )
            notifications.append(
                {
                    "clearance_id": clearance["id"],
                    "title": f"Agent Outreach: {target['target']}",
                    "description": f"Approve one outreach message for ${body.expected_deposit:.2f} deposit",
                    "scope": "agent-income:outreach:send",
                    "budget_amount": 0,
                    "budget_currency": "USD",
                    "expires_at": clearance["expires_at"],
                    "approval_url": clearance["approval_url"],
                }
            )

        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.outreach_campaign.created",
                family_user["display_name"],
                json.dumps({"run_id": run_id, "projected_amount": projected_amount, "targets": len(selected_targets)}),
                created_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    for notification in notifications:
        try:
            await send_clearance_telegram_notification(**notification)
        except Exception as exc:
            print(f"[telegram] agent outreach notification failed for {notification['clearance_id']}: {exc}")

    overview = await build_agent_income_dashboard(AGENT_INCOME_OWNER)
    return {
        "status": "queued",
        "run_id": run_id,
        "projected_amount": projected_amount,
        "task_count": len(selected_targets),
        "approval_state": "pending_clearance",
        "overview": overview,
    }


@app.post("/agent-income/api/tasks/{task_id}/execute", tags=["Agent Income"])
async def execute_agent_income_task(
    task_id: str,
    body: AgentIncomeTaskExecution,
    family_user: dict = Depends(get_agent_income_user),
):
    channel = body.channel.strip().lower()
    if channel != "email":
        raise HTTPException(status_code=400, detail="Only approved email outreach execution is supported right now")

    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*, c.status AS clearance_status
               FROM agent_income_tasks t
               LEFT JOIN clearances c ON c.id = t.clearance_id
               WHERE t.id = ?""",
            (task_id,),
        )
        task = await cursor.fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Agent income task not found")
        task = dict(task)
        if task.get("clearance_status") != "approved":
            raise HTTPException(status_code=409, detail="Task must be approved through Clearance before the agent can send outreach")

        metadata = _load_json(task.get("metadata"), {})
        outreach = metadata.get("outreach") or {}
        if not outreach:
            raise HTTPException(status_code=400, detail="This task has no executable outreach payload")
        execution = metadata.get("execution") or {}
        if execution.get("status") == "sent":
            return {"status": "already_sent", "task_id": task_id, "sent_at": execution.get("sent_at")}

        contact = outreach.get("contact")
        if not _valid_outreach_email(contact):
            raise HTTPException(status_code=409, detail="This target does not have a direct approved email contact")

        sent = await send_email(
            contact,
            outreach.get("subject") or task["title"],
            outreach.get("body") or task.get("deliverable") or "",
            reply_to=AGENT_INCOME_OUTREACH_REPLY_TO if EMAIL_PATTERN.fullmatch(AGENT_INCOME_OUTREACH_REPLY_TO or "") else None,
        )
        if not sent:
            raise HTTPException(status_code=503, detail="SMTP is not configured or the approved outreach email could not be sent")

        executed_at = now_iso()
        metadata["execution"] = {
            "status": "sent",
            "channel": "email",
            "sent_at": executed_at,
            "sent_by": family_user["display_name"],
            "note": body.note,
        }
        await db.execute(
            """UPDATE agent_income_tasks
               SET status = ?, updated_at = ?, metadata = ?
               WHERE id = ?""",
            ("sent_to_buyer", executed_at, json.dumps(metadata), task_id),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.outreach.sent",
                family_user["display_name"],
                json.dumps({"task_id": task_id, "target": outreach.get("target"), "contact": contact}),
                executed_at,
            ),
        )
        await db.commit()
        return {"status": "sent_to_buyer", "task_id": task_id, "sent_at": executed_at}
    finally:
        await db.close()


@app.post("/agent-income/api/spend-authorizations", tags=["Agent Income"])
async def create_agent_income_spend_authorization(
    body: AgentIncomeSpendAuthorizationCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    if body.protocol.lower() != "x402":
        raise HTTPException(status_code=400, detail="Only x402 spend authorization is supported right now")
    if body.amount_limit > AGENT_INCOME_SPEND_LIMIT_USD:
        raise HTTPException(status_code=400, detail=f"Spend budget exceeds the ${AGENT_INCOME_SPEND_LIMIT_USD:.2f} session limit")

    created_at = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=AGENT_INCOME_TARGET_WINDOW_HOURS)).isoformat()
    db = await get_db()
    try:
        clearance = await _insert_agent_clearance(
            db,
            title="Agent Income: approve x402 spend budget",
            description=(
                f"Authorize the agent to spend up to {body.amount_limit:.2f} {body.currency.upper()} "
                f"on x402 paid services for: {body.purpose}. Spending stops at the limit or expiry."
            ),
            scope="agent-income:x402-spend-budget",
            budget_amount=body.amount_limit,
            budget_currency=body.currency.upper(),
            expires_in_seconds=AGENT_INCOME_TARGET_WINDOW_HOURS * 3600,
            metadata={
                "product": "agent_income",
                "protocol": "x402",
                "purpose": body.purpose,
                "service_url": body.service_url,
                "approval_boundary": "session_spend_budget_only_no_trading_no_withdrawal",
            },
        )
        spend_id = generate_id("aispend")
        await db.execute(
            """INSERT INTO agent_income_spend_authorizations
               (id, owner, amount_limit, spent_amount, currency, protocol, status, clearance_id,
                requested_by, created_at, expires_at, metadata)
               VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                spend_id,
                AGENT_INCOME_OWNER,
                body.amount_limit,
                body.currency.upper(),
                "x402",
                "pending_clearance",
                clearance["id"],
                family_user["display_name"],
                created_at,
                expires_at,
                json.dumps({"purpose": body.purpose, "service_url": body.service_url}),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.spend_authorization.requested",
                family_user["display_name"],
                json.dumps({"spend_id": spend_id, "amount_limit": body.amount_limit, "clearance_id": clearance["id"]}),
                created_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    try:
        await send_clearance_telegram_notification(
            clearance_id=clearance["id"],
            title="Agent Income: approve x402 spend budget",
            description=f"Authorize up to {body.amount_limit:.2f} {body.currency.upper()} for {body.purpose}",
            scope="agent-income:x402-spend-budget",
            budget_amount=body.amount_limit,
            budget_currency=body.currency.upper(),
            expires_at=clearance["expires_at"],
            approval_url=clearance["approval_url"],
        )
    except Exception as exc:
        print(f"[telegram] agent spend authorization notification failed for {clearance['id']}: {exc}")

    overview = await build_agent_income_dashboard(AGENT_INCOME_OWNER)
    return {
        "status": "pending_clearance",
        "spend_authorization_id": spend_id,
        "approval_url": clearance["approval_url"],
        "overview": overview,
    }


@app.post("/agent-income/api/spend-authorizations/{spend_id}/usage", tags=["Agent Income"])
async def record_agent_income_spend_usage(
    spend_id: str,
    body: AgentIncomeSpendUsageCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT s.*, c.status AS clearance_status
               FROM agent_income_spend_authorizations s
               LEFT JOIN clearances c ON c.id = s.clearance_id
               WHERE s.id = ?""",
            (spend_id,),
        )
        spend = await cursor.fetchone()
        if not spend:
            raise HTTPException(status_code=404, detail="Spend authorization not found")
        spend = dict(spend)
        if spend.get("clearance_status") != "approved":
            raise HTTPException(status_code=409, detail="Spend budget must be approved before x402 usage can be recorded")
        if datetime.fromisoformat(spend["expires_at"]) <= datetime.now(timezone.utc):
            raise HTTPException(status_code=410, detail="Spend budget has expired")

        remaining = money(spend["amount_limit"] - spend["spent_amount"])
        if body.amount > remaining:
            raise HTTPException(status_code=400, detail="Spend exceeds remaining approved budget")

        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("x402", body.provider_ref),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This x402 spend reference has already been recorded")

        recorded_at = now_iso()
        ledger_id = generate_id("aile")
        metadata = _load_json(spend.get("metadata"), {})
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                "x402_service_spend",
                -body.amount,
                spend["currency"],
                "verified",
                "x402",
                body.provider_ref,
                recorded_at,
                json.dumps({
                    "spend_authorization_id": spend_id,
                    "recorded_by": family_user["display_name"],
                    "service_url": body.service_url,
                    "purpose": metadata.get("purpose"),
                    "note": body.note,
                }),
            ),
        )
        await db.execute(
            """UPDATE agent_income_spend_authorizations
               SET spent_amount = spent_amount + ?
               WHERE id = ?""",
            (body.amount, spend_id),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.x402_spend.recorded",
                family_user["display_name"],
                json.dumps({"spend_id": spend_id, "amount": body.amount, "service_url": body.service_url}),
                recorded_at,
            ),
        )
        await db.commit()
        return {"status": "recorded", "ledger_id": ledger_id, "remaining": money(remaining - body.amount)}
    finally:
        await db.close()


@app.post("/agent-income/api/wallet/nonce", tags=["Agent Income"])
async def create_agent_income_wallet_nonce(
    body: AgentIncomeWalletNonceRequest,
    family_user: dict = Depends(get_agent_income_user),
):
    address = _normalize_eth_address(body.address)
    nonce = secrets.token_urlsafe(32)
    issued_at = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=AGENT_INCOME_WALLET_CHALLENGE_MINUTES)).isoformat()
    host = urlparse(BASE_URL).hostname or BASE_URL.rstrip("/")
    message = (
        "Clearance Agent Income wallet verification\n"
        f"Domain: {host}\n"
        f"Address: {address}\n"
        f"Chain: Base ({PAYMENT_CHAIN_ID})\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n\n"
        "This signature proves wallet ownership. It does not authorize a transaction or withdrawal."
    )

    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO agent_income_wallet_challenges
               (nonce, owner, address, message, expires_at, used, created_at)
               VALUES (?, ?, ?, ?, ?, 0, ?)""",
            (nonce, AGENT_INCOME_OWNER, address, message, expires_at, issued_at),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.wallet.challenge_created",
                family_user["display_name"],
                json.dumps({"address": address, "expires_at": expires_at}),
                issued_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return {
        "nonce": nonce,
        "message": message,
        "expires_at": expires_at,
        "chain_id": PAYMENT_CHAIN_ID,
        "chain_hex": hex(PAYMENT_CHAIN_ID),
    }


@app.post("/agent-income/api/wallet/connect", tags=["Agent Income"])
async def connect_agent_income_wallet(
    body: AgentIncomeWalletConnect,
    family_user: dict = Depends(get_agent_income_user),
):
    if body.chain_id != PAYMENT_CHAIN_ID:
        raise HTTPException(status_code=400, detail=f"Switch wallet to Base chain id {PAYMENT_CHAIN_ID} before connecting")
    if not Account or not encode_defunct:
        raise HTTPException(status_code=503, detail="Wallet signature verification dependency is not installed")

    address = _normalize_eth_address(body.address)
    now = datetime.now(timezone.utc)
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM agent_income_wallet_challenges
               WHERE nonce = ? AND owner = ? AND lower(address) = ? AND used = 0""",
            (body.nonce, AGENT_INCOME_OWNER, address),
        )
        challenge = await cursor.fetchone()
        if not challenge:
            raise HTTPException(status_code=400, detail="Wallet challenge was not found or was already used")
        challenge = dict(challenge)
        if datetime.fromisoformat(challenge["expires_at"]) <= now:
            raise HTTPException(status_code=410, detail="Wallet challenge expired. Request a new nonce.")
        if not secrets.compare_digest(challenge["message"], body.message):
            raise HTTPException(status_code=400, detail="Signed wallet message does not match the issued challenge")

        try:
            recovered = Account.recover_message(encode_defunct(text=body.message), signature=body.signature)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Wallet signature could not be recovered") from exc

        if recovered.lower() != address:
            raise HTTPException(status_code=401, detail="Wallet signature did not match the submitted address")

        connected_at = now_iso()
        wallet_id = f"aiwallet_{hash_key(address)[:20]}"
        await db.execute(
            """INSERT INTO agent_income_wallets
               (id, owner, address, chain, chain_id, ens, verified, verification_method,
                last_nonce, last_signature, connected_at, updated_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(owner) DO UPDATE SET
                   address = excluded.address,
                   chain = excluded.chain,
                   chain_id = excluded.chain_id,
                   ens = excluded.ens,
                   verified = 1,
                   verification_method = excluded.verification_method,
                   last_nonce = excluded.last_nonce,
                   last_signature = excluded.last_signature,
                   updated_at = excluded.updated_at,
                   metadata = excluded.metadata""",
            (
                wallet_id,
                AGENT_INCOME_OWNER,
                address,
                PAYMENT_CHAIN,
                PAYMENT_CHAIN_ID,
                body.ens,
                "personal_sign_nonce",
                body.nonce,
                hash_key(body.signature),
                connected_at,
                connected_at,
                json.dumps({"connected_by": family_user["display_name"]}),
            ),
        )
        await db.execute(
            "UPDATE agent_income_wallet_challenges SET used = 1 WHERE nonce = ?",
            (body.nonce,),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.wallet.connected",
                family_user["display_name"],
                json.dumps({"address": address, "chain_id": body.chain_id}),
                connected_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return {"status": "connected", "address": address, "chain": PAYMENT_CHAIN, "chain_id": PAYMENT_CHAIN_ID}


@app.post("/agent-income/api/tasks/{task_id}/payment", tags=["Agent Income"])
async def record_agent_income_payment(
    task_id: str,
    body: AgentIncomePaymentCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT t.*, c.status AS clearance_status
               FROM agent_income_tasks t
               LEFT JOIN clearances c ON c.id = t.clearance_id
               WHERE t.id = ?""",
            (task_id,),
        )
        task = await cursor.fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Agent income task not found")
        task = dict(task)
        if task.get("clearance_status") != "approved":
            raise HTTPException(status_code=409, detail="Task must be approved by a human before payment is recorded")

        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                (body.provider, body.provider_ref),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This payment reference has already been recorded")

        verification_metadata = {}
        status = "pending_manual_review"
        if body.provider == "base_usdc":
            wallet = await (
                await db.execute("SELECT * FROM agent_income_wallets WHERE owner = ? AND verified = 1", (AGENT_INCOME_OWNER,))
            ).fetchone()
            if not wallet:
                raise HTTPException(status_code=400, detail="Connect and verify a Base wallet before recording Base USDC payments")
            verification = await verify_usdc_payment(body.provider_ref, body.amount, wallet["address"])
            verification_metadata = verification
            if not verification["verified"]:
                raise HTTPException(status_code=402, detail=verification["error"])
            status = "verified"

        ledger_id = generate_id("aile")
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                task_id,
                task["run_id"],
                "payment_received",
                body.amount,
                body.currency.upper(),
                status,
                body.provider,
                body.provider_ref,
                now_iso(),
                json.dumps({
                    "recorded_by": family_user["display_name"],
                    "note": body.note,
                    "verification": verification_metadata,
                }),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.payment.recorded",
                family_user["display_name"],
                json.dumps({"task_id": task_id, "amount": body.amount, "status": status, "provider": body.provider}),
                now_iso(),
            ),
        )
        await db.commit()
        return {"status": status, "ledger_id": ledger_id}
    finally:
        await db.close()


@app.post("/agent-income/api/withdrawals", tags=["Agent Income"])
async def create_agent_income_withdrawal(
    body: AgentIncomeWithdrawalCreate,
    family_user: dict = Depends(get_agent_income_user),
):
    if body.amount > AGENT_INCOME_WITHDRAWAL_LIMIT_USD:
        raise HTTPException(status_code=400, detail=f"Withdrawal exceeds the ${AGENT_INCOME_WITHDRAWAL_LIMIT_USD:.2f} per-request limit")

    db = await get_db()
    try:
        wallet = await (
            await db.execute("SELECT * FROM agent_income_wallets WHERE owner = ? AND verified = 1", (AGENT_INCOME_OWNER,))
        ).fetchone()
        if not wallet:
            raise HTTPException(status_code=400, detail="Connect and verify a Base wallet before requesting withdrawal")

        balances = await _agent_income_withdrawable_balance(db, AGENT_INCOME_OWNER)
        if body.amount > balances["withdrawable"]:
            raise HTTPException(status_code=400, detail="Withdrawal exceeds verified withdrawable balance")

        clearance = await _insert_agent_clearance(
            db,
            title="Agent Income: approve withdrawal",
            description=(
                f"Withdraw {body.amount:.2f} {body.currency.upper()} to {wallet['address']} on Base. "
                "Approving creates a payout instruction only; the server never signs wallet transactions."
            ),
            scope="agent-income:withdraw",
            budget_amount=body.amount,
            budget_currency=body.currency.upper(),
            expires_in_seconds=3600,
            metadata={
                "product": "agent_income",
                "withdrawal_amount": body.amount,
                "wallet_address": wallet["address"],
                "chain_id": PAYMENT_CHAIN_ID,
                "approval_boundary": "payout_instruction_only_no_server_private_key",
            },
        )
        withdrawal_id = generate_id("aiwd")
        await db.execute(
            """INSERT INTO agent_income_withdrawals
               (id, owner, wallet_address, amount, currency, chain, chain_id, status, clearance_id,
                requested_by, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                withdrawal_id,
                AGENT_INCOME_OWNER,
                wallet["address"],
                body.amount,
                body.currency.upper(),
                PAYMENT_CHAIN,
                PAYMENT_CHAIN_ID,
                "pending_clearance",
                clearance["id"],
                family_user["display_name"],
                now_iso(),
                json.dumps({"note": body.note}),
            ),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.withdrawal.requested",
                family_user["display_name"],
                json.dumps({"withdrawal_id": withdrawal_id, "amount": body.amount, "clearance_id": clearance["id"]}),
                now_iso(),
            ),
        )
        await db.commit()
    finally:
        await db.close()

    try:
        await send_clearance_telegram_notification(
            clearance_id=clearance["id"],
            title="Agent Income: approve withdrawal",
            description=f"Withdraw {body.amount:.2f} {body.currency.upper()} to connected Base wallet",
            scope="agent-income:withdraw",
            budget_amount=body.amount,
            budget_currency=body.currency.upper(),
            expires_at=clearance["expires_at"],
            approval_url=clearance["approval_url"],
        )
    except Exception as exc:
        print(f"[telegram] agent income withdrawal notification failed for {clearance['id']}: {exc}")

    return {
        "status": "pending_clearance",
        "withdrawal_id": withdrawal_id,
        "approval_url": clearance["approval_url"],
    }


@app.post("/agent-income/api/withdrawals/{withdrawal_id}/execution", tags=["Agent Income"])
async def record_agent_income_withdrawal_execution(
    withdrawal_id: str,
    body: AgentIncomeWithdrawalExecution,
    family_user: dict = Depends(get_agent_income_user),
):
    if not TX_HASH_RE.fullmatch(body.tx_hash):
        raise HTTPException(status_code=400, detail="A valid Base transaction hash is required")

    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT w.*, c.status AS clearance_status
               FROM agent_income_withdrawals w
               LEFT JOIN clearances c ON c.id = w.clearance_id
               WHERE w.id = ?""",
            (withdrawal_id,),
        )
        withdrawal = await cursor.fetchone()
        if not withdrawal:
            raise HTTPException(status_code=404, detail="Withdrawal not found")
        withdrawal = dict(withdrawal)
        if withdrawal.get("clearance_status") != "approved":
            raise HTTPException(status_code=409, detail="Withdrawal must be approved before recording execution")

        duplicate = await (
            await db.execute(
                "SELECT id FROM agent_income_withdrawals WHERE executed_tx_hash = ? AND id != ?",
                (body.tx_hash, withdrawal_id),
            )
        ).fetchone()
        if duplicate:
            raise HTTPException(status_code=409, detail="This withdrawal transaction hash is already recorded")

        decided_at = now_iso()
        await db.execute(
            """UPDATE agent_income_withdrawals
               SET status = ?, decided_at = ?, executed_tx_hash = ?
               WHERE id = ?""",
            ("submitted_tx", decided_at, body.tx_hash, withdrawal_id),
        )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.withdrawal.execution_recorded",
                family_user["display_name"],
                json.dumps({"withdrawal_id": withdrawal_id, "tx_hash": body.tx_hash}),
                decided_at,
            ),
        )
        await db.commit()
        return {"status": "submitted_tx", "withdrawal_id": withdrawal_id, "tx_hash": body.tx_hash}
    finally:
        await db.close()


@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    return PlainTextResponse(
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /.well-known/x402.json\n"
        "Allow: /.well-known/agent-card.json\n"
        "Allow: /.well-known/agent.json\n"
        "Allow: /.well-known/402index-verify.txt\n"
        f"Sitemap: {BASE_URL.rstrip('/')}/sitemap.xml\n"
    )


@app.get("/sitemap.xml", include_in_schema=False)
async def sitemap_xml():
    today = datetime.now(timezone.utc).date().isoformat()
    urls = [
        ("", "daily", "0.8"),
        ("/bot-comm/market", "hourly", "0.9"),
        ("/bot-comm/agents.json", "hourly", "0.6"),
        ("/.well-known/x402.json", "hourly", "0.6"),
        ("/.well-known/agent-card.json", "hourly", "0.6"),
        ("/llms.txt", "daily", "0.6"),
    ]
    body = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for path, changefreq, priority in urls:
        body.extend([
            "  <url>",
            f"    <loc>{html.escape(BASE_URL.rstrip('/') + path)}</loc>",
            f"    <lastmod>{today}</lastmod>",
            f"    <changefreq>{changefreq}</changefreq>",
            f"    <priority>{priority}</priority>",
            "  </url>",
        ])
    body.append("</urlset>")
    return PlainTextResponse("\n".join(body) + "\n", media_type="application/xml")


@app.get("/llms.txt", include_in_schema=False)
async def llms_txt():
    return PlainTextResponse(_bot_comm_llms_text(full=False), media_type="text/plain; charset=utf-8")


@app.get("/llms-full.txt", include_in_schema=False)
async def llms_full_txt():
    return PlainTextResponse(_bot_comm_llms_text(full=True), media_type="text/plain; charset=utf-8")


@app.get("/favicon.ico", include_in_schema=False)
@app.head("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/favicon.svg?v=chevrons-20260508")


# --- Payments ---

OTHER_ASSET_POLICY = (
    "Other assets or networks are accepted only through invoice-confirmed instructions "
    "priced to a USD-equivalent amount."
)
RELEASE_RULE = (
    "Fixed-price plans issue keys automatically after confirmed on-chain verification. Non-default assets or custom arrangements remain manual."
)


@app.post("/v1/payments/crypto", tags=["Payments"])
async def submit_crypto_payment(request: Request):
    """
    Submit a crypto payment for a paid tier.

    REQUIREMENTS:
    - Default crypto rail is USDC on Base using the published payment instructions
    - Amount must be >= tier price in USDC
    - Transaction must have 12+ confirmations
    - Only the configured USDC token on Base is accepted on this endpoint
    - Fixed-price keys are issued only after payment is verified on-chain

    Refunds: Email support to discuss.
    """
    body = await request.json()
    email = body.get("email")
    tx_hash = body.get("tx_hash")
    tier = body.get("tier")

    if not email or not tx_hash or not tier:
        raise HTTPException(status_code=400, detail="email, tx_hash, and tier are required")

    if tier not in TIER_PRICES:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Choose: {list(TIER_PRICES.keys())}")

    price = TIER_PRICES[tier]

    db = await get_db()
    try:
        # DEFENSE: Replay attack — check for duplicate tx hash
        cursor = await db.execute(
            "SELECT id FROM payments WHERE tx_hash = ?", (tx_hash,)
        )
        if await cursor.fetchone():
            raise HTTPException(status_code=409, detail="This transaction hash has already been used. Each payment requires a unique transaction.")

        # DEFENSE: On-chain verification — ALL checks must pass before key is issued
        verification = await verify_usdc_payment(tx_hash, price)

        if not verification["verified"]:
            # Record the failed attempt for monitoring
            await db.execute(
                """INSERT INTO payments (id, email, amount, currency, tx_hash, status, tier, provider, created_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (generate_id("pay"), email, price, "USDC", tx_hash, "rejected",
                 tier, "base_usdc", now_iso(), json.dumps({
                     "error": verification["error"],
                     "confirmations": verification["confirmations"],
                     "amount_received": verification.get("amount_usdc"),
                 }))
            )
            await db.commit()

            raise HTTPException(
                status_code=402,
                detail=verification["error"]
            )

        response = await fulfill_paid_tier(
            email=email,
            tier=tier,
            amount=float(verification["amount_usdc"]),
            currency="USDC",
            provider="base_usdc",
            provider_ref=tx_hash,
            metadata={
                "tx_hash": tx_hash,
                "from": verification["from_address"],
                "confirmations": verification["confirmations"],
            },
        )
        response.update({
            "amount_verified": verification["amount_usdc"],
            "confirmations": verification["confirmations"],
        })
        return response
    finally:
        await db.close()


@app.post("/v1/payments/stripe/checkout", tags=["Payments"])
async def create_stripe_checkout_session(request: Request):
    """Create a Stripe-hosted card checkout session for Pro or Scale."""
    if not STRIPE_SECRET_KEY or stripe is None:
        raise HTTPException(status_code=503, detail="Stripe card checkout is not connected on this host. Use USDC on Base checkout.")

    body = await request.json()
    tier = body.get("tier")
    email = body.get("email")
    if tier not in TIER_PRICES:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Choose: {list(TIER_PRICES.keys())}")
    if not email:
        raise HTTPException(status_code=400, detail="email is required")

    stripe.api_key = STRIPE_SECRET_KEY
    price_usd = TIER_PRICES[tier]
    # Carry ambassador attribution through Stripe metadata so the webhook
    # can persist `referred_by` on the payments row when checkout completes.
    ref = _read_ref_cookie(request) or ""
    base_metadata = {"email": email, "tier": tier, "product": "clearance", "ref": ref}
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=email,
            client_reference_id=email,
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
            metadata=base_metadata,
            subscription_data={"metadata": base_metadata},
            line_items=[
                {
                    "quantity": 1,
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": price_usd * 100,
                        "recurring": {"interval": "month"},
                        "product_data": {
                            "name": f"Clearance {tier.capitalize()}",
                            "description": f"{TIER_LIMITS[tier]:,} human-approved clearances per month",
                        },
                    },
                }
            ],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to start Stripe checkout: {exc}") from exc

    return {"checkout_url": session.url, "session_id": session.id, "tier": tier}


@app.post("/agent-income/api/stripe/checkout", tags=["Agent Income", "Payments"])
async def create_agent_income_stripe_checkout_session(request: Request):
    """Create a one-time Stripe Checkout session for a fixed Agent Income offer."""
    if not STRIPE_SECRET_KEY or stripe is None:
        raise HTTPException(status_code=503, detail="Stripe card checkout is not connected on this host. Use USDC on Base checkout.")

    body = await request.json()
    offer = _agent_income_paid_offer(str(body.get("service") or body.get("service_key") or body.get("slug") or "").strip())
    email = str(body.get("email") or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email is required for card checkout")
    payload = body.get("payload") or body.get("input") or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be an object")
    customer_input = _agent_income_extract_paid_input(payload)

    stripe.api_key = STRIPE_SECRET_KEY
    base_url = BASE_URL.rstrip("/")
    session_metadata = {
        "product": "agent_income",
        "service_key": offer["key"],
        "service_slug": offer["slug"],
        "email": email,
    }
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            customer_email=email,
            client_reference_id=f"agent-income:{offer['key']}:{email}",
            success_url=f"{base_url}/agent-income/stripe/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base_url}{offer['path']}?checkout=cancelled",
            metadata=session_metadata,
            payment_intent_data={"metadata": session_metadata},
            line_items=[
                {
                    "quantity": 1,
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": int(round(float(offer["price_usdc"]) * 100)),
                        "product_data": {
                            "name": f"Agent Income - {offer['label']}",
                            "description": offer["description"][:1000],
                        },
                    },
                }
            ],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to start Stripe checkout: {exc}") from exc

    db = await get_db()
    try:
        ledger_id = generate_id("aile")
        await db.execute(
            """INSERT INTO agent_income_ledger
               (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ledger_id,
                None,
                None,
                "stripe_checkout_pending",
                float(offer["price_usdc"]),
                "USD",
                "pending",
                "stripe",
                session.id,
                now_iso(),
                json.dumps({
                    "project": "agent-income",
                    "service": offer["key"],
                    "service_label": offer["label"],
                    "email": email,
                    "customer_input": customer_input,
                    "stripe_session": session.id,
                    "checkout_url": session.url,
                }),
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return {
        "checkout_url": session.url,
        "session_id": session.id,
        "service": offer["key"],
        "price_usd": float(offer["price_usdc"]),
        "ledger_id": ledger_id,
    }


@app.post("/v1/payments/scram/stripe/checkout", tags=["Payments", "SCRAM"])
@app.post("/v1/payments/scam-check/stripe/checkout", tags=["Payments", "SCRAM"])
async def create_scam_check_stripe_checkout_session(request: Request):
    """Create a Stripe-hosted one-time checkout session for SCRAM credits."""
    if not STRIPE_SECRET_KEY or stripe is None:
        raise HTTPException(
            status_code=503,
            detail="Stripe card checkout is not connected on this host. Use the live payment page.",
        )

    body = await request.json()
    pack_key = body.get("pack", "checks_100")
    phone_number = body.get("phone") or body.get("From")
    pack = SCAMCHECK_CREDIT_PACKS.get(pack_key)
    if not pack:
        raise HTTPException(status_code=400, detail=f"Invalid pack. Choose: {list(SCAMCHECK_CREDIT_PACKS.keys())}")
    if not phone_number:
        raise HTTPException(status_code=400, detail="phone is required so credits can be fulfilled")

    stripe.api_key = STRIPE_SECRET_KEY
    price_id = os.getenv(pack["env_price_id"], "")
    line_item = {"quantity": 1}
    if price_id:
        line_item["price"] = price_id
    else:
        line_item["price_data"] = {
            "currency": "usd",
            "unit_amount": int(pack["price_usd"] * 100),
            "product_data": {
                "name": pack["label"],
                "description": "Prepaid SCRAM SMS credits",
            },
        }

    phone_hash = hash_phone(str(phone_number))
    metadata = {
        "product": "scam_check",
        "pack": pack_key,
        "credits": str(pack["credits"]),
        "phone_hash": phone_hash,
    }
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            client_reference_id=phone_hash,
            success_url=SCAMCHECK_STRIPE_SUCCESS_URL,
            cancel_url=SCAMCHECK_STRIPE_CANCEL_URL,
            metadata=metadata,
            line_items=[line_item],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to start Stripe checkout: {exc}") from exc

    return {
        "checkout_url": session.url,
        "session_id": session.id,
        "pack": pack_key,
        "credits": pack["credits"],
    }


async def fulfill_agent_income_stripe_checkout_session(session: dict) -> dict:
    """Record a paid Agent Income Stripe Checkout Session and produce the paid artifact."""
    metadata = dict(session.get("metadata") or {})
    offer = _agent_income_paid_offer(metadata.get("service_key") or metadata.get("service_slug") or "")
    if session.get("payment_status") not in ("paid", "no_payment_required") and session.get("status") != "complete":
        raise HTTPException(status_code=402, detail="Stripe checkout is not paid yet")

    provider_ref = session["id"]
    amount_total = session.get("amount_total")
    amount = (float(amount_total) / 100) if amount_total is not None else float(offer["price_usdc"])
    currency = (session.get("currency") or "usd").upper()
    db = await get_db()
    try:
        existing = await (
            await db.execute(
                "SELECT * FROM agent_income_ledger WHERE provider = ? AND provider_ref = ?",
                ("stripe", provider_ref),
            )
        ).fetchone()
        existing_metadata = {}
        if existing and existing["metadata"]:
            try:
                existing_metadata = json.loads(existing["metadata"])
            except json.JSONDecodeError:
                existing_metadata = {}
        if existing and existing["status"] == "verified":
            return {
                "status": "verified",
                "tier": offer["label"],
                "message": f"Payment already verified for {offer['label']}.",
                "ledger_id": existing["id"],
                "service": offer["key"],
                "amount": float(existing["amount"]),
                "currency": existing["currency"],
                "result": existing_metadata.get("output"),
            }

        customer_input = existing_metadata.get("customer_input") or {}
        output = _agent_income_paid_offer_output(offer, customer_input)
        economics = _agent_income_offer_economics(offer)
        ledger_id = existing["id"] if existing else generate_id("aile")
        recorded_at = now_iso()
        ledger_metadata = {
            **existing_metadata,
            "project": "agent-income",
            "service": offer["key"],
            "service_label": offer["label"],
            "email": metadata.get("email") or session.get("customer_email"),
            "customer_input_hash": output["input_hash"],
            "output": output,
            "economics": economics,
            "stripe_customer": session.get("customer"),
            "stripe_payment_status": session.get("payment_status"),
            "stripe_session": provider_ref,
            "clearance_status": "productized_inbound_paid_endpoint",
            "charge_first_spend_second_deliver_third": True,
        }
        if existing:
            await db.execute(
                """UPDATE agent_income_ledger
                   SET event_type = ?, amount = ?, currency = ?, status = ?, metadata = ?
                   WHERE id = ?""",
                (
                    "paid_offer_payment",
                    amount,
                    currency,
                    "verified",
                    json.dumps(ledger_metadata),
                    ledger_id,
                ),
            )
        else:
            await db.execute(
                """INSERT INTO agent_income_ledger
                   (id, task_id, run_id, event_type, amount, currency, status, provider, provider_ref, created_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ledger_id,
                    None,
                    None,
                    "paid_offer_payment",
                    amount,
                    currency,
                    "verified",
                    "stripe",
                    provider_ref,
                    recorded_at,
                    json.dumps(ledger_metadata),
                ),
            )
        await db.execute(
            """INSERT INTO audit_log (event, actor, metadata, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                "agent_income.stripe_offer.delivered",
                metadata.get("email") or session.get("customer_email") or "stripe_customer",
                json.dumps({"service": offer["key"], "amount": amount, "currency": currency, "ledger_id": ledger_id, "stripe_session": provider_ref}),
                recorded_at,
            ),
        )
        await db.commit()
    finally:
        await db.close()

    return {
        "status": "verified",
        "tier": offer["label"],
        "message": f"Payment verified for {offer['label']}.",
        "ledger_id": ledger_id,
        "service": offer["key"],
        "amount": amount,
        "currency": currency,
        "result": output,
        "receipt": {
            "ledger_id": ledger_id,
            "provider": "stripe",
            "provider_ref": provider_ref,
            "amount": amount,
            "currency": currency,
        },
    }


async def fulfill_stripe_checkout_session(session: dict) -> dict:
    """Fulfill a verified Stripe Checkout Session from webhook or success redirect."""
    metadata = dict(session.get("metadata") or {})
    if metadata.get("product") == "agent_income":
        return await fulfill_agent_income_stripe_checkout_session(session)
    if metadata.get("product") == "scam_check":
        phone_hash = metadata.get("phone_hash")
        credits = int(metadata.get("credits") or "0")
        if not phone_hash or credits <= 0:
            raise HTTPException(status_code=400, detail="Stripe scam-check session is missing phone_hash or credits")
        amount_total = session.get("amount_total")
        return await add_paid_credits_by_hash(
            phone_hash=phone_hash,
            credits=credits,
            reason=metadata.get("pack") or "stripe_checkout",
            provider="stripe",
            provider_ref=session["id"],
            amount=(float(amount_total) / 100) if amount_total is not None else None,
            currency=(session.get("currency") or "usd").upper(),
        )

    tier = metadata.get("tier")
    email = metadata.get("email") or session.get("customer_email")
    customer_details = session.get("customer_details") or {}
    email = email or customer_details.get("email")

    if tier not in TIER_PRICES or not email:
        raise HTTPException(status_code=400, detail="Stripe session is missing Clearance tier or email metadata")
    if session.get("payment_status") not in ("paid", "no_payment_required") and session.get("status") != "complete":
        raise HTTPException(status_code=402, detail="Stripe checkout is not paid yet")

    amount_total = session.get("amount_total") or (TIER_PRICES[tier] * 100)
    return await fulfill_paid_tier(
        email=email,
        tier=tier,
        amount=float(amount_total) / 100,
        currency=(session.get("currency") or "usd").upper(),
        provider="stripe",
        provider_ref=session["id"],
        metadata={
            "stripe_customer": session.get("customer"),
            "stripe_subscription": session.get("subscription"),
            "stripe_payment_status": session.get("payment_status"),
        },
        referred_by=metadata.get("ref"),
    )


def render_stripe_success_page(result: dict) -> HTMLResponse:
    status = html.escape(str(result.get("status") or "verified"))
    tier = html.escape(str(result.get("tier") or "paid"))
    message = html.escape(str(result.get("message") or "Payment verified."))
    api_key = str(result.get("api_key") or "")
    api_key_block = (
        f"""
        <div class="key-box">
          <div class="label">API key - shown once</div>
          <code id="api-key">{html.escape(api_key)}</code>
          <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('api-key').textContent);this.textContent='Copied'">Copy API key</button>
        </div>
        """
        if api_key else
        """
        <div class="key-box">
          <div class="label">Access updated</div>
          <p>Your existing Clearance key was upgraded for this plan.</p>
        </div>
        """
    )
    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payment verified - Clearance</title>
  <style>
    *{{box-sizing:border-box}}
    body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#080b12;color:#f7f3e8;font:15px/1.5 Inter,system-ui,sans-serif}}
    main{{width:min(680px,calc(100vw - 32px));border:1px solid rgba(245,158,11,.24);border-radius:18px;padding:28px;background:#101624;box-shadow:0 24px 80px rgba(0,0,0,.35)}}
    .eyebrow{{color:#f59e0b;text-transform:uppercase;letter-spacing:.16em;font-size:12px;font-weight:800}}
    h1{{margin:8px 0 8px;font-size:34px;line-height:1.05}}
    p{{color:#cbd5e1;margin:0 0 18px}}
    .key-box{{margin:20px 0;padding:16px;border:1px solid rgba(148,163,184,.22);border-radius:12px;background:#070b12}}
    .label{{color:#94a3b8;text-transform:uppercase;letter-spacing:.12em;font-size:11px;margin-bottom:8px}}
    code{{display:block;white-space:normal;word-break:break-all;color:#fef3c7;background:#111827;border:1px solid rgba(245,158,11,.18);border-radius:10px;padding:14px}}
    button,a{{display:inline-flex;align-items:center;justify-content:center;margin-top:12px;border:0;border-radius:999px;padding:11px 16px;background:#f59e0b;color:#111827;text-decoration:none;font-weight:800;cursor:pointer}}
    a.secondary{{background:transparent;color:#f7f3e8;border:1px solid rgba(148,163,184,.35);margin-left:8px}}
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">{status}</div>
    <h1>Clearance {tier} is active.</h1>
    <p>{message}</p>
    {api_key_block}
    <a href="/tutorial">Start setup</a>
    <a class="secondary" href="/">Back to Clearance</a>
  </main>
</body>
</html>""")


def render_agent_income_stripe_success_page(result: dict) -> HTMLResponse:
    status = html.escape(str(result.get("status") or "verified"))
    service = html.escape(str(result.get("tier") or result.get("service") or "Agent Income offer"))
    message = html.escape(str(result.get("message") or "Payment verified."))
    ledger_id = html.escape(str(result.get("ledger_id") or ""))
    result_json = html.escape(json.dumps(result.get("result") or {}, indent=2))
    receipt_json = html.escape(json.dumps(result.get("receipt") or {}, indent=2))
    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payment verified - Agent Income</title>
  <style>
    *{{box-sizing:border-box}}
    body{{margin:0;min-height:100vh;background:#101116;color:#f7f8fb;font:15px/1.5 Inter,system-ui,sans-serif}}
    main{{width:min(920px,calc(100vw - 32px));margin:0 auto;padding:38px 0 56px}}
    .eyebrow{{color:#51d49f;text-transform:uppercase;letter-spacing:.16em;font-size:12px;font-weight:800}}
    h1{{margin:8px 0 8px;font-size:clamp(34px,6vw,58px);line-height:1}}
    p{{color:#aeb7c4}}
    .panel{{border:1px solid #2b303b;border-radius:8px;background:#17191f;padding:18px;margin-top:16px}}
    code,pre{{font-family:"SF Mono",Menlo,monospace;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}}
    pre{{margin:0;border:1px solid #2b303b;border-radius:8px;background:#101219;padding:12px;color:#dfe6ef}}
    a,button{{display:inline-flex;align-items:center;justify-content:center;border-radius:8px;padding:10px 12px;text-decoration:none;font-weight:800}}
    a{{color:#17130e;background:#e8912d;margin-top:14px}}
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">{status}</div>
    <h1>{service}</h1>
    <p>{message}</p>
    <div class="panel">
      <strong>Receipt</strong>
      <p>Ledger ID: <code>{ledger_id}</code></p>
      <pre>{receipt_json}</pre>
    </div>
    <div class="panel">
      <strong>Paid artifact</strong>
      <pre>{result_json}</pre>
    </div>
    <a href="/agent-income/agents">Back to Agent Income</a>
  </main>
</body>
</html>""")


@app.get("/v1/payments/stripe/success", response_class=HTMLResponse, tags=["Payments"])
async def stripe_checkout_success(session_id: str):
    """Verify Stripe Checkout on return and issue/upgrade access immediately."""
    if not STRIPE_SECRET_KEY or stripe is None:
        raise HTTPException(status_code=503, detail="Stripe card checkout is not connected on this host.")
    if not session_id.startswith("cs_"):
        raise HTTPException(status_code=400, detail="Invalid Stripe checkout session")
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to verify Stripe checkout: {exc}") from exc
    result = await fulfill_stripe_checkout_session(session)
    return render_stripe_success_page(result)


@app.get("/agent-income/stripe/success", response_class=HTMLResponse, tags=["Agent Income", "Payments"])
async def agent_income_stripe_checkout_success(session_id: str):
    """Verify Stripe Checkout on return and deliver the Agent Income paid artifact."""
    if not STRIPE_SECRET_KEY or stripe is None:
        raise HTTPException(status_code=503, detail="Stripe card checkout is not connected on this host.")
    if not session_id.startswith("cs_"):
        raise HTTPException(status_code=400, detail="Invalid Stripe checkout session")
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to verify Stripe checkout: {exc}") from exc
    result = await fulfill_agent_income_stripe_checkout_session(session)
    return render_agent_income_stripe_success_page(result)


@app.post("/v1/payments/stripe/webhook", tags=["Payments"])
async def stripe_webhook(request: Request):
    """Fulfill paid tiers from signed Stripe Checkout webhooks."""
    if not STRIPE_WEBHOOK_SECRET or stripe is None:
        logging.getLogger("clearance.stripe").warning(
            "Stripe webhook delivery rejected (503): %s. "
            "Card payments cannot be fulfilled via webhook until this is fixed.",
            "STRIPE_WEBHOOK_SECRET is unset" if not STRIPE_WEBHOOK_SECRET else "stripe SDK is not installed",
        )
        raise HTTPException(status_code=503, detail="Stripe webhook is not configured.")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature") from exc

    if event["type"] not in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        return {"received": True, "ignored": event["type"]}

    response = await fulfill_stripe_checkout_session(event["data"]["object"])
    return {"received": True, **response}


@app.get("/v1/payments/info", tags=["Payments"])
async def payment_info():
    """
    Get payment information for subscribing to a paid tier.
    Machine-readable endpoint for AI agents to discover how to pay.
    """
    return {
        "wallet": {
            "address": PAYMENT_WALLET,
            "ens": PAYMENT_ENS,
            "chain": PAYMENT_CHAIN,
            "chain_id": PAYMENT_CHAIN_ID,
            "accepted_tokens": ["USDC"],
            "usdc_contract": USDC_CONTRACT,
        },
        "checkout_policy": {
            "default_payment_method": "Card via Stripe or USDC on Base" if STRIPE_SECRET_KEY else "USDC on Base",
            "card_checkout": "Stripe Checkout" if STRIPE_SECRET_KEY else "not_configured",
            "other_assets_policy": OTHER_ASSET_POLICY,
            "pricing_rule": "Non-default payments must map to a clear USD-equivalent amount before fulfillment.",
            "release_rule": RELEASE_RULE,
            "supported_non_default_assets": "invoice-confirmed only",
        },
        "tiers": {
            "starter": {"price_usdc": 0, "clearances_per_month": 50},
            "pro": {"price_usdc": 19, "clearances_per_month": 1000},
            "scale": {"price_usdc": 49, "clearances_per_month": 10000},
        },
        "scam_check": {
            "public_url": SCRAM_BASE_URL,
            "sms_webhook": "/v1/sms/inbound",
            "whatsapp_webhook": "/v1/whatsapp/inbound",
            "telegram_webhook": "/v1/scram/telegram/webhook",
            "imessage_adapter": "/v1/scram/imessage/inbound",
            "public_webhooks": {
                "sms": f"{SCRAM_BASE_URL}/v1/sms/inbound",
                "whatsapp": f"{SCRAM_BASE_URL}/v1/whatsapp/inbound",
                "telegram": f"{SCRAM_BASE_URL}/v1/scram/telegram/webhook",
                "imessage_adapter": f"{SCRAM_BASE_URL}/v1/scram/imessage/inbound",
            },
            "demo_page": "/scram",
            "free_checks": get_initial_free_checks(),
            "free_helper_messages": get_initial_free_help_messages(),
            "text_code": SCRAM_TEXT_CODE,
            "twilio_short_code": TWILIO_SHORT_CODE,
            "twilio_signature_validation": twilio_signature_validation_enabled(),
            "twilio_whatsapp_from_configured": bool(TWILIO_WHATSAPP_FROM),
            "helper_model": os.getenv("SCRAM_OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini",
            "credit_packs": {
                key: {
                    "label": pack["label"],
                    "credits": pack["credits"],
                    "price_usd": pack["price_usd"],
                }
                for key, pack in SCAMCHECK_CREDIT_PACKS.items()
            },
            "payment_url": scamcheck_payment_url(),
        },
        "verification": {
            "min_confirmations": MIN_CONFIRMATIONS,
            "method": "on-chain RPC verification",
            "no_key_until_verified": True,
            "manual_release_required": False,
            "checkout_mode": "stripe_checkout_or_self_serve_usdc_on_base",
        },
        "instructions": (
            "Use /v1/payments/stripe/checkout for card checkout, or send the exact USDC amount on Base chain to the published payment identity and POST to /v1/payments/crypto with email, tx_hash, and tier. Fixed-price plan keys are issued automatically once payment verification passes."
            if STRIPE_SECRET_KEY else
            "Send the exact USDC amount on Base chain to the published payment identity and POST to /v1/payments/crypto with email, tx_hash, and tier. Fixed-price plan keys are issued automatically once payment verification passes."
        ),
        "refunds": f"Email {PAYMENT_SUPPORT_EMAIL}",
    }


@app.get("/v1/scram/readiness", tags=["SCRAM"])
async def scram_readiness():
    """Report whether real customer messages can reach SCRAM without exposing secrets."""
    base_url = SCRAM_BASE_URL.rstrip("/")
    twilio_account_configured = bool(os.getenv("TWILIO_ACCOUNT_SID"))
    twilio_auth_configured = bool(TWILIO_AUTH_TOKEN)
    twilio_sender_configured = bool(
        os.getenv("TWILIO_MESSAGING_SERVICE_SID")
        or os.getenv("SMS_FROM_NUMBER")
        or TWILIO_SHORT_CODE
    )
    public_https_base = base_url.startswith("https://") and "localhost" not in base_url and "127.0.0.1" not in base_url
    twilio_ready = (
        SMS_PROVIDER.strip().lower() == "twilio"
        and twilio_account_configured
        and twilio_auth_configured
        and twilio_sender_configured
        and public_https_base
    )

    blockers = []
    if SMS_PROVIDER.strip().lower() != "twilio":
        blockers.append("Set SMS_PROVIDER=twilio for production SMS.")
    if not twilio_account_configured:
        blockers.append("Set TWILIO_ACCOUNT_SID.")
    if not twilio_auth_configured:
        blockers.append("Set TWILIO_AUTH_TOKEN.")
    if not public_https_base:
        blockers.append("Set SCRAM_BASE_URL to https://scram.nauti-labs.com.")
    blockers.append(
        "Confirm short code 72726 is provisioned in Twilio and its inbound webhook points to /v1/sms/inbound."
    )

    return {
        "status": "ready" if twilio_ready else "not_ready",
        "text_code": SCRAM_TEXT_CODE,
        "twilio_short_code": TWILIO_SHORT_CODE,
        "public_base_url": base_url,
        "site_url": base_url,
        "webhooks": {
            "sms": f"{base_url}/v1/sms/inbound",
            "whatsapp": f"{base_url}/v1/whatsapp/inbound",
            "telegram": f"{base_url}/v1/scram/telegram/webhook",
            "imessage_adapter": f"{base_url}/v1/scram/imessage/inbound",
        },
        "configured": {
            "sms_provider": SMS_PROVIDER,
            "public_https_base": public_https_base,
            "twilio_account_sid": twilio_account_configured,
            "twilio_auth_token": twilio_auth_configured,
            "twilio_messaging_service_sid": bool(os.getenv("TWILIO_MESSAGING_SERVICE_SID")),
            "twilio_signature_validation": twilio_signature_validation_enabled(),
            "sms_from_number_or_short_code": twilio_sender_configured,
            "telegram_bot_token": bool(TELEGRAM_BOT_TOKEN),
            "telegram_webhook_secret": bool(TELEGRAM_WEBHOOK_SECRET),
            "openai_api_key": bool(os.getenv("OPENAI_API_KEY")),
        },
        "real_sms_can_reach_scram": twilio_ready,
        "blockers": blockers if not twilio_ready else blockers[-1:],
    }


# --- Health ---

@app.get("/health", tags=["System"])
async def health():
    return {"status": "operational", "service": "clearance", "version": "1.0.0"}


@app.get("/{ambassador}", tags=["Pages"], include_in_schema=False)
async def ambassador_vanity_redirect(ambassador: str, request: Request):
    """Accept common copied links like /davidfx and canonicalize configured refs."""
    ref = await canonical_traffic_ref(ambassador, require_configured=True)
    if not ref:
        raise HTTPException(status_code=404, detail="Not Found")
    await _record_visit(request, ref)
    response = RedirectResponse(url="/", status_code=302)
    _set_ref_cookie(response, ref)
    return response


# --- Run ---

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "0") == "1",
    )
