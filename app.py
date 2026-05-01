"""
Clearance by Nauti-Labs
Human Approval API for AI Agent Commerce

The missing auth layer between human intent and agent execution.
"""

import os
import re
import json
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Header, Request, Depends, Response, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

try:
    import stripe
except ImportError:  # pragma: no cover - dependency is optional in minimal local runs
    stripe = None

try:
    from jose import jwt, JWTError
except ImportError:  # pragma: no cover - exercised in local fallback runtime
    from jwt_compat import jwt, JWTError

from database import init_db, get_db
from crypto_verify import verify_usdc_payment
from models import (
    CreateClearance, ApproveAction, CreateAPIKey, RegisterWebhook,
    ClearanceResponse, VerifyResponse, APIKeyResponse, UsageResponse,
    ErrorResponse, ClearanceStatus, Tier,
    FamilyLogin, FamilySyncPayload, FamilyPayeeCreate,
    FamilyActionCreate, FamilyActionDecision,
)

load_dotenv()

DEFAULT_JWT_SECRET = "dev-secret-change-in-production"
JWT_SECRET = os.getenv("JWT_SECRET_KEY", DEFAULT_JWT_SECRET)
JWT_ALGORITHM = "HS256"
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", BASE_URL)
BRAND_URL = os.getenv("BRAND_URL", "https://nauti-labs.com")
PAYMENT_WALLET = os.getenv("PAYMENT_WALLET", "")
PAYMENT_ENS = os.getenv("PAYMENT_ENS", "")
PAYMENT_CHAIN = os.getenv("PAYMENT_CHAIN", "base")
PAYMENT_CHAIN_ID = int(os.getenv("PAYMENT_CHAIN_ID", "8453"))
PAYMENT_SUPPORT_EMAIL = os.getenv("PAYMENT_SUPPORT_EMAIL", "consulting@nauti-labs.com")
USDC_CONTRACT = os.getenv("USDC_CONTRACT", "")
MIN_CONFIRMATIONS = int(os.getenv("MIN_CONFIRMATIONS", "12"))
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", f"{BASE_URL.rstrip('/')}/?checkout=success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", f"{BASE_URL.rstrip('/')}/?checkout=cancelled")
FAMILY_SESSION_COOKIE = os.getenv("FAMILY_SESSION_COOKIE", "clearance_family_session")
FAMILY_SESSION_HOURS = int(os.getenv("FAMILY_SESSION_HOURS", "18"))
FAMILY_SYNC_TOKEN = os.getenv("FAMILY_SYNC_TOKEN", "")
FAMILY_PRODUCT_NAME = os.getenv("FAMILY_PRODUCT_NAME", "Harbor Ledger")
FAMILY_HOUSEHOLD_NAME = os.getenv("FAMILY_HOUSEHOLD_NAME", "LeBlanc Family")

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
    yield


# --- App ---

app = FastAPI(
    title="Clearance API",
    description="Human Approval API for AI Agent Commerce. Agents request clearance, humans approve, services verify.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/v1/docs",
    redoc_url="/v1/redoc",
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
TRAFFIC_ADMIN_COOKIE = "nauti_traffic_admin"
TRAFFIC_ADMIN_SESSION_HOURS = int(os.getenv("NAUTI_TRAFFIC_ADMIN_SESSION_HOURS", "12"))
TRAFFIC_CONFIG_KEY = "nauti_traffic_config"
TRUSTED_BY_PATH = Path(__file__).resolve().parent / "static" / "trusted_by.json"
_REF_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_ADMIN_PATH_RE = re.compile(r"^[a-zA-Z0-9_-]{16,128}$")
_BOT_RE = re.compile(r"bot|crawler|spider|preview|fetch|monitoring", re.IGNORECASE)


def _validate_ref(value):
    """Sanitize ambassador / ref names. Returns canonicalized lowercase name or None."""
    if not value:
        return None
    s = str(value).strip()
    if not _REF_RE.match(s):
        return None
    return s.lower()


def _is_bot_ua(ua: str) -> bool:
    return bool(ua) and bool(_BOT_RE.search(ua))


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
                    request.client.host if request.client else None,
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
    return {
        "_comment": config.get("_comment", ""),
        "captain": captain,
        "_first_mates_doc": config.get(
            "_first_mates_doc",
            "Up to 10 First Mate badges total. Tier below Captain. Add ref names lowercased.",
        ),
        "first_mates": _dedupe(config.get("first_mates"))[:10],
        "ref_aliases": _clean_mapping(config.get("ref_aliases")),
        "hidden_refs": _dedupe(config.get("hidden_refs")),
        "avatar_overrides": _clean_mapping(config.get("avatar_overrides")),
        "avatar_urls": _clean_mapping(config.get("avatar_urls")),
        "trusted_by": config.get("trusted_by") if isinstance(config.get("trusted_by"), list) else [],
        "onboarding": config.get("onboarding") if isinstance(config.get("onboarding"), list) else [],
    }


def _merge_traffic_config(base: dict, override: dict | None) -> dict:
    merged = json.loads(json.dumps(base))
    if isinstance(override, dict):
        for key in ("captain", "first_mates", "trusted_by", "onboarding", "hidden_refs"):
            if key in override:
                merged[key] = override[key]
        for key in ("ref_aliases", "avatar_overrides", "avatar_urls"):
            if isinstance(override.get(key), dict):
                current = merged.get(key) if isinstance(merged.get(key), dict) else {}
                current.update(override[key])
                merged[key] = current
    return _normalize_traffic_config(merged)


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
    return RedirectResponse(url=f"{_traffic_admin_path(access_token)}{suffix}", status_code=303)


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
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


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
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent")
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=FREE_KEY_SIGNUP_WINDOW_MINUTES)).isoformat()

        cursor = await db.execute(
            "SELECT id, tier FROM api_keys WHERE email = ? AND active = 1",
            (body.email,)
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

        # Ambassador attribution: read the visit cookie set by /r/{name} or ?ref=.
        ref = _read_ref_cookie(request)

        await db.execute(
            """INSERT INTO api_keys (id, key_hash, email, name, tier, credits_remaining, credits_reset_at, created_at, referred_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (key_id, key_h, body.email, body.name, "starter", 50, reset_at, now_iso(), ref)
        )
        await db.commit()

        await db.execute(
            """INSERT INTO audit_log (api_key_id, event, actor, ip, user_agent, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                key_id,
                "key.created",
                body.email,
                client_ip,
                user_agent,
                json.dumps({"tier": "starter", "referred_by": ref}),
                now_iso(),
            )
        )
        await db.commit()

        return APIKeyResponse(
            api_key=raw_key,
            tier=Tier.starter,
            credits_remaining=50,
            message="Store this key securely — it won't be shown again."
        )
    finally:
        await db.close()


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

        # TODO: Fire webhook if callback_url is set

        return {
            "id": clearance_id,
            "status": new_status,
            "decided_at": decided_at,
            "token": token,
        }
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
            return templates.TemplateResponse("approve.html", {
                "request": request,
                "error": "Clearance not found",
                "clearance": None,
            })

        clearance = dict(row)
        clearance["metadata"] = json.loads(clearance["metadata"]) if clearance["metadata"] else None

        return templates.TemplateResponse("approve.html", {
            "request": request,
            "clearance": clearance,
            "error": None,
            "base_url": BASE_URL,
        })
    finally:
        await db.close()


# --- Landing Page ---

@app.get("/", response_class=HTMLResponse, tags=["Pages"])
async def landing_page(request: Request):
    # Resolve ref: explicit ?ref= wins, else ?utm_source=, else existing cookie.
    ref = (
        _validate_ref(request.query_params.get("ref"))
        or _validate_ref(request.query_params.get("utm_source"))
        or _read_ref_cookie(request)
    )
    # Log the visit (server-side, provable receipt)
    await _record_visit(request, ref)

    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "base_url": BASE_URL.rstrip("/"),
            "brand_url": BRAND_URL.rstrip("/"),
            "support_email": PAYMENT_SUPPORT_EMAIL,
            "payment_ens": PAYMENT_ENS or "invoice-required",
            "payment_wallet": PAYMENT_WALLET,
            "payment_chain_id": PAYMENT_CHAIN_ID,
            "usdc_contract": USDC_CONTRACT,
        },
    )
    if ref:
        _set_ref_cookie(response, ref)
    return response


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


async def _ambassador_stats_payload(ref: str) -> dict:
    """Compute one ambassador's stats. Used by both admin + public endpoints.

    Privacy: never includes emails or IPs. Per-tier paid breakdown included.
    """
    db = await get_db()
    try:
        click_total = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM visits WHERE ref = ? AND is_bot = 0", (ref,)
        )).fetchone())["n"]
        first_click = (await (await db.execute(
            "SELECT MIN(created_at) AS t FROM visits WHERE ref = ?", (ref,)
        )).fetchone())["t"]
        last_click = (await (await db.execute(
            "SELECT MAX(created_at) AS t FROM visits WHERE ref = ?", (ref,)
        )).fetchone())["t"]
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
        return {
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


async def _general_traffic_payload() -> dict:
    """Aggregate non-attributed visits + signups (Telegram / Reddit / direct / SEO / etc)."""
    db = await get_db()
    try:
        clicks = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM visits WHERE ref IS NULL AND is_bot = 0 AND path = '/'"
        )).fetchone())["n"]
        signups = (await (await db.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE referred_by IS NULL"
        )).fetchone())["n"]
        tier_rows = await (await db.execute(
            """SELECT tier, COUNT(*) AS n, COALESCE(SUM(amount), 0) AS rev
               FROM payments
               WHERE referred_by IS NULL AND status = 'verified'
               GROUP BY tier"""
        )).fetchall()
        tier_map = {r["tier"]: {"count": r["n"], "monthly_revenue_usd": float(r["rev"])} for r in tier_rows}
        pro = tier_map.get("pro", {"count": 0, "monthly_revenue_usd": 0.0})
        scale = tier_map.get("scale", {"count": 0, "monthly_revenue_usd": 0.0})
        total_paid = pro["count"] + scale["count"]
        total_rev = pro["monthly_revenue_usd"] + scale["monthly_revenue_usd"]
        free_signups = max(signups - total_paid, 0)
        return {
            "clicks": clicks,
            "free_signups": free_signups,
            "pro": pro,
            "scale": scale,
            "paid_conversions": total_paid,
            "monthly_revenue_usd": total_rev,
        }
    finally:
        await db.close()


@app.get("/v1/traffic/config", tags=["Public"])
async def public_traffic_config():
    """Public display config for Nauti-Traffic. No visitor metadata."""
    return await load_traffic_config()


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
        return templates.TemplateResponse(
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

    config = await load_traffic_config()
    stats = await public_traffic_leaderboard()
    return templates.TemplateResponse(
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


@app.post("/nauti-traffic/admin/{access_token}/login", tags=["Admin"])
async def nauti_traffic_admin_login(access_token: str, pin: str = Form("")):
    admin_path = _verify_traffic_admin_path(access_token)
    if not re.fullmatch(r"\d{6}", TRAFFIC_ADMIN_PIN):
        return _traffic_admin_redirect(access_token, "error=pin_not_configured")
    if not secrets.compare_digest(pin.strip(), TRAFFIC_ADMIN_PIN):
        return _traffic_admin_redirect(access_token, "error=bad_pin")

    redirect = _traffic_admin_redirect(access_token, "notice=unlocked")
    redirect.set_cookie(
        TRAFFIC_ADMIN_COOKIE,
        _make_traffic_admin_token(access_token),
        max_age=TRAFFIC_ADMIN_SESSION_HOURS * 3600,
        httponly=True,
        secure=not _is_local_url(BASE_URL),
        samesite="lax",
        path=admin_path,
    )
    return redirect


@app.post("/nauti-traffic/admin/{access_token}/logout", tags=["Admin"])
async def nauti_traffic_admin_logout(access_token: str):
    admin_path = _verify_traffic_admin_path(access_token)
    response = _traffic_admin_redirect(access_token, "notice=locked")
    response.delete_cookie(TRAFFIC_ADMIN_COOKIE, path=admin_path)
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
    first_mates = _dedupe(config.get("first_mates"))
    hidden_refs = set(_dedupe(config.get("hidden_refs")))
    hidden_refs.discard(clean_ref)

    badge = badge.strip().lower()
    if badge == "captain":
        config["captain"] = clean_ref
        first_mates = [item for item in first_mates if item != clean_ref]
    elif badge == "first_mate":
        if clean_ref != config.get("captain") and clean_ref not in first_mates:
            if len(first_mates) >= 10:
                return _traffic_admin_redirect(access_token, "error=first_mates_full")
            first_mates.append(clean_ref)
    else:
        first_mates = [item for item in first_mates if item != clean_ref]
        if config.get("captain") == clean_ref:
            config["captain"] = None

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
    db = await get_db()
    try:
        cur = await db.execute("""
            SELECT DISTINCT ref FROM (
                SELECT ref FROM visits WHERE ref IS NOT NULL
                UNION
                SELECT referred_by AS ref FROM api_keys WHERE referred_by IS NOT NULL
                UNION
                SELECT referred_by AS ref FROM payments WHERE referred_by IS NOT NULL
            )
        """)
        refs = [r["ref"] for r in await cur.fetchall() if r["ref"]]
    finally:
        await db.close()

    rows = []
    for ref in refs:
        try:
            rows.append(await _ambassador_stats_payload(ref))
        except Exception:
            continue
    rows.sort(key=lambda x: (x["clicks"], x["paid_conversions"]), reverse=True)
    return {
        "ambassadors": rows,
        "count": len(rows),
        "general_traffic": await _general_traffic_payload(),
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
        "family_login.html",
        {
            "request": request,
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
        "family_dashboard.html",
        {
            "request": request,
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


@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    return PlainTextResponse("User-agent: *\nAllow: /\n")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/favicon.svg")


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
        raise HTTPException(status_code=503, detail="Stripe checkout is not configured yet. Use USDC checkout or email support.")

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


@app.post("/v1/payments/stripe/webhook", tags=["Payments"])
async def stripe_webhook(request: Request):
    """Fulfill paid tiers from signed Stripe Checkout webhooks."""
    if not STRIPE_WEBHOOK_SECRET or stripe is None:
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

    session = event["data"]["object"]
    metadata = dict(session.get("metadata") or {})
    tier = metadata.get("tier")
    email = metadata.get("email") or session.get("customer_email")
    customer_details = session.get("customer_details") or {}
    email = email or customer_details.get("email")

    if tier not in TIER_PRICES or not email:
        raise HTTPException(status_code=400, detail="Stripe session is missing Clearance tier or email metadata")

    amount_total = session.get("amount_total") or (TIER_PRICES[tier] * 100)
    response = await fulfill_paid_tier(
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
    )
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
            "default_payment_method": "Card via Stripe or USDC on Base",
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
        "verification": {
            "min_confirmations": MIN_CONFIRMATIONS,
            "method": "on-chain RPC verification",
            "no_key_until_verified": True,
            "manual_release_required": False,
            "checkout_mode": "stripe_checkout_or_self_serve_usdc_on_base",
        },
        "instructions": "Use /v1/payments/stripe/checkout for card checkout, or send the exact USDC amount on Base chain to the published payment identity and POST to /v1/payments/crypto with email, tx_hash, and tier. Fixed-price plan keys are issued automatically once payment verification passes.",
        "refunds": f"Email {PAYMENT_SUPPORT_EMAIL}",
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
