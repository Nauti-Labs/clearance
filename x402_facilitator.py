"""Settle standard x402 v2 exact (EIP-3009) payments through a facilitator.

The facilitator URL defaults to the Coinbase CDP facilitator. CDP_API_KEY_ID and
CDP_API_KEY_SECRET are sent as a short-lived bearer JWT when both are set.
Expected payment failures return a result dict. They do not raise.
"""

import base64
import json
import os
import secrets
import time
from urllib.parse import urlparse

import httpx

DEFAULT_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"


def facilitator_url() -> str:
    configured = (os.getenv("X402_FACILITATOR_URL") or DEFAULT_FACILITATOR_URL).strip()
    return configured.rstrip("/") or DEFAULT_FACILITATOR_URL


def credentials_configured() -> bool:
    return bool(os.getenv("CDP_API_KEY_ID", "").strip() and os.getenv("CDP_API_KEY_SECRET", "").strip())


def decode_payment_header(value: str) -> dict:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Empty payment header")
    if raw.startswith("{"):
        parsed = json.loads(raw)
    else:
        padded = raw + "=" * ((4 - len(raw) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            decoded = base64.urlsafe_b64decode(padded)
        parsed = json.loads(decoded.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Payment header must be a JSON object")
    return parsed


def _failure(message: str) -> dict:
    return {"ok": False, "error": message, "tx_hash": None, "payer": None}


def _load_cdp_signing_key(secret: str):
    """Return (key, jwt_alg) for an Ed25519 seed or a PEM private key."""
    normalized = secret.replace("\\n", "\n").strip()
    if "BEGIN" in normalized:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(normalized.encode("utf-8"), password=None)
        alg = "EdDSA" if key.__class__.__name__.startswith("Ed25519") else "ES256"
        return key, alg

    raw = base64.b64decode(normalized)
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("CDP_API_KEY_SECRET must be a base64 Ed25519 key or a PEM private key")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(raw), "EdDSA"


def _cdp_jwt(method: str, url: str) -> str:
    import jwt

    key_id = os.getenv("CDP_API_KEY_ID", "").strip()
    secret = os.getenv("CDP_API_KEY_SECRET", "").strip()
    if not key_id or not secret:
        raise RuntimeError("CDP API credentials are not configured")
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    now = int(time.time())
    key, alg = _load_cdp_signing_key(secret)
    headers = {
        "alg": alg,
        "typ": "JWT",
        "kid": key_id,
        "nonce": secrets.token_hex(16),
    }
    payload = {
        "sub": key_id,
        "iss": "cdp",
        "aud": ["cdp_service"],
        "nbf": now,
        "exp": now + 120,
        "uri": f"{method.upper()} {parsed.netloc}{path}",
    }
    token = jwt.encode(payload, key, algorithm=alg, headers=headers)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _accept_objects(requirements: dict) -> list[dict]:
    accepts = requirements.get("accepts") if isinstance(requirements, dict) else None
    if isinstance(accepts, list):
        return [item for item in accepts if isinstance(item, dict)]
    return []


def _scheme_of(payload: dict, requirements: dict) -> str:
    accepted = payload.get("accepted") if isinstance(payload.get("accepted"), dict) else {}
    for source in (payload.get("scheme"), accepted.get("scheme")):
        if source:
            return str(source)
    accepts = _accept_objects(requirements)
    if accepts and accepts[0].get("scheme"):
        return str(accepts[0]["scheme"])
    return "exact"


def _matching_requirements(payload: dict, requirements: dict) -> dict:
    accepts = _accept_objects(requirements)
    accepted = payload.get("accepted") if isinstance(payload.get("accepted"), dict) else {}
    if accepted:
        for item in accepts:
            scheme_ok = not accepted.get("scheme") or item.get("scheme") == accepted.get("scheme")
            network_ok = not accepted.get("network") or item.get("network") == accepted.get("network")
            if scheme_ok and network_ok:
                return item
    for item in accepts:
        if item.get("scheme") == "exact":
            return item
    return accepts[0] if accepts else {}


def prepare_facilitator_body(payment_payload: dict, requirements: dict) -> dict:
    """Copy the client payload and keep resource plus extensions.bazaar."""
    payload = json.loads(json.dumps(payment_payload))
    resource = payload.get("resource")
    resource_url = resource.get("url") if isinstance(resource, dict) else (resource if isinstance(resource, str) else "")
    if not resource_url:
        req_resource = requirements.get("resource") if isinstance(requirements.get("resource"), dict) else {}
        accept = _matching_requirements(payload, requirements)
        if req_resource.get("url"):
            payload["resource"] = {
                "url": req_resource.get("url"),
                "description": req_resource.get("description") or accept.get("description") or "",
                "mimeType": req_resource.get("mimeType") or accept.get("mimeType") or "application/json",
            }
        else:
            payload["resource"] = {
                "url": accept.get("resource") or "",
                "description": accept.get("description") or "",
                "mimeType": accept.get("mimeType") or "application/json",
            }
    elif isinstance(resource, str):
        payload["resource"] = {"url": resource, "mimeType": "application/json"}

    extensions = payload.get("extensions") if isinstance(payload.get("extensions"), dict) else {}
    if "bazaar" not in extensions:
        bazaar = None
        req_extensions = requirements.get("extensions") if isinstance(requirements.get("extensions"), dict) else {}
        if "bazaar" in req_extensions:
            bazaar = req_extensions.get("bazaar")
        if bazaar is not None:
            extensions["bazaar"] = bazaar
    payload["extensions"] = extensions
    payload.setdefault("x402Version", requirements.get("x402Version") or 2)
    return {
        "x402Version": int(payload.get("x402Version") or requirements.get("x402Version") or 2),
        "paymentPayload": payload,
        "paymentRequirements": _matching_requirements(payload, requirements),
    }


async def _post_json(url: str, body: dict) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if credentials_configured():
        headers["Authorization"] = f"Bearer {_cdp_jwt('POST', url)}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(url, json=body, headers=headers)
    try:
        data = response.json()
    except Exception:
        data = {"error": (response.text or "")[:300]}
    if not isinstance(data, dict):
        data = {"error": "Facilitator returned a non-object response"}
    if response.status_code >= 400:
        reason = data.get("invalidReason") or data.get("errorReason") or data.get("error") or data.get("message")
        raise httpx.HTTPStatusError(
            str(reason or f"Facilitator returned HTTP {response.status_code}"),
            request=response.request,
            response=response,
        )
    return data


def _error_text(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return str(exc)
    if isinstance(exc, httpx.HTTPError):
        return f"Payment facilitator could not be reached ({type(exc).__name__})."
    return f"Payment facilitator request failed ({type(exc).__name__})."


async def verify_and_settle(payment_header: str, requirements: dict) -> dict:
    """Verify then settle an x402 exact payment. Never raises for expected failures."""
    if not credentials_configured():
        return _failure(
            "Standard x402 settlement is not configured. Set CDP_API_KEY_ID and CDP_API_KEY_SECRET, "
            "or pay with a direct Base USDC transfer using X-Payment-Tx and quote_id."
        )
    try:
        decoded = decode_payment_header(payment_header)
    except Exception:
        return _failure("PAYMENT-SIGNATURE is not a valid x402 payment payload.")

    scheme = _scheme_of(decoded, requirements or {})
    if scheme != "exact":
        return _failure("Only the x402 exact (EIP-3009) scheme is accepted.")

    try:
        body = prepare_facilitator_body(decoded, requirements or {})
    except Exception:
        return _failure("Could not build the x402 facilitator request from this payment payload.")

    resource = body["paymentPayload"].get("resource") if isinstance(body["paymentPayload"].get("resource"), dict) else {}
    if not resource.get("url"):
        return _failure("x402 payment payload is missing resource.url.")
    if "bazaar" not in (body["paymentPayload"].get("extensions") or {}):
        return _failure("x402 payment payload is missing extensions.bazaar.")

    base = facilitator_url()
    try:
        verified = await _post_json(f"{base}/verify", body)
    except Exception as exc:
        return _failure(_error_text(exc) or "Payment facilitator rejected verification.")

    if not verified.get("isValid", False):
        reason = verified.get("invalidReason") or verified.get("error") or "Payment verification failed"
        return _failure(str(reason))

    try:
        settled = await _post_json(f"{base}/settle", body)
    except Exception as exc:
        return _failure(_error_text(exc) or "Payment facilitator rejected settlement.")

    if settled.get("success") is False:
        reason = settled.get("errorReason") or settled.get("error") or settled.get("invalidReason") or "Settlement failed"
        return _failure(str(reason))

    tx_hash = str(settled.get("transaction") or settled.get("txHash") or settled.get("tx") or "").strip()
    payer = str(settled.get("payer") or verified.get("payer") or "").strip()
    if not tx_hash:
        return _failure("Facilitator settled the payment without a transaction hash.")
    return {"ok": True, "error": None, "tx_hash": tx_hash, "payer": payer}
