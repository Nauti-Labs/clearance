import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

try:
    import jwt as _pyjwt
    from jwt.exceptions import InvalidTokenError as _PyJWTError
except ImportError:  # pragma: no cover - requirements pin PyJWT
    _pyjwt = None
    _PyJWTError = Exception


class JWTError(Exception):
    pass


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _json_dumps(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _reject_expired(payload: dict) -> None:
    expires_at = payload.get("expires_at")
    if not expires_at:
        return
    try:
        expires_dt = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError) as exc:
        raise JWTError("Invalid expires_at value") from exc
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_dt:
        raise JWTError("Token has expired")


def encode(payload: dict, secret: str, algorithm: str = "HS256") -> str:
    if _pyjwt is not None:
        if algorithm != "HS256":
            raise JWTError("Only HS256 is supported")
        token = _pyjwt.encode(payload, secret, algorithm=algorithm)
        return token if isinstance(token, str) else token.decode("ascii")

    if algorithm != "HS256":
        raise JWTError("Only HS256 is supported in the built-in JWT fallback")

    header = {"alg": algorithm, "typ": "JWT"}
    signing_input = ".".join(
        [
            _b64url_encode(_json_dumps(header)),
            _b64url_encode(_json_dumps(payload)),
        ]
    )
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def decode(token: str, secret: str, algorithms: list[str] | None = None) -> dict:
    allowed = algorithms or ["HS256"]
    if "HS256" not in allowed:
        raise JWTError("Unsupported JWT algorithm")

    if _pyjwt is not None:
        try:
            payload = _pyjwt.decode(token, secret, algorithms=allowed)
        except _PyJWTError as exc:
            raise JWTError(str(exc)) from exc
        _reject_expired(payload)
        return payload

    try:
        header_segment, payload_segment, signature_segment = token.split(".")
    except ValueError as exc:
        raise JWTError("Invalid token format") from exc

    signing_input = f"{header_segment}.{payload_segment}"
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()

    actual_signature = _b64url_decode(signature_segment)
    if not hmac.compare_digest(actual_signature, expected_signature):
        raise JWTError("Invalid token signature")

    try:
        payload = json.loads(_b64url_decode(payload_segment))
    except json.JSONDecodeError as exc:
        raise JWTError("Invalid token payload") from exc

    _reject_expired(payload)
    return payload


class _JWTModule:
    @staticmethod
    def encode(payload: dict, secret: str, algorithm: str = "HS256") -> str:
        return encode(payload, secret, algorithm=algorithm)

    @staticmethod
    def decode(token: str, secret: str, algorithms: list[str] | None = None) -> dict:
        return decode(token, secret, algorithms=algorithms)


jwt = _JWTModule()
