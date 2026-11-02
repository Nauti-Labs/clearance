"""Inbound message formatting and outbound SMS.

TODO: provider delivery was not in this checkout. Outbound sends are not
attempted. Signature checks follow the public Twilio request algorithm when
TWILIO_AUTH_TOKEN is set.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from xml.sax.saxutils import escape


def twilio_signature_validation_enabled() -> bool:
    flag = os.getenv("TWILIO_VALIDATE_SIGNATURE", "true").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    return bool(os.getenv("TWILIO_AUTH_TOKEN", "").strip())


def validate_twilio_webhook_signature(
    *,
    url: str,
    params: dict,
    signature: str,
    auth_token: str,
) -> bool:
    if not auth_token or not signature:
        return False
    material = url or ""
    for key in sorted(params):
        value = params[key]
        if isinstance(value, (list, tuple)):
            for item in value:
                material += str(key) + str(item)
        else:
            material += str(key) + str(value)
    digest = hmac.new(auth_token.encode("utf-8"), material.encode("utf-8"), hashlib.sha1).digest()
    expected = base64.b64encode(digest).decode("ascii")
    return hmac.compare_digest(expected, signature.strip())


def build_twiml_message(text: str) -> str:
    safe = escape(text or "")
    return f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{safe}</Message></Response>'


def format_help_intro(text_code: str, free_messages: int) -> str:
    return (
        f"SCRAM helper is on. Text your question, or text DONE when you are finished. "
        f"New numbers start with {free_messages} helper messages. Text code {text_code}."
    )


def format_help_reply(from_number: str | None, text_code: str) -> str:
    sender = from_number or text_code
    return f"Send the suspicious message and SCRAM will score it. You can also text HELP. Sender {sender}."


def format_out_of_help_reply(payment_url: str) -> str:
    return f"No helper messages left. Credits: {payment_url}"


def format_out_of_credits_reply(payment_url: str) -> str:
    return f"No scam-check credits left. Credits: {payment_url}"


def format_sms_reply(analysis: dict) -> str:
    verdict = str(analysis.get("verdict") or "unknown")
    summary = str(analysis.get("summary") or "No summary.")
    return f"SCRAM {verdict}: {summary}"


async def send_sms(to_number: str, body: str) -> dict:
    del to_number, body
    provider = os.getenv("SMS_PROVIDER", "local").strip().lower() or "local"
    return {
        "sent": False,
        "provider": provider,
        "detail": "SMS delivery is not configured in this build.",
    }
