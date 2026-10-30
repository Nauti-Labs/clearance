"""SCRAM credit ledger.

TODO: the original credit ledger was not in this checkout. This module is a
minimal in-memory stand-in so the app can import and boot. Counts reset when
the process restarts and are not a billing system.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def get_initial_free_checks() -> int:
    return _int_env("SCRAM_FREE_CHECKS", 3)


def get_initial_free_help_messages() -> int:
    return _int_env("SCRAM_FREE_HELP_MESSAGES", 5)


def hash_phone(phone: str) -> str:
    normalized = "".join(ch for ch in str(phone or "") if ch.isdigit() or ch == "+")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


_ACCOUNTS: dict[str, dict[str, Any]] = {}


def _account(phone_or_hash: str, *, already_hashed: bool = False) -> dict[str, Any]:
    phone_hash = phone_or_hash if already_hashed else hash_phone(phone_or_hash)
    account = _ACCOUNTS.get(phone_hash)
    if account is None:
        account = {
            "phone_hash": phone_hash,
            "free_checks_remaining": get_initial_free_checks(),
            "free_help_messages_remaining": get_initial_free_help_messages(),
            "paid_credits_remaining": 0,
            "opted_out": False,
            "help_mode_active": False,
        }
        _ACCOUNTS[phone_hash] = account
    return account


def _summary(account: dict[str, Any]) -> dict[str, Any]:
    return {
        "phone_hash": account["phone_hash"],
        "free_checks_remaining": account["free_checks_remaining"],
        "free_help_messages_remaining": account["free_help_messages_remaining"],
        "paid_credits_remaining": account["paid_credits_remaining"],
        "help_mode_active": account["help_mode_active"],
        "opted_out": account["opted_out"],
    }


async def get_sms_credit_summary(from_number: str) -> dict[str, Any]:
    return _summary(_account(from_number))


async def set_sms_opt_out(from_number: str, opted_out: bool) -> None:
    account = _account(from_number)
    account["opted_out"] = bool(opted_out)
    if opted_out:
        account["help_mode_active"] = False


async def set_help_mode(from_number: str, active: bool) -> None:
    account = _account(from_number)
    account["help_mode_active"] = bool(active) and not account["opted_out"]


def _reserve(account: dict[str, Any], free_field: str) -> dict[str, Any]:
    if account["opted_out"]:
        return {"allowed": False, "reason": "opted_out", "phone_hash": account["phone_hash"]}
    if account[free_field] > 0:
        account[free_field] -= 1
        return {"allowed": True, "source": "free", "phone_hash": account["phone_hash"]}
    if account["paid_credits_remaining"] > 0:
        account["paid_credits_remaining"] -= 1
        return {"allowed": True, "source": "paid", "phone_hash": account["phone_hash"]}
    return {"allowed": False, "reason": "no_credits", "phone_hash": account["phone_hash"]}


async def reserve_help_credit(from_number: str) -> dict[str, Any]:
    return _reserve(_account(from_number), "free_help_messages_remaining")


async def reserve_sms_credit(from_number: str) -> dict[str, Any]:
    return _reserve(_account(from_number), "free_checks_remaining")


async def record_help_message(
    *,
    phone_hash: str,
    provider: str,
    provider_message_id: str | None,
    user_message_hash: str,
    reply_hash: str,
    model: str,
    llm_provider: str,
    credit_source: str,
    attachments: list | None = None,
) -> str:
    # TODO: persist help transcripts in the database. This id is local only.
    del provider, provider_message_id, user_message_hash, reply_hash, model, llm_provider, credit_source, attachments
    return f"help_{secrets.token_hex(8)}"


async def record_sms_check(
    *,
    phone_hash: str,
    provider: str,
    provider_message_id: str | None,
    message_hash: str,
    analysis: dict,
    attachments: list | None = None,
) -> str:
    # TODO: persist scam-check rows in the database. This id is local only.
    del phone_hash, provider, provider_message_id, message_hash, analysis, attachments
    return f"chk_{secrets.token_hex(8)}"


async def add_paid_credits_by_hash(
    *,
    phone_hash: str,
    credits: int,
    reason: str,
    provider: str,
    provider_ref: str,
    amount: float | None = None,
    currency: str | None = None,
) -> dict[str, Any]:
    # TODO: tie this to the verified payment row. Memory only for now.
    account = _account(phone_hash, already_hashed=True)
    added = max(0, int(credits))
    account["paid_credits_remaining"] += added
    return {
        "status": "verified",
        "phone_hash": phone_hash,
        "credits_added": added,
        "paid_credits_remaining": account["paid_credits_remaining"],
        "reason": reason,
        "provider": provider,
        "provider_ref": provider_ref,
        "amount": amount,
        "currency": currency,
    }
