"""
On-chain USDC payment verification for Base chain.

Verifies:
1. Transaction exists and succeeded
2. 12+ block confirmations (finalized)
3. It's a USDC transfer (correct contract)
4. Recipient is the provided wallet, or PAYMENT_WALLET when omitted
5. Every matching USDC Transfer log is considered; the sum to that recipient must be >= price
6. When not_before is set, the payment block is not older than that quote
7. Not a duplicate (handled in app.py)

No keys issued until ALL checks pass.
"""

import os
import httpx
import re
from datetime import datetime, timezone

# ERC-20 Transfer(address from, address to, uint256 value) event signature
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# USDC has 6 decimals
USDC_DECIMALS = 6


def _usdc_contract() -> str:
    return (os.getenv("USDC_CONTRACT") or "").strip().lower()


def _default_recipient() -> str:
    return (os.getenv("PAYMENT_WALLET") or "").strip().lower()


def _base_rpc() -> str:
    return os.getenv("BASE_RPC_URL", "https://mainnet.base.org")


def _min_confirmations() -> int:
    try:
        return int(os.getenv("MIN_CONFIRMATIONS", "12"))
    except ValueError:
        return 12


def _is_valid_tx_hash(tx_hash: str) -> bool:
    """Strict validation of tx hash format."""
    return bool(re.match(r'^0x[a-fA-F0-9]{64}$', tx_hash))


async def _rpc_call(method: str, params: list) -> dict:
    """Make a JSON-RPC call to Base mainnet."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(_base_rpc(), json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise ValueError(f"RPC error: {data['error']}")
        return data.get("result")


def _hex_to_int(hex_str: str) -> int:
    """Convert hex string to int."""
    if not hex_str:
        return 0
    return int(hex_str, 16)


def _parse_address_from_topic(topic: str) -> str:
    """Extract address from a 32-byte log topic (padded to 32 bytes)."""
    # Address is last 20 bytes of the 32-byte topic
    return "0x" + topic[-40:].lower()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def verify_usdc_payment(
    tx_hash: str,
    expected_amount_usd: float,
    recipient: str | None = None,
    *,
    not_before: datetime | None = None,
) -> dict:
    """
    Verify a USDC payment on Base chain.

    recipient defaults to PAYMENT_WALLET. Every USDC Transfer log is inspected.
    A log counts only when the contract is USDC and `to` is the recipient.
    The summed amount to that recipient must be >= expected_amount_usd.

    Returns dict with:
        verified: bool - True only if ALL checks pass
        error: str|None - Human-readable error if verification failed
        amount_usdc: float|None - Actual USDC amount transferred to the recipient
        confirmations: int - Number of block confirmations
        from_address: str|None - Sender address of the first matching transfer
        block_number: int|None - Block the tx was included in
        block_timestamp: int|None - Unix timestamp of that block
    """
    result = {
        "verified": False,
        "error": None,
        "amount_usdc": None,
        "confirmations": 0,
        "from_address": None,
        "block_number": None,
        "block_timestamp": None,
    }

    expected_recipient = (recipient or _default_recipient() or "").strip().lower()
    usdc_contract = _usdc_contract()

    # --- Check 1: Valid tx hash format ---
    if not _is_valid_tx_hash(tx_hash):
        result["error"] = "Invalid transaction hash format. Must be 0x followed by 64 hex characters."
        return result

    if not expected_recipient:
        result["error"] = "Receiving wallet is not configured."
        return result

    if not usdc_contract:
        result["error"] = "USDC contract is not configured."
        return result

    try:
        # --- Check 2: Get transaction receipt ---
        receipt = await _rpc_call("eth_getTransactionReceipt", [tx_hash])

        if receipt is None:
            result["error"] = "Transaction not found. It may be pending or on a different chain. We only accept USDC on Base."
            return result

        # --- Check 3: Transaction succeeded ---
        tx_status = _hex_to_int(receipt.get("status", "0x0"))
        if tx_status != 1:
            result["error"] = "Transaction failed on-chain. Send a new payment."
            return result

        # --- Check 4: Sufficient confirmations ---
        tx_block = _hex_to_int(receipt.get("blockNumber", "0x0"))
        result["block_number"] = tx_block

        current_block_hex = await _rpc_call("eth_blockNumber", [])
        current_block = _hex_to_int(current_block_hex)
        confirmations = current_block - tx_block
        result["confirmations"] = confirmations

        min_confirmations = _min_confirmations()
        if confirmations < min_confirmations:
            result["error"] = f"Transaction has {confirmations} confirmations. Need {min_confirmations}+. Wait ~30 seconds and try again."
            return result

        # --- Check 5: Every USDC Transfer log to the recipient ---
        matched_amount = 0
        matched_from = None
        saw_usdc_transfer = False
        for log in receipt.get("logs", []) or []:
            log_address = str(log.get("address", "")).lower()
            topics = log.get("topics", []) or []
            topic0 = str(topics[0]).lower() if topics else ""
            if log_address != usdc_contract or len(topics) < 3 or topic0 != TRANSFER_TOPIC:
                continue
            saw_usdc_transfer = True
            to_address = _parse_address_from_topic(str(topics[2]))
            if to_address != expected_recipient:
                continue
            raw_amount = _hex_to_int(log.get("data", "0x0"))
            matched_amount += raw_amount
            if matched_from is None:
                matched_from = _parse_address_from_topic(str(topics[1]))

        if not saw_usdc_transfer:
            result["error"] = "No USDC transfer found in this transaction. We only accept USDC on Base chain."
            return result

        if matched_from is None:
            result["error"] = "Payment was sent to a different address, not our wallet."
            return result

        result["from_address"] = matched_from
        usdc_amount = matched_amount / (10 ** USDC_DECIMALS)
        result["amount_usdc"] = usdc_amount

        # --- Check 6: Amount covers the price ---
        if usdc_amount < expected_amount_usd:
            result["error"] = f"Underpayment. Sent ${usdc_amount:.2f} USDC but tier requires ${expected_amount_usd:.2f}. Send the remaining amount in a new transaction."
            return result

        # --- Check 7: Payment block is not older than the quote ---
        block_timestamp = None
        block = await _rpc_call("eth_getBlockByNumber", [receipt.get("blockNumber"), False])
        if isinstance(block, dict):
            block_timestamp = _hex_to_int(block.get("timestamp"))
        result["block_timestamp"] = block_timestamp
        if not_before is not None:
            if not block_timestamp:
                result["error"] = "Could not read the payment block timestamp to bind it to the quote."
                return result
            threshold = int(_as_utc(not_before).timestamp())
            if block_timestamp < threshold:
                result["error"] = "Payment transaction is older than the quote. Send a new USDC transfer after requesting a quote."
                return result

        # --- ALL CHECKS PASSED ---
        result["verified"] = True
        return result

    except httpx.HTTPError as e:
        result["error"] = f"Could not reach Base chain RPC. Try again in a moment. ({type(e).__name__})"
        return result
    except ValueError as e:
        result["error"] = f"RPC error: {str(e)}"
        return result
    except Exception as e:
        result["error"] = f"Verification error: {str(e)}"
        return result
