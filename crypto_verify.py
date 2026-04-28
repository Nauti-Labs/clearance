"""
On-chain USDC payment verification for Base chain.

Verifies:
1. Transaction exists and succeeded
2. 12+ block confirmations (finalized)
3. It's a USDC transfer (correct contract)
4. Recipient is our wallet
5. Amount >= expected price
6. Not a duplicate (handled in app.py)

No keys issued until ALL checks pass.
"""

import os
import httpx
import re

# Base chain USDC contract (6 decimals)
USDC_CONTRACT = os.getenv(
    "USDC_CONTRACT",
    "",
).lower()

# Our receiving wallet
OUR_WALLET = os.getenv(
    "PAYMENT_WALLET",
    "",
).lower()

# Base mainnet RPC (public, no key needed)
BASE_RPC = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

# ERC-20 Transfer(address from, address to, uint256 value) event signature
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Minimum confirmations before we trust the tx
MIN_CONFIRMATIONS = int(os.getenv("MIN_CONFIRMATIONS", "12"))

# USDC has 6 decimals
USDC_DECIMALS = 6


def _is_valid_tx_hash(tx_hash: str) -> bool:
    """Strict validation of tx hash format."""
    return bool(re.match(r'^0x[a-fA-F0-9]{64}$', tx_hash))


async def _rpc_call(method: str, params: list) -> dict:
    """Make a JSON-RPC call to Base mainnet."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(BASE_RPC, json={
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


async def verify_usdc_payment(tx_hash: str, expected_amount_usd: float) -> dict:
    """
    Verify a USDC payment on Base chain.

    Returns dict with:
        verified: bool - True only if ALL checks pass
        error: str|None - Human-readable error if verification failed
        amount_usdc: float|None - Actual USDC amount transferred
        confirmations: int - Number of block confirmations
        from_address: str|None - Sender address
        block_number: int|None - Block the tx was included in
    """
    result = {
        "verified": False,
        "error": None,
        "amount_usdc": None,
        "confirmations": 0,
        "from_address": None,
        "block_number": None,
    }

    # --- Check 1: Valid tx hash format ---
    if not _is_valid_tx_hash(tx_hash):
        result["error"] = "Invalid transaction hash format. Must be 0x followed by 64 hex characters."
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

        if confirmations < MIN_CONFIRMATIONS:
            result["error"] = f"Transaction has {confirmations} confirmations. Need {MIN_CONFIRMATIONS}+. Wait ~30 seconds and try again."
            return result

        # --- Check 5: Parse Transfer event logs ---
        # Find the USDC Transfer event in the logs
        usdc_transfer = None
        for log in receipt.get("logs", []):
            log_address = log.get("address", "").lower()
            topics = log.get("topics", [])

            # Must be from USDC contract with Transfer event signature
            if log_address == USDC_CONTRACT and len(topics) >= 3 and topics[0] == TRANSFER_TOPIC:
                usdc_transfer = log
                break

        if usdc_transfer is None:
            result["error"] = "No USDC transfer found in this transaction. We only accept USDC on Base chain."
            return result

        # --- Check 6: Verify recipient is our wallet ---
        topics = usdc_transfer["topics"]
        to_address = _parse_address_from_topic(topics[2])

        if to_address != OUR_WALLET:
            result["error"] = "Payment was sent to a different address, not our wallet."
            return result

        # Parse sender
        from_address = _parse_address_from_topic(topics[1])
        result["from_address"] = from_address

        # --- Check 7: Verify amount ---
        raw_amount = _hex_to_int(usdc_transfer.get("data", "0x0"))
        usdc_amount = raw_amount / (10 ** USDC_DECIMALS)
        result["amount_usdc"] = usdc_amount

        if usdc_amount < expected_amount_usd:
            result["error"] = f"Underpayment. Sent ${usdc_amount:.2f} USDC but tier requires ${expected_amount_usd:.2f}. Send the remaining amount in a new transaction."
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
