"""SCRAM helper replies.

TODO: the model-backed helper was not in this checkout. Replies are a fixed
safety notice. No outside model is called and no message text is stored.
"""

from __future__ import annotations

import hashlib


def hash_help_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


async def generate_scram_help(body: str, attachments: list | None = None) -> dict:
    del body, attachments
    return {
        "reply": (
            "This build does not call a language model. "
            "Do not send money, codes, or account access because of an unsolicited message. "
            "Check the request with a known contact on a channel you already use."
        ),
        "model": "unavailable",
        "provider": "stub",
    }
