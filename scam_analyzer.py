"""Message risk scoring.

TODO: the original scam analyzer was not in this checkout. This is a small
keyword heuristic so inbound checks return a structured result. It is not a
classifier and it does not fetch links or attachments.
"""

from __future__ import annotations

import hashlib


_SUSPICIOUS_TERMS = (
    "seed phrase",
    "private key",
    "gift card",
    "wire transfer",
    "urgent",
    "act now",
    "verify your account",
    "crypto wallet",
    "one-time code",
    "remote access",
)


class ScamAnalysis:
    def __init__(self, verdict: str, score: int, reasons: list[str], summary: str):
        self.verdict = verdict
        self.score = score
        self.reasons = reasons
        self.summary = summary

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "reasons": self.reasons,
            "summary": self.summary,
        }


def message_fingerprint(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


def analyze_scam_text(body: str, attachments: list | None = None) -> ScamAnalysis:
    text = (body or "").strip()
    lowered = text.lower()
    reasons = [term for term in _SUSPICIOUS_TERMS if term in lowered]
    if attachments:
        reasons.append("attachment present")
    if not text and not attachments:
        return ScamAnalysis(
            verdict="unknown",
            score=0,
            reasons=["empty message"],
            summary="No message text was provided.",
        )
    score = min(100, 20 * len(reasons))
    if score >= 40:
        verdict = "suspicious"
        summary = "The message matches common high-pressure patterns. Treat it as untrusted."
    elif score > 0:
        verdict = "review"
        summary = "The message has a few risk signals. Confirm it before acting."
    else:
        verdict = "low_signal"
        summary = "No keyword signals were found. This is not a clearance to trust the sender."
    return ScamAnalysis(verdict=verdict, score=score, reasons=reasons, summary=summary)
