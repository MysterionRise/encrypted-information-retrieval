"""One redaction policy for logs and audit records.

:func:`redact` walks dicts, lists and scalars and removes anything that could carry plaintext,
keys or personal data before it is written anywhere:

- values under a sensitive key name (``password``, ``token``, ``plaintext``, ``content``,
  ``query`` and similar) become ``[REDACTED]``, whatever their type;
- ``bytes`` become ``[REDACTED_BYTES]``;
- strings are scanned for key-like base64, card numbers (Luhn-checked), US SSNs and email
  addresses.

Structural fields (request IDs, hash-chain links, timestamps, routes, status codes) are never
pattern-scanned, so a lower-case hex digest or a millisecond timestamp stays readable.
"""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "content",
        "credentials",
        "encryption_key",
        "key",
        "keys",
        "master_key",
        "password",
        "plaintext",
        "private_key",
        "query",
        "search_key",
        "secret",
        "secret_key",
        "token",
        "tokens",
    }
)

STRUCTURAL_KEYS = frozenset(
    {
        "correlation_id",
        "entry_hash",
        "level",
        "logger",
        "method",
        "prev_hash",
        "request_id",
        "route",
        "seq",
        "status",
        "timestamp",
    }
)

REDACTED = "[REDACTED]"
REDACTED_BYTES = "[REDACTED_BYTES]"

_KEY_RUN = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _looks_like_key(run: str) -> bool:
    """A long base64 run is key-like if it has base64 punctuation or mixes case and digits.

    That keeps lower-case hex digests and long all-digit numbers readable.
    """
    if any(ch in run for ch in "+/="):
        return True
    return (
        any(ch.islower() for ch in run)
        and any(ch.isupper() for ch in run)
        and any(ch.isdigit() for ch in run)
    )


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_card(match: re.Match[str]) -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    return "[REDACTED_CARD]" if _luhn_valid(digits) else match.group(0)


def _redact_key(match: re.Match[str]) -> str:
    return "[REDACTED_KEY]" if _looks_like_key(match.group(0)) else match.group(0)


def redact_text(text: str) -> str:
    """Replace key-like base64, card numbers, SSNs and email addresses in ``text``."""
    text = _KEY_RUN.sub(_redact_key, text)
    text = _CARD.sub(_redact_card, text)
    text = _SSN.sub("[REDACTED_SSN]", text)
    return _EMAIL.sub("[REDACTED_EMAIL]", text)


def redact(value: Any, *, key: str | None = None) -> Any:
    """Return a copy of ``value`` that is safe to log or audit.

    ``key`` is the name the value is stored under, if any; it decides whether the value is
    dropped outright (sensitive key) or left unscanned (structural key).
    """
    if key is not None and key.lower() in SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, (bytes, bytearray, memoryview)):
        return REDACTED_BYTES
    if isinstance(value, dict):
        return {k: redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        if key is not None and key.lower() in STRUCTURAL_KEYS:
            return value
        return redact_text(value)
    return value
