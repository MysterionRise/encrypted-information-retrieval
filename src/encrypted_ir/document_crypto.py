"""Versioned, context-bound AES-256-GCM encryption for stored documents (ADR-007).

Sealed format, version 1::

    version (u8 = 1) || algorithm (u8 = 1, AES-256-GCM) || key_id_len (u8) || key_id || nonce (12)
    || ciphertext || tag (16)

The header is authenticated: the AES-GCM associated data is the header followed by the
length-prefixed label ``encrypted-ir/document/v1``, the purpose, the tenant ID and the document
ID. A ciphertext therefore only opens for the row (tenant, document), the purpose ("content",
"metadata" or "keywords") and the key it was sealed for. Swapping ciphertexts between rows, tenants or purposes,
editing the header, or pointing the row at another key all fail authentication.

Rows written before version 1 store ``iv (12) || tag (16) || ciphertext`` with no associated data.
They are identified by ``documents.algorithm == "aes-gcm"`` and opened by :func:`open_legacy`.
"""

from __future__ import annotations

import os
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DocumentIntegrityError

__all__ = [
    "ALGORITHM",
    "LEGACY_ALGORITHM",
    "PURPOSE_CONTENT",
    "PURPOSE_KEYWORDS",
    "PURPOSE_METADATA",
    "length_prefixed",
    "open_legacy",
    "open_sealed",
    "seal",
]

FORMAT_VERSION = 1
ALG_AES_256_GCM = 1
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MAX_KEY_ID_BYTES = 255

ALGORITHM = "aes-256-gcm/v1"  # value stored in documents.algorithm for sealed rows
LEGACY_ALGORITHM = "aes-gcm"  # rows written before the versioned header existed
PURPOSE_CONTENT = "content"
PURPOSE_METADATA = "metadata"
PURPOSE_KEYWORDS = "keywords"  # the sorted keyword list, kept so rotation can re-tokenize
_PURPOSES = frozenset({PURPOSE_CONTENT, PURPOSE_METADATA, PURPOSE_KEYWORDS})
_AAD_LABEL = b"encrypted-ir/document/v1"


def length_prefixed(*parts: bytes | str) -> bytes:
    """Encode each part as a 4-byte big-endian length followed by its bytes (UTF-8 for str)."""
    encoded = bytearray()
    for part in parts:
        data = part.encode("utf-8") if isinstance(part, str) else part
        encoded += len(data).to_bytes(4, "big") + data
    return bytes(encoded)


def _header(key_id: str, nonce: bytes) -> bytes:
    key_id_bytes = key_id.encode("utf-8")
    if not 1 <= len(key_id_bytes) <= MAX_KEY_ID_BYTES:
        raise ValueError(f"key_id must be 1 to {MAX_KEY_ID_BYTES} bytes")
    return bytes([FORMAT_VERSION, ALG_AES_256_GCM, len(key_id_bytes)]) + key_id_bytes + nonce


def _associated_data(header: bytes, purpose: str, tenant_id: str, doc_id: str) -> bytes:
    return header + length_prefixed(_AAD_LABEL, purpose, tenant_id, doc_id)


def _check_inputs(key: bytes, purpose: str) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("Document keys must be 32 bytes")
    if purpose not in _PURPOSES:
        raise ValueError(f"purpose must be one of {sorted(_PURPOSES)}")


def seal(
    key: bytes,
    plaintext: bytes,
    *,
    key_id: str,
    tenant_id: str,
    doc_id: str,
    purpose: str,
) -> bytes:
    """Encrypt ``plaintext`` for one (tenant, document, purpose) under ``key_id``."""
    _check_inputs(key, purpose)
    nonce = os.urandom(NONCE_SIZE)
    header = _header(key_id, nonce)
    body = AESGCM(key).encrypt(
        nonce, plaintext, _associated_data(header, purpose, tenant_id, doc_id)
    )
    return header + cast(bytes, body)


def _parse(blob: bytes) -> tuple[bytes, str, bytes, bytes]:
    """Split a sealed blob into (header, key_id, nonce, ciphertext-with-tag)."""
    if len(blob) < 3:
        raise DocumentIntegrityError("Sealed document is too short")
    version, algorithm, key_id_len = blob[0], blob[1], blob[2]
    if version != FORMAT_VERSION or algorithm != ALG_AES_256_GCM:
        raise DocumentIntegrityError("Unsupported sealed document version or algorithm")
    header_end = 3 + key_id_len + NONCE_SIZE
    if key_id_len == 0 or len(blob) < header_end + TAG_SIZE:
        raise DocumentIntegrityError("Sealed document header is malformed")
    try:
        key_id = blob[3 : 3 + key_id_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DocumentIntegrityError("Sealed document header is malformed") from exc
    return blob[:header_end], key_id, blob[3 + key_id_len : header_end], blob[header_end:]


def open_sealed(
    key: bytes,
    blob: bytes,
    *,
    key_id: str,
    tenant_id: str,
    doc_id: str,
    purpose: str,
) -> bytes:
    """Decrypt a blob produced by :func:`seal` for exactly this context.

    Raises:
        DocumentIntegrityError: If the header is malformed, names another key, or
            authentication fails for this tenant, document and purpose.
    """
    _check_inputs(key, purpose)
    header, header_key_id, nonce, body = _parse(blob)
    if header_key_id != key_id:
        raise DocumentIntegrityError("Sealed document names a different key")
    try:
        return cast(
            bytes,
            AESGCM(key).decrypt(nonce, body, _associated_data(header, purpose, tenant_id, doc_id)),
        )
    except InvalidTag as exc:
        raise DocumentIntegrityError("Sealed document failed authentication") from exc


def open_legacy(key: bytes, blob: bytes) -> bytes:
    """Decrypt a pre-version-1 document blob: ``iv (12) || tag (16) || ciphertext``, no AAD."""
    if len(key) != KEY_SIZE:
        raise ValueError("Document keys must be 32 bytes")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise DocumentIntegrityError("Legacy document is too short")
    iv, tag, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE : NONCE_SIZE + TAG_SIZE], blob[28:]
    try:
        return cast(bytes, AESGCM(key).decrypt(iv, ciphertext + tag, None))
    except InvalidTag as exc:
        raise DocumentIntegrityError("Legacy document failed authentication") from exc
