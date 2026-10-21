"""Tests for the context-bound document ciphertext format (issue #40, ADR-007)."""

from __future__ import annotations

import os

import pytest

from encrypted_ir import document_crypto
from encrypted_ir.document_crypto import PURPOSE_CONTENT, PURPOSE_METADATA, open_sealed, seal
from encrypted_ir.errors import DocumentIntegrityError
from encrypted_ir.searchable import SearchableEncryption

KEY = bytes(range(32))
CONTEXT = {
    "key_id": "document_encryption_0123456789abcdef",
    "tenant_id": "tenant-a",
    "doc_id": "d1",
}


def _seal(plaintext: bytes = b"quarterly fraud report", **overrides) -> bytes:
    args = {**CONTEXT, "purpose": PURPOSE_CONTENT, **overrides}
    return seal(KEY, plaintext, **args)


def _open(blob: bytes, key: bytes = KEY, **overrides) -> bytes:
    args = {**CONTEXT, "purpose": PURPOSE_CONTENT, **overrides}
    return open_sealed(key, blob, **args)


def test_round_trip():
    assert _open(_seal()) == b"quarterly fraud report"


def test_header_layout():
    blob = _seal(b"x")
    key_id = CONTEXT["key_id"].encode()

    assert blob[0] == document_crypto.FORMAT_VERSION
    assert blob[1] == document_crypto.ALG_AES_256_GCM
    assert blob[2] == len(key_id)
    assert blob[3 : 3 + len(key_id)] == key_id
    assert len(blob) == 3 + len(key_id) + 12 + 1 + 16


def test_nonces_are_unique():
    assert _seal() != _seal()


@pytest.mark.parametrize(
    "region",
    ["version", "algorithm", "key_id_length", "key_id", "nonce", "ciphertext", "tag"],
)
def test_any_bit_flip_is_detected(region):
    blob = bytearray(_seal())
    key_id_len = blob[2]
    offsets = {
        "version": 0,
        "algorithm": 1,
        "key_id_length": 2,
        "key_id": 3,
        "nonce": 3 + key_id_len,
        "ciphertext": 3 + key_id_len + 12,
        "tag": len(blob) - 1,
    }
    blob[offsets[region]] ^= 0x01

    with pytest.raises(DocumentIntegrityError):
        _open(bytes(blob))


@pytest.mark.parametrize(
    "override",
    [
        {"tenant_id": "tenant-b"},
        {"doc_id": "d2"},
        {"purpose": PURPOSE_METADATA},
        {"key_id": "document_encryption_ffffffffffffffff"},
    ],
)
def test_wrong_context_is_rejected(override):
    with pytest.raises(DocumentIntegrityError):
        _open(_seal(), **override)


def test_cross_tenant_swap_fails_even_with_the_same_key_bytes():
    """The old format would decrypt here: same key, no associated data."""
    blob_for_a = _seal(tenant_id="tenant-a")

    with pytest.raises(DocumentIntegrityError):
        _open(blob_for_a, tenant_id="tenant-b")


def test_context_fields_cannot_be_shifted_between_each_other():
    """Length prefixes keep ("ab", "c") distinct from ("a", "bc")."""
    blob = _seal(tenant_id="ab", doc_id="c")

    with pytest.raises(DocumentIntegrityError):
        _open(blob, tenant_id="a", doc_id="bc")


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x01\x01\x05abc", b"\x01\x01\x00" + bytes(40)])
def test_truncated_or_malformed_blobs_are_rejected(blob):
    with pytest.raises(DocumentIntegrityError):
        _open(blob)


def test_wrong_key_is_rejected():
    with pytest.raises(DocumentIntegrityError):
        _open(_seal(), key=os.urandom(32))


def test_key_id_length_is_bounded():
    with pytest.raises(ValueError):
        _seal(key_id="k" * 256)
    with pytest.raises(ValueError):
        _seal(key_id="")


def test_unknown_purpose_is_rejected():
    with pytest.raises(ValueError):
        _seal(purpose="attachments")


def test_legacy_blobs_still_open():
    legacy_blob, _ = SearchableEncryption(KEY).encrypt_document("legacy text", keywords=set())

    assert document_crypto.open_legacy(KEY, legacy_blob) == b"legacy text"


def test_legacy_open_rejects_tampering():
    legacy_blob, _ = SearchableEncryption(KEY).encrypt_document("legacy text", keywords=set())
    tampered = bytearray(legacy_blob)
    tampered[-1] ^= 0x01

    with pytest.raises(DocumentIntegrityError):
        document_crypto.open_legacy(KEY, bytes(tampered))
    with pytest.raises(DocumentIntegrityError):
        document_crypto.open_legacy(KEY, b"short")


def test_sealed_blob_does_not_open_as_legacy():
    with pytest.raises(DocumentIntegrityError):
        document_crypto.open_legacy(KEY, _seal())


def test_length_prefixed_encoding():
    assert document_crypto.length_prefixed("ab", b"c") == b"\x00\x00\x00\x02ab\x00\x00\x00\x01c"
