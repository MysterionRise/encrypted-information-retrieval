"""Tests for deterministic encryption module."""

import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from encrypted_ir.deterministic import DeterministicEncryption


class TestDeterministicEncryption:
    """Test deterministic encryption functionality."""

    def test_key_generation(self):
        """Test key generation."""
        key = DeterministicEncryption.generate_key()
        assert len(key) == 64  # 512 bits

    def test_key_derivation(self):
        """Test key derivation from password."""
        password = "test_password_123"
        key1, salt = DeterministicEncryption.derive_key(password)
        assert len(key1) == 64
        assert len(salt) == 32

        # Same password and salt should produce same key
        key2, _ = DeterministicEncryption.derive_key(password, salt)
        assert key1 == key2

    def test_encryption_decryption(self):
        """Test basic encryption and decryption."""
        encryptor = DeterministicEncryption()
        plaintext = "sensitive data"

        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)

        assert decrypted.decode("utf-8") == plaintext

    def test_deterministic_property(self):
        """Test that same plaintext produces same ciphertext."""
        encryptor = DeterministicEncryption()
        plaintext = "account_12345"

        ciphertext1 = encryptor.encrypt(plaintext)
        ciphertext2 = encryptor.encrypt(plaintext)

        assert ciphertext1 == ciphertext2

    def test_different_plaintext_different_ciphertext(self):
        """Test that different plaintexts produce different ciphertexts."""
        encryptor = DeterministicEncryption()

        ciphertext1 = encryptor.encrypt("account_12345")
        ciphertext2 = encryptor.encrypt("account_67890")

        assert ciphertext1 != ciphertext2

    def test_base64_encoding(self):
        """Test base64 encoding/decoding."""
        encryptor = DeterministicEncryption()
        plaintext = "test data"

        ciphertext_b64 = encryptor.encrypt_to_base64(plaintext)
        assert isinstance(ciphertext_b64, str)

        decrypted = encryptor.decrypt_from_base64(ciphertext_b64)
        assert decrypted.decode("utf-8") == plaintext

    def test_search_index(self):
        """Test search index creation."""
        encryptor = DeterministicEncryption()
        value = "search_value"

        index1 = encryptor.search_index(value)
        index2 = encryptor.search_index(value)

        # Same value should produce same index
        assert index1 == index2

    def test_key_export_import(self):
        """Test key export and import."""
        encryptor1 = DeterministicEncryption()
        plaintext = "test message"
        ciphertext = encryptor1.encrypt(plaintext)

        # Export and import key
        key_b64 = encryptor1.export_key()
        encryptor2 = DeterministicEncryption.import_key(key_b64)

        # Should be able to decrypt with imported key
        decrypted = encryptor2.decrypt(ciphertext)
        assert decrypted.decode("utf-8") == plaintext

    def test_bytes_encryption(self):
        """Test encryption of bytes."""
        encryptor = DeterministicEncryption()
        plaintext = b"binary data \x00\x01\x02"

        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            DeterministicEncryption(key=b"too_short")

    def test_decryption_with_wrong_key(self):
        """Test that decryption with wrong key fails."""
        encryptor1 = DeterministicEncryption()
        encryptor2 = DeterministicEncryption()

        plaintext = "secret"
        ciphertext = encryptor1.encrypt(plaintext)

        # Attempt to decrypt with different key should fail
        with pytest.raises(ValueError):
            encryptor2.decrypt(ciphertext)

    def test_authenticated_encryption(self):
        """Test authenticated encryption with associated data."""
        encryptor = DeterministicEncryption()
        plaintext = "message"
        associated_data = [b"context1", b"context2"]

        ciphertext = encryptor.encrypt(plaintext, associated_data)
        decrypted = encryptor.decrypt(ciphertext, associated_data)

        assert decrypted.decode("utf-8") == plaintext

        # Wrong associated data should fail
        with pytest.raises(ValueError):
            encryptor.decrypt(ciphertext, [b"wrong"])

    def test_key_derivation_uses_600k_iterations(self):
        """derive_key uses PBKDF2-HMAC-SHA256 with the OWASP figure of 600,000 iterations."""
        assert DeterministicEncryption.PBKDF2_ITERATIONS == 600_000
        salt = bytes(16)
        key, returned_salt = DeterministicEncryption.derive_key("correct horse", salt)

        assert returned_salt == salt
        assert key == hashlib.pbkdf2_hmac("sha256", b"correct horse", salt, 600_000, 64)
        assert key.hex() == (
            "d4a33cdd8ff2436bb3565c2e7f8f5a81fd3549872db80d6ff6d3d53f1ec15bc3"
            "3a30f69d4f9ece9b7f35c8930cf646466be52cbdf0daa6453bf46a434117fc76"
        )


# RFC 5297, Appendix A.1: deterministic authenticated encryption (one AD component).
RFC5297_A1_KEY = bytes.fromhex(
    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
)
RFC5297_A1_AD = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
RFC5297_A1_PLAINTEXT = bytes.fromhex("112233445566778899aabbccddee")
RFC5297_A1_OUTPUT = bytes.fromhex("85632d07c6e8f37f950acd320a2ecc93" "40c02b9690c4dc04daef7f6afe5c")

# RFC 5297, Appendix A.2: nonce-based authenticated encryption. The nonce is the last
# associated-data component, as RFC 5297 section 3 specifies.
RFC5297_A2_KEY = bytes.fromhex(
    "7f7e7d7c7b7a79787776757473727170" "404142434445464748494a4b4c4d4e4f"
)
RFC5297_A2_AD1 = bytes.fromhex(
    "00112233445566778899aabbccddeeff" "deaddadadeaddadaffeeddccbbaa9988" "7766554433221100"
)
RFC5297_A2_AD2 = bytes.fromhex("102030405060708090a0")
RFC5297_A2_NONCE = bytes.fromhex("09f911029d74e35bd84156c5635688c0")
RFC5297_A2_PLAINTEXT = bytes.fromhex(
    "7468697320697320736f6d6520706c61"
    "696e7465787420746f20656e63727970"
    "74207573696e67205349562d414553"
)
RFC5297_A2_OUTPUT = bytes.fromhex(
    "7bdb6e3b432667eb06f4d14bff2fbd0f"
    "cb900f2fddbe404326601965c889bf17"
    "dba77ceb094fa663b7a3f748ba8af829"
    "ea64ad544a272e9c485b62a3fd5c0d"
)


def _with_cipher(key: bytes) -> DeterministicEncryption:
    """A DeterministicEncryption whose AES-SIV cipher uses ``key``.

    The RFC 5297 vectors use 256-bit keys (AES-SIV with AES-128), while the class
    accepts only 512-bit keys, so the vectors run through the class's own
    encrypt/decrypt code with the cipher swapped.
    """
    encryptor = DeterministicEncryption()
    encryptor._cipher = AESSIV(key)
    return encryptor


class TestRFC5297Vectors:
    """Known-answer tests from RFC 5297 Appendix A."""

    def test_a1_primitive(self):
        aessiv = AESSIV(RFC5297_A1_KEY)
        assert aessiv.encrypt(RFC5297_A1_PLAINTEXT, [RFC5297_A1_AD]) == RFC5297_A1_OUTPUT
        assert aessiv.decrypt(RFC5297_A1_OUTPUT, [RFC5297_A1_AD]) == RFC5297_A1_PLAINTEXT

    def test_a1_through_deterministic_encryption(self):
        encryptor = _with_cipher(RFC5297_A1_KEY)
        assert encryptor.encrypt(RFC5297_A1_PLAINTEXT, [RFC5297_A1_AD]) == RFC5297_A1_OUTPUT
        assert encryptor.decrypt(RFC5297_A1_OUTPUT, [RFC5297_A1_AD]) == RFC5297_A1_PLAINTEXT
        with pytest.raises(ValueError):
            encryptor.decrypt(RFC5297_A1_OUTPUT, [])

    def test_a2_primitive(self):
        ad = [RFC5297_A2_AD1, RFC5297_A2_AD2, RFC5297_A2_NONCE]
        aessiv = AESSIV(RFC5297_A2_KEY)
        assert aessiv.encrypt(RFC5297_A2_PLAINTEXT, ad) == RFC5297_A2_OUTPUT
        assert aessiv.decrypt(RFC5297_A2_OUTPUT, ad) == RFC5297_A2_PLAINTEXT

    def test_a2_through_deterministic_encryption(self):
        """Several associated-data components are passed through in order."""
        encryptor = _with_cipher(RFC5297_A2_KEY)
        ad = [RFC5297_A2_AD1, RFC5297_A2_AD2, RFC5297_A2_NONCE]
        assert encryptor.encrypt(RFC5297_A2_PLAINTEXT, ad) == RFC5297_A2_OUTPUT
        assert encryptor.decrypt(RFC5297_A2_OUTPUT, ad) == RFC5297_A2_PLAINTEXT
        with pytest.raises(ValueError):
            encryptor.decrypt(RFC5297_A2_OUTPUT, [RFC5297_A2_AD2, RFC5297_A2_AD1, RFC5297_A2_NONCE])

    def test_512_bit_key_golden_vector(self):
        """Pin the class's own 512-bit-key output (AES-SIV with AES-256)."""
        encryptor = DeterministicEncryption(bytes(range(64)))
        assert encryptor.encrypt(b"account-12345").hex() == (
            "45dfa5a1146ca4fbd33c8f437f6a73b563c6cc32fce36e6327bea4fa01"
        )
        assert encryptor.encrypt(b"account-12345", [b"tenant-1", b"accounts"]).hex() == (
            "9561aac1922f62628bd1c42f7cb4a9f94e3ecbf71301de2b9223fa11b8"
        )
        assert encryptor.encrypt_to_base64("123-45-6789") == "TzwXHnAsaK1YrWyjlvV141+RuwBmRD5umO1J"


_AD = st.lists(st.binary(max_size=32), max_size=3)


class TestAESSIVProperties:
    """Property tests for DeterministicEncryption (AES-SIV)."""

    ENCRYPTOR = DeterministicEncryption(bytes(range(64)))

    @settings(max_examples=50, deadline=None)
    @given(plaintext=st.binary(max_size=256), associated_data=_AD)
    def test_round_trip(self, plaintext, associated_data):
        ciphertext = self.ENCRYPTOR.encrypt(plaintext, associated_data)
        assert len(ciphertext) == len(plaintext) + 16  # synthetic IV
        assert self.ENCRYPTOR.decrypt(ciphertext, associated_data) == plaintext

    @settings(max_examples=50, deadline=None)
    @given(plaintext=st.binary(max_size=256), associated_data=_AD)
    def test_deterministic_and_matches_aessiv(self, plaintext, associated_data):
        first = self.ENCRYPTOR.encrypt(plaintext, associated_data)
        assert self.ENCRYPTOR.encrypt(plaintext, associated_data) == first
        assert AESSIV(bytes(range(64))).encrypt(plaintext, associated_data) == first

    @settings(max_examples=50, deadline=None)
    @given(text=st.text(max_size=64))
    def test_text_round_trip_through_base64(self, text):
        encoded = self.ENCRYPTOR.encrypt_to_base64(text)
        assert self.ENCRYPTOR.search_index(text) == encoded
        assert self.ENCRYPTOR.decrypt_from_base64(encoded) == text.encode("utf-8")

    @settings(max_examples=50, deadline=None)
    @given(a=st.binary(max_size=64), b=st.binary(max_size=64))
    def test_distinct_plaintexts_give_distinct_ciphertexts(self, a, b):
        assume(a != b)
        assert self.ENCRYPTOR.encrypt(a) != self.ENCRYPTOR.encrypt(b)
