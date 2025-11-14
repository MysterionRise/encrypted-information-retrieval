"""Tests for deterministic encryption module."""

import pytest
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

        assert decrypted.decode('utf-8') == plaintext

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
        assert decrypted.decode('utf-8') == plaintext

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
        assert decrypted.decode('utf-8') == plaintext

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

        assert decrypted.decode('utf-8') == plaintext

        # Wrong associated data should fail
        with pytest.raises(ValueError):
            encryptor.decrypt(ciphertext, [b"wrong"])
