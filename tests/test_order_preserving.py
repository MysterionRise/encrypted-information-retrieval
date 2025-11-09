"""Tests for order-preserving encryption module."""

import pytest
from encrypted_ir.order_preserving import OrderPreservingEncryption


class TestOrderPreservingEncryption:
    """Test order-preserving encryption functionality."""

    def test_key_generation(self):
        """Test key generation."""
        key = OrderPreservingEncryption.generate_key()
        assert len(key) == 32

    def test_integer_encryption(self):
        """Test basic integer encryption."""
        encryptor = OrderPreservingEncryption()

        value = 12345
        encrypted = encryptor.encrypt_int(value)

        assert isinstance(encrypted, int)
        assert encrypted > 0

    def test_order_preservation(self):
        """Test that order is preserved after encryption."""
        encryptor = OrderPreservingEncryption()

        values = [100, 500, 1000, 5000, 10000]
        encrypted = [encryptor.encrypt_int(v) for v in values]

        # Order should be preserved
        for i in range(len(encrypted) - 1):
            assert encrypted[i] < encrypted[i + 1]

    def test_deterministic_property(self):
        """Test that same value produces same ciphertext."""
        encryptor = OrderPreservingEncryption()

        value = 777
        enc1 = encryptor.encrypt_int(value)
        enc2 = encryptor.encrypt_int(value)

        assert enc1 == enc2

    def test_float_encryption(self):
        """Test float encryption with precision."""
        encryptor = OrderPreservingEncryption()

        amount = 1234.56
        encrypted = encryptor.encrypt_float(amount, precision=2)

        assert isinstance(encrypted, int)
        assert encrypted > 0

    def test_amount_encryption(self):
        """Test monetary amount encryption."""
        encryptor = OrderPreservingEncryption()

        amounts = [10.50, 100.00, 1000.00, 5000.99]
        encrypted = [encryptor.encrypt_amount(amt) for amt in amounts]

        # Order should be preserved
        for i in range(len(encrypted) - 1):
            assert encrypted[i] < encrypted[i + 1]

    def test_comparison(self):
        """Test encrypted value comparison."""
        encryptor = OrderPreservingEncryption()

        val1 = encryptor.encrypt_int(100)
        val2 = encryptor.encrypt_int(200)

        assert encryptor.compare_encrypted(val1, val2) == -1
        assert encryptor.compare_encrypted(val2, val1) == 1
        assert encryptor.compare_encrypted(val1, val1) == 0

    def test_range_query(self):
        """Test range query on encrypted values."""
        encryptor = OrderPreservingEncryption()

        values = [100, 200, 300, 400, 500]
        encrypted = [encryptor.encrypt_int(v) for v in values]

        # Query for values between 150 and 450
        min_enc = encryptor.encrypt_int(150)
        max_enc = encryptor.encrypt_int(450)

        result = encryptor.range_query(encrypted, min_enc, max_enc)

        # Should return encrypted values for 200, 300, 400
        assert len(result) == 3

    def test_range_query_no_min(self):
        """Test range query with only maximum."""
        encryptor = OrderPreservingEncryption()

        values = [100, 200, 300, 400, 500]
        encrypted = [encryptor.encrypt_int(v) for v in values]

        max_enc = encryptor.encrypt_int(250)
        result = encryptor.range_query(encrypted, None, max_enc)

        # Should return values <= 250 (100, 200)
        assert len(result) == 2

    def test_range_query_no_max(self):
        """Test range query with only minimum."""
        encryptor = OrderPreservingEncryption()

        values = [100, 200, 300, 400, 500]
        encrypted = [encryptor.encrypt_int(v) for v in values]

        min_enc = encryptor.encrypt_int(350)
        result = encryptor.range_query(encrypted, min_enc, None)

        # Should return values >= 350 (400, 500)
        assert len(result) == 2

    def test_bytes_conversion(self):
        """Test conversion to/from bytes."""
        encryptor = OrderPreservingEncryption()

        value = 12345
        encrypted_bytes = encryptor.encrypt_int_to_bytes(value)

        assert isinstance(encrypted_bytes, bytes)
        assert len(encrypted_bytes) == 8

        # Convert back to int
        encrypted_int = encryptor.decrypt_int_from_bytes(encrypted_bytes)
        assert encrypted_int == encryptor.encrypt_int(value)

    def test_base64_encoding(self):
        """Test base64 encoding."""
        encryptor = OrderPreservingEncryption()

        value = 9999
        encrypted_b64 = encryptor.encrypt_int_to_base64(value)

        assert isinstance(encrypted_b64, str)

        # Decode back to int
        encrypted_int = encryptor.decrypt_int_from_base64(encrypted_b64)
        assert encrypted_int == encryptor.encrypt_int(value)

    def test_key_export_import(self):
        """Test key export and import."""
        encryptor1 = OrderPreservingEncryption()
        value = 5555
        enc1 = encryptor1.encrypt_int(value)

        # Export and import key
        key_b64 = encryptor1.export_key()
        encryptor2 = OrderPreservingEncryption.import_key(key_b64)

        # Should produce same encryption with same key
        enc2 = encryptor2.encrypt_int(value)
        assert enc1 == enc2

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            OrderPreservingEncryption(key=b"short")

    def test_value_out_of_range(self):
        """Test that values out of range raise error."""
        encryptor = OrderPreservingEncryption(plaintext_bits=8)

        # Max value for 8 bits is 255
        with pytest.raises(ValueError):
            encryptor.encrypt_int(256)

        # Negative values not supported
        with pytest.raises(ValueError):
            encryptor.encrypt_int(-1)

    def test_cache_functionality(self):
        """Test that caching works correctly."""
        encryptor = OrderPreservingEncryption()

        value = 1234
        enc1 = encryptor.encrypt_int(value)

        # Should use cache
        enc2 = encryptor.encrypt_int(value)
        assert enc1 == enc2

        # Clear cache and encrypt again
        encryptor.clear_cache()
        enc3 = encryptor.encrypt_int(value)

        # Should still be same (deterministic)
        assert enc1 == enc3

    def test_different_keys_different_ciphertexts(self):
        """Test that different keys produce different ciphertexts."""
        encryptor1 = OrderPreservingEncryption()
        encryptor2 = OrderPreservingEncryption()

        value = 777
        enc1 = encryptor1.encrypt_int(value)
        enc2 = encryptor2.encrypt_int(value)

        # Different keys should (very likely) produce different ciphertexts
        assert enc1 != enc2

    def test_large_value_encryption(self):
        """Test encryption of large values."""
        encryptor = OrderPreservingEncryption(plaintext_bits=32)

        large_value = 2**30  # 1 billion+
        encrypted = encryptor.encrypt_int(large_value)

        assert encrypted > 0

    def test_transaction_scenario(self):
        """Test realistic transaction amount scenario."""
        encryptor = OrderPreservingEncryption()

        # Transaction amounts in dollars
        amounts = [10.50, 25.00, 100.00, 250.50, 1000.00, 5000.00]
        encrypted_amounts = [encryptor.encrypt_amount(amt) for amt in amounts]

        # Find transactions over $100
        threshold = encryptor.encrypt_amount(100.00)
        large_txns = [enc for enc in encrypted_amounts if enc >= threshold]

        # Should find 4 transactions >= $100
        assert len(large_txns) == 4
