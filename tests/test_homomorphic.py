"""Tests for homomorphic encryption module."""

import pytest
import tenseal as ts
from encrypted_ir.homomorphic import BasicHomomorphicEncryption


class TestBasicHomomorphicEncryption:
    """Test homomorphic encryption functionality."""

    def test_context_creation(self):
        """Test context creation."""
        context = BasicHomomorphicEncryption.create_context()
        assert context is not None
        assert isinstance(context, ts.Context)

    def test_value_encryption_decryption(self):
        """Test single value encryption and decryption."""
        encryptor = BasicHomomorphicEncryption()

        value = 42.5
        encrypted = encryptor.encrypt_value(value)
        decrypted = encryptor.decrypt_value(encrypted)

        # Allow small floating-point error
        assert abs(decrypted - value) < 0.01

    def test_vector_encryption_decryption(self):
        """Test vector encryption and decryption."""
        encryptor = BasicHomomorphicEncryption()

        values = [1.5, 2.5, 3.5, 4.5]
        encrypted = encryptor.encrypt_vector(values)
        decrypted = encryptor.decrypt_vector(encrypted)

        # Check all values match (with small error tolerance)
        for orig, dec in zip(values, decrypted):
            assert abs(orig - dec) < 0.01

    def test_homomorphic_addition(self):
        """Test homomorphic addition."""
        encryptor = BasicHomomorphicEncryption()

        val1 = 10.0
        val2 = 20.0

        enc1 = encryptor.encrypt_value(val1)
        enc2 = encryptor.encrypt_value(val2)

        # Add encrypted values
        enc_sum = encryptor.add_encrypted(enc1, enc2)
        result = encryptor.decrypt_value(enc_sum)

        expected = val1 + val2
        assert abs(result - expected) < 0.01

    def test_homomorphic_addition_with_plain(self):
        """Test adding plaintext to encrypted value."""
        encryptor = BasicHomomorphicEncryption()

        encrypted_val = 15.0
        plain_val = 5.0

        enc = encryptor.encrypt_value(encrypted_val)
        enc_result = encryptor.add_plain(enc, plain_val)
        result = encryptor.decrypt_value(enc_result)

        expected = encrypted_val + plain_val
        assert abs(result - expected) < 0.01

    def test_homomorphic_subtraction(self):
        """Test homomorphic subtraction."""
        encryptor = BasicHomomorphicEncryption()

        val1 = 30.0
        val2 = 10.0

        enc1 = encryptor.encrypt_value(val1)
        enc2 = encryptor.encrypt_value(val2)

        enc_diff = encryptor.subtract_encrypted(enc1, enc2)
        result = encryptor.decrypt_value(enc_diff)

        expected = val1 - val2
        assert abs(result - expected) < 0.01

    def test_homomorphic_subtraction_with_plain(self):
        """Test subtracting plaintext from encrypted value."""
        encryptor = BasicHomomorphicEncryption()

        encrypted_val = 50.0
        plain_val = 15.0

        enc = encryptor.encrypt_value(encrypted_val)
        enc_result = encryptor.subtract_plain(enc, plain_val)
        result = encryptor.decrypt_value(enc_result)

        expected = encrypted_val - plain_val
        assert abs(result - expected) < 0.01

    def test_homomorphic_multiplication(self):
        """Test homomorphic multiplication."""
        encryptor = BasicHomomorphicEncryption()

        val1 = 5.0
        val2 = 3.0

        enc1 = encryptor.encrypt_value(val1)
        enc2 = encryptor.encrypt_value(val2)

        enc_product = encryptor.multiply_encrypted(enc1, enc2)
        result = encryptor.decrypt_value(enc_product)

        expected = val1 * val2
        assert abs(result - expected) < 0.1

    def test_homomorphic_multiplication_with_plain(self):
        """Test multiplying encrypted value by plaintext."""
        encryptor = BasicHomomorphicEncryption()

        encrypted_val = 7.0
        plain_val = 4.0

        enc = encryptor.encrypt_value(encrypted_val)
        enc_result = encryptor.multiply_plain(enc, plain_val)
        result = encryptor.decrypt_value(enc_result)

        expected = encrypted_val * plain_val
        assert abs(result - expected) < 0.1

    def test_vector_sum(self):
        """Test sum of encrypted vector."""
        encryptor = BasicHomomorphicEncryption()

        values = [10.0, 20.0, 30.0, 40.0]
        encrypted = encryptor.encrypt_vector(values)
        result = encryptor.sum_vector(encrypted)

        expected = sum(values)
        assert abs(result - expected) < 0.1

    def test_vector_mean(self):
        """Test mean of encrypted vector."""
        encryptor = BasicHomomorphicEncryption()

        values = [10.0, 20.0, 30.0, 40.0]
        encrypted = encryptor.encrypt_vector(values)
        result = encryptor.mean_vector(encrypted)

        expected = sum(values) / len(values)
        assert abs(result - expected) < 0.1

    def test_dot_product(self):
        """Test dot product of encrypted vectors."""
        encryptor = BasicHomomorphicEncryption()

        vec1 = [1.0, 2.0, 3.0]
        vec2 = [4.0, 5.0, 6.0]

        enc1 = encryptor.encrypt_vector(vec1)
        enc2 = encryptor.encrypt_vector(vec2)

        result = encryptor.dot_product(enc1, enc2)

        expected = sum(a * b for a, b in zip(vec1, vec2))
        assert abs(result - expected) < 0.5

    def test_weighted_sum(self):
        """Test weighted sum of encrypted vector."""
        encryptor = BasicHomomorphicEncryption()

        values = [10.0, 20.0, 30.0]
        weights = [0.5, 0.3, 0.2]

        encrypted = encryptor.encrypt_vector(values)
        result = encryptor.weighted_sum(encrypted, weights)

        expected = sum(v * w for v, w in zip(values, weights))
        assert abs(result - expected) < 0.5

    def test_serialization(self):
        """Test serialization and deserialization of encrypted values."""
        encryptor = BasicHomomorphicEncryption()

        value = 123.45
        encrypted = encryptor.encrypt_value(value)

        # Serialize
        serialized = encryptor.serialize_encrypted(encrypted)
        assert isinstance(serialized, bytes)

        # Deserialize
        deserialized = encryptor.deserialize_encrypted(serialized)
        result = encryptor.decrypt_value(deserialized)

        assert abs(result - value) < 0.01

    def test_base64_serialization(self):
        """Test base64 serialization."""
        encryptor = BasicHomomorphicEncryption()

        value = 99.99
        encrypted = encryptor.encrypt_value(value)

        # Serialize to base64
        serialized_b64 = encryptor.serialize_encrypted_to_base64(encrypted)
        assert isinstance(serialized_b64, str)

        # Deserialize from base64
        deserialized = encryptor.deserialize_encrypted_from_base64(serialized_b64)
        result = encryptor.decrypt_value(deserialized)

        assert abs(result - value) < 0.01

    def test_context_export_import(self):
        """Test context export and import."""
        encryptor1 = BasicHomomorphicEncryption()

        value = 42.0
        encrypted = encryptor1.encrypt_value(value)

        # Export context
        context_bytes = encryptor1.export_context()
        assert isinstance(context_bytes, bytes)

        # Import context
        encryptor2 = BasicHomomorphicEncryption.import_context(context_bytes)

        # Should be able to decrypt with imported context
        result = encryptor2.decrypt_value(encrypted)
        assert abs(result - value) < 0.01

    def test_context_base64_export_import(self):
        """Test context export/import with base64."""
        encryptor1 = BasicHomomorphicEncryption()

        value = 77.7
        encrypted = encryptor1.encrypt_value(value)

        # Export to base64
        context_b64 = encryptor1.export_context_to_base64()
        assert isinstance(context_b64, str)

        # Import from base64
        encryptor2 = BasicHomomorphicEncryption.import_context_from_base64(context_b64)

        # Should be able to decrypt
        result = encryptor2.decrypt_value(encrypted)
        assert abs(result - value) < 0.01

    def test_integer_encryption(self):
        """Test encryption of integers."""
        encryptor = BasicHomomorphicEncryption()

        value = 100
        encrypted = encryptor.encrypt_value(value)
        result = encryptor.decrypt_value(encrypted)

        assert abs(result - value) < 0.01

    def test_complex_calculation(self):
        """Test complex calculation on encrypted data."""
        encryptor = BasicHomomorphicEncryption()

        # Encrypt values
        a = encryptor.encrypt_value(10.0)
        b = encryptor.encrypt_value(5.0)
        c = encryptor.encrypt_value(2.0)

        # Compute (a + b) * c
        sum_ab = encryptor.add_encrypted(a, b)
        result_enc = encryptor.multiply_encrypted(sum_ab, c)
        result = encryptor.decrypt_value(result_enc)

        expected = (10.0 + 5.0) * 2.0
        assert abs(result - expected) < 0.5

    def test_public_context_export(self):
        """Test export of public context (without secret key)."""
        encryptor = BasicHomomorphicEncryption()

        public_context = encryptor.export_public_context()
        assert isinstance(public_context, bytes)

        # Public context should be different from full context
        full_context = encryptor.export_context()
        assert public_context != full_context
