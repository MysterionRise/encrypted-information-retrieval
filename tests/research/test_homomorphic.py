"""Tests for homomorphic encryption module."""

import base64

import pytest

ts = pytest.importorskip("tenseal")

from encrypted_ir.research.homomorphic import BasicHomomorphicEncryption  # noqa: E402


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
        result = encryptor.decrypt_value(encryptor.sum_vector(encrypted))

        expected = sum(values)
        assert abs(result - expected) < 0.1

    def test_vector_mean(self):
        """Test mean of encrypted vector."""
        encryptor = BasicHomomorphicEncryption()

        values = [10.0, 20.0, 30.0, 40.0]
        encrypted = encryptor.encrypt_vector(values)
        result = encryptor.decrypt_value(encryptor.mean_vector(encrypted))

        expected = sum(values) / len(values)
        assert abs(result - expected) < 0.1

    def test_dot_product(self):
        """Test dot product of encrypted vectors."""
        encryptor = BasicHomomorphicEncryption()

        vec1 = [1.0, 2.0, 3.0]
        vec2 = [4.0, 5.0, 6.0]

        enc1 = encryptor.encrypt_vector(vec1)
        enc2 = encryptor.encrypt_vector(vec2)

        result = encryptor.decrypt_value(encryptor.dot_product(enc1, enc2))

        expected = sum(a * b for a, b in zip(vec1, vec2))
        assert abs(result - expected) < 0.5

    def test_weighted_sum(self):
        """Test weighted sum of encrypted vector."""
        encryptor = BasicHomomorphicEncryption()

        values = [10.0, 20.0, 30.0]
        weights = [0.5, 0.3, 0.2]

        encrypted = encryptor.encrypt_vector(values)
        result = encryptor.decrypt_value(encryptor.weighted_sum(encrypted, weights))

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

        # Export context, explicitly including the secret key
        context_bytes = encryptor1.export_context(save_secret_key=True)
        assert isinstance(context_bytes, bytes)

        # Import context
        encryptor2 = BasicHomomorphicEncryption.import_context(context_bytes)

        # Should be able to decrypt with imported context
        restored = encryptor2.deserialize_encrypted(encryptor1.serialize_encrypted(encrypted))
        result = encryptor2.decrypt_value(restored)
        assert abs(result - value) < 0.01

    def test_context_base64_export_import(self):
        """Test context export/import with base64."""
        encryptor1 = BasicHomomorphicEncryption()

        value = 77.7
        encrypted = encryptor1.encrypt_value(value)

        # Export to base64
        context_b64 = encryptor1.export_context_to_base64(save_secret_key=True)
        assert isinstance(context_b64, str)

        # Import from base64
        encryptor2 = BasicHomomorphicEncryption.import_context_from_base64(context_b64)

        # Should be able to decrypt
        restored = encryptor2.deserialize_encrypted(encryptor1.serialize_encrypted(encrypted))
        result = encryptor2.decrypt_value(restored)
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
        full_context = encryptor.export_context(save_secret_key=True)
        assert public_context != full_context


class TestHomomorphicAggregates:
    """Regression tests (#38): the aggregates decrypted every element first."""

    def setup_method(self):
        self.client = BasicHomomorphicEncryption()
        # The "server" holds only the public context: it can compute but not decrypt.
        self.server = BasicHomomorphicEncryption.import_context(self.client.export_public_context())

    def _to_server(self, encrypted):
        return self.server.deserialize_encrypted(self.client.serialize_encrypted(encrypted))

    def _to_client(self, encrypted):
        return self.client.deserialize_encrypted(self.server.serialize_encrypted(encrypted))

    def test_server_cannot_decrypt(self):
        assert self.client.has_secret_key
        assert not self.server.has_secret_key
        encrypted = self._to_server(self.client.encrypt_vector([1.0, 2.0]))
        with pytest.raises(ValueError, match="secret"):
            self.server.decrypt_vector(encrypted)

    def test_aggregates_run_without_the_secret_key(self):
        values = [10.0, 20.0, 30.0, 40.0]
        other = [0.5, 1.5, 2.5, 3.5]
        weights = [0.1, 0.2, 0.3, 0.4]
        enc_values = self._to_server(self.client.encrypt_vector(values))
        enc_other = self._to_server(self.client.encrypt_vector(other))

        results = {
            "sum": self.server.sum_vector(enc_values),
            "mean": self.server.mean_vector(enc_values),
            "dot": self.server.dot_product(enc_values, enc_other),
            "weighted": self.server.weighted_sum(enc_values, weights),
        }
        expected = {
            "sum": sum(values),
            "mean": sum(values) / len(values),
            "dot": sum(a * b for a, b in zip(values, other)),
            "weighted": sum(v * w for v, w in zip(values, weights)),
        }
        for name, encrypted in results.items():
            assert isinstance(encrypted, ts.CKKSVector)
            assert encrypted.size() == 1
            decrypted = self.client.decrypt_value(self._to_client(encrypted))
            assert decrypted == pytest.approx(expected[name], abs=0.01), name

    def test_aggregates_never_decrypt(self, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("aggregate decrypted its input")

        monkeypatch.setattr(self.client, "decrypt_vector", forbidden)
        monkeypatch.setattr(self.client, "decrypt_value", forbidden)
        enc = self.client.encrypt_vector([1.0, 2.0, 3.0])
        for result in (
            self.client.sum_vector(enc),
            self.client.mean_vector(enc),
            self.client.dot_product(enc, enc),
            self.client.weighted_sum(enc, [1.0, 1.0, 1.0]),
        ):
            assert isinstance(result, ts.CKKSVector)

    def test_weighted_sum_rejects_wrong_number_of_weights(self):
        enc = self.client.encrypt_vector([1.0, 2.0, 3.0])
        with pytest.raises(ValueError, match="Expected 3 weights, got 2"):
            self.client.weighted_sum(enc, [0.5, 0.5])
        with pytest.raises(ValueError, match="Expected 3 weights, got 4"):
            self.client.weighted_sum(enc, [0.5, 0.5, 0.5, 0.5])

    def test_dot_product_rejects_different_lengths(self):
        enc3 = self.client.encrypt_vector([1.0, 2.0, 3.0])
        enc2 = self.client.encrypt_vector([1.0, 2.0])
        with pytest.raises(ValueError, match="lengths differ"):
            self.client.dot_product(enc3, enc2)

    def test_galois_keys_are_required_for_slot_sums(self):
        """Galois keys are generated because sum() and dot() rotate slots."""
        assert self.client.context.has_galois_keys()
        context = ts.context(
            ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        context.global_scale = 2**40
        context.generate_relin_keys()
        no_galois = BasicHomomorphicEncryption(context)
        with pytest.raises(ValueError, match="Galois"):
            no_galois.sum_vector(no_galois.encrypt_vector([1.0, 2.0]))


class TestHomomorphicContextExport:
    """Regression tests (#38): the secret key was exported by default, and import accepted
    anything."""

    def test_export_context_omits_secret_key_by_default(self):
        owner = BasicHomomorphicEncryption()
        serialized = owner.serialize_encrypted(owner.encrypt_value(42.0))

        for exported in (
            owner.export_context(),
            base64.b64decode(owner.export_context_to_base64()),
        ):
            imported = BasicHomomorphicEncryption.import_context(exported)
            assert not imported.has_secret_key
            with pytest.raises(ValueError, match="secret"):
                imported.decrypt_value(imported.deserialize_encrypted(serialized))

    def test_secret_key_export_is_explicit(self):
        owner = BasicHomomorphicEncryption()
        serialized = owner.serialize_encrypted(owner.encrypt_value(42.0))
        for exported in (
            owner.export_context(save_secret_key=True),
            base64.b64decode(owner.export_context_to_base64(save_secret_key=True)),
        ):
            imported = BasicHomomorphicEncryption.import_context(exported)
            assert imported.has_secret_key
            decrypted = imported.decrypt_value(imported.deserialize_encrypted(serialized))
            assert decrypted == pytest.approx(42.0, abs=0.01)

    @pytest.mark.parametrize("data", [b"", b"not a context", bytes(64)])
    def test_import_rejects_garbage(self, data):
        with pytest.raises(ValueError, match="TenSEAL context"):
            BasicHomomorphicEncryption.import_context(data)

    def test_import_rejects_non_bytes(self):
        with pytest.raises(ValueError, match="bytes"):
            BasicHomomorphicEncryption.import_context("not bytes")

    def test_import_rejects_bfv_context(self):
        bfv = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=4096, plain_modulus=1032193)
        with pytest.raises(ValueError, match="not a CKKS context"):
            BasicHomomorphicEncryption.import_context(bfv.serialize())

    def test_rejects_ckks_context_without_usable_scale(self):
        context = ts.context(
            ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        with pytest.raises(ValueError, match="global scale"):
            BasicHomomorphicEncryption(context)
        context.global_scale = 0
        with pytest.raises(ValueError, match="positive global scale"):
            BasicHomomorphicEncryption(context)

    def test_import_rejects_invalid_base64(self):
        with pytest.raises(ValueError, match="base64"):
            BasicHomomorphicEncryption.import_context_from_base64("not base64!")

    @pytest.mark.parametrize("context", ["context", 42, object()])
    def test_constructor_rejects_non_context(self, context):
        with pytest.raises(ValueError, match="TenSEAL context"):
            BasicHomomorphicEncryption(context)
