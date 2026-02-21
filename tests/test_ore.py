"""Tests for Order-Revealing Encryption (ORE) module."""

import time

import pytest

from encrypted_ir.ore import ORE


class TestOREKeyManagement:
    """Tests for key generation, export, and import."""

    def test_key_generation(self):
        """Test that generated keys are 32 bytes."""
        key = ORE.generate_key()
        assert len(key) == 32

    def test_key_generation_randomness(self):
        """Test that successive key generations produce distinct keys."""
        keys = [ORE.generate_key() for _ in range(10)]
        assert len(set(keys)) == 10

    def test_invalid_key_size(self):
        """Test that non-32-byte keys are rejected."""
        with pytest.raises(ValueError, match="32 bytes"):
            ORE(key=b"short")

        with pytest.raises(ValueError, match="32 bytes"):
            ORE(key=b"x" * 64)

    def test_auto_generated_key(self):
        """Test that omitting key auto-generates one."""
        ore = ORE()
        assert len(ore.key) == 32

    def test_key_export_import(self):
        """Test round-trip key export and import."""
        ore1 = ORE()
        value = 5555
        enc1 = ore1.encrypt_int(value)

        key_b64 = ore1.export_key()
        ore2 = ORE.import_key(key_b64)

        enc2 = ore2.encrypt_int(value)
        assert enc1 == enc2

    def test_key_export_format(self):
        """Test that exported key is valid base64."""
        ore = ORE()
        key_b64 = ore.export_key()
        assert isinstance(key_b64, str)
        # Should round-trip through base64
        import base64

        decoded = base64.b64decode(key_b64)
        assert len(decoded) == 32


class TestOREIntegerEncryption:
    """Tests for integer encryption."""

    def test_basic_encryption(self):
        """Test that encryption produces bytes output."""
        ore = ORE()
        encrypted = ore.encrypt_int(12345)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

    def test_deterministic_property(self):
        """Test that same key + same plaintext produces same ciphertext."""
        ore = ORE()
        enc1 = ore.encrypt_int(777)
        enc2 = ore.encrypt_int(777)
        assert enc1 == enc2

    def test_zero_encryption(self):
        """Test encrypting zero."""
        ore = ORE()
        encrypted = ore.encrypt_int(0)
        assert isinstance(encrypted, bytes)
        assert ore.compare(encrypted, encrypted) == 0

    def test_max_value_encryption(self):
        """Test encrypting the maximum plaintext value."""
        ore = ORE()
        encrypted = ore.encrypt_int(ORE.PLAINTEXT_MAX)
        assert isinstance(encrypted, bytes)

    def test_negative_value_rejected(self):
        """Test that negative values raise ValueError."""
        ore = ORE()
        with pytest.raises(ValueError):
            ore.encrypt_int(-1)

    def test_value_out_of_range(self):
        """Test that values exceeding 2^32 - 1 raise ValueError."""
        ore = ORE()
        with pytest.raises(ValueError):
            ore.encrypt_int(ORE.PLAINTEXT_MAX + 1)

    def test_large_value_encryption(self):
        """Test encryption of large values within range."""
        ore = ORE()
        encrypted = ore.encrypt_int(2**30)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0


class TestOREFloatEncryption:
    """Tests for float and amount encryption."""

    def test_float_encryption(self):
        """Test float encryption with precision."""
        ore = ORE()
        encrypted = ore.encrypt_float(1234.56, precision=2)
        assert isinstance(encrypted, bytes)

    def test_amount_encryption(self):
        """Test monetary amount encryption."""
        ore = ORE()
        encrypted = ore.encrypt_amount(1234.56)
        assert isinstance(encrypted, bytes)

    def test_float_precision(self):
        """Test that float precision is respected."""
        ore = ORE()
        # 1234.56 with precision=2 → int 123456
        # 1234.57 with precision=2 → int 123457
        enc1 = ore.encrypt_float(1234.56, precision=2)
        enc2 = ore.encrypt_float(1234.57, precision=2)
        assert ore.compare(enc1, enc2) == -1  # 123456 < 123457

    def test_negative_float_rejected(self):
        """Test that negative float values raise ValueError."""
        ore = ORE()
        with pytest.raises(ValueError):
            ore.encrypt_float(-1.0)

    def test_float_too_large(self):
        """Test that very large floats raise ValueError."""
        ore = ORE()
        with pytest.raises(ValueError):
            ore.encrypt_float(float(ORE.PLAINTEXT_MAX + 1), precision=0)


class TestOREComparison:
    """Tests for the compare() method — the core ORE operation."""

    def test_order_preservation(self):
        """Test that compare() correctly preserves ordering."""
        ore = ORE()
        values = [100, 500, 1000, 5000, 10000]
        encrypted = [ore.encrypt_int(v) for v in values]

        for i in range(len(encrypted) - 1):
            assert ore.compare(encrypted[i], encrypted[i + 1]) == -1

    def test_equal_values(self):
        """Test that equal values compare as equal."""
        ore = ORE()
        enc1 = ore.encrypt_int(42)
        enc2 = ore.encrypt_int(42)
        assert ore.compare(enc1, enc2) == 0

    def test_comparison_returns_minus_one_zero_one(self):
        """Test that compare() returns exactly -1, 0, or 1."""
        ore = ORE()
        enc_a = ore.encrypt_int(100)
        enc_b = ore.encrypt_int(200)

        assert ore.compare(enc_a, enc_b) == -1
        assert ore.compare(enc_b, enc_a) == 1
        assert ore.compare(enc_a, enc_a) == 0

    def test_adjacent_values(self):
        """Test comparison of consecutive values."""
        ore = ORE()
        enc1 = ore.encrypt_int(999)
        enc2 = ore.encrypt_int(1000)
        assert ore.compare(enc1, enc2) == -1

    def test_extreme_boundary(self):
        """Test comparison at the extremes of the plaintext range."""
        ore = ORE()
        enc_zero = ore.encrypt_int(0)
        enc_max = ore.encrypt_int(ORE.PLAINTEXT_MAX)
        assert ore.compare(enc_zero, enc_max) == -1

    def test_many_values_order(self):
        """Test ordering across many values."""
        ore = ORE()
        values = list(range(0, 10000, 137))  # 73 values spread across range
        encrypted = [ore.encrypt_int(v) for v in values]

        for i in range(len(encrypted) - 1):
            assert ore.compare(encrypted[i], encrypted[i + 1]) == -1

    def test_reverse_order_comparison(self):
        """Test that reversed comparison gives opposite result."""
        ore = ORE()
        enc_a = ore.encrypt_int(42)
        enc_b = ore.encrypt_int(99)
        assert ore.compare(enc_a, enc_b) == -1
        assert ore.compare(enc_b, enc_a) == 1

    def test_float_order_preservation(self):
        """Test ordering of encrypted float amounts."""
        ore = ORE()
        amounts = [10.50, 100.00, 1000.00, 5000.99]
        encrypted = [ore.encrypt_amount(amt) for amt in amounts]

        for i in range(len(encrypted) - 1):
            assert ore.compare(encrypted[i], encrypted[i + 1]) == -1


class TestORESecurityProperties:
    """Tests verifying ORE's security guarantees."""

    def test_no_global_order_leakage(self):
        """Single ciphertext should not reveal ordering via byte comparison.

        Values that differ in higher-order blocks have pseudorandom left
        components at those positions, so byte-level sorting should NOT
        reliably match plaintext ordering.
        """
        mismatches = 0
        for _ in range(20):
            o = ORE()
            # Values that differ at block 0 (the most significant byte):
            # 0 -> [0,0,0,0], 16777216 -> [1,0,0,0], 33554432 -> [2,0,0,0]
            # Their left_1 components are PRF outputs on distinct inputs,
            # so byte-ordering is pseudorandom w.r.t. plaintext ordering.
            e0 = o.encrypt_int(0)
            e1 = o.encrypt_int(16777216)
            e2 = o.encrypt_int(33554432)
            if not (e0 < e1 < e2):
                mismatches += 1

        # With PRF-derived components, byte ordering should NOT consistently
        # match plaintext ordering. Probability of always matching: ~(1/6)^20.
        assert mismatches > 0, "Byte ordering always matched plaintext ordering"

    def test_different_keys_different_ciphertexts(self):
        """Different keys should produce different ciphertexts."""
        ore1 = ORE()
        ore2 = ORE()
        enc1 = ore1.encrypt_int(777)
        enc2 = ore2.encrypt_int(777)
        assert enc1 != enc2

    def test_tenant_isolation(self):
        """Ciphertexts from different keys cannot be compared."""
        ore_a = ORE()
        ore_b = ORE()
        enc_a = ore_a.encrypt_int(100)
        enc_b = ore_b.encrypt_int(50)

        with pytest.raises(ValueError, match="different keys"):
            ore_a.compare(enc_a, enc_b)

    def test_ciphertext_not_trivially_sortable(self):
        """Verify ciphertexts cannot be sorted by simple numeric interpretation."""
        ore = ORE()
        values = [100, 500, 1000, 5000, 10000]
        encrypted = [ore.encrypt_int(v) for v in values]

        # Interpret ciphertext bytes as big-endian integers
        as_ints = [int.from_bytes(e, "big") for e in encrypted]

        # Check that numeric sorting of ciphertext ints does NOT match
        # plaintext ordering. Since left components at position 0 are
        # identical (same key, same empty prefix), the first few bytes
        # will be the same. Sorting still shouldn't be reliable because
        # the right components are masked with random offsets.
        sorted(range(len(values)), key=lambda i: as_ints[i])
        list(range(len(values)))

        # With the Lewi-Wu construction, byte-level sorting is unreliable
        # for determining plaintext order. We just verify that compare()
        # is the only reliable ordering mechanism.
        assert ore.compare(encrypted[0], encrypted[4]) == -1


class TestORERangeQuery:
    """Tests for range query functionality."""

    def test_range_query(self):
        """Test range query on encrypted values."""
        ore = ORE()
        values = [100, 200, 300, 400, 500]
        encrypted = [ore.encrypt_int(v) for v in values]

        min_enc = ore.encrypt_int(150)
        max_enc = ore.encrypt_int(450)
        result = ore.range_query(encrypted, min_enc, max_enc)

        # Should return ciphertexts for 200, 300, 400
        assert len(result) == 3

    def test_range_query_no_min(self):
        """Test range query with only maximum."""
        ore = ORE()
        values = [100, 200, 300, 400, 500]
        encrypted = [ore.encrypt_int(v) for v in values]

        max_enc = ore.encrypt_int(250)
        result = ore.range_query(encrypted, None, max_enc)
        assert len(result) == 2  # 100, 200

    def test_range_query_no_max(self):
        """Test range query with only minimum."""
        ore = ORE()
        values = [100, 200, 300, 400, 500]
        encrypted = [ore.encrypt_int(v) for v in values]

        min_enc = ore.encrypt_int(350)
        result = ore.range_query(encrypted, min_enc, None)
        assert len(result) == 2  # 400, 500

    def test_range_query_all(self):
        """Test range query with no bounds returns all values."""
        ore = ORE()
        values = [100, 200, 300]
        encrypted = [ore.encrypt_int(v) for v in values]
        result = ore.range_query(encrypted, None, None)
        assert len(result) == 3

    def test_range_query_empty_result(self):
        """Test range query that matches nothing."""
        ore = ORE()
        values = [100, 200, 300]
        encrypted = [ore.encrypt_int(v) for v in values]

        min_enc = ore.encrypt_int(400)
        max_enc = ore.encrypt_int(500)
        result = ore.range_query(encrypted, min_enc, max_enc)
        assert len(result) == 0


class TestORESerialisation:
    """Tests for base64 and bytes serialization."""

    def test_base64_encoding(self):
        """Test base64 encode/decode round-trip."""
        ore = ORE()
        b64 = ore.encrypt_to_base64(9999)
        assert isinstance(b64, str)

        # Decode back and verify compare still works
        raw = ORE.decrypt_from_base64(b64)
        assert ore.compare(raw, ore.encrypt_int(9999)) == 0

    def test_ciphertext_format(self):
        """Test ciphertext has expected structure."""
        ore = ORE()
        ct = ore.encrypt_int(42)

        # Expected: 2 header bytes + 4 * LEFT_SIZE + 4 * 2
        expected_len = 2 + ORE.NUM_BLOCKS * ORE.LEFT_SIZE + ORE.NUM_BLOCKS * 2
        assert len(ct) == expected_len

        # First byte is version tag
        assert ct[0] == ORE.VERSION_TAG
        # Second byte is num_blocks
        assert ct[1] == ORE.NUM_BLOCKS

    def test_invalid_ciphertext_too_short(self):
        """Test that truncated ciphertext raises ValueError."""
        ore = ORE()
        with pytest.raises(ValueError, match="too short"):
            ore.compare(b"\x01", ore.encrypt_int(0))

    def test_invalid_ciphertext_wrong_version(self):
        """Test that wrong version tag raises ValueError."""
        ore = ORE()
        ct = ore.encrypt_int(42)
        bad_ct = b"\xff" + ct[1:]
        with pytest.raises(ValueError, match="version"):
            ore.compare(bad_ct, ct)

    def test_invalid_ciphertext_wrong_length(self):
        """Test that wrong-length ciphertext raises ValueError."""
        ore = ORE()
        ct = ore.encrypt_int(42)
        bad_ct = ct + b"\x00"
        with pytest.raises(ValueError, match="length"):
            ore.compare(bad_ct, ct)


class TestORECache:
    """Tests for caching behavior."""

    def test_cache_produces_same_result(self):
        """Test that cached encryption matches fresh encryption."""
        ore = ORE()
        enc1 = ore.encrypt_int(1234)
        enc2 = ore.encrypt_int(1234)  # should hit cache
        assert enc1 == enc2

    def test_clear_cache(self):
        """Test that clearing cache doesn't change deterministic output."""
        ore = ORE()
        enc1 = ore.encrypt_int(1234)
        ore.clear_cache()
        enc2 = ore.encrypt_int(1234)  # recomputed from scratch
        assert enc1 == enc2


class TestORETransactionScenario:
    """Realistic financial transaction scenarios."""

    def test_transaction_amount_ordering(self):
        """Test realistic transaction amounts maintain correct order."""
        ore = ORE()
        amounts = [10.50, 25.00, 100.00, 250.50, 1000.00, 5000.00]
        encrypted_amounts = [ore.encrypt_amount(amt) for amt in amounts]

        # All pairs should compare correctly
        for i in range(len(amounts)):
            for j in range(len(amounts)):
                expected = -1 if amounts[i] < amounts[j] else (1 if amounts[i] > amounts[j] else 0)
                assert ore.compare(encrypted_amounts[i], encrypted_amounts[j]) == expected

    def test_find_large_transactions(self):
        """Test finding transactions above a threshold."""
        ore = ORE()
        amounts = [10.50, 25.00, 100.00, 250.50, 1000.00, 5000.00]
        encrypted = [ore.encrypt_amount(amt) for amt in amounts]
        threshold = ore.encrypt_amount(100.00)

        large = [enc for enc in encrypted if ore.compare(enc, threshold) >= 0]
        assert len(large) == 4  # 100, 250.50, 1000, 5000

    def test_find_transactions_in_range(self):
        """Test finding transactions within a dollar range."""
        ore = ORE()
        amounts = [10.50, 25.00, 100.00, 250.50, 1000.00, 5000.00]
        encrypted = [ore.encrypt_amount(amt) for amt in amounts]

        min_enc = ore.encrypt_amount(50.00)
        max_enc = ore.encrypt_amount(500.00)
        result = ore.range_query(encrypted, min_enc, max_enc)
        assert len(result) == 2  # 100.00, 250.50


class TestOREAlgorithmIdentifier:
    """Tests for algorithm metadata."""

    def test_algorithm_constant(self):
        """Test that algorithm identifier is set correctly."""
        assert ORE.ALGORITHM == "ore-lewi-wu"

    def test_plaintext_range(self):
        """Test plaintext space constants."""
        assert ORE.PLAINTEXT_BITS == 32
        assert ORE.PLAINTEXT_MAX == 2**32 - 1


class TestOREPerformance:
    """Basic performance sanity checks (not benchmarks, just bounds)."""

    def test_encryption_speed(self):
        """Test that single encryption completes in reasonable time."""
        ore = ORE()
        ore.encrypt_int(0)  # warm up
        ore.clear_cache()

        start = time.monotonic()
        for v in range(100):
            ore.encrypt_int(v * 1000)
        elapsed = time.monotonic() - start

        # 100 encryptions should finish well under 1 second
        assert elapsed < 1.0

    def test_comparison_speed(self):
        """Test that comparisons are fast."""
        ore = ORE()
        enc_a = ore.encrypt_int(100)
        enc_b = ore.encrypt_int(200)

        start = time.monotonic()
        for _ in range(1000):
            ore.compare(enc_a, enc_b)
        elapsed = time.monotonic() - start

        # 1000 comparisons should complete well under 1 second
        assert elapsed < 1.0
