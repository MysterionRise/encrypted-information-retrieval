"""Tests for Order-Revealing Encryption (ORE) module."""

import functools
import struct
from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from encrypted_ir.research.ore import ORE


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

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0.29, 29),  # int(0.29 * 100) == 28
            (1.15, 115),  # int(1.15 * 100) == 114
            (4.35, 435),  # int(4.35 * 100) == 434
            (1234.56, 123456),
            (0.0, 0),
            (-0.0, 0),
            (7, 700),
            (Decimal("19.99"), 1999),
        ],
    )
    def test_fixed_point_is_exact(self, value, expected):
        """Regression (#38): encrypt_float truncated, so 0.29 became 28 and 1.15 became 114."""
        assert ORE.to_fixed_point(value, precision=2) == expected
        ore = ORE()
        assert ore.encrypt_float(value, precision=2) == ore.encrypt_int(expected)

    @pytest.mark.parametrize(
        "value,precision,expected",
        [
            (Decimal("1.005"), 2, 100),  # half-to-even: 100.5 -> 100
            (Decimal("1.015"), 2, 102),  # half-to-even: 101.5 -> 102
            (2.5, 0, 2),
            (3.5, 0, 4),
            (0.123456, 3, 123),
        ],
    )
    def test_fixed_point_rounds_half_to_even(self, value, precision, expected):
        """Digits beyond the precision are rounded half-to-even, not truncated."""
        assert ORE.to_fixed_point(value, precision=precision) == expected

    def test_amount_regression_values_order_correctly(self):
        """0.29 must sort above 0.28 and equal a separately encoded 29 cents."""
        ore = ORE()
        assert ore.compare(ore.encrypt_amount(0.29), ore.encrypt_amount(0.28)) == 1
        assert ore.compare(ore.encrypt_amount(0.29), ore.encrypt_amount(Decimal("0.29"))) == 0

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), Decimal("NaN")])
    def test_non_finite_values_rejected(self, value):
        """NaN and infinities are rejected instead of being cast to an integer."""
        with pytest.raises(ValueError, match="finite"):
            ORE().encrypt_float(value)

    def test_negative_precision_rejected(self):
        with pytest.raises(ValueError, match="precision"):
            ORE().encrypt_float(1.0, precision=-1)

    @pytest.mark.parametrize("value", ["1.00", True, None])
    def test_non_numeric_values_rejected(self, value):
        with pytest.raises(ValueError, match="int, float or Decimal"):
            ORE.to_fixed_point(value)

    def test_value_just_under_limit_accepted(self):
        max_amount = Decimal(ORE.PLAINTEXT_MAX).scaleb(-2)
        assert ORE.to_fixed_point(max_amount) == ORE.PLAINTEXT_MAX
        with pytest.raises(ValueError, match="too large"):
            ORE.to_fixed_point(max_amount + Decimal("0.01"))


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

    def test_raw_bytes_not_sortable(self):
        """Raw ciphertext bytes do not reliably sort in plaintext order.

        Values that differ in higher-order blocks have pseudorandom left
        components at those positions, so byte-level sorting does not
        reliably match plaintext ordering. This is NOT a confidentiality
        property: compare() orders ciphertexts without any key
        (see test_compare_requires_no_key).
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

    def test_compare_requires_no_key(self):
        """Known leakage: compare() never uses the instance key.

        An ORE instance holding an unrelated key sorts another key's
        ciphertexts into plaintext order, so anyone holding the ciphertext
        column learns the total order, the same leakage as OPE.
        Documented in the module docstring and issue #34.
        """
        owner = ORE()
        outsider = ORE()  # independent random key
        values = [900, 5, 70000, 16777300, 12, 4294967295, 0, 65536]
        ciphertexts = [owner.encrypt_int(v) for v in values]

        recovered = sorted(ciphertexts, key=functools.cmp_to_key(outsider.compare))

        assert [values[ciphertexts.index(c)] for c in recovered] == sorted(values)

    def test_right_component_leaks_block_differences(self):
        """Known leakage: right components reveal plaintext byte differences.

        right_0 is the most significant byte plus a per-key constant, so the
        difference of two right_0 values equals the difference of the most
        significant bytes. For ciphertexts that share a prefix, the same holds
        at the first differing block. Documented in the module docstring.
        """
        ore = ORE()
        right_offset = 2 + ORE.NUM_BLOCKS * ORE.LEFT_SIZE

        def right(ciphertext: bytes, block: int) -> int:
            start = right_offset + 2 * block
            return struct.unpack(">H", ciphertext[start : start + 2])[0]

        high = ore.encrypt_int(0x05_00_00_00)
        low = ore.encrypt_int(0x02_00_00_00)
        assert (right(high, 0) - right(low, 0)) % ORE.MODULUS == 3

        shared_prefix_a = ore.encrypt_int(0x01_02_03_09)
        shared_prefix_b = ore.encrypt_int(0x01_02_03_05)
        assert (right(shared_prefix_a, 3) - right(shared_prefix_b, 3)) % ORE.MODULUS == 4


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
        assert len(ore._cache) == 0
        enc2 = ore.encrypt_int(1234)  # recomputed from scratch
        assert enc1 == enc2

    def test_cache_is_bounded(self):
        """Regression (#38): the plaintext -> ciphertext cache grew without bound."""
        ore = ORE(cache_size=16)
        for value in range(1000):
            ore.encrypt_int(value)
        assert len(ore._cache) == 16
        assert list(ore._cache) == list(range(984, 1000))

    def test_default_cache_size(self):
        ore = ORE()
        assert ore.cache_size == ORE.DEFAULT_CACHE_SIZE == 1024
        for value in range(ORE.DEFAULT_CACHE_SIZE + 10):
            ore.encrypt_int(value)
        assert len(ore._cache) == ORE.DEFAULT_CACHE_SIZE

    def test_cache_evicts_least_recently_used(self):
        ore = ORE(cache_size=2)
        ore.encrypt_int(1)
        ore.encrypt_int(2)
        ore.encrypt_int(1)  # touch 1, so 2 is now least recently used
        ore.encrypt_int(3)
        assert set(ore._cache) == {1, 3}

    def test_cache_disabled(self):
        ore = ORE(cache_size=0)
        enc1 = ore.encrypt_int(42)
        assert len(ore._cache) == 0
        assert ore.encrypt_int(42) == enc1

    @pytest.mark.parametrize("cache_size", [-1, 1.5, True])
    def test_invalid_cache_size(self, cache_size):
        with pytest.raises(ValueError, match="cache_size"):
            ORE(cache_size=cache_size)

    def test_cached_value_is_not_recomputed(self, monkeypatch):
        """A cache hit returns the stored ciphertext without calling the PRF again."""
        ore = ORE()
        calls = []
        original_prf = ore._prf

        def counting_prf(subkey, data):
            calls.append(data)
            return original_prf(subkey, data)

        monkeypatch.setattr(ore, "_prf", counting_prf)
        first = ore.encrypt_int(5000)
        assert len(calls) == 2 * ORE.NUM_BLOCKS
        assert ore.encrypt_int(5000) == first
        assert len(calls) == 2 * ORE.NUM_BLOCKS

    def test_evicted_value_is_recomputed_identically(self):
        ore = ORE(cache_size=1)
        first = ore.encrypt_int(7)
        ore.encrypt_int(8)  # evicts 7
        assert 7 not in ore._cache
        assert ore.encrypt_int(7) == first


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
        assert ORE.ALGORITHM == "ore-clww-prototype"

    def test_plaintext_range(self):
        """Test plaintext space constants."""
        assert ORE.PLAINTEXT_BITS == 32
        assert ORE.PLAINTEXT_MAX == 2**32 - 1


class TestOREProperties:
    """Property tests: ORE comparison agrees with plaintext ordering."""

    ORE_INSTANCE = ORE(key=bytes(range(32)))

    @settings(max_examples=50, deadline=None)
    @given(
        a=st.integers(min_value=0, max_value=ORE.PLAINTEXT_MAX),
        b=st.integers(min_value=0, max_value=ORE.PLAINTEXT_MAX),
    )
    def test_compare_matches_integer_order(self, a, b):
        ore = self.ORE_INSTANCE
        expected = (a > b) - (a < b)
        assert ore.compare(ore.encrypt_int(a), ore.encrypt_int(b)) == expected
        assert ore.compare(ore.encrypt_int(b), ore.encrypt_int(a)) == -expected

    @settings(max_examples=50, deadline=None)
    @given(
        a=st.integers(min_value=0, max_value=ORE.PLAINTEXT_MAX),
        shared_prefix_blocks=st.integers(min_value=0, max_value=ORE.NUM_BLOCKS - 1),
        low_bits=st.integers(min_value=0, max_value=ORE.PLAINTEXT_MAX),
    )
    def test_compare_matches_order_for_shared_prefixes(self, a, shared_prefix_blocks, low_bits):
        """Values sharing leading blocks exercise the later-block comparison path."""
        shift = ORE.PLAINTEXT_BITS - shared_prefix_blocks * ORE.BLOCK_BITS
        mask = (1 << shift) - 1
        b = (a & ~mask) | (low_bits & mask)
        ore = self.ORE_INSTANCE
        expected = (a > b) - (a < b)
        assert ore.compare(ore.encrypt_int(a), ore.encrypt_int(b)) == expected

    @settings(max_examples=50, deadline=None)
    @given(
        a=st.decimals(min_value=0, max_value=42_949_672, places=2),
        b=st.decimals(min_value=0, max_value=42_949_672, places=2),
    )
    def test_amount_compare_matches_decimal_order(self, a, b):
        ore = self.ORE_INSTANCE
        expected = (a > b) - (a < b)
        assert ore.compare(ore.encrypt_amount(a), ore.encrypt_amount(b)) == expected
