"""
Benchmarks for the research prototypes: ORE, CKKS (TenSEAL) and the use-case demos.

CKKS benchmarks skip unless the research extra is installed.

Run with: make bench
Or:       PYTHONPATH=src pytest benchmarks/ --benchmark-only
"""

import pytest

from encrypted_ir.research.ore import ORE

try:
    from encrypted_ir.research.homomorphic import BasicHomomorphicEncryption
except ImportError:
    BasicHomomorphicEncryption = None

# ===========================================================================
# Order-Revealing Encryption (ORE) Benchmarks
# ===========================================================================


class TestOREBenchmarks:
    """Benchmarks for the CLWW-style ORE prototype."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.ore = ORE()

    # -- Encrypt --

    @pytest.mark.benchmark(group="ore-encrypt")
    def test_encrypt_small_int(self, benchmark):
        """ORE encrypt: small integer (100)."""

        # Clear cache each iteration to measure real encryption
        def encrypt():
            self.ore.clear_cache()
            return self.ore.encrypt_int(100)

        benchmark(encrypt)

    @pytest.mark.benchmark(group="ore-encrypt")
    def test_encrypt_medium_int(self, benchmark):
        """ORE encrypt: medium integer (1,000,000)."""

        def encrypt():
            self.ore.clear_cache()
            return self.ore.encrypt_int(1000000)

        benchmark(encrypt)

    @pytest.mark.benchmark(group="ore-encrypt")
    def test_encrypt_large_int(self, benchmark):
        """ORE encrypt: large integer (max 2^32-1)."""

        def encrypt():
            self.ore.clear_cache()
            return self.ore.encrypt_int(2**32 - 1)

        benchmark(encrypt)

    @pytest.mark.benchmark(group="ore-encrypt")
    def test_encrypt_amount(self, benchmark):
        """ORE encrypt: monetary amount (1234.56)."""

        def encrypt():
            self.ore.clear_cache()
            return self.ore.encrypt_amount(1234.56)

        benchmark(encrypt)

    # -- Compare --

    @pytest.mark.benchmark(group="ore-compare")
    def test_compare_two_values(self, benchmark):
        """ORE compare: pairwise comparison of two ciphertexts."""
        ct1 = self.ore.encrypt_int(50000)
        ct2 = self.ore.encrypt_int(75000)
        benchmark(self.ore.compare, ct1, ct2)

    @pytest.mark.benchmark(group="ore-compare")
    def test_compare_equal_values(self, benchmark):
        """ORE compare: comparison of equal ciphertexts."""
        ct1 = self.ore.encrypt_int(50000)
        ct2 = self.ore.encrypt_int(50000)
        benchmark(self.ore.compare, ct1, ct2)

    # -- Range query --

    @pytest.mark.benchmark(group="ore-range")
    def test_range_query_10_values(self, benchmark):
        """ORE range query: filter 10 encrypted values."""
        values = [self.ore.encrypt_int(i * 1000) for i in range(10)]
        min_ct = self.ore.encrypt_int(3000)
        max_ct = self.ore.encrypt_int(7000)
        benchmark(self.ore.range_query, values, min_ct, max_ct)

    @pytest.mark.benchmark(group="ore-range")
    def test_range_query_100_values(self, benchmark):
        """ORE range query: filter 100 encrypted values."""
        values = [self.ore.encrypt_int(i * 100) for i in range(100)]
        min_ct = self.ore.encrypt_int(3000)
        max_ct = self.ore.encrypt_int(7000)
        benchmark(self.ore.range_query, values, min_ct, max_ct)

    @pytest.mark.benchmark(group="ore-range")
    def test_range_query_1000_values(self, benchmark):
        """ORE range query: filter 1000 encrypted values."""
        values = [self.ore.encrypt_int(i * 10) for i in range(1000)]
        min_ct = self.ore.encrypt_int(3000)
        max_ct = self.ore.encrypt_int(7000)
        benchmark(self.ore.range_query, values, min_ct, max_ct)

    # -- Batch encryption --

    @pytest.mark.benchmark(group="ore-batch")
    def test_encrypt_batch_10(self, benchmark):
        """ORE batch encrypt: 10 integers."""

        def encrypt_batch():
            ore = ORE(self.ore.key)
            return [ore.encrypt_int(i * 1000) for i in range(10)]

        benchmark(encrypt_batch)

    @pytest.mark.benchmark(group="ore-batch")
    def test_encrypt_batch_100(self, benchmark):
        """ORE batch encrypt: 100 integers."""

        def encrypt_batch():
            ore = ORE(self.ore.key)
            return [ore.encrypt_int(i * 100) for i in range(100)]

        benchmark(encrypt_batch)

    # -- Cache effect --

    @pytest.mark.benchmark(group="ore-cache")
    def test_encrypt_cached(self, benchmark):
        """ORE encrypt: cached (repeated encryption of same value)."""
        self.ore.encrypt_int(50000)  # Prime cache
        benchmark(self.ore.encrypt_int, 50000)

    @pytest.mark.benchmark(group="ore-cache")
    def test_encrypt_uncached(self, benchmark):
        """ORE encrypt: uncached (fresh encryption each time)."""

        def encrypt():
            self.ore.clear_cache()
            return self.ore.encrypt_int(50000)

        benchmark(encrypt)


# ===========================================================================
# Homomorphic Encryption Benchmarks
# ===========================================================================


@pytest.mark.skipif(
    BasicHomomorphicEncryption is None,
    reason="TenSEAL is an optional research dependency",
)
class TestHomomorphicBenchmarks:
    """Benchmarks for CKKS homomorphic encryption (claimed 1000-10000x slower)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.he = BasicHomomorphicEncryption()

    # -- Encrypt --

    @pytest.mark.benchmark(group="he-encrypt")
    def test_encrypt_single_value(self, benchmark):
        """HE encrypt: single float value."""
        benchmark(self.he.encrypt_value, 42.5)

    @pytest.mark.benchmark(group="he-encrypt")
    def test_encrypt_vector_10(self, benchmark):
        """HE encrypt: vector of 10 values."""
        values = [float(i) for i in range(10)]
        benchmark(self.he.encrypt_vector, values)

    @pytest.mark.benchmark(group="he-encrypt")
    def test_encrypt_vector_100(self, benchmark):
        """HE encrypt: vector of 100 values."""
        values = [float(i) for i in range(100)]
        benchmark(self.he.encrypt_vector, values)

    @pytest.mark.benchmark(group="he-encrypt")
    def test_encrypt_vector_1000(self, benchmark):
        """HE encrypt: vector of 1000 values."""
        values = [float(i) for i in range(1000)]
        benchmark(self.he.encrypt_vector, values)

    # -- Decrypt --

    @pytest.mark.benchmark(group="he-decrypt")
    def test_decrypt_single_value(self, benchmark):
        """HE decrypt: single encrypted value."""
        enc = self.he.encrypt_value(42.5)
        benchmark(self.he.decrypt_value, enc)

    @pytest.mark.benchmark(group="he-decrypt")
    def test_decrypt_vector_100(self, benchmark):
        """HE decrypt: vector of 100 values."""
        enc = self.he.encrypt_vector([float(i) for i in range(100)])
        benchmark(self.he.decrypt_vector, enc)

    # -- Arithmetic operations --

    @pytest.mark.benchmark(group="he-arithmetic")
    def test_add_encrypted(self, benchmark):
        """HE arithmetic: encrypted + encrypted addition."""
        enc1 = self.he.encrypt_value(42.5)
        enc2 = self.he.encrypt_value(17.3)
        benchmark(self.he.add_encrypted, enc1, enc2)

    @pytest.mark.benchmark(group="he-arithmetic")
    def test_add_plain(self, benchmark):
        """HE arithmetic: encrypted + plaintext addition."""
        enc = self.he.encrypt_value(42.5)
        benchmark(self.he.add_plain, enc, 17.3)

    @pytest.mark.benchmark(group="he-arithmetic")
    def test_multiply_encrypted(self, benchmark):
        """HE arithmetic: encrypted * encrypted multiplication."""
        enc1 = self.he.encrypt_value(42.5)
        enc2 = self.he.encrypt_value(3.0)
        benchmark(self.he.multiply_encrypted, enc1, enc2)

    @pytest.mark.benchmark(group="he-arithmetic")
    def test_multiply_plain(self, benchmark):
        """HE arithmetic: encrypted * plaintext multiplication."""
        enc = self.he.encrypt_value(42.5)
        benchmark(self.he.multiply_plain, enc, 3.0)

    @pytest.mark.benchmark(group="he-arithmetic")
    def test_subtract_encrypted(self, benchmark):
        """HE arithmetic: encrypted - encrypted subtraction."""
        enc1 = self.he.encrypt_value(42.5)
        enc2 = self.he.encrypt_value(17.3)
        benchmark(self.he.subtract_encrypted, enc1, enc2)

    # -- Vector operations --

    @pytest.mark.benchmark(group="he-vector")
    def test_dot_product_10(self, benchmark):
        """HE vector: dot product of two 10-element vectors."""
        v1 = self.he.encrypt_vector([float(i) for i in range(10)])
        v2 = self.he.encrypt_vector([float(i) * 0.1 for i in range(10)])
        benchmark(self.he.dot_product, v1, v2)

    @pytest.mark.benchmark(group="he-vector")
    def test_weighted_sum_10(self, benchmark):
        """HE vector: weighted sum of 10-element vector."""
        enc = self.he.encrypt_vector([float(i) for i in range(10)])
        weights = [0.1] * 10
        benchmark(self.he.weighted_sum, enc, weights)

    # -- Serialization --

    @pytest.mark.benchmark(group="he-serialization")
    def test_serialize_encrypted(self, benchmark):
        """HE serialization: serialize single encrypted value."""
        enc = self.he.encrypt_value(42.5)
        benchmark(self.he.serialize_encrypted, enc)

    @pytest.mark.benchmark(group="he-serialization")
    def test_deserialize_encrypted(self, benchmark):
        """HE serialization: deserialize single encrypted value."""
        enc = self.he.encrypt_value(42.5)
        data = self.he.serialize_encrypted(enc)
        benchmark(self.he.deserialize_encrypted, data)

    # -- Roundtrip --

    @pytest.mark.benchmark(group="he-roundtrip")
    def test_encrypt_add_decrypt_roundtrip(self, benchmark):
        """HE roundtrip: encrypt two values, add, decrypt."""

        def roundtrip():
            e1 = self.he.encrypt_value(42.5)
            e2 = self.he.encrypt_value(17.3)
            result = self.he.add_encrypted(e1, e2)
            return self.he.decrypt_value(result)

        benchmark(roundtrip)

    @pytest.mark.benchmark(group="he-roundtrip")
    def test_encrypt_multiply_decrypt_roundtrip(self, benchmark):
        """HE roundtrip: encrypt two values, multiply, decrypt."""

        def roundtrip():
            e1 = self.he.encrypt_value(42.5)
            e2 = self.he.encrypt_value(3.0)
            result = self.he.multiply_encrypted(e1, e2)
            return self.he.decrypt_value(result)

        benchmark(roundtrip)

    # -- Context creation (one-time cost) --

    @pytest.mark.benchmark(group="he-setup")
    def test_context_creation(self, benchmark):
        """HE setup: create CKKS context with key generation."""
        benchmark.pedantic(
            BasicHomomorphicEncryption,
            rounds=5,
            iterations=1,
        )


# ===========================================================================
# Integration Benchmarks (Use Cases)
# ===========================================================================


class TestUseCasesBenchmarks:
    """End-to-end benchmarks for financial services use cases."""

    # -- Credit scoring (HE-based) --

    @pytest.mark.skipif(
        BasicHomomorphicEncryption is None,
        reason="TenSEAL is an optional research dependency",
    )
    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_encrypt_data(self, benchmark):
        """Use case: encrypt financial data for credit scoring."""
        from encrypted_ir.research.use_cases import CreditScoring

        scorer = CreditScoring()
        benchmark(scorer.encrypt_financial_data, 85000.0, 25000.0, 60)

    @pytest.mark.skipif(
        BasicHomomorphicEncryption is None,
        reason="TenSEAL is an optional research dependency",
    )
    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_calculate(self, benchmark):
        """Use case: calculate credit score on encrypted data."""
        from encrypted_ir.research.use_cases import CreditScoring

        scorer = CreditScoring()
        encrypted_data = scorer.encrypt_financial_data(85000.0, 25000.0, 60)
        benchmark(scorer.calculate_credit_score, encrypted_data)

    @pytest.mark.skipif(
        BasicHomomorphicEncryption is None,
        reason="TenSEAL is an optional research dependency",
    )
    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_full_pipeline(self, benchmark):
        """Use case: full credit scoring pipeline (encrypt + calculate)."""
        from encrypted_ir.research.use_cases import CreditScoring

        scorer = CreditScoring()

        def full_pipeline():
            data = scorer.encrypt_financial_data(85000.0, 25000.0, 60)
            return scorer.calculate_credit_score(data)

        benchmark(full_pipeline)

    # -- Document search --

    @pytest.mark.benchmark(group="usecase-docsearch")
    def test_docsearch_encrypt_and_search(self, benchmark):
        """Use case: encrypt 5 documents then keyword search."""
        from encrypted_ir.key_manager import KeyManager
        from encrypted_ir.research.use_cases import DocumentSearch

        km = KeyManager()
        ds = DocumentSearch(km)

        docs = [
            "Quarterly financial report shows revenue growth in Q4",
            "Risk assessment indicates stable market conditions",
            "Compliance audit completed for regulatory requirements",
            "Investment portfolio exceeded benchmark returns by 3 percent",
            "Annual report summarizes quarterly performance metrics",
        ]
        for i, doc in enumerate(docs):
            ds.encrypt_document(f"doc_{i}", doc)

        benchmark(ds.search_documents, "quarterly")

    @pytest.mark.benchmark(group="usecase-docsearch")
    def test_docsearch_boolean_search(self, benchmark):
        """Use case: boolean AND search across encrypted documents."""
        from encrypted_ir.key_manager import KeyManager
        from encrypted_ir.research.use_cases import DocumentSearch

        km = KeyManager()
        ds = DocumentSearch(km)

        docs = [
            "Quarterly financial report shows strong revenue growth",
            "Risk assessment and compliance audit results",
            "Investment portfolio quarterly review with risk analysis",
        ]
        for i, doc in enumerate(docs):
            ds.encrypt_document(f"doc_{i}", doc)

        benchmark(ds.boolean_search_documents, ["quarterly", "risk"], "AND")


# ===========================================================================
# Throughput Benchmarks
# ===========================================================================


class TestResearchThroughputBenchmarks:
    """Throughput benchmarks for research prototypes."""

    @pytest.mark.benchmark(group="throughput")
    def test_ore_encrypt_throughput(self, benchmark):
        """Throughput: ORE encryptions per iteration (batch of 100)."""
        ore = ORE()

        def encrypt_batch():
            ore.clear_cache()
            return [ore.encrypt_int(i * 100) for i in range(100)]

        benchmark(encrypt_batch)
