"""
Benchmarking Suite for Encrypted Information Retrieval

Measures encrypt/decrypt throughput, search latency, and HE operation times
across different data sizes. Validates README performance claims:

| Encryption Type   | Claimed Slowdown vs Plaintext |
|-------------------|-------------------------------|
| Deterministic     | 2-5x                         |
| Searchable        | 10-50x                       |
| Order-Preserving  | 5-30x                        |
| Homomorphic       | 1000-10000x                  |

Run with: make bench
Or:       PYTHONPATH=src:$PYTHONPATH pytest tests/test_benchmarks.py --benchmark-only
"""

import os
import time
import hashlib
import hmac

import pytest

from encrypted_ir.deterministic import DeterministicEncryption
from encrypted_ir.searchable import SearchableEncryption
from encrypted_ir.ore import ORE
from encrypted_ir.homomorphic import BasicHomomorphicEncryption
from encrypted_ir.blind_index import BlindIndexGenerator, BlindIndexConfig, BlindIndexSearch


# ---------------------------------------------------------------------------
# Test data generators
# ---------------------------------------------------------------------------

def _random_string(n: int) -> str:
    """Generate a random ASCII string of length n."""
    return os.urandom(n).hex()[:n]


SMALL_TEXT = "account-12345"
MEDIUM_TEXT = "The quarterly financial report shows strong growth in all sectors " * 10
LARGE_TEXT = "Transaction record with detailed metadata and audit trail information " * 100

SAMPLE_DOCUMENT = (
    "The quarterly financial report for Q4 2025 shows strong revenue growth. "
    "Net income increased by 15 percent compared to the previous quarter. "
    "Risk assessment indicates stable market conditions with moderate volatility. "
    "The compliance team completed all regulatory audits successfully. "
    "Investment portfolio performance exceeded benchmark returns by 3 percent."
)

SAMPLE_INTEGERS = [100, 1000, 10000, 100000, 1000000, 42949672]


# ===========================================================================
# Plaintext Baselines
# ===========================================================================

class TestPlaintextBaselines:
    """Plaintext operation baselines for measuring encryption overhead."""

    @pytest.mark.benchmark(group="baseline-hash")
    def test_sha256_small(self, benchmark):
        """Baseline: SHA-256 hash of small data."""
        data = SMALL_TEXT.encode()
        benchmark(hashlib.sha256, data)

    @pytest.mark.benchmark(group="baseline-hash")
    def test_sha256_medium(self, benchmark):
        """Baseline: SHA-256 hash of medium data."""
        data = MEDIUM_TEXT.encode()
        benchmark(hashlib.sha256, data)

    @pytest.mark.benchmark(group="baseline-hash")
    def test_sha256_large(self, benchmark):
        """Baseline: SHA-256 hash of large data."""
        data = LARGE_TEXT.encode()
        benchmark(hashlib.sha256, data)

    @pytest.mark.benchmark(group="baseline-hmac")
    def test_hmac_sha256(self, benchmark):
        """Baseline: HMAC-SHA256 (used by searchable/blind index)."""
        key = os.urandom(32)
        data = SMALL_TEXT.encode()
        benchmark(hmac.new, key, data, hashlib.sha256)

    @pytest.mark.benchmark(group="baseline-comparison")
    def test_plaintext_equality(self, benchmark):
        """Baseline: Plaintext string equality comparison."""
        a = "account-12345"
        b = "account-12345"
        benchmark(lambda: a == b)

    @pytest.mark.benchmark(group="baseline-comparison")
    def test_plaintext_integer_compare(self, benchmark):
        """Baseline: Plaintext integer comparison."""
        a, b = 50000, 75000
        benchmark(lambda: a < b)

    @pytest.mark.benchmark(group="baseline-arithmetic")
    def test_plaintext_addition(self, benchmark):
        """Baseline: Plaintext float addition."""
        a, b = 50000.50, 75000.25
        benchmark(lambda: a + b)

    @pytest.mark.benchmark(group="baseline-arithmetic")
    def test_plaintext_multiplication(self, benchmark):
        """Baseline: Plaintext float multiplication."""
        a, b = 50000.50, 0.035
        benchmark(lambda: a * b)

    @pytest.mark.benchmark(group="baseline-search")
    def test_plaintext_keyword_search(self, benchmark):
        """Baseline: Plaintext substring search in document."""
        doc = SAMPLE_DOCUMENT
        benchmark(lambda: "quarterly" in doc)


# ===========================================================================
# Deterministic Encryption Benchmarks
# ===========================================================================

class TestDeterministicBenchmarks:
    """Benchmarks for AES-SIV deterministic encryption (claimed 2-5x slower)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.enc = DeterministicEncryption()

    # -- Encrypt --

    @pytest.mark.benchmark(group="deterministic-encrypt")
    def test_encrypt_small(self, benchmark):
        """Deterministic encrypt: 13-byte account number."""
        benchmark(self.enc.encrypt, SMALL_TEXT)

    @pytest.mark.benchmark(group="deterministic-encrypt")
    def test_encrypt_medium(self, benchmark):
        """Deterministic encrypt: ~650-byte text."""
        benchmark(self.enc.encrypt, MEDIUM_TEXT)

    @pytest.mark.benchmark(group="deterministic-encrypt")
    def test_encrypt_large(self, benchmark):
        """Deterministic encrypt: ~7KB text."""
        benchmark(self.enc.encrypt, LARGE_TEXT)

    # -- Decrypt --

    @pytest.mark.benchmark(group="deterministic-decrypt")
    def test_decrypt_small(self, benchmark):
        """Deterministic decrypt: small ciphertext."""
        ct = self.enc.encrypt(SMALL_TEXT)
        benchmark(self.enc.decrypt, ct)

    @pytest.mark.benchmark(group="deterministic-decrypt")
    def test_decrypt_medium(self, benchmark):
        """Deterministic decrypt: medium ciphertext."""
        ct = self.enc.encrypt(MEDIUM_TEXT)
        benchmark(self.enc.decrypt, ct)

    @pytest.mark.benchmark(group="deterministic-decrypt")
    def test_decrypt_large(self, benchmark):
        """Deterministic decrypt: large ciphertext."""
        ct = self.enc.encrypt(LARGE_TEXT)
        benchmark(self.enc.decrypt, ct)

    # -- Search index --

    @pytest.mark.benchmark(group="deterministic-search")
    def test_search_index(self, benchmark):
        """Deterministic: create searchable index (encrypt + base64)."""
        benchmark(self.enc.search_index, SMALL_TEXT)

    @pytest.mark.benchmark(group="deterministic-search")
    def test_search_equality_check(self, benchmark):
        """Deterministic: equality check via index comparison."""
        idx1 = self.enc.search_index("account-12345")
        idx2 = self.enc.search_index("account-12345")
        benchmark(lambda: idx1 == idx2)

    # -- Key derivation --

    @pytest.mark.benchmark(group="deterministic-keygen")
    def test_key_generation(self, benchmark):
        """Deterministic: key generation (AES-SIV 512-bit)."""
        benchmark(DeterministicEncryption.generate_key)

    @pytest.mark.benchmark(group="deterministic-keygen")
    @pytest.mark.slow
    def test_key_derivation_pbkdf2(self, benchmark):
        """Deterministic: PBKDF2 key derivation (480k iterations)."""
        salt = os.urandom(32)
        benchmark.pedantic(
            DeterministicEncryption.derive_key,
            args=("my-secure-password",),
            kwargs={"salt": salt},
            rounds=3,
            iterations=1,
        )

    # -- Roundtrip --

    @pytest.mark.benchmark(group="deterministic-roundtrip")
    def test_roundtrip_small(self, benchmark):
        """Deterministic: full encrypt-decrypt roundtrip (small)."""

        def roundtrip():
            ct = self.enc.encrypt(SMALL_TEXT)
            return self.enc.decrypt(ct)

        benchmark(roundtrip)


# ===========================================================================
# Searchable Encryption Benchmarks
# ===========================================================================

class TestSearchableBenchmarks:
    """Benchmarks for searchable symmetric encryption (claimed 10-50x slower)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.enc = SearchableEncryption()

    # -- Document encryption --

    @pytest.mark.benchmark(group="searchable-encrypt")
    def test_encrypt_short_document(self, benchmark):
        """Searchable encrypt: short document (~50 words)."""
        doc = SAMPLE_DOCUMENT[:200]
        benchmark(self.enc.encrypt_document, doc)

    @pytest.mark.benchmark(group="searchable-encrypt")
    def test_encrypt_medium_document(self, benchmark):
        """Searchable encrypt: medium document (~100 words)."""
        benchmark(self.enc.encrypt_document, SAMPLE_DOCUMENT)

    @pytest.mark.benchmark(group="searchable-encrypt")
    def test_encrypt_large_document(self, benchmark):
        """Searchable encrypt: large document (~500 words)."""
        large_doc = SAMPLE_DOCUMENT * 5
        benchmark(self.enc.encrypt_document, large_doc)

    # -- Document decryption --

    @pytest.mark.benchmark(group="searchable-decrypt")
    def test_decrypt_document(self, benchmark):
        """Searchable decrypt: medium document."""
        enc_doc, _ = self.enc.encrypt_document(SAMPLE_DOCUMENT)
        benchmark(self.enc.decrypt_document, enc_doc)

    # -- Search token generation --

    @pytest.mark.benchmark(group="searchable-search")
    def test_generate_search_token(self, benchmark):
        """Searchable: generate single search token."""
        benchmark(self.enc.generate_search_query, "quarterly")

    @pytest.mark.benchmark(group="searchable-search")
    def test_single_keyword_search(self, benchmark):
        """Searchable: single keyword search against document tokens."""
        _, tokens = self.enc.encrypt_document(SAMPLE_DOCUMENT)
        query = self.enc.generate_search_query("quarterly")
        benchmark(self.enc.search, query, tokens)

    # -- Boolean search --

    @pytest.mark.benchmark(group="searchable-boolean")
    def test_boolean_and_search(self, benchmark):
        """Searchable: boolean AND search (2 keywords)."""
        _, tokens = self.enc.encrypt_document(SAMPLE_DOCUMENT)
        query = self.enc.boolean_search_query(["quarterly", "revenue"], "AND")
        benchmark(self.enc.boolean_search, query, tokens)

    @pytest.mark.benchmark(group="searchable-boolean")
    def test_boolean_or_search(self, benchmark):
        """Searchable: boolean OR search (3 keywords)."""
        _, tokens = self.enc.encrypt_document(SAMPLE_DOCUMENT)
        query = self.enc.boolean_search_query(["quarterly", "compliance", "risk"], "OR")
        benchmark(self.enc.boolean_search, query, tokens)

    # -- Multi-document search --

    @pytest.mark.benchmark(group="searchable-multi")
    def test_search_across_10_documents(self, benchmark):
        """Searchable: search keyword across 10 encrypted documents."""
        docs = []
        for i in range(10):
            _, tokens = self.enc.encrypt_document(
                f"Document {i}: " + SAMPLE_DOCUMENT
            )
            docs.append(tokens)
        query = self.enc.generate_search_query("quarterly")

        def search_all():
            return [self.enc.search(query, t) for t in docs]

        benchmark(search_all)

    @pytest.mark.benchmark(group="searchable-multi")
    def test_search_across_100_documents(self, benchmark):
        """Searchable: search keyword across 100 encrypted documents."""
        docs = []
        for i in range(100):
            _, tokens = self.enc.encrypt_document(
                f"Document {i}: " + SAMPLE_DOCUMENT
            )
            docs.append(tokens)
        query = self.enc.generate_search_query("quarterly")

        def search_all():
            return [self.enc.search(query, t) for t in docs]

        benchmark(search_all)

    # -- Encrypt + search roundtrip --

    @pytest.mark.benchmark(group="searchable-roundtrip")
    def test_encrypt_and_search_roundtrip(self, benchmark):
        """Searchable: full encrypt-document-then-search roundtrip."""

        def roundtrip():
            _, tokens = self.enc.encrypt_document(SAMPLE_DOCUMENT)
            query = self.enc.generate_search_query("quarterly")
            return self.enc.search(query, tokens)

        benchmark(roundtrip)


# ===========================================================================
# Order-Revealing Encryption (ORE) Benchmarks
# ===========================================================================

class TestOREBenchmarks:
    """Benchmarks for Lewi-Wu ORE (replaces deprecated OPE, claimed 5-30x slower)."""

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
# Blind Index Benchmarks
# ===========================================================================

class TestBlindIndexBenchmarks:
    """Benchmarks for HMAC-based blind indexes."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.master_key = os.urandom(32)
        self.gen = BlindIndexGenerator("tenant_1", self.master_key)
        self.config = BlindIndexConfig(field_name="account_number")
        self.email_config = BlindIndexConfig(
            field_name="email", case_sensitive=False, output_length=16
        )

    # -- Index creation --

    @pytest.mark.benchmark(group="blind-index-create")
    def test_create_index(self, benchmark):
        """Blind index: create single index."""
        benchmark(self.gen.create_index, "ACC-12345", self.config)

    @pytest.mark.benchmark(group="blind-index-create")
    def test_create_index_email(self, benchmark):
        """Blind index: create index for email (with normalization)."""
        benchmark(self.gen.create_index, "User@Example.COM", self.email_config)

    @pytest.mark.benchmark(group="blind-index-create")
    def test_create_index_raw(self, benchmark):
        """Blind index: create raw bytes index (no base64)."""
        benchmark(self.gen.create_index_raw, "ACC-12345", self.config)

    # -- Verification --

    @pytest.mark.benchmark(group="blind-index-verify")
    def test_verify_index(self, benchmark):
        """Blind index: verify an index matches a value."""
        idx = self.gen.create_index("ACC-12345", self.config)
        benchmark(self.gen.verify_index, "ACC-12345", idx, self.config)

    # -- Search --

    @pytest.mark.benchmark(group="blind-index-search")
    def test_search_10_records(self, benchmark):
        """Blind index: search across 10 indexed records."""
        search = BlindIndexSearch("tenant_1", self.master_key)
        records = {
            f"rec_{i}": {"account_number": f"ACC-{10000 + i}"}
            for i in range(10)
        }
        index_map = search.index_records(records, "account_number", self.config)
        benchmark(search.search, "ACC-10005", index_map, self.config)

    @pytest.mark.benchmark(group="blind-index-search")
    def test_search_100_records(self, benchmark):
        """Blind index: search across 100 indexed records."""
        search = BlindIndexSearch("tenant_1", self.master_key)
        records = {
            f"rec_{i}": {"account_number": f"ACC-{10000 + i}"}
            for i in range(100)
        }
        index_map = search.index_records(records, "account_number", self.config)
        benchmark(search.search, "ACC-10050", index_map, self.config)

    @pytest.mark.benchmark(group="blind-index-search")
    def test_search_1000_records(self, benchmark):
        """Blind index: search across 1000 indexed records."""
        search = BlindIndexSearch("tenant_1", self.master_key)
        records = {
            f"rec_{i}": {"account_number": f"ACC-{10000 + i}"}
            for i in range(1000)
        }
        index_map = search.index_records(records, "account_number", self.config)
        benchmark(search.search, "ACC-10500", index_map, self.config)

    # -- Batch indexing --

    @pytest.mark.benchmark(group="blind-index-batch")
    def test_index_100_records(self, benchmark):
        """Blind index: batch index 100 records."""
        search = BlindIndexSearch("tenant_1", self.master_key)
        records = {
            f"rec_{i}": {"account_number": f"ACC-{10000 + i}"}
            for i in range(100)
        }
        benchmark(search.index_records, records, "account_number", self.config)

    # -- Multi-tenant isolation --

    @pytest.mark.benchmark(group="blind-index-tenant")
    def test_cross_tenant_index(self, benchmark):
        """Blind index: index creation across different tenants."""

        def create_two_tenant_indexes():
            gen1 = BlindIndexGenerator("tenant_1", self.master_key)
            gen2 = BlindIndexGenerator("tenant_2", self.master_key)
            idx1 = gen1.create_index("ACC-12345", self.config)
            idx2 = gen2.create_index("ACC-12345", self.config)
            return idx1, idx2

        benchmark(create_two_tenant_indexes)


# ===========================================================================
# Integration Benchmarks (Use Cases)
# ===========================================================================

class TestUseCasesBenchmarks:
    """End-to-end benchmarks for financial services use cases."""

    # -- Credit scoring (HE-based) --

    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_encrypt_data(self, benchmark):
        """Use case: encrypt financial data for credit scoring."""
        from encrypted_ir.use_cases import CreditScoring

        scorer = CreditScoring()
        benchmark(scorer.encrypt_financial_data, 85000.0, 25000.0, 60)

    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_calculate(self, benchmark):
        """Use case: calculate credit score on encrypted data."""
        from encrypted_ir.use_cases import CreditScoring

        scorer = CreditScoring()
        encrypted_data = scorer.encrypt_financial_data(85000.0, 25000.0, 60)
        benchmark(scorer.calculate_credit_score, encrypted_data)

    @pytest.mark.benchmark(group="usecase-credit")
    def test_credit_score_full_pipeline(self, benchmark):
        """Use case: full credit scoring pipeline (encrypt + calculate)."""
        from encrypted_ir.use_cases import CreditScoring

        scorer = CreditScoring()

        def full_pipeline():
            data = scorer.encrypt_financial_data(85000.0, 25000.0, 60)
            return scorer.calculate_credit_score(data)

        benchmark(full_pipeline)

    # -- Document search --

    @pytest.mark.benchmark(group="usecase-docsearch")
    def test_docsearch_encrypt_and_search(self, benchmark):
        """Use case: encrypt 5 documents then keyword search."""
        from encrypted_ir.use_cases import DocumentSearch
        from encrypted_ir.key_manager import KeyManager

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
        from encrypted_ir.use_cases import DocumentSearch
        from encrypted_ir.key_manager import KeyManager

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
# Throughput Benchmarks (operations per second)
# ===========================================================================

class TestThroughputBenchmarks:
    """Throughput-oriented benchmarks measuring operations per second."""

    @pytest.mark.benchmark(group="throughput")
    def test_deterministic_encrypt_throughput(self, benchmark):
        """Throughput: deterministic encryptions per iteration (batch of 100)."""
        enc = DeterministicEncryption()
        accounts = [f"ACC-{10000 + i}" for i in range(100)]

        def encrypt_batch():
            return [enc.encrypt(a) for a in accounts]

        benchmark(encrypt_batch)

    @pytest.mark.benchmark(group="throughput")
    def test_searchable_token_throughput(self, benchmark):
        """Throughput: search token generations per iteration (batch of 100)."""
        enc = SearchableEncryption()
        keywords = [f"keyword_{i}" for i in range(100)]

        def generate_tokens():
            return [enc.generate_search_query(kw) for kw in keywords]

        benchmark(generate_tokens)

    @pytest.mark.benchmark(group="throughput")
    def test_ore_encrypt_throughput(self, benchmark):
        """Throughput: ORE encryptions per iteration (batch of 100)."""
        ore = ORE()

        def encrypt_batch():
            ore.clear_cache()
            return [ore.encrypt_int(i * 100) for i in range(100)]

        benchmark(encrypt_batch)

    @pytest.mark.benchmark(group="throughput")
    def test_blind_index_throughput(self, benchmark):
        """Throughput: blind index creations per iteration (batch of 100)."""
        gen = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="account")
        values = [f"ACC-{10000 + i}" for i in range(100)]

        def index_batch():
            return [gen.create_index(v, config) for v in values]

        benchmark(index_batch)
