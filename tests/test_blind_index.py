"""Tests for blind index module."""

import pytest
from encrypted_ir.blind_index import (
    BlindIndexGenerator,
    BlindIndexConfig,
    BlindIndexSearch,
    create_ssn_index,
    create_email_index,
    create_account_index
)


class TestBlindIndexGenerator:
    """Test blind index generation."""

    def test_master_key_generation(self):
        """Test master key generation."""
        key = BlindIndexGenerator.generate_master_key()
        assert len(key) == 32  # 256 bits

    def test_initialization_with_key(self):
        """Test initialization with provided key."""
        master_key = b"0" * 32
        generator = BlindIndexGenerator("tenant_1", master_key)
        assert generator.tenant_id == "tenant_1"
        assert generator.master_key == master_key

    def test_initialization_without_key(self):
        """Test initialization without key (auto-generate)."""
        generator = BlindIndexGenerator("tenant_1")
        assert len(generator.master_key) == 32

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError, match="32 bytes"):
            BlindIndexGenerator("tenant_1", b"short")

    def test_deterministic_indexing(self):
        """Test that same value produces same index."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        index1 = generator.create_index("value123", config)
        index2 = generator.create_index("value123", config)

        assert index1 == index2

    def test_different_values_different_indexes(self):
        """Test that different values produce different indexes."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        index1 = generator.create_index("value1", config)
        index2 = generator.create_index("value2", config)

        assert index1 != index2

    def test_case_insensitive_default(self):
        """Test that indexing is case-insensitive by default."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="email")

        index1 = generator.create_index("User@Example.Com", config)
        index2 = generator.create_index("user@example.com", config)

        assert index1 == index2

    def test_case_sensitive_mode(self):
        """Test case-sensitive indexing."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="account", case_sensitive=True)

        index1 = generator.create_index("ABC123", config)
        index2 = generator.create_index("abc123", config)

        assert index1 != index2

    def test_unicode_normalization(self):
        """Test Unicode normalization."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="name")

        # "café" with composed vs decomposed accents
        index1 = generator.create_index("café", config)
        index2 = generator.create_index("cafe\u0301", config)  # decomposed

        # Should be equal after NFKC normalization
        assert index1 == index2

    def test_whitespace_handling(self):
        """Test that leading/trailing whitespace is stripped."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        index1 = generator.create_index("  value  ", config)
        index2 = generator.create_index("value", config)

        assert index1 == index2

    def test_different_tenants_different_indexes(self):
        """Test that same value produces different indexes for different tenants."""
        master_key = BlindIndexGenerator.generate_master_key()
        generator1 = BlindIndexGenerator("tenant_1", master_key)
        generator2 = BlindIndexGenerator("tenant_2", master_key)

        config = BlindIndexConfig(field_name="ssn")
        value = "123-45-6789"

        index1 = generator1.create_index(value, config)
        index2 = generator2.create_index(value, config)

        # Different tenants should produce different indexes
        assert index1 != index2

    def test_different_fields_different_indexes(self):
        """Test that same value produces different indexes for different fields."""
        generator = BlindIndexGenerator("tenant_1")

        config1 = BlindIndexConfig(field_name="field1")
        config2 = BlindIndexConfig(field_name="field2")
        value = "test_value"

        index1 = generator.create_index(value, config1)
        index2 = generator.create_index(value, config2)

        assert index1 != index2

    def test_index_length(self):
        """Test custom index length."""
        generator = BlindIndexGenerator("tenant_1")

        config_short = BlindIndexConfig(field_name="test", output_length=8)
        config_long = BlindIndexConfig(field_name="test", output_length=32)

        index_short = generator.create_index_raw("value", config_short)
        index_long = generator.create_index_raw("value", config_long)

        assert len(index_short) == 8
        assert len(index_long) == 32

    def test_create_index_raw(self):
        """Test raw index creation (bytes)."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test", output_length=16)

        index_raw = generator.create_index_raw("value", config)

        assert isinstance(index_raw, bytes)
        assert len(index_raw) == 16

    def test_verify_index(self):
        """Test index verification."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="ssn")

        value = "123-45-6789"
        index = generator.create_index(value, config)

        # Correct value should verify
        assert generator.verify_index(value, index, config) is True

        # Wrong value should not verify
        assert generator.verify_index("987-65-4321", index, config) is False

    def test_key_rotation(self):
        """Test master key rotation."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        # Create index with original key
        index1 = generator.create_index("value", config)

        # Rotate key
        new_key = BlindIndexGenerator.generate_master_key()
        generator.rotate_key(new_key)

        # Same value should now produce different index
        index2 = generator.create_index("value", config)
        assert index1 != index2

    def test_key_rotation_invalid_size(self):
        """Test that invalid key size raises error on rotation."""
        generator = BlindIndexGenerator("tenant_1")

        with pytest.raises(ValueError, match="32 bytes"):
            generator.rotate_key(b"short")

    def test_export_import_master_key(self):
        """Test master key export and import."""
        generator1 = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        # Create index
        value = "test_value"
        index1 = generator1.create_index(value, config)

        # Export key
        key_b64 = generator1.export_master_key()
        assert isinstance(key_b64, str)

        # Import key into new generator
        generator2 = BlindIndexGenerator.import_master_key(key_b64, "tenant_1")

        # Should produce same index
        index2 = generator2.create_index(value, config)
        assert index1 == index2

    def test_field_key_caching(self):
        """Test that field keys are cached."""
        generator = BlindIndexGenerator("tenant_1")

        # Derive field key twice
        key1 = generator._derive_field_key("field1")
        key2 = generator._derive_field_key("field1")

        # Should return same key (from cache)
        assert key1 == key2
        assert key1 is key2  # Same object

    def test_constant_time_verification(self):
        """Test that verify_index uses constant-time comparison."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        value = "test"
        index = generator.create_index(value, config)

        # Verification should be constant-time (uses hmac.compare_digest)
        # This test just ensures it works; timing analysis would be needed for full verification
        assert generator.verify_index(value, index, config) is True


class TestBlindIndexSearch:
    """Test blind index search functionality."""

    def test_index_records(self):
        """Test indexing a set of records."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email")

        records = {
            "rec1": {"email": "alice@example.com", "name": "Alice"},
            "rec2": {"email": "bob@example.com", "name": "Bob"},
            "rec3": {"email": "charlie@example.com", "name": "Charlie"}
        }

        index_map = search.index_records(records, "email", config)

        # Should have 3 indexes
        assert len(index_map) == 3

        # Each index should map to a record
        assert "rec1" in index_map.values()
        assert "rec2" in index_map.values()
        assert "rec3" in index_map.values()

    def test_index_records_missing_field(self):
        """Test indexing records with missing field."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email")

        records = {
            "rec1": {"email": "alice@example.com"},
            "rec2": {"name": "Bob"},  # Missing email
            "rec3": {"email": None}    # Null email
        }

        index_map = search.index_records(records, "email", config)

        # Should only index rec1
        assert len(index_map) == 1
        assert "rec1" in index_map.values()

    def test_search_single_match(self):
        """Test searching for a value."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email")

        records = {
            "rec1": {"email": "alice@example.com"},
            "rec2": {"email": "bob@example.com"}
        }

        index_map = search.index_records(records, "email", config)
        results = search.search("alice@example.com", index_map, config)

        assert len(results) == 1
        assert results[0] == "rec1"

    def test_search_no_match(self):
        """Test searching for non-existent value."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email")

        records = {
            "rec1": {"email": "alice@example.com"},
            "rec2": {"email": "bob@example.com"}
        }

        index_map = search.index_records(records, "email", config)
        results = search.search("nonexistent@example.com", index_map, config)

        assert len(results) == 0

    def test_search_case_insensitive(self):
        """Test case-insensitive search."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email", case_sensitive=False)

        records = {
            "rec1": {"email": "Alice@Example.COM"}
        }

        index_map = search.index_records(records, "email", config)
        results = search.search("alice@example.com", index_map, config)

        assert len(results) == 1
        assert results[0] == "rec1"

    def test_multi_search(self):
        """Test searching for multiple values."""
        search = BlindIndexSearch("tenant_1")
        config = BlindIndexConfig(field_name="email")

        records = {
            "rec1": {"email": "alice@example.com"},
            "rec2": {"email": "bob@example.com"},
            "rec3": {"email": "charlie@example.com"}
        }

        index_map = search.index_records(records, "email", config)
        results = search.multi_search(
            ["alice@example.com", "charlie@example.com", "nonexistent@example.com"],
            index_map,
            config
        )

        assert len(results) == 3
        assert len(results["alice@example.com"]) == 1
        assert len(results["charlie@example.com"]) == 1
        assert len(results["nonexistent@example.com"]) == 0


class TestConvenienceFunctions:
    """Test convenience functions for common use cases."""

    def test_create_ssn_index(self):
        """Test SSN index creation."""
        master_key = BlindIndexGenerator.generate_master_key()

        index1 = create_ssn_index("123-45-6789", "tenant_1", master_key)
        index2 = create_ssn_index("123-45-6789", "tenant_1", master_key)

        # Same SSN should produce same index
        assert index1 == index2

        # Different SSN should produce different index
        index3 = create_ssn_index("987-65-4321", "tenant_1", master_key)
        assert index1 != index3

    def test_create_email_index(self):
        """Test email index creation."""
        master_key = BlindIndexGenerator.generate_master_key()

        index1 = create_email_index("user@example.com", "tenant_1", master_key)
        index2 = create_email_index("user@example.com", "tenant_1", master_key)

        assert index1 == index2

        # Case-insensitive
        index3 = create_email_index("User@Example.COM", "tenant_1", master_key)
        assert index1 == index3

    def test_create_account_index(self):
        """Test account number index creation."""
        master_key = BlindIndexGenerator.generate_master_key()

        index1 = create_account_index("ACC-12345", "tenant_1", master_key)
        index2 = create_account_index("ACC-12345", "tenant_1", master_key)

        assert index1 == index2

        # Case-sensitive for account numbers
        index3 = create_account_index("acc-12345", "tenant_1", master_key)
        assert index1 != index3


class TestSecurityProperties:
    """Test security properties of blind indexes."""

    def test_preimage_resistance(self):
        """Test that index doesn't reveal plaintext."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="ssn")

        ssn = "123-45-6789"
        index = generator.create_index(ssn, config)

        # Index should not contain plaintext
        assert ssn not in index
        assert "123" not in index
        assert "45" not in index
        assert "6789" not in index

    def test_collision_resistance(self):
        """Test collision resistance (different values → different indexes)."""
        generator = BlindIndexGenerator("tenant_1")
        config = BlindIndexConfig(field_name="test")

        # Generate many indexes
        indexes = set()
        for i in range(1000):
            index = generator.create_index(f"value_{i}", config)
            indexes.add(index)

        # Should have 1000 unique indexes (no collisions)
        assert len(indexes) == 1000

    def test_tenant_isolation(self):
        """Test that tenants cannot correlate indexes."""
        master_key = BlindIndexGenerator.generate_master_key()

        generator1 = BlindIndexGenerator("tenant_1", master_key)
        generator2 = BlindIndexGenerator("tenant_2", master_key)

        config = BlindIndexConfig(field_name="ssn")

        # Same SSN in different tenants
        ssn = "123-45-6789"
        index1 = generator1.create_index(ssn, config)
        index2 = generator2.create_index(ssn, config)

        # Indexes should be different (tenant isolation)
        assert index1 != index2

    def test_field_separation(self):
        """Test that different fields produce different indexes."""
        generator = BlindIndexGenerator("tenant_1")

        config_ssn = BlindIndexConfig(field_name="ssn")
        config_phone = BlindIndexConfig(field_name="phone")

        value = "123456789"
        index_ssn = generator.create_index(value, config_ssn)
        index_phone = generator.create_index(value, config_phone)

        # Same value, different fields → different indexes
        assert index_ssn != index_phone
