"""Tests for key management module."""

import pytest
from datetime import datetime, timedelta
from encrypted_ir.key_manager import KeyManager, KeyMetadata


class TestKeyMetadata:
    """Test key metadata functionality."""

    def test_metadata_creation(self):
        """Test metadata creation."""
        metadata = KeyMetadata(
            key_id="test_key_001",
            key_type="deterministic",
            created_at=datetime.now(),
            rotation_period_days=90
        )

        assert metadata.key_id == "test_key_001"
        assert metadata.key_type == "deterministic"
        assert metadata.active is True

    def test_metadata_serialization(self):
        """Test metadata to/from dict."""
        metadata = KeyMetadata(
            key_id="test_key_002",
            key_type="searchable",
            created_at=datetime.now(),
            description="Test key"
        )

        # Convert to dict
        data = metadata.to_dict()
        assert isinstance(data, dict)
        assert data['key_id'] == "test_key_002"

        # Convert back from dict
        metadata2 = KeyMetadata.from_dict(data)
        assert metadata2.key_id == metadata.key_id
        assert metadata2.key_type == metadata.key_type

    def test_needs_rotation(self):
        """Test rotation check."""
        # Create metadata with old rotation date
        metadata = KeyMetadata(
            key_id="test_key_003",
            key_type="ope",
            created_at=datetime.now(),
            rotation_period_days=30
        )

        # Recently created - doesn't need rotation
        assert metadata.needs_rotation() is False

        # Simulate old key
        metadata.last_rotated = datetime.now() - timedelta(days=31)
        assert metadata.needs_rotation() is True

        # Inactive keys don't need rotation
        metadata.active = False
        assert metadata.needs_rotation() is False

    def test_is_expired(self):
        """Test expiration check."""
        # Key without expiration
        metadata = KeyMetadata(
            key_id="test_key_004",
            key_type="deterministic",
            created_at=datetime.now()
        )
        assert metadata.is_expired() is False

        # Key with future expiration
        metadata.expires_at = datetime.now() + timedelta(days=30)
        assert metadata.is_expired() is False

        # Key with past expiration
        metadata.expires_at = datetime.now() - timedelta(days=1)
        assert metadata.is_expired() is True


class TestKeyManager:
    """Test key manager functionality."""

    def test_master_key_generation(self):
        """Test master key generation."""
        master_key = KeyManager.generate_master_key()
        assert len(master_key) == 32

    def test_master_key_derivation(self):
        """Test master key derivation from password."""
        password = "secure_password_123"
        master_key1, salt = KeyManager.derive_master_key(password)

        assert len(master_key1) == 32
        assert len(salt) == 32

        # Same password and salt should produce same key
        master_key2, _ = KeyManager.derive_master_key(password, salt)
        assert master_key1 == master_key2

    def test_key_creation(self):
        """Test key creation."""
        manager = KeyManager()

        key_id = manager.create_key(
            key_type="deterministic",
            key_size=32,
            description="Test encryption key"
        )

        assert key_id is not None
        assert "deterministic" in key_id

    def test_key_retrieval(self):
        """Test key retrieval."""
        manager = KeyManager()

        key_id = manager.create_key("searchable")
        key = manager.get_key(key_id)

        assert key is not None
        assert len(key) == 32

    def test_key_not_found(self):
        """Test retrieving non-existent key."""
        manager = KeyManager()

        with pytest.raises(KeyError):
            manager.get_key("nonexistent_key")

    def test_inactive_key_retrieval(self):
        """Test that inactive keys cannot be retrieved."""
        manager = KeyManager()

        key_id = manager.create_key("ope")
        manager.delete_key(key_id)

        # Should raise error for inactive key
        with pytest.raises(ValueError, match="inactive"):
            manager.get_key(key_id)

    def test_expired_key_retrieval(self):
        """Test that expired keys cannot be retrieved."""
        manager = KeyManager()

        key_id = manager.create_key("deterministic")
        metadata = manager.get_metadata(key_id)

        # Set expiration to past
        metadata.expires_at = datetime.now() - timedelta(days=1)

        with pytest.raises(ValueError, match="expired"):
            manager.get_key(key_id)

    def test_key_rotation(self):
        """Test key rotation."""
        manager = KeyManager()

        old_key_id = manager.create_key("deterministic")
        new_key_id = manager.rotate_key(old_key_id)

        assert new_key_id != old_key_id

        # Old key should be inactive
        old_metadata = manager.get_metadata(old_key_id)
        assert old_metadata.active is False

        # New key should be active
        new_metadata = manager.get_metadata(new_key_id)
        assert new_metadata.active is True

    def test_key_deletion(self):
        """Test key deletion."""
        manager = KeyManager()

        key_id = manager.create_key("searchable")
        manager.delete_key(key_id)

        # Key should be marked inactive
        metadata = manager.get_metadata(key_id)
        assert metadata.active is False

    def test_list_keys(self):
        """Test listing keys."""
        manager = KeyManager()

        # Create multiple keys
        manager.create_key("deterministic")
        manager.create_key("searchable")
        manager.create_key("ope")

        # List all active keys
        keys = manager.list_keys()
        assert len(keys) == 3

        # List by type
        det_keys = manager.list_keys(key_type="deterministic")
        assert len(det_keys) == 1

    def test_list_keys_with_inactive(self):
        """Test listing keys including inactive."""
        manager = KeyManager()

        key_id1 = manager.create_key("deterministic")
        key_id2 = manager.create_key("deterministic")

        manager.delete_key(key_id1)

        # Active only
        active_keys = manager.list_keys(active_only=True)
        assert len(active_keys) == 1

        # Include inactive
        all_keys = manager.list_keys(active_only=False)
        assert len(all_keys) == 2

    def test_keys_needing_rotation(self):
        """Test finding keys that need rotation."""
        manager = KeyManager()

        # Create key with short rotation period
        key_id = manager.create_key("deterministic", rotation_period_days=30)

        # No rotation needed initially
        keys = manager.get_keys_needing_rotation()
        assert len(keys) == 0

        # Simulate old key
        metadata = manager.get_metadata(key_id)
        metadata.last_rotated = datetime.now() - timedelta(days=31)

        # Now should need rotation
        keys = manager.get_keys_needing_rotation()
        assert len(keys) == 1
        assert keys[0] == key_id

    def test_get_metadata(self):
        """Test metadata retrieval."""
        manager = KeyManager()

        key_id = manager.create_key("ope", description="Test OPE key")
        metadata = manager.get_metadata(key_id)

        assert metadata.key_id == key_id
        assert metadata.key_type == "ope"
        assert metadata.description == "Test OPE key"

    def test_access_counting(self):
        """Test that key access is counted."""
        manager = KeyManager()

        key_id = manager.create_key("deterministic")

        # Access key multiple times
        for _ in range(5):
            manager.get_key(key_id)

        metadata = manager.get_metadata(key_id)
        assert metadata.access_count == 5

    def test_export_import_keys(self):
        """Test key export and import."""
        manager1 = KeyManager()

        # Create some keys
        key_id1 = manager1.create_key("deterministic")
        key_id2 = manager1.create_key("searchable")

        # Export keys
        password = "export_password_456"
        encrypted_bundle = manager1.export_keys(password)
        assert isinstance(encrypted_bundle, str)

        # Import into new manager
        manager2 = KeyManager()
        manager2.import_keys(encrypted_bundle, password)

        # Should be able to retrieve imported keys
        key1 = manager2.get_key(key_id1)
        key2 = manager2.get_key(key_id2)

        assert key1 == manager1.get_key(key_id1)
        assert key2 == manager1.get_key(key_id2)

    def test_audit_log(self):
        """Test audit logging."""
        manager = KeyManager()

        key_id = manager.create_key("deterministic")
        manager.get_key(key_id)
        manager.rotate_key(key_id)

        # Check audit log
        logs = manager.get_audit_log()
        assert len(logs) >= 3  # create, get, rotate

        # Check specific key log
        key_logs = manager.get_audit_log(key_id=key_id)
        assert len(key_logs) >= 2  # create, get

    def test_audit_log_limit(self):
        """Test audit log limit."""
        manager = KeyManager()

        # Create many keys
        for i in range(20):
            manager.create_key("deterministic")

        # Get limited log
        logs = manager.get_audit_log(limit=10)
        assert len(logs) == 10

    def test_invalid_master_key_size(self):
        """Test that invalid master key size raises error."""
        with pytest.raises(ValueError):
            KeyManager(master_key=b"too_short")

    def test_different_master_keys(self):
        """Test that different managers have different master keys."""
        manager1 = KeyManager()
        manager2 = KeyManager()

        # Keys should be independent
        key_id = "test_key_999"
        # Creating in one manager shouldn't affect the other

        id1 = manager1.create_key("deterministic")
        id2 = manager2.create_key("deterministic")

        # IDs should be different
        assert id1 != id2

    def test_key_export_password_protection(self):
        """Test that wrong password fails import."""
        manager1 = KeyManager()
        manager1.create_key("deterministic")

        # Export with one password
        bundle = manager1.export_keys("password123")

        # Try to import with wrong password
        manager2 = KeyManager()
        with pytest.raises(Exception):  # Will raise crypto error
            manager2.import_keys(bundle, "wrong_password")

    def test_custom_rotation_periods(self):
        """Test different rotation periods for different key types."""
        manager = KeyManager()

        key_id1 = manager.create_key("deterministic", rotation_period_days=30)
        key_id2 = manager.create_key("searchable", rotation_period_days=90)

        metadata1 = manager.get_metadata(key_id1)
        metadata2 = manager.get_metadata(key_id2)

        assert metadata1.rotation_period_days == 30
        assert metadata2.rotation_period_days == 90
