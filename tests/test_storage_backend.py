"""Tests for storage backend module."""

import os
import shutil
import tempfile
from datetime import datetime

import pytest

from encrypted_ir.key_manager import KeyManager
from encrypted_ir.storage_backend import FileStorageBackend, StorageBackend


class TestStorageBackendInterface:
    """Test that StorageBackend is a proper abstract interface."""

    def test_cannot_instantiate_abstract_class(self):
        """StorageBackend cannot be instantiated directly."""
        with pytest.raises(TypeError):
            StorageBackend()

    def test_subclass_must_implement_all_methods(self):
        """Subclass missing methods cannot be instantiated."""

        class IncompleteBackend(StorageBackend):
            def save_key(self, key_id, encrypted_key, metadata):
                pass

        with pytest.raises(TypeError):
            IncompleteBackend()


class TestFileStorageBackend:
    """Test file-based storage backend."""

    @pytest.fixture
    def storage_dir(self):
        """Create a temporary directory for storage tests."""
        d = tempfile.mkdtemp()
        yield d
        shutil.rmtree(d)

    @pytest.fixture
    def encryption_key(self):
        """Generate a stable encryption key for tests."""
        return os.urandom(32)

    @pytest.fixture
    def backend(self, storage_dir, encryption_key):
        """Create a FileStorageBackend instance."""
        return FileStorageBackend(storage_dir, encryption_key)

    def test_invalid_encryption_key_size(self, storage_dir):
        """Reject encryption keys that aren't 32 bytes."""
        with pytest.raises(ValueError):
            FileStorageBackend(storage_dir, b"too_short")

    def test_creates_storage_directory(self):
        """Storage directory is created if it doesn't exist."""
        d = tempfile.mkdtemp()
        shutil.rmtree(d)
        subdir = os.path.join(d, "nested", "path")
        try:
            FileStorageBackend(subdir, os.urandom(32))
            assert os.path.isdir(subdir)
        finally:
            shutil.rmtree(d)

    def test_save_and_load_key(self, backend):
        """Keys can be saved and loaded back."""
        key_id = "test_key_001"
        encrypted_key = os.urandom(44)  # nonce(12) + ciphertext(32)
        metadata = {"key_id": key_id, "key_type": "deterministic", "active": True}

        backend.save_key(key_id, encrypted_key, metadata)
        result = backend.load_key(key_id)

        assert result is not None
        loaded_key, loaded_metadata = result
        assert loaded_key == encrypted_key
        assert loaded_metadata["key_id"] == key_id

    def test_load_nonexistent_key(self, backend):
        """Loading a key that doesn't exist returns None."""
        assert backend.load_key("nonexistent") is None

    def test_delete_key(self, backend):
        """Keys can be deleted from storage."""
        key_id = "test_key_del"
        backend.save_key(key_id, os.urandom(44), {"key_id": key_id})

        assert backend.delete_key(key_id) is True
        assert backend.load_key(key_id) is None

    def test_delete_nonexistent_key(self, backend):
        """Deleting a nonexistent key returns False."""
        assert backend.delete_key("nonexistent") is False

    def test_list_keys(self, backend):
        """All stored key IDs can be listed."""
        backend.save_key("key_a", os.urandom(44), {"key_id": "key_a"})
        backend.save_key("key_b", os.urandom(44), {"key_id": "key_b"})
        backend.save_key("key_c", os.urandom(44), {"key_id": "key_c"})

        keys = backend.list_keys()
        assert set(keys) == {"key_a", "key_b", "key_c"}

    def test_list_keys_empty(self, backend):
        """Listing keys on empty store returns empty list."""
        assert backend.list_keys() == []

    def test_load_all(self, backend):
        """All keys and metadata can be loaded at once."""
        backend.save_key("k1", b"data1_padding_for_test", {"key_id": "k1", "type": "a"})
        backend.save_key("k2", b"data2_padding_for_test", {"key_id": "k2", "type": "b"})

        keys, metadata = backend.load_all()
        assert len(keys) == 2
        assert keys["k1"] == b"data1_padding_for_test"
        assert metadata["k2"]["type"] == "b"

    def test_load_all_empty(self, backend):
        """Loading all from empty store returns empty dicts."""
        keys, metadata = backend.load_all()
        assert keys == {}
        assert metadata == {}

    def test_save_and_load_audit_entry(self, backend):
        """Audit entries can be saved and loaded."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "key_id": "test_key",
            "operation": "create",
            "success": True,
            "details": "test",
        }
        backend.save_audit_entry(entry)

        logs = backend.load_audit_log()
        assert len(logs) == 1
        assert logs[0]["key_id"] == "test_key"

    def test_audit_log_filtering(self, backend):
        """Audit log can be filtered by key_id."""
        for i in range(5):
            backend.save_audit_entry(
                {"key_id": f"key_{i % 2}", "operation": "get", "timestamp": str(i)}
            )

        all_logs = backend.load_audit_log()
        assert len(all_logs) == 5

        key0_logs = backend.load_audit_log(key_id="key_0")
        assert len(key0_logs) == 3

    def test_audit_log_limit(self, backend):
        """Audit log respects the limit parameter."""
        for i in range(20):
            backend.save_audit_entry({"key_id": "k", "timestamp": str(i)})

        logs = backend.load_audit_log(limit=5)
        assert len(logs) == 5

    def test_audit_log_empty(self, backend):
        """Loading audit log when no entries exist returns empty list."""
        assert backend.load_audit_log() == []

    def test_persistence_across_instances(self, storage_dir, encryption_key):
        """Data persists when a new backend instance is created for the same dir."""
        backend1 = FileStorageBackend(storage_dir, encryption_key)
        backend1.save_key("persistent_key", b"secret_data_here!!!", {"key_id": "persistent_key"})

        # Create a new backend instance pointing to the same directory
        backend2 = FileStorageBackend(storage_dir, encryption_key)
        result = backend2.load_key("persistent_key")

        assert result is not None
        loaded_key, _ = result
        assert loaded_key == b"secret_data_here!!!"

    def test_wrong_encryption_key_fails(self, storage_dir, encryption_key):
        """Data encrypted with one key cannot be read with another."""
        backend1 = FileStorageBackend(storage_dir, encryption_key)
        backend1.save_key("secret", os.urandom(44), {"key_id": "secret"})

        wrong_key = os.urandom(32)
        backend2 = FileStorageBackend(storage_dir, wrong_key)
        with pytest.raises(Exception):  # AES-GCM decryption failure
            backend2.load_key("secret")

    def test_overwrite_existing_key(self, backend):
        """Saving a key with the same ID overwrites the previous value."""
        backend.save_key("k", b"original_value_pad", {"key_id": "k", "version": 1})
        backend.save_key("k", b"updated__value_pad", {"key_id": "k", "version": 2})

        _, metadata = backend.load_key("k")
        assert metadata["version"] == 2


class TestKeyManagerWithFileBackend:
    """Test KeyManager integration with FileStorageBackend."""

    @pytest.fixture
    def storage_dir(self):
        d = tempfile.mkdtemp()
        yield d
        shutil.rmtree(d)

    @pytest.fixture
    def master_key(self):
        return os.urandom(32)

    @pytest.fixture
    def manager(self, storage_dir, master_key):
        backend = FileStorageBackend(storage_dir, master_key)
        return KeyManager(master_key=master_key, storage_backend=backend)

    def test_keys_persist_across_restarts(self, storage_dir, master_key):
        """Keys created in one KeyManager survive into a new instance."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        key_id = mgr1.create_key("deterministic", description="persistent test key")
        original_key = mgr1.get_key(key_id)

        # Simulate process restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        restored_key = mgr2.get_key(key_id)
        assert restored_key == original_key

    def test_metadata_persists(self, storage_dir, master_key):
        """Key metadata survives a restart."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        key_id = mgr1.create_key(
            "searchable", rotation_period_days=60, description="searchable key"
        )

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        metadata = mgr2.get_metadata(key_id)
        assert metadata.key_type == "searchable"
        assert metadata.rotation_period_days == 60
        assert metadata.description == "searchable key"

    def test_deletion_persists(self, storage_dir, master_key):
        """Deleted (inactive) keys stay inactive after restart."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        key_id = mgr1.create_key("ope")
        mgr1.delete_key(key_id)

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        with pytest.raises(ValueError, match="inactive"):
            mgr2.get_key(key_id)

    def test_rotation_persists(self, storage_dir, master_key):
        """Key rotation state persists across restarts."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        old_key_id = mgr1.create_key("deterministic")
        new_key_id = mgr1.rotate_key(old_key_id)

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        # Old key inactive
        old_meta = mgr2.get_metadata(old_key_id)
        assert old_meta.active is False

        # New key active and retrievable
        new_key = mgr2.get_key(new_key_id)
        assert new_key is not None

    def test_multiple_keys_persist(self, storage_dir, master_key):
        """Multiple keys of different types all persist."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        ids = []
        for key_type in ["deterministic", "searchable", "ope", "ore"]:
            ids.append(mgr1.create_key(key_type))

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        assert len(mgr2.list_keys()) == 4
        for key_id in ids:
            assert mgr2.get_key(key_id) is not None

    def test_audit_log_persists(self, storage_dir, master_key):
        """Audit log entries persist across restarts."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        key_id = mgr1.create_key("deterministic")
        mgr1.get_key(key_id)

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        logs = mgr2.get_audit_log()
        assert len(logs) >= 2  # create + get

    def test_existing_tests_still_pass_without_backend(self):
        """KeyManager without a backend works exactly as before."""
        manager = KeyManager()

        key_id = manager.create_key("deterministic")
        key = manager.get_key(key_id)
        assert key is not None
        assert len(key) == 32

        # Rotation
        new_key_id = manager.rotate_key(key_id)
        assert manager.get_metadata(key_id).active is False
        assert manager.get_metadata(new_key_id).active is True

    def test_import_export_with_backend(self, storage_dir, master_key):
        """Imported keys are persisted to the backend."""
        # Export from in-memory manager
        mgr_export = KeyManager()
        kid1 = mgr_export.create_key("deterministic")
        kid2 = mgr_export.create_key("searchable")
        bundle = mgr_export.export_keys("password123")

        # Import into backend-backed manager
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr_import = KeyManager(master_key=master_key, storage_backend=backend1)
        mgr_import.import_keys(bundle, "password123")

        # Restart and verify imported keys persisted
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr_verify = KeyManager(master_key=master_key, storage_backend=backend2)

        assert mgr_verify.get_key(kid1) is not None
        assert mgr_verify.get_key(kid2) is not None

    def test_access_count_persists(self, storage_dir, master_key):
        """Access counts are updated in the backend."""
        backend1 = FileStorageBackend(storage_dir, master_key)
        mgr1 = KeyManager(master_key=master_key, storage_backend=backend1)

        key_id = mgr1.create_key("deterministic")
        for _ in range(3):
            mgr1.get_key(key_id)

        # Restart
        backend2 = FileStorageBackend(storage_dir, master_key)
        mgr2 = KeyManager(master_key=master_key, storage_backend=backend2)

        metadata = mgr2.get_metadata(key_id)
        assert metadata.access_count == 3
