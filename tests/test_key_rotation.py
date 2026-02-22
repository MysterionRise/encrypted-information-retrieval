"""Tests for key rotation module."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from encrypted_ir.key_manager import KeyLifecycleState, KeyManager, KeyMetadata
from encrypted_ir.key_rotation import (
    KeyRotationManager,
    RotationPolicy,
    RotationPriority,
    RotationProgress,
    RotationStatus,
    VersionedBlob,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manager():
    """Create a fresh KeyManager."""
    return KeyManager()


@pytest.fixture
def rotation(manager):
    """Create a KeyRotationManager with default policy."""
    return KeyRotationManager(manager)


@pytest.fixture
def rotation_with_notify(manager):
    """Create a KeyRotationManager with notification callback."""
    notifications = []
    callback = lambda progress: notifications.append(progress)  # noqa: E731
    rm = KeyRotationManager(manager, notification_callback=callback)
    return rm, notifications


def _make_re_encrypt_fn(succeed=True):
    """Create a mock re-encrypt callback."""
    records = {}

    def fn(record_id, old_key, new_key):
        if succeed:
            records[record_id] = {"old_key": old_key, "new_key": new_key}
            return True
        return False

    fn.records = records
    return fn


# ---------------------------------------------------------------------------
# RotationPolicy
# ---------------------------------------------------------------------------


class TestRotationPolicy:
    """Test rotation policy configuration."""

    def test_default_values(self):
        policy = RotationPolicy()
        assert policy.dek_rotation_days == 90
        assert policy.kek_rotation_days == 365
        assert policy.transition_period_hours == 72
        assert policy.retention_years == 7
        assert policy.max_emergency_rotation_hours == 24

    def test_custom_values(self):
        policy = RotationPolicy(
            dek_rotation_days=30,
            kek_rotation_days=180,
            transition_period_hours=24,
            retention_years=10,
        )
        assert policy.dek_rotation_days == 30
        assert policy.kek_rotation_days == 180
        assert policy.retention_years == 10


# ---------------------------------------------------------------------------
# RotationProgress
# ---------------------------------------------------------------------------


class TestRotationProgress:
    """Test rotation progress tracking."""

    def test_progress_percent_empty(self):
        p = RotationProgress(
            rotation_id="test", old_key_id="old", new_key_id="new", total_records=0
        )
        assert p.progress_percent == 100.0

    def test_progress_percent_partial(self):
        p = RotationProgress(
            rotation_id="test",
            old_key_id="old",
            new_key_id="new",
            total_records=100,
            records_completed=50,
        )
        assert p.progress_percent == 50.0

    def test_is_complete(self):
        p = RotationProgress(
            rotation_id="test",
            old_key_id="old",
            new_key_id="new",
            status=RotationStatus.COMPLETED,
        )
        assert p.is_complete is True

        p.status = RotationStatus.ROLLED_BACK
        assert p.is_complete is True

        p.status = RotationStatus.IN_PROGRESS
        assert p.is_complete is False

    def test_to_dict(self):
        p = RotationProgress(
            rotation_id="rot_123",
            old_key_id="old_key",
            new_key_id="new_key",
            total_records=10,
            records_completed=7,
            records_failed=1,
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime(2026, 1, 1),
            priority=RotationPriority.EMERGENCY,
        )
        d = p.to_dict()
        assert d["rotation_id"] == "rot_123"
        assert d["progress_percent"] == 70.0
        assert d["priority"] == "emergency"
        assert d["status"] == "in_progress"


# ---------------------------------------------------------------------------
# VersionedBlob
# ---------------------------------------------------------------------------


class TestVersionedBlob:
    """Test versioned encrypted blob format."""

    def test_wrap_and_unwrap(self):
        key_id = "det_abc123"
        payload = b"encrypted_data_here"
        blob = VersionedBlob.wrap(key_id, payload)

        assert VersionedBlob.is_versioned(blob)
        key_hash, ciphertext = VersionedBlob.unwrap(blob)
        assert ciphertext == payload
        assert isinstance(key_hash, int)

    def test_is_versioned_true(self):
        blob = VersionedBlob.wrap("key_1", b"data")
        assert VersionedBlob.is_versioned(blob) is True

    def test_is_versioned_false_short(self):
        assert VersionedBlob.is_versioned(b"\xeb") is False

    def test_is_versioned_false_wrong_magic(self):
        assert VersionedBlob.is_versioned(b"\x00\x00\x00\x00\x00\x00data") is False

    def test_unwrap_invalid_short(self):
        with pytest.raises(ValueError, match="too short"):
            VersionedBlob.unwrap(b"\xeb")

    def test_unwrap_invalid_magic(self):
        with pytest.raises(ValueError, match="Invalid"):
            VersionedBlob.unwrap(b"\x00\x00\x00\x00\x00\x00data")

    def test_find_key_id(self):
        key_id = "det_target_key"
        blob = VersionedBlob.wrap(key_id, b"secret")
        candidates = ["det_other_key", key_id, "det_third_key"]
        assert VersionedBlob.find_key_id(blob, candidates) == key_id

    def test_find_key_id_no_match(self):
        blob = VersionedBlob.wrap("det_unknown", b"secret")
        candidates = ["det_a", "det_b"]
        assert VersionedBlob.find_key_id(blob, candidates) is None

    def test_find_key_id_non_versioned(self):
        assert VersionedBlob.find_key_id(b"raw_data", ["key_1"]) is None

    def test_consistent_hashing(self):
        """Same key ID always produces the same hash."""
        blob1 = VersionedBlob.wrap("my_key", b"data1")
        blob2 = VersionedBlob.wrap("my_key", b"data2")
        h1, _ = VersionedBlob.unwrap(blob1)
        h2, _ = VersionedBlob.unwrap(blob2)
        assert h1 == h2

    def test_different_keys_different_hashes(self):
        """Different key IDs produce different hashes (probabilistic)."""
        blob1 = VersionedBlob.wrap("key_alpha", b"data")
        blob2 = VersionedBlob.wrap("key_beta", b"data")
        h1, _ = VersionedBlob.unwrap(blob1)
        h2, _ = VersionedBlob.unwrap(blob2)
        assert h1 != h2


# ---------------------------------------------------------------------------
# KeyRotationManager - DEK Rotation
# ---------------------------------------------------------------------------


class TestDEKRotation:
    """Test DEK rotation with zero-downtime."""

    def test_basic_rotation(self, manager, rotation):
        """Rotate a key and verify old/new states."""
        old_id = manager.create_key("deterministic", rotation_period_days=90)
        progress = rotation.rotate_dek(old_id)

        assert progress.status == RotationStatus.COMPLETED
        assert progress.new_key_id != old_id

        old_meta = manager.get_metadata(old_id)
        assert old_meta.lifecycle_state == KeyLifecycleState.RETIRED
        assert old_meta.active is False

        new_meta = manager.get_metadata(progress.new_key_id)
        assert new_meta.lifecycle_state == KeyLifecycleState.ACTIVE
        assert new_meta.active is True
        assert new_meta.version == 2

    def test_rotation_preserves_key_type(self, manager, rotation):
        """New key inherits type and rotation period."""
        old_id = manager.create_key("searchable", rotation_period_days=60)
        progress = rotation.rotate_dek(old_id)

        new_meta = manager.get_metadata(progress.new_key_id)
        assert new_meta.key_type == "searchable"
        assert new_meta.rotation_period_days == 60

    def test_rotation_with_re_encryption(self, manager, rotation):
        """Rotation re-encrypts records via callback."""
        old_id = manager.create_key("deterministic")
        re_encrypt = _make_re_encrypt_fn(succeed=True)
        records = ["rec_1", "rec_2", "rec_3"]

        progress = rotation.rotate_dek(old_id, re_encrypt_fn=re_encrypt, record_ids=records)

        assert progress.records_completed == 3
        assert progress.records_failed == 0
        assert progress.progress_percent == 100.0
        assert len(re_encrypt.records) == 3

    def test_rotation_with_re_encryption_failures(self, manager, rotation):
        """Partial re-encryption failures are tracked."""
        old_id = manager.create_key("deterministic")

        call_count = 0

        def partial_fn(record_id, old_key, new_key):
            nonlocal call_count
            call_count += 1
            return call_count != 2  # fail on 2nd call

        records = ["rec_1", "rec_2", "rec_3"]
        progress = rotation.rotate_dek(old_id, re_encrypt_fn=partial_fn, record_ids=records)

        assert progress.records_completed == 2
        assert progress.records_failed == 1
        # Still completes because some records succeeded
        assert progress.status == RotationStatus.COMPLETED

    def test_rotation_all_re_encrypt_fail(self, manager, rotation):
        """If all re-encryptions fail, rotation fails."""
        old_id = manager.create_key("deterministic")
        re_encrypt = _make_re_encrypt_fn(succeed=False)
        records = ["rec_1", "rec_2"]

        progress = rotation.rotate_dek(old_id, re_encrypt_fn=re_encrypt, record_ids=records)

        assert progress.status == RotationStatus.FAILED
        assert progress.records_failed == 2

    def test_old_key_accessible_for_decryption(self, manager, rotation):
        """Old key remains accessible via get_key_for_decryption after rotation."""
        old_id = manager.create_key("deterministic")
        old_key = manager.get_key(old_id)

        rotation.rotate_dek(old_id)

        # get_key should fail (inactive)
        with pytest.raises(ValueError, match="inactive"):
            manager.get_key(old_id)

        # get_key_for_decryption should still work
        decryption_key = manager.get_key_for_decryption(old_id)
        assert decryption_key == old_key

    def test_multiple_active_deks_during_transition(self, manager, rotation):
        """Multiple DEKs of same type can coexist during rotation."""
        id1 = manager.create_key("deterministic")
        progress = rotation.rotate_dek(id1)
        id2 = progress.new_key_id

        # Both keys should be accessible for decryption
        key1 = manager.get_key_for_decryption(id1)
        key2 = manager.get_key(id2)
        assert key1 is not None
        assert key2 is not None
        assert key1 != key2

    def test_version_chain(self, manager, rotation):
        """Multiple rotations create a version chain."""
        id1 = manager.create_key("deterministic")
        p1 = rotation.rotate_dek(id1)
        id2 = p1.new_key_id
        p2 = rotation.rotate_dek(id2)
        id3 = p2.new_key_id

        meta1 = manager.get_metadata(id1)
        meta2 = manager.get_metadata(id2)
        meta3 = manager.get_metadata(id3)

        assert meta1.version == 1
        assert meta2.version == 2
        assert meta3.version == 3

        assert meta1.successor_key_id == id2
        assert meta2.predecessor_key_id == id1
        assert meta2.successor_key_id == id3

    def test_cannot_rotate_already_rotating(self, manager):
        """Cannot rotate a key that is already in rotating state."""
        old_id = manager.create_key("deterministic")
        metadata = manager.get_metadata(old_id)
        metadata.lifecycle_state = KeyLifecycleState.ROTATING
        manager._persist_key(old_id)

        rm = KeyRotationManager(manager)
        with pytest.raises(ValueError, match="already being rotated"):
            rm.rotate_dek(old_id)

    def test_cannot_rotate_destroyed_key(self, manager):
        """Cannot rotate a destroyed key."""
        old_id = manager.create_key("deterministic")
        metadata = manager.get_metadata(old_id)
        metadata.lifecycle_state = KeyLifecycleState.DESTROYED
        manager._persist_key(old_id)

        rm = KeyRotationManager(manager)
        with pytest.raises(ValueError, match="destroyed"):
            rm.rotate_dek(old_id)

    def test_rotation_without_records(self, manager, rotation):
        """Rotation without re-encryption records completes immediately."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)

        assert progress.status == RotationStatus.COMPLETED
        assert progress.total_records == 0
        assert progress.progress_percent == 100.0


# ---------------------------------------------------------------------------
# KeyRotationManager - KEK Rotation
# ---------------------------------------------------------------------------


class TestKEKRotation:
    """Test KEK (master key) rotation."""

    def test_kek_rotation(self, manager, rotation):
        """KEK rotation re-wraps all DEKs with new master key."""
        # Create some DEKs
        id1 = manager.create_key("deterministic")
        id2 = manager.create_key("searchable")
        key1_before = manager.get_key(id1)
        key2_before = manager.get_key(id2)

        # Mock KMS provider
        mock_kms = MagicMock()
        new_master = b"\x01" * 32
        mock_kms.generate_data_key.return_value = (new_master, b"encrypted_master")

        progress = rotation.rotate_kek(mock_kms)

        assert progress.status == RotationStatus.COMPLETED
        assert progress.records_completed == 2

        # DEK values unchanged (they're still the same bytes)
        assert manager.get_key(id1) == key1_before
        assert manager.get_key(id2) == key2_before

        # Master key should be updated
        assert manager.master_key == new_master

    def test_kek_rotation_specific_deks(self, manager, rotation):
        """KEK rotation can target specific DEKs."""
        id1 = manager.create_key("deterministic")
        manager.create_key("searchable")

        mock_kms = MagicMock()
        mock_kms.generate_data_key.return_value = (b"\x02" * 32, b"encrypted")

        progress = rotation.rotate_kek(mock_kms, dek_key_ids=[id1])
        assert progress.records_completed == 1


# ---------------------------------------------------------------------------
# Emergency Rotation
# ---------------------------------------------------------------------------


class TestEmergencyRotation:
    """Test emergency key rotation for compromise scenarios."""

    def test_emergency_rotation_marks_compromised(self, manager, rotation):
        """Emergency rotation marks old key as compromised."""
        old_id = manager.create_key("deterministic")
        progress = rotation.emergency_rotate(old_id)

        old_meta = manager.get_metadata(old_id)
        assert old_meta.compromise_detected_at is not None
        assert old_meta.lifecycle_state == KeyLifecycleState.RETIRED
        assert progress.priority == RotationPriority.EMERGENCY

    def test_emergency_rotation_re_encrypts(self, manager, rotation):
        """Emergency rotation re-encrypts records."""
        old_id = manager.create_key("deterministic")
        re_encrypt = _make_re_encrypt_fn(succeed=True)
        records = ["rec_1", "rec_2"]

        progress = rotation.emergency_rotate(old_id, re_encrypt_fn=re_encrypt, record_ids=records)

        assert progress.records_completed == 2
        assert progress.status == RotationStatus.COMPLETED

    def test_emergency_rotation_immediately_retires(self, manager, rotation):
        """Emergency rotation immediately retires the compromised key."""
        old_id = manager.create_key("deterministic")
        rotation.emergency_rotate(old_id)

        old_meta = manager.get_metadata(old_id)
        assert old_meta.active is False
        assert old_meta.lifecycle_state == KeyLifecycleState.RETIRED

    def test_compromised_key_still_decryptable(self, manager, rotation):
        """Compromised key is still accessible for decryption."""
        old_id = manager.create_key("deterministic")
        old_key = manager.get_key(old_id)

        rotation.emergency_rotate(old_id)

        # Still accessible for decryption
        assert manager.get_key_for_decryption(old_id) == old_key


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


class TestRollback:
    """Test rotation rollback capability."""

    def test_rollback_rotation(self, manager, rotation):
        """Rollback restores old key and deactivates new key."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)

        assert rotation.rollback_rotation(progress.rotation_id) is True

        old_meta = manager.get_metadata(old_id)
        assert old_meta.active is True
        assert old_meta.lifecycle_state == KeyLifecycleState.ACTIVE

        new_meta = manager.get_metadata(progress.new_key_id)
        assert new_meta.active is False
        assert new_meta.lifecycle_state == KeyLifecycleState.RETIRED

    def test_rollback_nonexistent(self, rotation):
        """Rollback of unknown rotation returns False."""
        assert rotation.rollback_rotation("nonexistent_rot") is False

    def test_rollback_updates_progress(self, manager, rotation):
        """Rollback updates progress status."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)

        rotation.rollback_rotation(progress.rotation_id)

        rolled = rotation.get_rotation_progress(progress.rotation_id)
        assert rolled is not None
        assert rolled.status == RotationStatus.ROLLED_BACK

    def test_rollback_from_history(self, manager, rotation):
        """Can rollback a completed rotation from history."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)
        rot_id = progress.rotation_id

        # Rotation is now in history (completed)
        assert rotation.rollback_rotation(rot_id) is True


# ---------------------------------------------------------------------------
# Progress & History
# ---------------------------------------------------------------------------


class TestProgressTracking:
    """Test rotation progress tracking and history."""

    def test_get_rotation_progress(self, manager, rotation):
        """Can retrieve progress by rotation ID."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)

        retrieved = rotation.get_rotation_progress(progress.rotation_id)
        assert retrieved is not None
        assert retrieved.rotation_id == progress.rotation_id

    def test_get_rotation_history(self, manager, rotation):
        """Completed rotations appear in history."""
        id1 = manager.create_key("deterministic")
        id2 = manager.create_key("searchable")

        rotation.rotate_dek(id1)
        rotation.rotate_dek(id2)

        history = rotation.get_rotation_history()
        assert len(history) == 2

    def test_active_rotations_empty_after_complete(self, manager, rotation):
        """No active rotations after all complete."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)

        assert len(rotation.get_active_rotations()) == 0


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class TestNotifications:
    """Test rotation notification callbacks."""

    def test_notifications_sent(self, manager, rotation_with_notify):
        """Notifications sent during rotation lifecycle."""
        rm, notifications = rotation_with_notify
        old_id = manager.create_key("deterministic")
        rm.rotate_dek(old_id)

        # Multiple notifications sent (start, finalize)
        assert len(notifications) >= 2
        # Final notification should be for a completed rotation
        statuses = {n.status for n in notifications}
        assert RotationStatus.COMPLETED in statuses

    def test_emergency_notifications(self, manager, rotation_with_notify):
        """Emergency rotations send notifications."""
        rm, notifications = rotation_with_notify
        old_id = manager.create_key("deterministic")
        rm.emergency_rotate(old_id)

        emergency_notifs = [n for n in notifications if n.priority == RotationPriority.EMERGENCY]
        assert len(emergency_notifs) >= 1


# ---------------------------------------------------------------------------
# Lifecycle Management
# ---------------------------------------------------------------------------


class TestKeyLifecycle:
    """Test key lifecycle management."""

    def test_archive_retired_key(self, manager, rotation):
        """Can archive a retired key."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)

        rotation.archive_key(old_id)

        meta = manager.get_metadata(old_id)
        assert meta.lifecycle_state == KeyLifecycleState.ARCHIVED
        assert meta.retention_expires_at is not None

    def test_archive_sets_retention(self, manager, rotation):
        """Archive sets retention period per policy."""
        policy = RotationPolicy(retention_years=10)
        rm = KeyRotationManager(manager, policy=policy)

        old_id = manager.create_key("deterministic")
        rm.rotate_dek(old_id)
        rm.archive_key(old_id)

        meta = manager.get_metadata(old_id)
        expected_min = datetime.now() + timedelta(days=10 * 365 - 1)
        assert meta.retention_expires_at > expected_min

    def test_cannot_archive_active_key(self, manager, rotation):
        """Cannot archive a key that is still active."""
        key_id = manager.create_key("deterministic")
        with pytest.raises(ValueError, match="active"):
            rotation.archive_key(key_id)

    def test_destroy_after_retention(self, manager, rotation):
        """Can destroy a key after retention period expires."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)
        rotation.archive_key(old_id)

        # Set retention to expired
        meta = manager.get_metadata(old_id)
        meta.retention_expires_at = datetime.now() - timedelta(days=1)
        manager._persist_key(old_id)

        assert rotation.destroy_key(old_id) is True
        assert manager.get_metadata(old_id).lifecycle_state == KeyLifecycleState.DESTROYED

    def test_cannot_destroy_before_retention(self, manager, rotation):
        """Cannot destroy a key before retention period without force."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)
        rotation.archive_key(old_id)

        with pytest.raises(ValueError, match="Retention period"):
            rotation.destroy_key(old_id)

    def test_force_destroy(self, manager, rotation):
        """Can force-destroy a key regardless of retention."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)
        rotation.archive_key(old_id)

        assert rotation.destroy_key(old_id, force=True) is True
        assert manager.get_metadata(old_id).lifecycle_state == KeyLifecycleState.DESTROYED

    def test_destroyed_key_not_decryptable(self, manager, rotation):
        """Destroyed keys cannot be used even for decryption."""
        old_id = manager.create_key("deterministic")
        rotation.rotate_dek(old_id)
        rotation.archive_key(old_id)
        rotation.destroy_key(old_id, force=True)

        with pytest.raises(ValueError, match="destroyed"):
            manager.get_key_for_decryption(old_id)

    def test_cannot_destroy_active_key(self, manager, rotation):
        """Cannot destroy a key that is still active."""
        key_id = manager.create_key("deterministic")
        with pytest.raises(ValueError, match="active"):
            rotation.destroy_key(key_id)

    def test_seven_year_retention(self, manager):
        """Default policy sets 7-year PCI retention."""
        rm = KeyRotationManager(manager)
        old_id = manager.create_key("deterministic")
        rm.rotate_dek(old_id)
        rm.archive_key(old_id)

        meta = manager.get_metadata(old_id)
        expected_min = datetime.now() + timedelta(days=7 * 365 - 1)
        assert meta.retention_expires_at > expected_min


# ---------------------------------------------------------------------------
# Lifecycle Report
# ---------------------------------------------------------------------------


class TestLifecycleReport:
    """Test lifecycle reporting."""

    def test_lifecycle_report(self, manager, rotation):
        """Lifecycle report contains all expected fields."""
        id1 = manager.create_key("deterministic")
        manager.create_key("searchable")
        rotation.rotate_dek(id1)

        report = rotation.get_lifecycle_report()

        assert report["total_keys"] >= 3  # id1, id2, new from rotation
        assert "state_counts" in report
        assert "keys_needing_rotation" in report
        assert "policy" in report
        assert report["policy"]["dek_rotation_days"] == 90
        assert report["policy"]["retention_years"] == 7

    def test_report_counts_states(self, manager, rotation):
        """Report correctly counts lifecycle states."""
        id1 = manager.create_key("deterministic")
        manager.create_key("searchable")
        rotation.rotate_dek(id1)

        report = rotation.get_lifecycle_report()
        assert KeyLifecycleState.ACTIVE in report["state_counts"]
        assert KeyLifecycleState.RETIRED in report["state_counts"]

    def test_report_identifies_needing_rotation(self, manager, rotation):
        """Report identifies keys needing rotation."""
        key_id = manager.create_key("deterministic", rotation_period_days=30)
        meta = manager.get_metadata(key_id)
        meta.last_rotated = datetime.now() - timedelta(days=31)

        report = rotation.get_lifecycle_report()
        assert key_id in report["keys_needing_rotation"]

    def test_report_identifies_compromised(self, manager, rotation):
        """Report identifies compromised keys."""
        key_id = manager.create_key("deterministic")
        rotation.emergency_rotate(key_id)

        report = rotation.get_lifecycle_report()
        assert key_id in report["compromised_keys"]


# ---------------------------------------------------------------------------
# Keys Due for Rotation
# ---------------------------------------------------------------------------


class TestKeysDueForRotation:
    """Test detection of keys needing rotation."""

    def test_no_keys_due(self, manager, rotation):
        """Fresh keys are not due for rotation."""
        manager.create_key("deterministic", rotation_period_days=90)
        assert len(rotation.get_keys_due_for_rotation()) == 0

    def test_keys_due_after_period(self, manager, rotation):
        """Keys past their rotation period are flagged."""
        key_id = manager.create_key("deterministic", rotation_period_days=30)
        meta = manager.get_metadata(key_id)
        meta.last_rotated = datetime.now() - timedelta(days=31)

        due = rotation.get_keys_due_for_rotation()
        assert len(due) == 1
        assert due[0]["key_id"] == key_id
        assert due[0]["days_since_rotation"] >= 31


# ---------------------------------------------------------------------------
# Key Chain
# ---------------------------------------------------------------------------


class TestKeyChain:
    """Test key version chain traversal."""

    def test_single_key_chain(self, manager, rotation):
        """Single key has chain of length 1."""
        key_id = manager.create_key("deterministic")
        chain = rotation.get_key_chain(key_id)
        assert chain == [key_id]

    def test_rotation_chain(self, manager, rotation):
        """Multiple rotations create a version chain."""
        id1 = manager.create_key("deterministic")
        p1 = rotation.rotate_dek(id1)
        id2 = p1.new_key_id
        p2 = rotation.rotate_dek(id2)
        id3 = p2.new_key_id

        # Querying any key in the chain returns the full chain
        assert rotation.get_key_chain(id1) == [id1, id2, id3]
        assert rotation.get_key_chain(id2) == [id1, id2, id3]
        assert rotation.get_key_chain(id3) == [id1, id2, id3]


# ---------------------------------------------------------------------------
# Resolve Key for Blob
# ---------------------------------------------------------------------------


class TestResolveKeyForBlob:
    """Test resolving key IDs from versioned blobs."""

    def test_resolve_known_key(self, manager, rotation):
        """Can resolve key ID from a versioned blob."""
        key_id = manager.create_key("deterministic")
        blob = VersionedBlob.wrap(key_id, b"encrypted_data")

        resolved = rotation.resolve_key_for_blob(blob)
        assert resolved == key_id

    def test_resolve_after_rotation(self, manager, rotation):
        """Can resolve both old and new key IDs after rotation."""
        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id)
        new_id = progress.new_key_id

        old_blob = VersionedBlob.wrap(old_id, b"old_data")
        new_blob = VersionedBlob.wrap(new_id, b"new_data")

        assert rotation.resolve_key_for_blob(old_blob) == old_id
        assert rotation.resolve_key_for_blob(new_blob) == new_id

    def test_resolve_non_versioned(self, rotation):
        """Non-versioned blob returns None."""
        assert rotation.resolve_key_for_blob(b"raw_unversioned_data") is None


# ---------------------------------------------------------------------------
# Re-encryption Exception Handling
# ---------------------------------------------------------------------------


class TestReEncryptionExceptions:
    """Test re-encryption callback exception handling."""

    def test_callback_exception_counted_as_failure(self, manager, rotation):
        """Exceptions in re-encrypt callback are treated as failures."""

        def failing_fn(record_id, old_key, new_key):
            raise RuntimeError("Database connection lost")

        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id, re_encrypt_fn=failing_fn, record_ids=["rec_1"])

        assert progress.records_failed == 1
        assert "Database connection lost" in progress.error_details[0]

    def test_mixed_success_and_exception(self, manager, rotation):
        """Mix of successful and failing re-encryptions tracked correctly."""
        call_count = 0

        def mixed_fn(record_id, old_key, new_key):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ValueError("Corrupt record")
            return True

        old_id = manager.create_key("deterministic")
        progress = rotation.rotate_dek(old_id, re_encrypt_fn=mixed_fn, record_ids=["a", "b", "c"])

        assert progress.records_completed == 2
        assert progress.records_failed == 1


# ---------------------------------------------------------------------------
# KeyMetadata Lifecycle Fields
# ---------------------------------------------------------------------------


class TestKeyMetadataLifecycle:
    """Test the new lifecycle fields on KeyMetadata."""

    def test_default_lifecycle_state(self):
        """New metadata defaults to active lifecycle."""
        meta = KeyMetadata(key_id="test", key_type="det", created_at=datetime.now())
        assert meta.lifecycle_state == KeyLifecycleState.ACTIVE
        assert meta.version == 1
        assert meta.successor_key_id is None
        assert meta.predecessor_key_id is None
        assert meta.retention_expires_at is None
        assert meta.compromise_detected_at is None
        assert meta.total_records_encrypted == 0

    def test_lifecycle_serialization(self):
        """Lifecycle fields survive to_dict/from_dict round-trip."""
        meta = KeyMetadata(key_id="test", key_type="det", created_at=datetime.now())
        meta.version = 3
        meta.lifecycle_state = KeyLifecycleState.ARCHIVED
        meta.successor_key_id = "next_key"
        meta.predecessor_key_id = "prev_key"
        meta.retention_expires_at = datetime(2033, 6, 15)
        meta.compromise_detected_at = datetime(2026, 1, 1)
        meta.total_records_encrypted = 42

        data = meta.to_dict()
        restored = KeyMetadata.from_dict(data)

        assert restored.version == 3
        assert restored.lifecycle_state == KeyLifecycleState.ARCHIVED
        assert restored.successor_key_id == "next_key"
        assert restored.predecessor_key_id == "prev_key"
        assert restored.retention_expires_at == datetime(2033, 6, 15)
        assert restored.compromise_detected_at == datetime(2026, 1, 1)
        assert restored.total_records_encrypted == 42

    def test_needs_rotation_respects_lifecycle(self):
        """needs_rotation() returns False for non-active lifecycle states."""
        meta = KeyMetadata(
            key_id="test",
            key_type="det",
            created_at=datetime.now(),
            rotation_period_days=1,
        )
        meta.last_rotated = datetime.now() - timedelta(days=10)

        # Active + past period -> needs rotation
        assert meta.needs_rotation() is True

        # Rotating -> doesn't need rotation
        meta.lifecycle_state = KeyLifecycleState.ROTATING
        assert meta.needs_rotation() is False

        # Retired -> doesn't need rotation
        meta.lifecycle_state = KeyLifecycleState.RETIRED
        assert meta.needs_rotation() is False

    def test_backward_compatible_from_dict(self):
        """from_dict works with old-format dicts (no lifecycle fields)."""
        old_dict = {
            "key_id": "legacy_key",
            "key_type": "det",
            "created_at": datetime.now().isoformat(),
            "active": True,
        }
        meta = KeyMetadata.from_dict(old_dict)
        assert meta.version == 1
        assert meta.lifecycle_state == KeyLifecycleState.ACTIVE
        assert meta.successor_key_id is None


# ---------------------------------------------------------------------------
# get_key_for_decryption
# ---------------------------------------------------------------------------


class TestGetKeyForDecryption:
    """Test KeyManager.get_key_for_decryption()."""

    def test_active_key(self, manager):
        """Can get active key for decryption."""
        key_id = manager.create_key("deterministic")
        key = manager.get_key_for_decryption(key_id)
        assert key == manager.get_key(key_id)

    def test_retired_key(self, manager):
        """Can get retired key for decryption."""
        key_id = manager.create_key("deterministic")
        expected = manager.get_key(key_id)
        meta = manager.get_metadata(key_id)
        meta.active = False
        meta.lifecycle_state = KeyLifecycleState.RETIRED

        key = manager.get_key_for_decryption(key_id)
        assert key == expected

    def test_archived_key(self, manager):
        """Can get archived key for decryption."""
        key_id = manager.create_key("deterministic")
        expected = manager.get_key(key_id)
        meta = manager.get_metadata(key_id)
        meta.active = False
        meta.lifecycle_state = KeyLifecycleState.ARCHIVED

        key = manager.get_key_for_decryption(key_id)
        assert key == expected

    def test_destroyed_key_raises(self, manager):
        """Cannot get destroyed key for decryption."""
        key_id = manager.create_key("deterministic")
        meta = manager.get_metadata(key_id)
        meta.lifecycle_state = KeyLifecycleState.DESTROYED

        with pytest.raises(ValueError, match="destroyed"):
            manager.get_key_for_decryption(key_id)

    def test_nonexistent_key_raises(self, manager):
        """Getting nonexistent key for decryption raises KeyError."""
        with pytest.raises(KeyError):
            manager.get_key_for_decryption("nonexistent")

    def test_increments_access_count(self, manager):
        """get_key_for_decryption increments access count."""
        key_id = manager.create_key("deterministic")
        manager.get_key_for_decryption(key_id)
        manager.get_key_for_decryption(key_id)
        meta = manager.get_metadata(key_id)
        assert meta.access_count >= 2
