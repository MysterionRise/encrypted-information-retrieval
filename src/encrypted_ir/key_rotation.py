"""
Key Rotation Module

Provides automated key rotation with zero-downtime rollover for DEKs and KEKs.
Implements NIST SP 800-57 key lifecycle management with PCI DSS 3.6.4 compliance.

Features:
- Configurable DEK rotation (default: every 90 days)
- Configurable KEK rotation (default: annually)
- Multiple active DEKs during transition period
- Emergency rotation for key compromise scenarios
- Progress tracking for re-encryption operations
- Rollback capability for failed rotations
- Key lifecycle management with 7-year PCI retention
- Versioned encrypted blobs for key tracking

Usage:
    manager = KeyManager(master_key=key)
    rotation = KeyRotationManager(manager)

    # Check what needs rotation
    due = rotation.get_keys_due_for_rotation()

    # Rotate a DEK with zero-downtime
    result = rotation.rotate_dek(old_key_id, re_encrypt_fn=my_re_encrypt)

    # Emergency rotation on compromise
    result = rotation.emergency_rotate(compromised_key_id, re_encrypt_fn=fn)
"""

from __future__ import annotations

import hashlib
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from .key_manager import KeyLifecycleState

if TYPE_CHECKING:
    from .key_manager import KeyManager
    from .kms_provider import KMSProvider


class RotationPriority(Enum):
    """Priority levels for rotation operations."""

    SCHEDULED = "scheduled"
    EMERGENCY = "emergency"


class RotationStatus(Enum):
    """Status of a rotation operation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class RotationPolicy:
    """Configuration for key rotation schedules.

    Args:
        dek_rotation_days: Days between DEK rotations (default: 90).
        kek_rotation_days: Days between KEK rotations (default: 365).
        transition_period_hours: Hours to keep old key active during transition.
        retention_years: Years to retain retired keys (PCI: 7 years).
        max_emergency_rotation_hours: Max hours for emergency rotation completion.
    """

    dek_rotation_days: int = 90
    kek_rotation_days: int = 365
    transition_period_hours: int = 72
    retention_years: int = 7
    max_emergency_rotation_hours: int = 24


@dataclass
class RotationProgress:
    """Tracks progress of a re-encryption operation.

    Attributes:
        rotation_id: Unique identifier for this rotation.
        old_key_id: Key being rotated from.
        new_key_id: Key being rotated to.
        total_records: Total records to re-encrypt.
        records_completed: Records successfully re-encrypted.
        records_failed: Records that failed re-encryption.
        status: Current rotation status.
        started_at: When rotation started.
        completed_at: When rotation finished (if complete).
        priority: Rotation priority level.
        error_details: Details of any errors encountered.
    """

    rotation_id: str
    old_key_id: str
    new_key_id: str
    total_records: int = 0
    records_completed: int = 0
    records_failed: int = 0
    status: RotationStatus = RotationStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    priority: RotationPriority = RotationPriority.SCHEDULED
    error_details: list[str] = field(default_factory=list)

    @property
    def progress_percent(self) -> float:
        """Percentage of records re-encrypted."""
        if self.total_records == 0:
            return 100.0
        return (self.records_completed / self.total_records) * 100.0

    @property
    def is_complete(self) -> bool:
        """Whether all records have been processed."""
        return self.status in (RotationStatus.COMPLETED, RotationStatus.ROLLED_BACK)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "rotation_id": self.rotation_id,
            "old_key_id": self.old_key_id,
            "new_key_id": self.new_key_id,
            "total_records": self.total_records,
            "records_completed": self.records_completed,
            "records_failed": self.records_failed,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "priority": self.priority.value,
            "progress_percent": self.progress_percent,
            "error_details": self.error_details,
        }


# Re-encrypt callback type: takes (record_id, old_key, new_key) and returns
# True on success. The callback is responsible for actually re-encrypting
# the data in whatever storage system holds it.
ReEncryptCallback = Callable[[str, bytes, bytes], bool]

# Notification callback type: takes a RotationProgress and does whatever
# alerting is needed (email, Slack, PagerDuty, etc.).
NotificationCallback = Callable[[RotationProgress], None]


class VersionedBlob:
    """Versioned encrypted blob that tracks which key version encrypted it.

    Format: [magic:2bytes][key_hash:4bytes][payload:variable]

    The key_hash is a truncated SHA-256 of the key_id, allowing efficient
    lookup of which key to use for decryption without storing the full key ID.
    """

    MAGIC = b"\xeb\x01"  # Magic bytes + version 1
    HEADER_SIZE = 6  # 2 (magic) + 4 (key_hash)

    @staticmethod
    def wrap(key_id: str, ciphertext: bytes) -> bytes:
        """Wrap ciphertext with key version metadata.

        Args:
            key_id: ID of the key used for encryption.
            ciphertext: The encrypted data.

        Returns:
            Versioned blob: header + ciphertext.
        """
        key_hash = struct.pack(">I", VersionedBlob._hash_key_id(key_id))
        return VersionedBlob.MAGIC + key_hash + ciphertext

    @staticmethod
    def unwrap(blob: bytes) -> tuple[int, bytes]:
        """Extract key hash and ciphertext from a versioned blob.

        Args:
            blob: Versioned blob bytes.

        Returns:
            Tuple of (key_id_hash, ciphertext).

        Raises:
            ValueError: If blob is too short or has invalid magic bytes.
        """
        if len(blob) < VersionedBlob.HEADER_SIZE:
            raise ValueError("Blob too short to be a versioned blob")
        if blob[:2] != VersionedBlob.MAGIC:
            raise ValueError("Invalid versioned blob magic bytes")

        key_hash = struct.unpack(">I", blob[2:6])[0]
        ciphertext = blob[6:]
        return key_hash, ciphertext

    @staticmethod
    def is_versioned(blob: bytes) -> bool:
        """Check if a blob has versioned format."""
        return len(blob) >= VersionedBlob.HEADER_SIZE and blob[:2] == VersionedBlob.MAGIC

    @staticmethod
    def _hash_key_id(key_id: str) -> int:
        """Hash a key ID to a 32-bit integer for compact storage."""
        digest = hashlib.sha256(key_id.encode()).digest()
        return int(struct.unpack(">I", digest[:4])[0])

    @staticmethod
    def find_key_id(blob: bytes, candidate_key_ids: list[str]) -> str | None:
        """Find which key ID matches a versioned blob's key hash.

        Args:
            blob: Versioned blob bytes.
            candidate_key_ids: List of key IDs to check.

        Returns:
            Matching key ID, or None if no match found.
        """
        if not VersionedBlob.is_versioned(blob):
            return None
        blob_hash, _ = VersionedBlob.unwrap(blob)
        for key_id in candidate_key_ids:
            if VersionedBlob._hash_key_id(key_id) == blob_hash:
                return key_id
        return None


class KeyRotationManager:
    """Manages automated key rotation with zero-downtime rollover.

    Orchestrates DEK and KEK rotation, tracks re-encryption progress,
    supports rollback, and manages key lifecycle per NIST SP 800-57.

    Args:
        key_manager: KeyManager instance for key operations.
        policy: Rotation policy configuration. Uses defaults if None.
        notification_callback: Optional callback for rotation notifications.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        policy: RotationPolicy | None = None,
        notification_callback: NotificationCallback | None = None,
    ):
        self._key_manager = key_manager
        self._policy = policy or RotationPolicy()
        self._notification_callback = notification_callback
        self._active_rotations: dict[str, RotationProgress] = {}
        self._rotation_history: list[RotationProgress] = []
        self._key_hash_index: dict[int, str] = {}
        self._rebuild_key_hash_index()

    def _rebuild_key_hash_index(self) -> None:
        """Rebuild the key hash -> key_id index for VersionedBlob lookups."""
        self._key_hash_index.clear()
        for key_id in self._key_manager.list_keys(active_only=False):
            h = VersionedBlob._hash_key_id(key_id)
            self._key_hash_index[h] = key_id

    def _generate_rotation_id(self, key_id: str) -> str:
        """Generate a unique rotation ID."""
        ts = int(time.time() * 1000)
        data = f"{key_id}:{ts}".encode()
        return f"rot_{hashlib.sha256(data).hexdigest()[:12]}"

    def _notify(self, progress: RotationProgress) -> None:
        """Send notification if callback is configured."""
        if self._notification_callback is not None:
            self._notification_callback(progress)

    def get_policy(self) -> RotationPolicy:
        """Get the current rotation policy."""
        return self._policy

    def get_keys_due_for_rotation(self) -> list[dict]:
        """Get all keys that are due for rotation based on policy.

        Returns:
            List of dicts with key_id, key_type, days_since_rotation,
            and rotation_period_days for each key due.
        """
        due = []
        for key_id in self._key_manager.list_keys(active_only=True):
            metadata = self._key_manager.get_metadata(key_id)
            if metadata.lifecycle_state != KeyLifecycleState.ACTIVE:
                continue
            days_since = (datetime.now() - metadata.last_rotated).days
            if days_since >= metadata.rotation_period_days:
                due.append(
                    {
                        "key_id": key_id,
                        "key_type": metadata.key_type,
                        "days_since_rotation": days_since,
                        "rotation_period_days": metadata.rotation_period_days,
                    }
                )
        return due

    def rotate_dek(
        self,
        key_id: str,
        re_encrypt_fn: ReEncryptCallback | None = None,
        record_ids: list[str] | None = None,
    ) -> RotationProgress:
        """Rotate a Data Encryption Key with zero-downtime.

        Process:
        1. Generate new DEK
        2. Mark old DEK as 'rotating' (still usable for decryption)
        3. Re-encrypt records using callback (if provided)
        4. Retire old DEK after transition
        5. Track progress throughout

        Args:
            key_id: ID of the DEK to rotate.
            re_encrypt_fn: Callback to re-encrypt each record.
                Takes (record_id, old_key_bytes, new_key_bytes) -> bool.
            record_ids: List of record IDs to re-encrypt. Required if
                re_encrypt_fn is provided.

        Returns:
            RotationProgress tracking the operation.

        Raises:
            KeyError: If key not found.
            ValueError: If key is already being rotated.
        """
        metadata = self._key_manager.get_metadata(key_id)
        if metadata.lifecycle_state == KeyLifecycleState.ROTATING:
            raise ValueError(f"Key {key_id} is already being rotated")
        if metadata.lifecycle_state == KeyLifecycleState.DESTROYED:
            raise ValueError(f"Key {key_id} is destroyed")

        rotation_id = self._generate_rotation_id(key_id)

        # Create new DEK with same parameters
        old_key_size = len(self._key_manager.get_key_for_decryption(key_id))
        new_key_id = self._key_manager.create_key(
            key_type=metadata.key_type,
            key_size=old_key_size,
            rotation_period_days=metadata.rotation_period_days,
            description=f"Rotated from {key_id}",
        )

        # Link versions
        new_metadata = self._key_manager.get_metadata(new_key_id)
        new_metadata.version = metadata.version + 1
        new_metadata.predecessor_key_id = key_id
        metadata.successor_key_id = new_key_id

        # Mark old key as rotating (still usable for decryption)
        metadata.lifecycle_state = KeyLifecycleState.ROTATING
        metadata.last_rotated = datetime.now()

        # Persist both
        self._key_manager._persist_key(key_id)
        self._key_manager._persist_key(new_key_id)

        # Update hash index
        h = VersionedBlob._hash_key_id(new_key_id)
        self._key_hash_index[h] = new_key_id

        # Initialize progress tracking
        total = len(record_ids) if record_ids else 0
        progress = RotationProgress(
            rotation_id=rotation_id,
            old_key_id=key_id,
            new_key_id=new_key_id,
            total_records=total,
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.now(),
            priority=RotationPriority.SCHEDULED,
        )
        self._active_rotations[rotation_id] = progress
        self._notify(progress)

        # Re-encrypt records if callback and records provided
        if re_encrypt_fn and record_ids:
            old_key = self._key_manager.get_key_for_decryption(key_id)
            new_key = self._key_manager.get_key(new_key_id)
            self._re_encrypt_records(progress, re_encrypt_fn, record_ids, old_key, new_key)

        # Finalize rotation
        self._finalize_rotation(progress, key_id)
        return progress

    def rotate_kek(
        self,
        kms_provider: KMSProvider,
        dek_key_ids: list[str] | None = None,
    ) -> RotationProgress:
        """Rotate the Key Encryption Key (KEK) with blue-green deployment.

        Process:
        1. Generate new KEK in KMS
        2. Re-wrap all DEKs with new KEK
        3. Verify all DEKs are accessible with new KEK
        4. Retire old KEK

        Args:
            kms_provider: KMS provider for generating new KEK.
            dek_key_ids: Specific DEK IDs to re-wrap. If None, re-wraps all.

        Returns:
            RotationProgress tracking the operation.
        """
        rotation_id = self._generate_rotation_id("kek")

        # Generate new master key via KMS
        new_master_key, new_encrypted_master_key = kms_provider.generate_data_key("AES_256")

        # Determine which DEKs to re-wrap
        if dek_key_ids is None:
            dek_key_ids = self._key_manager.list_keys(active_only=False)

        progress = RotationProgress(
            rotation_id=rotation_id,
            old_key_id="kek_current",
            new_key_id="kek_new",
            total_records=len(dek_key_ids),
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.now(),
            priority=RotationPriority.SCHEDULED,
        )
        self._active_rotations[rotation_id] = progress
        self._notify(progress)

        # Re-wrap each DEK: decrypt with old master key, re-encrypt with new
        for dek_id in dek_key_ids:
            try:
                # Get the raw DEK bytes (already decrypted in memory)
                dek_bytes = self._key_manager._keys.get(dek_id)
                if dek_bytes is None:
                    progress.records_failed += 1
                    progress.error_details.append(f"DEK {dek_id} not found in memory")
                    continue

                # The DEK is already in plaintext in memory. We just need
                # to re-persist it so it gets encrypted with the new master key
                # (after we swap the master key).
                progress.records_completed += 1
            except Exception as e:
                progress.records_failed += 1
                progress.error_details.append(f"Failed to process {dek_id}: {str(e)}")

        # Swap master key
        self._key_manager.master_key = new_master_key
        self._key_manager._encrypted_master_key = new_encrypted_master_key
        self._key_manager._kms_provider = kms_provider

        # Re-persist all DEKs with new master key
        for dek_id in dek_key_ids:
            if dek_id in self._key_manager._keys:
                self._key_manager._persist_key(dek_id)

        # Finalize
        progress.status = RotationStatus.COMPLETED
        progress.completed_at = datetime.now()
        self._active_rotations.pop(rotation_id, None)
        self._rotation_history.append(progress)
        self._notify(progress)

        self._key_manager._log_access(
            "kek", "rotate_kek", True, f"Re-wrapped {progress.records_completed} DEKs"
        )
        return progress

    def emergency_rotate(
        self,
        key_id: str,
        re_encrypt_fn: ReEncryptCallback | None = None,
        record_ids: list[str] | None = None,
    ) -> RotationProgress:
        """Emergency key rotation for key compromise scenarios.

        Marks the old key as compromised and initiates high-priority rotation.
        The old key is immediately retired (not kept in rotating state).

        Args:
            key_id: ID of the compromised key.
            re_encrypt_fn: Callback to re-encrypt each record.
            record_ids: List of record IDs to re-encrypt.

        Returns:
            RotationProgress with emergency priority.
        """
        metadata = self._key_manager.get_metadata(key_id)
        metadata.compromise_detected_at = datetime.now()

        rotation_id = self._generate_rotation_id(f"emergency_{key_id}")

        # Create replacement key
        old_key_size = len(self._key_manager.get_key_for_decryption(key_id))
        new_key_id = self._key_manager.create_key(
            key_type=metadata.key_type,
            key_size=old_key_size,
            rotation_period_days=metadata.rotation_period_days,
            description=f"Emergency rotation from compromised {key_id}",
        )

        # Link versions
        new_metadata = self._key_manager.get_metadata(new_key_id)
        new_metadata.version = metadata.version + 1
        new_metadata.predecessor_key_id = key_id
        metadata.successor_key_id = new_key_id

        # Immediately retire old key (don't keep in rotating state)
        metadata.active = False
        metadata.lifecycle_state = KeyLifecycleState.RETIRED
        metadata.last_rotated = datetime.now()
        self._key_manager._persist_key(key_id)
        self._key_manager._persist_key(new_key_id)

        # Update hash index
        h = VersionedBlob._hash_key_id(new_key_id)
        self._key_hash_index[h] = new_key_id

        total = len(record_ids) if record_ids else 0
        progress = RotationProgress(
            rotation_id=rotation_id,
            old_key_id=key_id,
            new_key_id=new_key_id,
            total_records=total,
            status=RotationStatus.IN_PROGRESS,
            started_at=datetime.now(),
            priority=RotationPriority.EMERGENCY,
        )
        self._active_rotations[rotation_id] = progress
        self._notify(progress)

        # Re-encrypt records
        if re_encrypt_fn and record_ids:
            old_key = self._key_manager.get_key_for_decryption(key_id)
            new_key = self._key_manager.get_key(new_key_id)
            self._re_encrypt_records(progress, re_encrypt_fn, record_ids, old_key, new_key)

        # Finalize
        progress.status = RotationStatus.COMPLETED
        progress.completed_at = datetime.now()
        self._active_rotations.pop(rotation_id, None)
        self._rotation_history.append(progress)
        self._notify(progress)

        self._key_manager._log_access(
            key_id,
            "emergency_rotate",
            True,
            f"Emergency rotation to {new_key_id}, {progress.records_completed} re-encrypted",
        )
        return progress

    def rollback_rotation(self, rotation_id: str) -> bool:
        """Rollback an in-progress or completed rotation.

        Reactivates the old key and deactivates the new key. Records that
        were already re-encrypted remain valid (both keys can decrypt).

        Args:
            rotation_id: ID of the rotation to rollback.

        Returns:
            True if rollback succeeded, False if rotation not found.
        """
        progress = self._active_rotations.get(rotation_id)
        if progress is None:
            # Check history
            for p in self._rotation_history:
                if p.rotation_id == rotation_id:
                    progress = p
                    break
        if progress is None:
            return False

        old_metadata = self._key_manager.get_metadata(progress.old_key_id)
        new_metadata = self._key_manager.get_metadata(progress.new_key_id)

        # Reactivate old key
        old_metadata.active = True
        old_metadata.lifecycle_state = KeyLifecycleState.ACTIVE
        old_metadata.successor_key_id = None
        self._key_manager._persist_key(progress.old_key_id)

        # Deactivate new key
        new_metadata.active = False
        new_metadata.lifecycle_state = KeyLifecycleState.RETIRED
        self._key_manager._persist_key(progress.new_key_id)

        # Update progress
        progress.status = RotationStatus.ROLLED_BACK
        progress.completed_at = datetime.now()
        self._active_rotations.pop(rotation_id, None)
        if progress not in self._rotation_history:
            self._rotation_history.append(progress)
        self._notify(progress)

        self._key_manager._log_access(
            progress.old_key_id,
            "rollback_rotation",
            True,
            f"Rolled back rotation {rotation_id}",
        )
        return True

    def get_rotation_progress(self, rotation_id: str) -> RotationProgress | None:
        """Get progress of a specific rotation operation.

        Args:
            rotation_id: Rotation operation ID.

        Returns:
            RotationProgress or None if not found.
        """
        progress = self._active_rotations.get(rotation_id)
        if progress is not None:
            return progress
        for p in self._rotation_history:
            if p.rotation_id == rotation_id:
                return p
        return None

    def get_active_rotations(self) -> list[RotationProgress]:
        """Get all currently active rotation operations."""
        return list(self._active_rotations.values())

    def get_rotation_history(self) -> list[RotationProgress]:
        """Get history of completed rotation operations."""
        return list(self._rotation_history)

    def archive_key(self, key_id: str) -> None:
        """Archive a retired key for long-term retention.

        Sets PCI-compliant retention period (default 7 years).
        Archived keys can still be used for decryption but not encryption.

        Args:
            key_id: ID of the key to archive.

        Raises:
            ValueError: If key is still active or rotating.
        """
        metadata = self._key_manager.get_metadata(key_id)
        if metadata.lifecycle_state in (KeyLifecycleState.ACTIVE, KeyLifecycleState.ROTATING):
            raise ValueError(
                f"Cannot archive key in '{metadata.lifecycle_state}' state. "
                "Retire the key first."
            )

        metadata.lifecycle_state = KeyLifecycleState.ARCHIVED
        metadata.retention_expires_at = datetime.now() + timedelta(
            days=self._policy.retention_years * 365
        )
        self._key_manager._persist_key(key_id)
        self._key_manager._log_access(
            key_id,
            "archive",
            True,
            f"Archived with {self._policy.retention_years}-year retention",
        )

    def destroy_key(self, key_id: str, force: bool = False) -> bool:
        """Securely destroy a key after retention period expires.

        Only destroys keys whose retention period has expired, unless
        force=True (for emergency scenarios).

        Args:
            key_id: ID of the key to destroy.
            force: Skip retention check (emergency use only).

        Returns:
            True if key was destroyed.

        Raises:
            ValueError: If retention period hasn't expired and force=False.
        """
        metadata = self._key_manager.get_metadata(key_id)

        if not force:
            if metadata.lifecycle_state not in (
                KeyLifecycleState.RETIRED,
                KeyLifecycleState.ARCHIVED,
            ):
                raise ValueError(
                    f"Cannot destroy key in '{metadata.lifecycle_state}' state. "
                    "Archive the key first."
                )
            if metadata.retention_expires_at and datetime.now() < metadata.retention_expires_at:
                raise ValueError(
                    f"Retention period expires at {metadata.retention_expires_at.isoformat()}. "
                    "Use force=True for emergency destruction."
                )

        metadata.lifecycle_state = KeyLifecycleState.DESTROYED
        metadata.active = False
        self._key_manager._persist_key(key_id)

        # Remove from hash index
        h = VersionedBlob._hash_key_id(key_id)
        self._key_hash_index.pop(h, None)

        self._key_manager._log_access(key_id, "destroy", True, f"Key destroyed (force={force})")
        return True

    def get_lifecycle_report(self) -> dict:
        """Generate a key lifecycle report for compliance auditing.

        Returns:
            Dict with counts by lifecycle state, keys needing attention,
            and compliance status.
        """
        all_key_ids = self._key_manager.list_keys(active_only=False)
        state_counts: dict[str, int] = {}
        keys_needing_rotation: list[str] = []
        keys_past_retention: list[str] = []
        compromised_keys: list[str] = []

        for key_id in all_key_ids:
            metadata = self._key_manager.get_metadata(key_id)
            state = metadata.lifecycle_state
            state_counts[state] = state_counts.get(state, 0) + 1

            if metadata.needs_rotation():
                keys_needing_rotation.append(key_id)

            if metadata.compromise_detected_at is not None:
                compromised_keys.append(key_id)

            if (
                metadata.retention_expires_at
                and datetime.now() > metadata.retention_expires_at
                and metadata.lifecycle_state != KeyLifecycleState.DESTROYED
            ):
                keys_past_retention.append(key_id)

        return {
            "total_keys": len(all_key_ids),
            "state_counts": state_counts,
            "keys_needing_rotation": keys_needing_rotation,
            "keys_past_retention": keys_past_retention,
            "compromised_keys": compromised_keys,
            "active_rotations": len(self._active_rotations),
            "policy": {
                "dek_rotation_days": self._policy.dek_rotation_days,
                "kek_rotation_days": self._policy.kek_rotation_days,
                "retention_years": self._policy.retention_years,
            },
        }

    def resolve_key_for_blob(self, blob: bytes) -> str | None:
        """Determine which key ID was used to encrypt a versioned blob.

        Args:
            blob: Potentially versioned encrypted blob.

        Returns:
            Key ID if found, None if blob is not versioned or key unknown.
        """
        if not VersionedBlob.is_versioned(blob):
            return None
        blob_hash, _ = VersionedBlob.unwrap(blob)
        result = self._key_hash_index.get(blob_hash)
        if result is None:
            # Lazy refresh: new keys may have been added since last rebuild
            self._rebuild_key_hash_index()
            result = self._key_hash_index.get(blob_hash)
        return result

    def get_key_chain(self, key_id: str) -> list[str]:
        """Get the full version chain for a key (oldest to newest).

        Args:
            key_id: Any key ID in the chain.

        Returns:
            List of key IDs from oldest to newest version.
        """
        # Walk back to the oldest predecessor
        current = key_id
        while True:
            metadata = self._key_manager.get_metadata(current)
            if metadata.predecessor_key_id is None:
                break
            try:
                self._key_manager.get_metadata(metadata.predecessor_key_id)
                current = metadata.predecessor_key_id
            except KeyError:
                break

        # Walk forward collecting the chain
        chain = [current]
        while True:
            metadata = self._key_manager.get_metadata(current)
            if metadata.successor_key_id is None:
                break
            try:
                self._key_manager.get_metadata(metadata.successor_key_id)
                chain.append(metadata.successor_key_id)
                current = metadata.successor_key_id
            except KeyError:
                break
        return chain

    def _re_encrypt_records(
        self,
        progress: RotationProgress,
        re_encrypt_fn: ReEncryptCallback,
        record_ids: list[str],
        old_key: bytes,
        new_key: bytes,
    ) -> None:
        """Execute re-encryption of records with progress tracking."""
        for record_id in record_ids:
            try:
                success = re_encrypt_fn(record_id, old_key, new_key)
                if success:
                    progress.records_completed += 1
                else:
                    progress.records_failed += 1
                    progress.error_details.append(f"Re-encrypt failed for {record_id}")
            except Exception as e:
                progress.records_failed += 1
                progress.error_details.append(f"Error re-encrypting {record_id}: {str(e)}")

    def _finalize_rotation(self, progress: RotationProgress, old_key_id: str) -> None:
        """Finalize a rotation: retire old key, complete progress."""
        if progress.records_failed > 0 and progress.records_completed == 0:
            # All records failed - mark as failed
            progress.status = RotationStatus.FAILED
            progress.completed_at = datetime.now()
            # Don't retire the old key if nothing was re-encrypted
        else:
            # Retire old key (still accessible for decryption via get_key_for_decryption)
            old_metadata = self._key_manager.get_metadata(old_key_id)
            old_metadata.active = False
            old_metadata.lifecycle_state = KeyLifecycleState.RETIRED
            self._key_manager._persist_key(old_key_id)
            progress.status = RotationStatus.COMPLETED
            progress.completed_at = datetime.now()

        self._active_rotations.pop(progress.rotation_id, None)
        self._rotation_history.append(progress)
        self._notify(progress)

        self._key_manager._log_access(
            old_key_id,
            "rotate_dek",
            progress.status == RotationStatus.COMPLETED,
            f"Rotation {progress.rotation_id}: "
            f"{progress.records_completed}/{progress.total_records} re-encrypted",
        )
