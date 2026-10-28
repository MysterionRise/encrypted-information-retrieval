"""
Key Management Module

Provides secure key generation, storage, rotation, and management.
Implements best practices for cryptographic key lifecycle management.

Supports pluggable storage backends for persistent key storage via the
StorageBackend interface. When no backend is provided, keys are stored
in memory only (lost on process exit).

Use Case: Centralized key management for all encryption operations,
key rotation, access control, and audit logging.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .audit import AuditEvent, AuditEventType, AuditWrite, derive_audit_key
from .errors import KeyIntegrityError

if TYPE_CHECKING:
    from .kms_provider import KMSProvider
    from .storage_backend import StorageBackend

# Wrapped-key format 1: AES-256-GCM under the master key with associated data binding the key
# to its tenant, ID, type and version. Rows without "wrap_format" in their metadata predate it
# and were wrapped with no associated data.
WRAP_FORMAT = 1
_WRAP_AAD_LABEL = b"encrypted-ir/tenant-key/v1"


def _length_prefixed(*parts: str | bytes) -> bytes:
    encoded = bytearray()
    for part in parts:
        data = part.encode("utf-8") if isinstance(part, str) else part
        encoded += len(data).to_bytes(4, "big") + data
    return bytes(encoded)


class KeyLifecycleState:
    """Key lifecycle states per NIST SP 800-57."""

    ACTIVE = "active"
    ROTATING = "rotating"
    RETIRED = "retired"
    ARCHIVED = "archived"
    DESTROYED = "destroyed"

    ALL = {ACTIVE, ROTATING, RETIRED, ARCHIVED, DESTROYED}
    DECRYPTABLE = {ACTIVE, ROTATING, RETIRED, ARCHIVED}


class KeyMetadata:
    """Metadata for encryption keys."""

    def __init__(
        self,
        key_id: str,
        key_type: str,
        created_at: datetime,
        expires_at: datetime | None = None,
        rotation_period_days: int = 90,
        description: str = "",
    ):
        self.key_id = key_id
        self.key_type = key_type
        self.created_at = created_at
        self.expires_at = expires_at
        self.rotation_period_days = rotation_period_days
        self.description = description
        self.last_rotated = created_at
        self.access_count = 0
        self.active = True
        self.version: int = 1
        self.lifecycle_state: str = KeyLifecycleState.ACTIVE
        self.successor_key_id: str | None = None
        self.predecessor_key_id: str | None = None
        self.retention_expires_at: datetime | None = None
        self.compromise_detected_at: datetime | None = None
        self.total_records_encrypted: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotation_period_days": self.rotation_period_days,
            "description": self.description,
            "last_rotated": self.last_rotated.isoformat(),
            "access_count": self.access_count,
            "active": self.active,
            "version": self.version,
            "lifecycle_state": self.lifecycle_state,
            "successor_key_id": self.successor_key_id,
            "predecessor_key_id": self.predecessor_key_id,
            "retention_expires_at": (
                self.retention_expires_at.isoformat() if self.retention_expires_at else None
            ),
            "compromise_detected_at": (
                self.compromise_detected_at.isoformat() if self.compromise_detected_at else None
            ),
            "total_records_encrypted": self.total_records_encrypted,
        }

    @staticmethod
    def from_dict(data: dict) -> KeyMetadata:
        """Create from dictionary."""
        metadata = KeyMetadata(
            key_id=data["key_id"],
            key_type=data["key_type"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
            rotation_period_days=data.get("rotation_period_days", 90),
            description=data.get("description", ""),
        )
        metadata.last_rotated = datetime.fromisoformat(data.get("last_rotated", data["created_at"]))
        metadata.access_count = data.get("access_count", 0)
        metadata.active = data.get("active", True)
        metadata.version = data.get("version", 1)
        metadata.lifecycle_state = data.get("lifecycle_state", KeyLifecycleState.ACTIVE)
        metadata.successor_key_id = data.get("successor_key_id")
        metadata.predecessor_key_id = data.get("predecessor_key_id")
        metadata.retention_expires_at = (
            datetime.fromisoformat(data["retention_expires_at"])
            if data.get("retention_expires_at")
            else None
        )
        metadata.compromise_detected_at = (
            datetime.fromisoformat(data["compromise_detected_at"])
            if data.get("compromise_detected_at")
            else None
        )
        metadata.total_records_encrypted = data.get("total_records_encrypted", 0)
        return metadata

    def needs_rotation(self) -> bool:
        """Check if key needs rotation."""
        if not self.active:
            return False
        if self.lifecycle_state != KeyLifecycleState.ACTIVE:
            return False
        days_since_rotation = (datetime.now() - self.last_rotated).days
        return days_since_rotation >= self.rotation_period_days

    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


class KeyManager:
    """
    Secure key management system.

    Handles generation, storage, rotation, and lifecycle of encryption keys.
    """

    def __init__(
        self,
        master_key: bytes = None,
        storage_backend: StorageBackend = None,
        audit_reads: bool = False,
        tenant_id: str | None = None,
    ):
        """
        Initialize key manager.

        Args:
            master_key: 256-bit master key for encrypting stored keys.
                       If None, generates a new master key.
            storage_backend: Optional persistent storage backend. When provided,
                           keys are persisted across process restarts. When None,
                           keys are stored in memory only.
            audit_reads: When True, every successful key read persists the updated
                       ``access_count`` and writes an audit entry. Off by default, so
                       read paths (search, decrypt) do not write to the backend.
                       ``access_count`` is always tracked in memory.
            tenant_id: Tenant the keys belong to. Wrapped keys are bound to it through
                       AES-GCM associated data. Defaults to the backend's ``tenant_id``
                       (or "" when there is none) and must match it if both are given.

        Key events (create, deactivate, rotate, import, failed reads) are written to the
        storage backend's audit chain (see :mod:`encrypted_ir.audit`), in the same
        transaction as the key change when there is one. Without a backend, or with a
        backend that has no audit store, nothing is audited.

        The manager is safe to share between threads. With a storage backend, keys
        written by another process are picked up by :meth:`refresh` or loaded on demand
        when an unknown key ID is requested.
        """
        if master_key is None:
            master_key = os.urandom(32)
        elif len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes (256 bits)")

        backend_tenant = getattr(storage_backend, "tenant_id", None)
        if not isinstance(backend_tenant, str):
            backend_tenant = None
        if tenant_id is None:
            tenant_id = backend_tenant or ""
        elif backend_tenant is not None and backend_tenant != tenant_id:
            raise ValueError("tenant_id does not match the storage backend's tenant")

        self.master_key = master_key
        self.tenant_id = tenant_id
        self._storage_backend = storage_backend
        self._kms_provider: KMSProvider | None = None
        self._encrypted_master_key: bytes | None = None
        self._audit_reads = audit_reads
        self._lock = threading.RLock()
        self._keys: dict[str, bytes] = {}
        self._metadata: dict[str, KeyMetadata] = {}

        if self._storage_backend is not None:
            self._load_from_backend()

    @classmethod
    def from_kms(
        cls,
        kms_provider: KMSProvider,
        storage_backend: StorageBackend = None,
        encrypted_master_key: bytes = None,
        tenant_id: str | None = None,
    ) -> KeyManager:
        """Create a KeyManager with KMS-protected master key.

        Uses envelope encryption: the cloud KMS generates or unwraps
        the master key, which then protects local encryption keys.

        Args:
            kms_provider: Cloud KMS provider for key wrapping.
            storage_backend: Optional persistent storage backend.
            encrypted_master_key: Previously KMS-encrypted master key
                for recovery. If None, generates a new master key via KMS.
            tenant_id: Tenant the keys belong to (see ``__init__``).

        Returns:
            KeyManager instance with KMS-protected master key.
        """
        if encrypted_master_key is not None:
            master_key = kms_provider.decrypt(encrypted_master_key)
            enc_mk = encrypted_master_key
        else:
            master_key, enc_mk = kms_provider.generate_data_key("AES_256")

        instance = cls(master_key=master_key, storage_backend=storage_backend, tenant_id=tenant_id)
        instance._kms_provider = kms_provider
        instance._encrypted_master_key = enc_mk
        return instance

    def get_encrypted_master_key(self) -> bytes | None:
        """Get the KMS-encrypted master key for secure storage.

        Returns:
            KMS-encrypted master key bytes, or None if not using KMS.
        """
        return self._encrypted_master_key

    def get_kms_provider(self) -> KMSProvider | None:
        """Get the configured KMS provider, if any.

        Returns:
            The KMS provider, or None if not using KMS.
        """
        return self._kms_provider

    @staticmethod
    def generate_master_key() -> bytes:
        """Generate a new master key."""
        return os.urandom(32)

    @staticmethod
    def derive_master_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive master key from password.

        Args:
            password: Master password
            salt: Salt for key derivation. If None, generates random salt.

        Returns:
            Tuple of (master_key, salt)
        """
        if salt is None:
            salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        master_key = kdf.derive(password.encode())
        return master_key, salt

    def _wrap_aad(self, key_id: str, key_type: str, version: int) -> bytes:
        """Associated data binding a wrapped key to its tenant, ID, type and version."""
        return _length_prefixed(_WRAP_AAD_LABEL, self.tenant_id, key_id, key_type, str(version))

    def _encrypt_key(self, key_id: str, key: bytes, metadata: KeyMetadata) -> bytes:
        """Wrap a key under the master key, bound to this tenant and the key's metadata."""
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)
        aad = self._wrap_aad(key_id, metadata.key_type, metadata.version)
        return cast(bytes, nonce + aesgcm.encrypt(nonce, key, aad))

    def _decrypt_key(self, key_id: str, encrypted_key: bytes, meta_dict: dict) -> bytes:
        """Unwrap a stored key.

        Format 1 keys must unwrap under this tenant and the stored key ID, type and version;
        keys stored before format 1 (no ``wrap_format``) unwrap with no associated data.

        Raises:
            KeyIntegrityError: If the key does not unwrap in this context.
        """
        aad = None
        if meta_dict.get("wrap_format") == WRAP_FORMAT:
            aad = self._wrap_aad(
                key_id, str(meta_dict.get("key_type", "")), int(meta_dict.get("version", 1))
            )
        try:
            return cast(
                bytes, AESGCM(self.master_key).decrypt(encrypted_key[:12], encrypted_key[12:], aad)
            )
        except (InvalidTag, ValueError) as exc:
            raise KeyIntegrityError(f"Key {key_id} failed to unwrap for this tenant") from exc

    def _generate_key_id(self, key_type: str) -> str:
        """Generate a unique key ID."""
        timestamp = datetime.now().isoformat()
        random_data = os.urandom(16)
        id_data = f"{key_type}:{timestamp}".encode() + random_data
        key_id = hashlib.sha256(id_data).hexdigest()[:16]
        return f"{key_type}_{key_id}"

    @staticmethod
    def _event(
        event_type: AuditEventType, key_id: str, success: bool, **details: Any
    ) -> AuditEvent:
        """An audit event about ``key_id``. Details never carry key material."""
        return AuditEvent(
            event_type=event_type,
            actor="key-manager",
            success=success,
            resource=key_id,
            details=details,
            key_id=None if key_id == "*" else key_id,
        )

    def _audit_write(self, event: AuditEvent) -> AuditWrite:
        return AuditWrite(event, derive_audit_key(self.master_key, self.tenant_id))

    def _audit(self, event: AuditEvent) -> None:
        """Append ``event`` to the backend's audit chain in its own transaction."""
        if self._storage_backend is not None:
            self._storage_backend.append_audit(self._audit_write(event))

    def _log_access(self, key_id: str, operation: str, success: bool, details: str = "") -> None:
        """Audit an operation recorded by ``KeyRotationManager`` (to be removed with it)."""
        self._audit(
            AuditEvent(
                event_type=f"key.{operation}",
                actor="key-manager",
                success=success,
                resource=key_id,
                details={"note": details},
                key_id=None if key_id in ("*", "kek") else key_id,
            )
        )

    def _load_from_backend(self):
        """Load all keys and metadata from the storage backend into memory."""
        self.refresh()

    def refresh(self) -> None:
        """Synchronize with the storage backend.

        Unwraps keys that are not in memory yet and replaces the metadata of every stored
        key with the stored version, so lifecycle changes made by another process (for
        example a rotation) become visible. Reads only; it never writes to the backend.
        """
        if self._storage_backend is None:
            return
        encrypted_keys, metadata_dicts = self._storage_backend.load_all()
        with self._lock:
            for key_id, encrypted_key in encrypted_keys.items():
                meta_dict = metadata_dicts.get(key_id, {})
                if key_id not in self._keys:
                    try:
                        self._keys[key_id] = self._decrypt_key(key_id, encrypted_key, meta_dict)
                    except KeyIntegrityError:
                        # A row that does not unwrap for this tenant is ignored rather than
                        # breaking every key of the tenant; requesting it raises (see below).
                        continue
                self._metadata[key_id] = KeyMetadata.from_dict(meta_dict)

    def _ensure_loaded(self, key_id: str) -> bool:
        """Load ``key_id`` from the backend if it is not in memory. Returns True if present."""
        if key_id in self._keys:
            return True
        if self._storage_backend is None:
            return False
        stored = self._storage_backend.load_key(key_id)
        if stored is None:
            return False
        encrypted_key, meta_dict = stored
        key = self._decrypt_key(key_id, encrypted_key, meta_dict)
        with self._lock:
            self._keys[key_id] = key
            self._metadata[key_id] = KeyMetadata.from_dict(meta_dict)
        return True

    def _record_read(self, key_id: str, operation: str) -> None:
        """Count a successful read; persist and audit it only when ``audit_reads`` is on."""
        with self._lock:
            self._metadata[key_id].access_count += 1
        if self._audit_reads:
            self._persist_key(
                key_id,
                audit=self._event(AuditEventType.KEY_READ, key_id, True, operation=operation),
            )

    def _persist_key(self, key_id: str, audit: AuditEvent | None = None):
        """Persist a key and its metadata, with ``audit`` in the same transaction."""
        if self._storage_backend is None:
            return
        metadata = self._metadata[key_id]
        encrypted_key = self._encrypt_key(key_id, self._keys[key_id], metadata)
        metadata_dict = {**metadata.to_dict(), "wrap_format": WRAP_FORMAT}
        self._storage_backend.save_key(
            key_id,
            encrypted_key,
            metadata_dict,
            audit=None if audit is None else self._audit_write(audit),
        )

    def create_key(
        self,
        key_type: str,
        key_size: int = 32,
        rotation_period_days: int = 90,
        description: str = "",
    ) -> str:
        """
        Create a new encryption key.

        Args:
            key_type: Type of key (e.g., 'deterministic', 'searchable', 'ope')
            key_size: Size of key in bytes (default: 32 = 256 bits)
            rotation_period_days: Days until key rotation recommended
            description: Human-readable description

        Returns:
            Key ID
        """
        key_id = self._generate_key_id(key_type)
        key = os.urandom(key_size)

        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            created_at=datetime.now(),
            rotation_period_days=rotation_period_days,
            description=description,
        )
        with self._lock:
            self._keys[key_id] = key
            self._metadata[key_id] = metadata

        self._persist_key(
            key_id, audit=self._event(AuditEventType.KEY_CREATE, key_id, True, key_type=key_type)
        )
        return key_id

    def get_key(self, key_id: str) -> bytes:
        """
        Retrieve a key by ID.

        Args:
            key_id: Key identifier

        Returns:
            Key bytes

        Raises:
            KeyError: If key not found
            ValueError: If key is expired or inactive
        """
        if not self._ensure_loaded(key_id):
            self._audit(self._event(AuditEventType.KEY_READ, key_id, False, reason="not_found"))
            raise KeyError(f"Key {key_id} not found")

        metadata = self._metadata[key_id]

        if not metadata.active:
            self._audit(self._event(AuditEventType.KEY_READ, key_id, False, reason="inactive"))
            raise ValueError(f"Key {key_id} is inactive")

        if metadata.is_expired():
            self._audit(self._event(AuditEventType.KEY_READ, key_id, False, reason="expired"))
            raise ValueError(f"Key {key_id} is expired")

        self._record_read(key_id, "get")
        return self._keys[key_id]

    def get_key_for_decryption(self, key_id: str) -> bytes:
        """Retrieve a key for decryption, even if retired or rotating.

        During key rotation, old keys must remain accessible for decrypting
        existing data. This method allows access to keys in any decryptable
        lifecycle state (active, rotating, retired, archived).

        Args:
            key_id: Key identifier.

        Returns:
            Key bytes.

        Raises:
            KeyError: If key not found.
            ValueError: If key is destroyed.
        """
        if not self._ensure_loaded(key_id):
            self._audit(self._event(AuditEventType.KEY_READ, key_id, False, reason="not_found"))
            raise KeyError(f"Key {key_id} not found")

        metadata = self._metadata[key_id]

        if metadata.lifecycle_state == KeyLifecycleState.DESTROYED:
            self._audit(self._event(AuditEventType.KEY_READ, key_id, False, reason="destroyed"))
            raise ValueError(f"Key {key_id} is destroyed and cannot be used")

        self._record_read(key_id, "get_for_decryption")
        return self._keys[key_id]

    def get_or_create_active_key(self, key_type: str, description: str = "") -> str:
        """Return the newest active key of ``key_type``, creating one if there is none.

        The lock is held across refresh, selection and creation, so concurrent callers in
        this process never create two keys. Across processes two keys can still be created
        at the same moment; every caller then converges on the newest one, ordered by
        ``created_at`` and then key ID.
        """
        with self._lock:
            self.refresh()
            newest = self._newest_active_key(key_type)
            if newest is not None:
                return newest
            created = self.create_key(key_type, key_size=32, description=description)
            self.refresh()
            return self._newest_active_key(key_type) or created

    def _newest_active_key(self, key_type: str) -> str | None:
        candidates = [
            key_id
            for key_id, metadata in self._metadata.items()
            if metadata.key_type == key_type
            and metadata.active
            and metadata.lifecycle_state == KeyLifecycleState.ACTIVE
            and not metadata.is_expired()
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda key_id: (self._metadata[key_id].created_at, key_id))

    def rotate_key(self, key_id: str) -> str:
        """
        Rotate a key (create new version).

        Args:
            key_id: Key to rotate

        Returns:
            New key ID

        Raises:
            KeyError: If key not found
        """
        if key_id not in self._metadata:
            raise KeyError(f"Key {key_id} not found")

        old_metadata = self._metadata[key_id]

        # Create new key with same parameters
        new_key_id = self.create_key(
            key_type=old_metadata.key_type,
            key_size=len(self._keys[key_id]),
            rotation_period_days=old_metadata.rotation_period_days,
            description=f"Rotated from {key_id}",
        )

        # Link versions
        new_metadata = self._metadata[new_key_id]
        new_metadata.version = old_metadata.version + 1
        new_metadata.predecessor_key_id = key_id
        old_metadata.successor_key_id = new_key_id

        # Mark old key as inactive
        old_metadata.active = False
        old_metadata.lifecycle_state = KeyLifecycleState.RETIRED
        self._persist_key(new_key_id)
        self._persist_key(
            key_id,
            audit=self._event(AuditEventType.KEY_ROTATE, key_id, True, successor_key_id=new_key_id),
        )

        return new_key_id

    def delete_key(self, key_id: str):
        """
        Delete a key (mark as inactive).

        Args:
            key_id: Key to delete

        Raises:
            KeyError: If key not found
        """
        if key_id not in self._metadata:
            raise KeyError(f"Key {key_id} not found")

        # Mark as inactive instead of actually deleting
        # (crypto-shredding - key deletion = data deletion)
        self._metadata[key_id].active = False
        self._persist_key(key_id, audit=self._event(AuditEventType.KEY_DEACTIVATE, key_id, True))

    def list_keys(self, key_type: str = None, active_only: bool = True) -> list[str]:
        """
        List all keys.

        Args:
            key_type: Filter by key type (None = all types)
            active_only: Only return active keys

        Returns:
            List of key IDs
        """
        keys = []
        for key_id, metadata in self._metadata.items():
            if active_only and not metadata.active:
                continue
            if key_type and metadata.key_type != key_type:
                continue
            keys.append(key_id)
        return keys

    def get_keys_needing_rotation(self) -> list[str]:
        """
        Get list of keys that need rotation.

        Returns:
            List of key IDs needing rotation
        """
        return [key_id for key_id, metadata in self._metadata.items() if metadata.needs_rotation()]

    def get_metadata(self, key_id: str) -> KeyMetadata:
        """
        Get key metadata.

        Args:
            key_id: Key identifier

        Returns:
            Key metadata

        Raises:
            KeyError: If key not found
        """
        if key_id not in self._metadata:
            raise KeyError(f"Key {key_id} not found")
        return self._metadata[key_id]

    def export_keys(self, password: str) -> str:
        """
        Export all keys encrypted with password.

        Args:
            password: Password to encrypt export

        Returns:
            Base64-encoded encrypted key bundle
        """
        # Derive key from password
        export_key, salt = self.derive_master_key(password)

        # Prepare data to export
        export_data: dict[str, Any] = {"keys": {}, "metadata": {}, "version": "1.0"}

        for key_id, key in self._keys.items():
            export_data["keys"][key_id] = base64.b64encode(key).decode("ascii")

        for key_id, metadata in self._metadata.items():
            export_data["metadata"][key_id] = metadata.to_dict()

        # Serialize and encrypt
        json_data = json.dumps(export_data).encode("utf-8")
        aesgcm = AESGCM(export_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json_data, None)

        # Combine salt + nonce + ciphertext
        bundle = salt + nonce + ciphertext
        return base64.b64encode(bundle).decode("ascii")

    def import_keys(self, encrypted_bundle: str, password: str):
        """
        Import keys from encrypted bundle.

        Args:
            encrypted_bundle: Base64-encoded encrypted key bundle
            password: Password to decrypt bundle
        """
        # Decode bundle
        bundle = base64.b64decode(encrypted_bundle)
        salt = bundle[:32]
        nonce = bundle[32:44]
        ciphertext = bundle[44:]

        # Derive key from password
        export_key, _ = self.derive_master_key(password, salt)

        # Decrypt
        aesgcm = AESGCM(export_key)
        json_data = aesgcm.decrypt(nonce, ciphertext, None)

        # Parse
        export_data = json.loads(json_data.decode("utf-8"))

        # Import keys and metadata
        for key_id, key_b64 in export_data["keys"].items():
            self._keys[key_id] = base64.b64decode(key_b64)

        for key_id, metadata_dict in export_data["metadata"].items():
            self._metadata[key_id] = KeyMetadata.from_dict(metadata_dict)

        # Persist all imported keys
        for key_id in export_data["keys"]:
            self._persist_key(key_id)

        self._audit(
            self._event(AuditEventType.KEY_IMPORT, "*", True, count=len(export_data["keys"]))
        )
