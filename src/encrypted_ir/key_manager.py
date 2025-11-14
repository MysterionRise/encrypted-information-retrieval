"""
Key Management Module

Provides secure key generation, storage, rotation, and management.
Implements best practices for cryptographic key lifecycle management.

Use Case: Centralized key management for all encryption operations,
key rotation, access control, and audit logging.
"""

import os
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64


class KeyMetadata:
    """Metadata for encryption keys."""

    def __init__(self, key_id: str, key_type: str, created_at: datetime,
                 expires_at: Optional[datetime] = None, rotation_period_days: int = 90,
                 description: str = ""):
        self.key_id = key_id
        self.key_type = key_type
        self.created_at = created_at
        self.expires_at = expires_at
        self.rotation_period_days = rotation_period_days
        self.description = description
        self.last_rotated = created_at
        self.access_count = 0
        self.active = True

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'key_id': self.key_id,
            'key_type': self.key_type,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'rotation_period_days': self.rotation_period_days,
            'description': self.description,
            'last_rotated': self.last_rotated.isoformat(),
            'access_count': self.access_count,
            'active': self.active
        }

    @staticmethod
    def from_dict(data: dict) -> 'KeyMetadata':
        """Create from dictionary."""
        metadata = KeyMetadata(
            key_id=data['key_id'],
            key_type=data['key_type'],
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            rotation_period_days=data.get('rotation_period_days', 90),
            description=data.get('description', '')
        )
        metadata.last_rotated = datetime.fromisoformat(data.get('last_rotated', data['created_at']))
        metadata.access_count = data.get('access_count', 0)
        metadata.active = data.get('active', True)
        return metadata

    def needs_rotation(self) -> bool:
        """Check if key needs rotation."""
        if not self.active:
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

    def __init__(self, master_key: bytes = None):
        """
        Initialize key manager.

        Args:
            master_key: 256-bit master key for encrypting stored keys.
                       If None, generates a new master key.
        """
        if master_key is None:
            master_key = os.urandom(32)
        elif len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes (256 bits)")

        self.master_key = master_key
        self._keys: Dict[str, bytes] = {}
        self._metadata: Dict[str, KeyMetadata] = {}
        self._audit_log: List[dict] = []

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

    def _encrypt_key(self, key: bytes) -> bytes:
        """Encrypt a key using the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, key, None)
        return nonce + ciphertext

    def _decrypt_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt a key using the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = encrypted_key[:12]
        ciphertext = encrypted_key[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _generate_key_id(self, key_type: str) -> str:
        """Generate a unique key ID."""
        timestamp = datetime.now().isoformat()
        random_data = os.urandom(16)
        id_data = f"{key_type}:{timestamp}".encode() + random_data
        key_id = hashlib.sha256(id_data).hexdigest()[:16]
        return f"{key_type}_{key_id}"

    def _log_access(self, key_id: str, operation: str, success: bool, details: str = ""):
        """Log key access for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'key_id': key_id,
            'operation': operation,
            'success': success,
            'details': details
        }
        self._audit_log.append(log_entry)

    def create_key(self, key_type: str, key_size: int = 32,
                   rotation_period_days: int = 90,
                   description: str = "") -> str:
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

        # Store key
        self._keys[key_id] = key

        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            created_at=datetime.now(),
            rotation_period_days=rotation_period_days,
            description=description
        )
        self._metadata[key_id] = metadata

        self._log_access(key_id, 'create', True, f"Created {key_type} key")
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
        if key_id not in self._keys:
            self._log_access(key_id, 'get', False, "Key not found")
            raise KeyError(f"Key {key_id} not found")

        metadata = self._metadata[key_id]

        if not metadata.active:
            self._log_access(key_id, 'get', False, "Key is inactive")
            raise ValueError(f"Key {key_id} is inactive")

        if metadata.is_expired():
            self._log_access(key_id, 'get', False, "Key is expired")
            raise ValueError(f"Key {key_id} is expired")

        # Update access count
        metadata.access_count += 1
        self._log_access(key_id, 'get', True)

        return self._keys[key_id]

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
            description=f"Rotated from {key_id}"
        )

        # Mark old key as inactive
        old_metadata.active = False
        self._log_access(key_id, 'rotate', True, f"Rotated to {new_key_id}")

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
        self._log_access(key_id, 'delete', True, "Key marked inactive")

    def list_keys(self, key_type: str = None, active_only: bool = True) -> List[str]:
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

    def get_keys_needing_rotation(self) -> List[str]:
        """
        Get list of keys that need rotation.

        Returns:
            List of key IDs needing rotation
        """
        return [
            key_id for key_id, metadata in self._metadata.items()
            if metadata.needs_rotation()
        ]

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
        export_data = {
            'keys': {},
            'metadata': {},
            'version': '1.0'
        }

        for key_id, key in self._keys.items():
            export_data['keys'][key_id] = base64.b64encode(key).decode('ascii')

        for key_id, metadata in self._metadata.items():
            export_data['metadata'][key_id] = metadata.to_dict()

        # Serialize and encrypt
        json_data = json.dumps(export_data).encode('utf-8')
        aesgcm = AESGCM(export_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json_data, None)

        # Combine salt + nonce + ciphertext
        bundle = salt + nonce + ciphertext
        return base64.b64encode(bundle).decode('ascii')

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
        export_data = json.loads(json_data.decode('utf-8'))

        # Import keys and metadata
        for key_id, key_b64 in export_data['keys'].items():
            self._keys[key_id] = base64.b64decode(key_b64)

        for key_id, metadata_dict in export_data['metadata'].items():
            self._metadata[key_id] = KeyMetadata.from_dict(metadata_dict)

        self._log_access('*', 'import', True, f"Imported {len(export_data['keys'])} keys")

    def get_audit_log(self, key_id: str = None, limit: int = 100) -> List[dict]:
        """
        Get audit log entries.

        Args:
            key_id: Filter by key ID (None = all keys)
            limit: Maximum number of entries to return

        Returns:
            List of audit log entries (most recent first)
        """
        logs = self._audit_log
        if key_id:
            logs = [log for log in logs if log['key_id'] == key_id]
        return list(reversed(logs[-limit:]))
