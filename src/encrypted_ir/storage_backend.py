"""
Storage Backend Module

Provides a pluggable interface for persistent key storage and a file-based
encrypted implementation. Enables KeyManager to persist keys across process
restarts.

The StorageBackend ABC defines the contract for any storage implementation.
The FileStorageBackend provides encrypted file-based storage using AES-GCM.
"""

from __future__ import annotations

import abc
import base64
import fcntl
import json
import os
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, insert, select
from sqlalchemy.engine import Engine

from .database import audit_log_table, create_database_schema, key_store_table


class StorageBackend(abc.ABC):
    """Abstract base class for key storage backends.

    Implementations must provide thread-safe persistent storage for:
    - Encrypted key material
    - Key metadata
    - Audit log entries

    Future implementations could include database-backed storage,
    HSM/KMS integration, or cloud key management services.
    """

    @abc.abstractmethod
    def save_key(self, key_id: str, encrypted_key: bytes, metadata: dict) -> None:
        """Persist a key and its metadata.

        Args:
            key_id: Unique key identifier.
            encrypted_key: Key material encrypted with the master key.
            metadata: Key metadata as a dictionary.
        """

    @abc.abstractmethod
    def load_key(self, key_id: str) -> tuple[bytes, dict] | None:
        """Load a key and its metadata.

        Args:
            key_id: Unique key identifier.

        Returns:
            Tuple of (encrypted_key, metadata_dict) or None if not found.
        """

    @abc.abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Remove a key from storage.

        Args:
            key_id: Unique key identifier.

        Returns:
            True if the key was found and deleted, False otherwise.
        """

    @abc.abstractmethod
    def list_keys(self) -> list[str]:
        """List all stored key IDs.

        Returns:
            List of key ID strings.
        """

    @abc.abstractmethod
    def save_audit_entry(self, entry: dict) -> None:
        """Persist an audit log entry.

        Args:
            entry: Audit log entry as a dictionary.
        """

    @abc.abstractmethod
    def load_audit_log(self, key_id: str | None = None, limit: int = 100) -> list[dict]:
        """Load audit log entries.

        Args:
            key_id: Filter by key ID (None for all).
            limit: Maximum entries to return.

        Returns:
            List of audit entries, most recent first.
        """

    @abc.abstractmethod
    def load_all(self) -> tuple[dict[str, bytes], dict[str, dict]]:
        """Load all keys and metadata from storage.

        Returns:
            Tuple of (keys_dict, metadata_dict) where keys_dict maps
            key_id -> encrypted_key_bytes and metadata_dict maps
            key_id -> metadata_dict.
        """


class FileStorageBackend(StorageBackend):
    """File-based encrypted storage backend.

    Stores keys and metadata in an AES-GCM encrypted JSON file on disk.
    Uses file-level locking to prevent concurrent corruption.

    Directory structure:
        storage_dir/
            keystore.enc    - Encrypted key store (keys + metadata)
            audit.jsonl     - Append-only audit log (one JSON entry per line)
    """

    KEYSTORE_FILENAME = "keystore.enc"
    AUDIT_FILENAME = "audit.jsonl"

    def __init__(self, storage_dir: str, encryption_key: bytes):
        """Initialize file storage backend.

        Args:
            storage_dir: Path to directory for storing encrypted files.
                        Created if it doesn't exist.
            encryption_key: 32-byte AES-256 key for encrypting the store file.
                          Typically the master key or a key derived from it.

        Raises:
            ValueError: If encryption_key is not 32 bytes.
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes (256 bits)")

        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._encryption_key = encryption_key
        self._keystore_path = self._storage_dir / self.KEYSTORE_FILENAME
        self._audit_path = self._storage_dir / self.AUDIT_FILENAME

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data with AES-GCM. Returns nonce + ciphertext."""
        aesgcm = AESGCM(self._encryption_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return cast(bytes, nonce + ciphertext)

    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data encrypted with _encrypt_data."""
        aesgcm = AESGCM(self._encryption_key)
        nonce = data[:12]
        ciphertext = data[12:]
        return cast(bytes, aesgcm.decrypt(nonce, ciphertext, None))

    def _read_store(self) -> dict[str, Any]:
        """Read and decrypt the key store file.

        Returns:
            Deserialized store dict with 'keys' and 'metadata' entries,
            or empty store if file doesn't exist.
        """
        if not self._keystore_path.exists():
            return {"keys": {}, "metadata": {}}

        with open(self._keystore_path, "rb") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                encrypted = f.read()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        plaintext = self._decrypt_data(encrypted)
        return cast(dict[str, Any], json.loads(plaintext.decode("utf-8")))

    def _write_store(self, store: dict) -> None:
        """Encrypt and write the key store file atomically.

        Uses write-to-temp-then-rename for crash safety.
        """
        plaintext = json.dumps(store).encode("utf-8")
        encrypted = self._encrypt_data(plaintext)

        tmp_path = self._keystore_path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        os.replace(str(tmp_path), str(self._keystore_path))

    def save_key(self, key_id: str, encrypted_key: bytes, metadata: dict) -> None:
        store = self._read_store()
        store["keys"][key_id] = base64.b64encode(encrypted_key).decode("ascii")
        store["metadata"][key_id] = metadata
        self._write_store(store)

    def load_key(self, key_id: str) -> tuple[bytes, dict] | None:
        store = self._read_store()
        if key_id not in store["keys"]:
            return None
        encrypted_key = base64.b64decode(store["keys"][key_id])
        metadata = store["metadata"].get(key_id, {})
        return encrypted_key, metadata

    def delete_key(self, key_id: str) -> bool:
        store = self._read_store()
        if key_id not in store["keys"]:
            return False
        del store["keys"][key_id]
        store["metadata"].pop(key_id, None)
        self._write_store(store)
        return True

    def list_keys(self) -> list[str]:
        store = self._read_store()
        return list(store["keys"].keys())

    def save_audit_entry(self, entry: dict) -> None:
        line = json.dumps(entry) + "\n"
        with open(self._audit_path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def load_audit_log(self, key_id: str | None = None, limit: int = 100) -> list[dict]:
        if not self._audit_path.exists():
            return []

        entries = []
        with open(self._audit_path) as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if key_id is None or entry.get("key_id") == key_id:
                        entries.append(entry)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        return list(reversed(entries[-limit:]))

    def load_all(self) -> tuple[dict[str, bytes], dict[str, dict]]:
        store = self._read_store()
        keys = {key_id: base64.b64decode(key_b64) for key_id, key_b64 in store["keys"].items()}
        return keys, store["metadata"]


class DatabaseStorageBackend(StorageBackend):
    """SQL database-backed key storage scoped to one tenant.

    The backend stores keys encrypted by ``KeyManager`` and keeps tenant data
    isolated by adding ``tenant_id`` to every query. It is intentionally small:
    KMS/HSM wrapping remains the responsibility of ``KeyManager.from_kms``.
    """

    def __init__(self, engine: Engine, tenant_id: str, auto_create_tables: bool = False):
        self._engine = engine
        self._tenant_id = tenant_id
        if auto_create_tables:
            create_database_schema(engine)

    @property
    def tenant_id(self) -> str:
        """Tenant identifier this backend is scoped to."""
        return self._tenant_id

    def save_key(self, key_id: str, encrypted_key: bytes, metadata: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                delete(key_store_table).where(
                    key_store_table.c.tenant_id == self._tenant_id,
                    key_store_table.c.key_id == key_id,
                )
            )
            conn.execute(
                insert(key_store_table).values(
                    tenant_id=self._tenant_id,
                    key_id=key_id,
                    encrypted_key=encrypted_key,
                    metadata_json=metadata,
                )
            )

    def load_key(self, key_id: str) -> tuple[bytes, dict] | None:
        stmt = select(key_store_table.c.encrypted_key, key_store_table.c.metadata_json).where(
            key_store_table.c.tenant_id == self._tenant_id,
            key_store_table.c.key_id == key_id,
        )
        with self._engine.connect() as conn:
            row = conn.execute(stmt).first()
        if row is None:
            return None
        return row.encrypted_key, dict(row.metadata_json)

    def delete_key(self, key_id: str) -> bool:
        with self._engine.begin() as conn:
            result = conn.execute(
                delete(key_store_table).where(
                    key_store_table.c.tenant_id == self._tenant_id,
                    key_store_table.c.key_id == key_id,
                )
            )
        return bool(result.rowcount > 0)

    def list_keys(self) -> list[str]:
        stmt = select(key_store_table.c.key_id).where(
            key_store_table.c.tenant_id == self._tenant_id
        )
        with self._engine.connect() as conn:
            return [row.key_id for row in conn.execute(stmt)]

    def save_audit_entry(self, entry: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                insert(audit_log_table).values(
                    tenant_id=self._tenant_id,
                    key_id=entry.get("key_id"),
                    entry_json=entry,
                )
            )

    def load_audit_log(self, key_id: str | None = None, limit: int = 100) -> list[dict]:
        stmt = select(audit_log_table.c.entry_json).where(
            audit_log_table.c.tenant_id == self._tenant_id
        )
        if key_id is not None:
            stmt = stmt.where(audit_log_table.c.key_id == key_id)
        stmt = stmt.order_by(audit_log_table.c.id.desc()).limit(limit)

        with self._engine.connect() as conn:
            return [dict(row.entry_json) for row in conn.execute(stmt)]

    def load_all(self) -> tuple[dict[str, bytes], dict[str, dict]]:
        stmt = select(
            key_store_table.c.key_id,
            key_store_table.c.encrypted_key,
            key_store_table.c.metadata_json,
        ).where(key_store_table.c.tenant_id == self._tenant_id)

        keys: dict[str, bytes] = {}
        metadata: dict[str, dict] = {}
        with self._engine.connect() as conn:
            for row in conn.execute(stmt):
                keys[row.key_id] = row.encrypted_key
                metadata[row.key_id] = dict(row.metadata_json)
        return keys, metadata
