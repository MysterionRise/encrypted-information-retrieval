"""
Deterministic Encryption Module

Provides deterministic encryption for equality searches on encrypted data.
Uses AES-SIV (Synthetic IV) for deterministic authenticated encryption.

Use Case: Account numbers, customer IDs, SSN/Tax IDs where equality
searches are needed but pattern analysis risk is acceptable.
"""

import os
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import base64


class DeterministicEncryption:
    """
    Deterministic encryption using AES-SIV.

    Same plaintext always produces the same ciphertext, enabling equality searches.
    Provides authenticity through built-in MAC.
    """

    def __init__(self, key: bytes = None):
        """
        Initialize deterministic encryption.

        Args:
            key: 512-bit key (64 bytes) for AES-SIV. If None, generates a new key.
        """
        if key is None:
            key = AESSIV.generate_key(bit_length=512)
        elif len(key) != 64:
            raise ValueError("Key must be 64 bytes (512 bits) for AES-SIV")

        self.key = key
        self._cipher = AESSIV(key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new 512-bit key for AES-SIV."""
        return AESSIV.generate_key(bit_length=512)

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive a key from a password using PBKDF2.

        Args:
            password: Password string
            salt: Salt for key derivation. If None, generates random salt.

        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=480000,  # OWASP recommendation for 2024
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt(self, plaintext: Union[str, bytes], associated_data: list[bytes] = None) -> bytes:
        """
        Encrypt data deterministically.

        Args:
            plaintext: Data to encrypt (str or bytes)
            associated_data: Optional list of associated data for authenticated encryption

        Returns:
            Encrypted ciphertext (bytes)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        if associated_data is None:
            associated_data = []

        ciphertext = self._cipher.encrypt(plaintext, associated_data)
        return ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: list[bytes] = None) -> bytes:
        """
        Decrypt data.

        Args:
            ciphertext: Encrypted data
            associated_data: Optional list of associated data (must match encryption)

        Returns:
            Decrypted plaintext (bytes)

        Raises:
            InvalidTag: If authentication fails
        """
        if associated_data is None:
            associated_data = []

        try:
            plaintext = self._cipher.decrypt(ciphertext, associated_data)
            return plaintext
        except InvalidTag as e:
            raise ValueError("Decryption failed - invalid key or corrupted data") from e

    def encrypt_to_base64(
        self, plaintext: Union[str, bytes], associated_data: list[bytes] = None
    ) -> str:
        """
        Encrypt and encode as base64 string for storage.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional associated data

        Returns:
            Base64-encoded ciphertext
        """
        ciphertext = self.encrypt(plaintext, associated_data)
        return base64.b64encode(ciphertext).decode("ascii")

    def decrypt_from_base64(
        self, ciphertext_b64: str, associated_data: list[bytes] = None
    ) -> bytes:
        """
        Decrypt from base64-encoded ciphertext.

        Args:
            ciphertext_b64: Base64-encoded ciphertext
            associated_data: Optional associated data

        Returns:
            Decrypted plaintext (bytes)
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        return self.decrypt(ciphertext, associated_data)

    def search_index(self, plaintext: Union[str, bytes]) -> str:
        """
        Create a searchable index value for equality comparisons.

        Args:
            plaintext: Data to create index for

        Returns:
            Base64-encoded deterministic hash suitable for indexing
        """
        # For deterministic searchability, we encrypt and return the result
        # Same plaintext will always produce the same index
        return self.encrypt_to_base64(plaintext)

    def export_key(self) -> str:
        """Export key as base64 string."""
        return base64.b64encode(self.key).decode("ascii")

    @staticmethod
    def import_key(key_b64: str) -> "DeterministicEncryption":
        """
        Import key from base64 string.

        Args:
            key_b64: Base64-encoded key

        Returns:
            DeterministicEncryption instance with imported key
        """
        key = base64.b64decode(key_b64)
        return DeterministicEncryption(key)
