"""
Cloud KMS Provider Module

Provides a pluggable interface for cloud Key Management Service integration.
Enables envelope encryption: the cloud KMS protects the master key, which
in turn protects the local encryption keys managed by KeyManager.

Supported providers:
- AWS KMS (AWSKMSProvider)
- Azure Key Vault and GCP KMS can be added by implementing KMSProvider.

Usage:
    # AWS KMS envelope encryption
    provider = AWSKMSProvider(key_id="alias/my-key", region="us-east-1")
    manager = KeyManager.from_kms(provider)

    # Keys are now protected by AWS KMS via envelope encryption
    key_id = manager.create_key("deterministic")
"""

import abc
import base64
from typing import Optional


class KMSProvider(abc.ABC):
    """Abstract base class for cloud KMS providers.

    KMS providers implement envelope encryption: the cloud KMS key
    (Customer Master Key / CMK) wraps and unwraps data encryption keys
    used locally. The CMK never leaves the cloud KMS boundary.

    Implementations must be thread-safe for concurrent encrypt/decrypt
    operations.
    """

    @abc.abstractmethod
    def generate_data_key(self, key_spec: str = "AES_256") -> tuple[bytes, bytes]:
        """Generate a data encryption key via the KMS.

        The KMS generates a random data key and returns both the plaintext
        and a KMS-encrypted copy. The plaintext is used locally; the
        encrypted copy is stored for later retrieval.

        Args:
            key_spec: Key specification. "AES_256" (default) or "AES_128".

        Returns:
            Tuple of (plaintext_key, encrypted_key) where encrypted_key
            is the key material wrapped by the KMS master key.
        """

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using the KMS key.

        Used to wrap existing key material (e.g., an existing master key)
        for secure storage.

        Args:
            plaintext: Data to encrypt (max 4096 bytes for AWS KMS).

        Returns:
            Encrypted ciphertext blob.
        """

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using the KMS key.

        Used to unwrap previously encrypted key material.

        Args:
            ciphertext: Encrypted data blob.

        Returns:
            Decrypted plaintext bytes.
        """

    @abc.abstractmethod
    def get_key_id(self) -> str:
        """Get the KMS key identifier.

        Returns:
            The key ID, ARN, or alias identifying the KMS key.
        """

    @abc.abstractmethod
    def key_exists(self) -> bool:
        """Check if the configured KMS key exists and is usable.

        Returns:
            True if the key exists, is enabled, and the caller has
            permission to use it.
        """


class AWSKMSProvider(KMSProvider):
    """AWS KMS provider for envelope encryption.

    Uses AWS Key Management Service to generate, wrap, and unwrap
    data encryption keys. The AWS CMK (Customer Master Key) never
    leaves the KMS service boundary.

    Requires the ``boto3`` package and valid AWS credentials
    (via environment variables, IAM role, or AWS config file).

    Args:
        key_id: AWS KMS key identifier. Accepts:
            - Key ID: "1234abcd-12ab-34cd-56ef-1234567890ab"
            - Key ARN: "arn:aws:kms:us-east-1:123456789012:key/..."
            - Alias: "alias/my-key"
        region: AWS region (e.g., "us-east-1"). If None, uses the
            default region from AWS config/environment.
        boto3_session: Optional pre-configured boto3.Session. If None,
            creates a new session with default credentials.
    """

    def __init__(
        self,
        key_id: str,
        region: Optional[str] = None,
        boto3_session: Optional[object] = None,
    ):
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "boto3 is required for AWS KMS integration. "
                "Install it with: pip install 'encrypted-information-retrieval[aws]'"
            ) from e

        self._key_id = key_id

        if boto3_session is not None:
            self._client = boto3_session.client("kms", region_name=region)
        else:
            self._client = boto3.client("kms", region_name=region)

    def generate_data_key(self, key_spec: str = "AES_256") -> tuple[bytes, bytes]:
        """Generate a data key using AWS KMS GenerateDataKey API.

        Args:
            key_spec: "AES_256" (32 bytes) or "AES_128" (16 bytes).

        Returns:
            Tuple of (plaintext_key, encrypted_key).

        Raises:
            botocore.exceptions.ClientError: On AWS API errors.
        """
        response = self._client.generate_data_key(
            KeyId=self._key_id,
            KeySpec=key_spec,
        )
        return response["Plaintext"], response["CiphertextBlob"]

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using AWS KMS Encrypt API.

        Args:
            plaintext: Data to encrypt (max 4096 bytes).

        Returns:
            Encrypted ciphertext blob.

        Raises:
            botocore.exceptions.ClientError: On AWS API errors.
            ValueError: If plaintext exceeds 4096 bytes.
        """
        if len(plaintext) > 4096:
            raise ValueError("AWS KMS encrypt supports a maximum of 4096 bytes")

        response = self._client.encrypt(
            KeyId=self._key_id,
            Plaintext=plaintext,
        )
        return response["CiphertextBlob"]

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using AWS KMS Decrypt API.

        Args:
            ciphertext: Encrypted data blob from encrypt() or
                generate_data_key().

        Returns:
            Decrypted plaintext bytes.

        Raises:
            botocore.exceptions.ClientError: On AWS API errors.
        """
        response = self._client.decrypt(
            CiphertextBlob=ciphertext,
        )
        return response["Plaintext"]

    def get_key_id(self) -> str:
        """Get the configured AWS KMS key identifier."""
        return self._key_id

    def key_exists(self) -> bool:
        """Check if the KMS key exists and is enabled.

        Makes a DescribeKey API call to verify the key is accessible.

        Returns:
            True if key exists, is enabled, and caller has permission.
        """
        try:
            response = self._client.describe_key(KeyId=self._key_id)
            key_metadata = response["KeyMetadata"]
            return key_metadata["Enabled"] and key_metadata["KeyState"] == "Enabled"
        except Exception:
            return False


class EnvelopeEncryption:
    """Utility for envelope encryption workflows.

    Envelope encryption is the standard pattern for protecting data
    encryption keys with a cloud KMS:

    1. Generate a data encryption key (DEK) via KMS
    2. Use the plaintext DEK locally for encryption
    3. Store the KMS-encrypted DEK alongside the encrypted data
    4. To decrypt: unwrap the DEK via KMS, then decrypt locally

    This class provides helpers for the common envelope encryption
    pattern used with KeyManager.
    """

    def __init__(self, kms_provider: KMSProvider):
        self._provider = kms_provider

    def generate_master_key(self) -> tuple[bytes, bytes]:
        """Generate a master key protected by KMS.

        Returns:
            Tuple of (plaintext_master_key, encrypted_master_key).
            Store encrypted_master_key for later recovery.
        """
        return self._provider.generate_data_key("AES_256")

    def wrap_master_key(self, master_key: bytes) -> bytes:
        """Wrap an existing master key with KMS.

        Args:
            master_key: Existing 32-byte master key.

        Returns:
            KMS-encrypted master key blob.
        """
        return self._provider.encrypt(master_key)

    def unwrap_master_key(self, encrypted_master_key: bytes) -> bytes:
        """Unwrap a master key using KMS.

        Args:
            encrypted_master_key: KMS-encrypted master key blob.

        Returns:
            Plaintext 32-byte master key.
        """
        return self._provider.decrypt(encrypted_master_key)

    def encrypted_master_key_to_str(self, encrypted_master_key: bytes) -> str:
        """Encode encrypted master key for storage (e.g., in config files).

        Args:
            encrypted_master_key: KMS-encrypted master key blob.

        Returns:
            Base64-encoded string.
        """
        return base64.b64encode(encrypted_master_key).decode("ascii")

    def encrypted_master_key_from_str(self, encoded: str) -> bytes:
        """Decode a stored encrypted master key.

        Args:
            encoded: Base64-encoded encrypted master key string.

        Returns:
            Encrypted master key bytes.
        """
        return base64.b64decode(encoded)
