"""Tests for cloud KMS provider module."""

import os
import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch

from encrypted_ir.kms_provider import KMSProvider, AWSKMSProvider, EnvelopeEncryption
from encrypted_ir.key_manager import KeyManager
from encrypted_ir.storage_backend import FileStorageBackend


class TestKMSProviderInterface:
    """Test that KMSProvider is a proper abstract interface."""

    def test_cannot_instantiate_abstract_class(self):
        """KMSProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            KMSProvider()

    def test_subclass_must_implement_all_methods(self):
        """Subclass missing methods cannot be instantiated."""

        class IncompleteProvider(KMSProvider):
            def encrypt(self, plaintext):
                pass

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_complete_subclass_can_be_instantiated(self):
        """Subclass implementing all methods can be instantiated."""

        class CompleteProvider(KMSProvider):
            def generate_data_key(self, key_spec="AES_256"):
                return os.urandom(32), os.urandom(64)

            def encrypt(self, plaintext):
                return plaintext

            def decrypt(self, ciphertext):
                return ciphertext

            def get_key_id(self):
                return "test-key"

            def key_exists(self):
                return True

        provider = CompleteProvider()
        assert provider.get_key_id() == "test-key"


class MockKMSProvider(KMSProvider):
    """In-memory mock KMS provider for testing."""

    def __init__(self, key_id="mock-key-123"):
        self._key_id = key_id
        self._xor_byte = 0x5A  # Simple XOR for mock encrypt/decrypt

    def generate_data_key(self, key_spec="AES_256"):
        size = 32 if key_spec == "AES_256" else 16
        plaintext = os.urandom(size)
        encrypted = self.encrypt(plaintext)
        return plaintext, encrypted

    def encrypt(self, plaintext):
        # Simple reversible transform for testing
        return bytes(b ^ self._xor_byte for b in plaintext)

    def decrypt(self, ciphertext):
        # XOR is its own inverse
        return bytes(b ^ self._xor_byte for b in ciphertext)

    def get_key_id(self):
        return self._key_id

    def key_exists(self):
        return True


class TestMockKMSProvider:
    """Test the mock provider itself to ensure tests are valid."""

    def test_encrypt_decrypt_roundtrip(self):
        provider = MockKMSProvider()
        data = os.urandom(32)
        encrypted = provider.encrypt(data)
        assert encrypted != data
        assert provider.decrypt(encrypted) == data

    def test_generate_data_key(self):
        provider = MockKMSProvider()
        plaintext, encrypted = provider.generate_data_key()
        assert len(plaintext) == 32
        assert provider.decrypt(encrypted) == plaintext

    def test_generate_data_key_aes_128(self):
        provider = MockKMSProvider()
        plaintext, encrypted = provider.generate_data_key("AES_128")
        assert len(plaintext) == 16


class TestKeyManagerFromKMS:
    """Test KeyManager.from_kms factory method."""

    def test_from_kms_creates_manager(self):
        """from_kms creates a functional KeyManager."""
        provider = MockKMSProvider()
        manager = KeyManager.from_kms(provider)

        key_id = manager.create_key("deterministic")
        key = manager.get_key(key_id)
        assert len(key) == 32

    def test_from_kms_stores_encrypted_master_key(self):
        """from_kms stores the encrypted master key for recovery."""
        provider = MockKMSProvider()
        manager = KeyManager.from_kms(provider)

        enc_mk = manager.get_encrypted_master_key()
        assert enc_mk is not None
        # Verify it can be decrypted back to the master key
        assert provider.decrypt(enc_mk) == manager.master_key

    def test_from_kms_stores_provider(self):
        """from_kms stores a reference to the KMS provider."""
        provider = MockKMSProvider()
        manager = KeyManager.from_kms(provider)
        assert manager.get_kms_provider() is provider

    def test_from_kms_recovery_with_encrypted_master_key(self):
        """Can recover a KeyManager using a stored encrypted master key."""
        provider = MockKMSProvider()

        # Create original manager
        manager1 = KeyManager.from_kms(provider)
        key_id = manager1.create_key("deterministic")
        original_key = manager1.get_key(key_id)
        enc_mk = manager1.get_encrypted_master_key()

        # Recover using encrypted master key (simulating restart)
        manager2 = KeyManager.from_kms(provider, encrypted_master_key=enc_mk)
        assert manager2.master_key == manager1.master_key

    def test_from_kms_with_storage_backend(self):
        """from_kms works with a storage backend for full persistence."""
        storage_dir = tempfile.mkdtemp()
        try:
            provider = MockKMSProvider()

            # Create manager with KMS + file backend
            master_key_for_backend = os.urandom(32)
            backend1 = FileStorageBackend(storage_dir, master_key_for_backend)
            manager1 = KeyManager.from_kms(provider, storage_backend=backend1)
            key_id = manager1.create_key("searchable", description="kms test key")
            original_key = manager1.get_key(key_id)
            enc_mk = manager1.get_encrypted_master_key()

            # Simulate restart: recover master key from KMS, reload from backend
            recovered_mk = provider.decrypt(enc_mk)
            backend2 = FileStorageBackend(storage_dir, master_key_for_backend)
            manager2 = KeyManager(master_key=recovered_mk, storage_backend=backend2)

            restored_key = manager2.get_key(key_id)
            assert restored_key == original_key
        finally:
            shutil.rmtree(storage_dir)

    def test_from_kms_different_providers_different_keys(self):
        """Different KMS providers produce different master keys."""
        provider1 = MockKMSProvider("key-1")
        provider2 = MockKMSProvider("key-2")

        manager1 = KeyManager.from_kms(provider1)
        manager2 = KeyManager.from_kms(provider2)

        assert manager1.master_key != manager2.master_key

    def test_no_kms_returns_none(self):
        """KeyManager without KMS returns None for KMS-specific getters."""
        manager = KeyManager()
        assert manager.get_encrypted_master_key() is None
        assert manager.get_kms_provider() is None

    def test_from_kms_all_key_operations_work(self):
        """Full lifecycle works with KMS-created manager."""
        provider = MockKMSProvider()
        manager = KeyManager.from_kms(provider)

        # Create
        key_id = manager.create_key("deterministic", description="lifecycle test")

        # Get
        key = manager.get_key(key_id)
        assert key is not None

        # Metadata
        meta = manager.get_metadata(key_id)
        assert meta.key_type == "deterministic"

        # Rotate
        new_key_id = manager.rotate_key(key_id)
        assert manager.get_metadata(key_id).active is False
        assert manager.get_metadata(new_key_id).active is True

        # Delete
        manager.delete_key(new_key_id)
        assert manager.get_metadata(new_key_id).active is False

        # Audit
        logs = manager.get_audit_log()
        assert len(logs) >= 3

    def test_from_kms_export_import(self):
        """Export/import works with KMS-created manager."""
        provider = MockKMSProvider()
        manager1 = KeyManager.from_kms(provider)

        key_id = manager1.create_key("deterministic")
        bundle = manager1.export_keys("password123")

        manager2 = KeyManager.from_kms(provider)
        manager2.import_keys(bundle, "password123")

        assert manager2.get_key(key_id) == manager1.get_key(key_id)


class TestEnvelopeEncryption:
    """Test the EnvelopeEncryption utility class."""

    def test_generate_master_key(self):
        provider = MockKMSProvider()
        envelope = EnvelopeEncryption(provider)

        plaintext, encrypted = envelope.generate_master_key()
        assert len(plaintext) == 32
        assert provider.decrypt(encrypted) == plaintext

    def test_wrap_unwrap_master_key(self):
        provider = MockKMSProvider()
        envelope = EnvelopeEncryption(provider)

        master_key = os.urandom(32)
        wrapped = envelope.wrap_master_key(master_key)
        unwrapped = envelope.unwrap_master_key(wrapped)
        assert unwrapped == master_key

    def test_encrypted_master_key_serialization(self):
        provider = MockKMSProvider()
        envelope = EnvelopeEncryption(provider)

        _, encrypted = envelope.generate_master_key()
        encoded = envelope.encrypted_master_key_to_str(encrypted)
        decoded = envelope.encrypted_master_key_from_str(encoded)
        assert decoded == encrypted
        assert isinstance(encoded, str)


class TestAWSKMSProvider:
    """Test AWS KMS provider with mocked boto3."""

    @pytest.fixture
    def mock_boto3_client(self):
        """Create a mock boto3 KMS client."""
        client = MagicMock()
        return client

    @pytest.fixture
    def provider(self, mock_boto3_client):
        """Create an AWSKMSProvider with mocked boto3."""
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_boto3_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            provider = AWSKMSProvider(key_id="alias/test-key", region="us-east-1")
            provider._client = mock_boto3_client
            return provider

    def test_generate_data_key(self, provider, mock_boto3_client):
        """generate_data_key calls AWS KMS GenerateDataKey."""
        plaintext_key = os.urandom(32)
        encrypted_key = os.urandom(64)
        mock_boto3_client.generate_data_key.return_value = {
            "Plaintext": plaintext_key,
            "CiphertextBlob": encrypted_key,
        }

        pt, ct = provider.generate_data_key()

        assert pt == plaintext_key
        assert ct == encrypted_key
        mock_boto3_client.generate_data_key.assert_called_once_with(
            KeyId="alias/test-key",
            KeySpec="AES_256",
        )

    def test_generate_data_key_aes_128(self, provider, mock_boto3_client):
        """generate_data_key passes key_spec to AWS."""
        mock_boto3_client.generate_data_key.return_value = {
            "Plaintext": os.urandom(16),
            "CiphertextBlob": os.urandom(64),
        }

        provider.generate_data_key("AES_128")

        mock_boto3_client.generate_data_key.assert_called_once_with(
            KeyId="alias/test-key",
            KeySpec="AES_128",
        )

    def test_encrypt(self, provider, mock_boto3_client):
        """encrypt calls AWS KMS Encrypt."""
        plaintext = os.urandom(32)
        ciphertext = os.urandom(64)
        mock_boto3_client.encrypt.return_value = {"CiphertextBlob": ciphertext}

        result = provider.encrypt(plaintext)

        assert result == ciphertext
        mock_boto3_client.encrypt.assert_called_once_with(
            KeyId="alias/test-key",
            Plaintext=plaintext,
        )

    def test_encrypt_rejects_oversized_plaintext(self, provider):
        """encrypt raises ValueError for data over 4096 bytes."""
        with pytest.raises(ValueError, match="4096"):
            provider.encrypt(os.urandom(4097))

    def test_decrypt(self, provider, mock_boto3_client):
        """decrypt calls AWS KMS Decrypt."""
        ciphertext = os.urandom(64)
        plaintext = os.urandom(32)
        mock_boto3_client.decrypt.return_value = {"Plaintext": plaintext}

        result = provider.decrypt(ciphertext)

        assert result == plaintext
        mock_boto3_client.decrypt.assert_called_once_with(CiphertextBlob=ciphertext)

    def test_get_key_id(self, provider):
        """get_key_id returns the configured key ID."""
        assert provider.get_key_id() == "alias/test-key"

    def test_key_exists_true(self, provider, mock_boto3_client):
        """key_exists returns True for enabled keys."""
        mock_boto3_client.describe_key.return_value = {
            "KeyMetadata": {"Enabled": True, "KeyState": "Enabled"}
        }
        assert provider.key_exists() is True

    def test_key_exists_disabled(self, provider, mock_boto3_client):
        """key_exists returns False for disabled keys."""
        mock_boto3_client.describe_key.return_value = {
            "KeyMetadata": {"Enabled": False, "KeyState": "Disabled"}
        }
        assert provider.key_exists() is False

    def test_key_exists_api_error(self, provider, mock_boto3_client):
        """key_exists returns False on API errors."""
        mock_boto3_client.describe_key.side_effect = Exception("AccessDenied")
        assert provider.key_exists() is False

    def test_boto3_not_installed(self):
        """AWSKMSProvider raises ImportError when boto3 is missing."""
        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(ImportError, match="boto3"):
                AWSKMSProvider(key_id="alias/test-key")

    def test_custom_session(self, mock_boto3_client):
        """AWSKMSProvider accepts a pre-configured boto3 session."""
        mock_session = MagicMock()
        mock_session.client.return_value = mock_boto3_client
        mock_boto3 = MagicMock()

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            provider = AWSKMSProvider(
                key_id="alias/test-key",
                region="eu-west-1",
                boto3_session=mock_session,
            )

        mock_session.client.assert_called_once_with("kms", region_name="eu-west-1")


class TestKeyManagerFromKMSWithAWSMock:
    """Integration tests: KeyManager.from_kms with mocked AWS KMS."""

    @pytest.fixture
    def aws_provider(self):
        """Create AWSKMSProvider with realistic mock."""
        mock_client = MagicMock()

        # Simulate real KMS behavior: encrypt wraps, decrypt unwraps
        def mock_generate_data_key(KeyId, KeySpec):
            size = 32 if KeySpec == "AES_256" else 16
            plaintext = os.urandom(size)
            tag = os.urandom(16)
            ciphertext = tag + plaintext  # Simple: tag + plaintext
            return {"Plaintext": plaintext, "CiphertextBlob": ciphertext}

        def mock_encrypt(KeyId, Plaintext):
            tag = os.urandom(16)
            ciphertext = tag + Plaintext
            return {"CiphertextBlob": ciphertext}

        def mock_decrypt(CiphertextBlob):
            plaintext = CiphertextBlob[16:]
            return {"Plaintext": plaintext}

        mock_client.generate_data_key.side_effect = mock_generate_data_key
        mock_client.encrypt.side_effect = mock_encrypt
        mock_client.decrypt.side_effect = mock_decrypt

        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            provider = AWSKMSProvider(
                key_id="arn:aws:kms:us-east-1:123:key/abc", region="us-east-1"
            )
            provider._client = mock_client
            return provider

    def test_full_workflow(self, aws_provider):
        """End-to-end: create manager via KMS, create/get keys, recover."""
        # Create manager with KMS
        manager = KeyManager.from_kms(aws_provider)
        enc_mk = manager.get_encrypted_master_key()

        # Create and use keys
        key_id = manager.create_key("deterministic", description="aws test")
        original_key = manager.get_key(key_id)

        # Recover master key from KMS-encrypted blob
        recovered_mk = aws_provider.decrypt(enc_mk)
        assert recovered_mk == manager.master_key

    def test_full_workflow_with_persistence(self, aws_provider):
        """End-to-end with file backend persistence."""
        storage_dir = tempfile.mkdtemp()
        try:
            backend_key = os.urandom(32)

            # Create and populate
            backend1 = FileStorageBackend(storage_dir, backend_key)
            manager1 = KeyManager.from_kms(aws_provider, storage_backend=backend1)
            enc_mk = manager1.get_encrypted_master_key()
            key_id = manager1.create_key("searchable")
            original_key = manager1.get_key(key_id)

            # Simulate restart: unwrap master key, reload backend
            recovered_mk = aws_provider.decrypt(enc_mk)
            backend2 = FileStorageBackend(storage_dir, backend_key)
            manager2 = KeyManager(master_key=recovered_mk, storage_backend=backend2)

            assert manager2.get_key(key_id) == original_key
        finally:
            shutil.rmtree(storage_dir)
