"""Application master-key resolution."""

from __future__ import annotations

from typing import Protocol

from .kms_provider import AWSKMSProvider, KMSProvider
from .settings import EncryptedIRSettings


class KMSProviderFactory(Protocol):
    """Factory protocol used by tests to inject fake KMS providers."""

    def __call__(self, settings: EncryptedIRSettings) -> KMSProvider:
        """Create a KMS provider from settings."""


def _aws_provider_from_settings(settings: EncryptedIRSettings) -> KMSProvider:
    if not settings.aws_kms_key_id:
        raise ValueError("ENCRYPTED_IR_AWS_KMS_KEY_ID is required for AWS KMS")
    return AWSKMSProvider(settings.aws_kms_key_id, region=settings.aws_region)


def resolve_master_key(
    settings: EncryptedIRSettings,
    kms_provider_factory: KMSProviderFactory | None = None,
) -> tuple[bytes, str]:
    """Resolve the app master key and return ``(key, source)``.

    In dev/test mode, this may return a raw env-provided or generated key. In
    production mode, settings validation ensures AWS KMS is used.
    """
    if settings.uses_kms:
        if settings.encrypted_master_key is None:
            raise ValueError("Encrypted master key is required for KMS unwrap")
        provider_factory = kms_provider_factory or _aws_provider_from_settings
        provider = provider_factory(settings)
        master_key = provider.decrypt(settings.encrypted_master_key)
        if len(master_key) != 32:
            raise ValueError("KMS-unwrapped master key must be exactly 32 bytes")
        return master_key, "aws-kms"

    if settings.master_key is None:
        raise ValueError("Master key is not configured")
    if len(settings.master_key) != 32:
        raise ValueError("Master key must be exactly 32 bytes")
    if settings.generated_ephemeral_master_key:
        return settings.master_key, "ephemeral-dev"
    return settings.master_key, "raw-env"
