"""Settings shared by the operator tools: the API's database and master key."""

from __future__ import annotations

from encrypted_ir.master_key import resolve_master_key
from encrypted_ir.settings import EncryptedIRSettings


def load_settings_and_master_key() -> tuple[EncryptedIRSettings, bytes]:
    """Read the API's ``ENCRYPTED_IR_*`` settings and resolve its master key.

    Raises:
        ValueError: If the settings are invalid or no master key is configured. A generated
            ephemeral key is refused: it would not match the key the API used.
    """
    settings = EncryptedIRSettings.from_env()
    if settings.generated_ephemeral_master_key:
        raise ValueError(
            "No master key is configured; set the one the API uses "
            "(ENCRYPTED_IR_MASTER_KEY_B64 or the KMS settings)"
        )
    master_key, _ = resolve_master_key(settings)
    return settings, master_key
