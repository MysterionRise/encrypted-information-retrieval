"""Runtime settings for the Encrypted IR API."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_origins(value: str | None) -> list[str]:
    if not value:
        return ["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:8000"]
    return [origin.strip() for origin in value.split(",") if origin.strip()]


def _load_master_key(value: str | None) -> tuple[bytes, bool]:
    if not value:
        return os.urandom(32), True

    key = base64.b64decode(value)
    if len(key) != 32:
        raise ValueError("ENCRYPTED_IR_MASTER_KEY_B64 must decode to exactly 32 bytes")
    return key, False


def _load_optional_bytes_b64(value: str | None, name: str) -> bytes | None:
    if not value:
        return None
    try:
        return base64.b64decode(value)
    except Exception as e:
        raise ValueError(f"{name} must be valid base64") from e


@dataclass(frozen=True)
class EncryptedIRSettings:
    """Application settings loaded from environment variables."""

    environment: str = "dev"
    database_url: str = "sqlite+pysqlite:///:memory:"
    master_key: bytes | None = field(default_factory=lambda: os.urandom(32))
    generated_ephemeral_master_key: bool = True
    raw_master_key_configured: bool = False
    auto_create_tables: bool = True
    cors_origins: list[str] = field(default_factory=lambda: _parse_origins(None))
    dev_auth_enabled: bool = True
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    kms_provider: str | None = None
    aws_kms_key_id: str | None = None
    aws_region: str | None = None
    encrypted_master_key: bytes | None = None

    @property
    def is_production(self) -> bool:
        return self.environment == "prod"

    @property
    def uses_kms(self) -> bool:
        return self.kms_provider is not None

    def validate(self) -> None:  # noqa: C901
        """Validate environment-specific safety rules."""
        if self.environment not in {"dev", "test", "prod"}:
            raise ValueError("ENCRYPTED_IR_ENV must be one of: dev, test, prod")

        if self.is_production:
            if self.dev_auth_enabled:
                raise ValueError("ENCRYPTED_IR_DEV_AUTH_ENABLED must be false in prod")
            if self.auto_create_tables:
                raise ValueError("ENCRYPTED_IR_AUTO_CREATE_TABLES must be false in prod")
            if self.raw_master_key_configured:
                raise ValueError("ENCRYPTED_IR_MASTER_KEY_B64 is not allowed in prod; use KMS")
            missing_oidc = [
                name
                for name, value in {
                    "ENCRYPTED_IR_OIDC_ISSUER": self.oidc_issuer,
                    "ENCRYPTED_IR_OIDC_AUDIENCE": self.oidc_audience,
                    "ENCRYPTED_IR_OIDC_JWKS_URL": self.oidc_jwks_url,
                }.items()
                if not value
            ]
            if missing_oidc:
                raise ValueError(f"Missing production OIDC settings: {', '.join(missing_oidc)}")
            if self.kms_provider != "aws":
                raise ValueError("ENCRYPTED_IR_KMS_PROVIDER=aws is required in prod")
            if not self.aws_kms_key_id:
                raise ValueError("ENCRYPTED_IR_AWS_KMS_KEY_ID is required in prod")
            if not self.encrypted_master_key:
                raise ValueError("ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64 is required in prod")

        if self.kms_provider and self.kms_provider != "aws":
            raise ValueError("Only ENCRYPTED_IR_KMS_PROVIDER=aws is currently supported")

        if self.kms_provider == "aws" and not self.encrypted_master_key:
            raise ValueError(
                "ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64 is required when KMS provider is aws"
            )

        if self.master_key is None and not self.uses_kms:
            raise ValueError("A master key or KMS configuration is required")

    @classmethod
    def from_env(cls) -> EncryptedIRSettings:
        raw_master_value = os.environ.get("ENCRYPTED_IR_MASTER_KEY_B64")
        kms_provider = os.environ.get("ENCRYPTED_IR_KMS_PROVIDER")
        if kms_provider:
            master_key = None
            generated = False
        else:
            master_key, generated = _load_master_key(raw_master_value)

        settings = cls(
            environment=os.environ.get("ENCRYPTED_IR_ENV", "dev").lower(),
            database_url=os.environ.get("DATABASE_URL", "sqlite+pysqlite:///:memory:"),
            master_key=master_key,
            generated_ephemeral_master_key=generated,
            raw_master_key_configured=raw_master_value is not None,
            auto_create_tables=_parse_bool(
                os.environ.get("ENCRYPTED_IR_AUTO_CREATE_TABLES"), default=True
            ),
            cors_origins=_parse_origins(os.environ.get("ENCRYPTED_IR_CORS_ORIGINS")),
            dev_auth_enabled=_parse_bool(os.environ.get("ENCRYPTED_IR_DEV_AUTH_ENABLED"), True),
            oidc_issuer=os.environ.get("ENCRYPTED_IR_OIDC_ISSUER"),
            oidc_audience=os.environ.get("ENCRYPTED_IR_OIDC_AUDIENCE"),
            oidc_jwks_url=os.environ.get("ENCRYPTED_IR_OIDC_JWKS_URL"),
            tenant_claim=os.environ.get("ENCRYPTED_IR_TENANT_CLAIM", "tenant_id"),
            roles_claim=os.environ.get("ENCRYPTED_IR_ROLES_CLAIM", "roles"),
            kms_provider=kms_provider,
            aws_kms_key_id=os.environ.get("ENCRYPTED_IR_AWS_KMS_KEY_ID"),
            aws_region=os.environ.get("AWS_REGION"),
            encrypted_master_key=_load_optional_bytes_b64(
                os.environ.get("ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64"),
                "ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64",
            ),
        )
        settings.validate()
        return settings
