"""
Blind Index Module

Implements HMAC-based blind indexes for equality search with reduced leakage.
Follows the CipherSweet pattern for scoped equality within tenants.

Use Case: Equality searches on account numbers, SSNs, emails where you want
to minimize global frequency analysis and scope leakage to tenant boundaries.

Security Properties:
- Equality leakage scoped to tenant (not global)
- Collision-resistant (2^128 security for HMAC-256-128)
- Preimage-resistant (cannot recover plaintext from index)
- Per-tenant salting reduces cross-tenant correlation

References:
- CipherSweet: https://ciphersweet.paragonie.com/internals/blind-index
- NIST FIPS 198-1: HMAC
- ADR-002: docs/DECISIONS.md
"""

import os
import hmac
import hashlib
import unicodedata
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
import base64


@dataclass
class BlindIndexConfig:
    """
    Configuration for blind index generation.

    Attributes:
        field_name: Name of the field being indexed (e.g., 'ssn', 'account_number')
        output_length: Length of index in bytes (default: 16 = 128 bits)
        case_sensitive: Whether to preserve case (default: False)
        unicode_normalize: Unicode normalization form (default: 'NFKC')
    """
    field_name: str
    output_length: int = 16
    case_sensitive: bool = False
    unicode_normalize: str = 'NFKC'


class BlindIndexGenerator:
    """
    Generate blind indexes for equality searches with scoped leakage.

    Uses HMAC-SHA256 with per-tenant salts to create searchable indexes
    that reveal equality only within tenant scope.

    Example:
        >>> generator = BlindIndexGenerator(tenant_id="tenant_123")
        >>> config = BlindIndexConfig(field_name="account_number")
        >>> index = generator.create_index("ACC-12345", config)
        >>> # Same value produces same index
        >>> assert index == generator.create_index("ACC-12345", config)
    """

    def __init__(self, tenant_id: str, master_key: bytes = None):
        """
        Initialize blind index generator for a tenant.

        Args:
            tenant_id: Unique tenant identifier
            master_key: Master key for deriving per-field keys (32 bytes)
                       If None, generates a new master key
        """
        if master_key is None:
            master_key = os.urandom(32)
        elif len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes (256 bits)")

        self.tenant_id = tenant_id
        self.master_key = master_key
        self._field_keys: Dict[str, bytes] = {}

    @staticmethod
    def generate_master_key() -> bytes:
        """Generate a new 256-bit master key."""
        return os.urandom(32)

    def _derive_field_key(self, field_name: str) -> bytes:
        """
        Derive a per-field key from the master key.

        Uses HMAC-SHA256 as a KDF to generate field-specific keys.

        Args:
            field_name: Name of the field

        Returns:
            32-byte derived key
        """
        if field_name in self._field_keys:
            return self._field_keys[field_name]

        # KDF: HMAC-SHA256(master_key, tenant_id || field_name)
        context = f"{self.tenant_id}:{field_name}".encode('utf-8')
        derived_key = hmac.new(
            self.master_key,
            context,
            hashlib.sha256
        ).digest()

        self._field_keys[field_name] = derived_key
        return derived_key

    def _normalize_value(self, value: str, config: BlindIndexConfig) -> str:
        """
        Normalize input value for consistent indexing.

        Args:
            value: Input value to normalize
            config: Index configuration

        Returns:
            Normalized value
        """
        # Strip leading/trailing whitespace
        normalized = value.strip()

        # Unicode normalization (e.g., decompose accented characters)
        if config.unicode_normalize:
            normalized = unicodedata.normalize(config.unicode_normalize, normalized)

        # Case normalization
        if not config.case_sensitive:
            normalized = normalized.lower()

        return normalized

    def create_index(self, value: str, config: BlindIndexConfig) -> str:
        """
        Create a blind index for a value.

        The index is deterministic: same value → same index (within tenant/field).

        Args:
            value: Value to index
            config: Index configuration

        Returns:
            Base64-encoded blind index

        Example:
            >>> generator = BlindIndexGenerator("tenant_1")
            >>> config = BlindIndexConfig(field_name="email")
            >>> index = generator.create_index("user@example.com", config)
        """
        # Normalize input
        normalized = self._normalize_value(value, config)

        # Get field-specific key
        field_key = self._derive_field_key(config.field_name)

        # Compute HMAC
        h = hmac.new(
            field_key,
            normalized.encode('utf-8'),
            hashlib.sha256
        )

        # Truncate to desired output length
        index_bytes = h.digest()[:config.output_length]

        # Encode as base64 for storage
        return base64.b64encode(index_bytes).decode('ascii')

    def create_index_raw(self, value: str, config: BlindIndexConfig) -> bytes:
        """
        Create a blind index and return raw bytes (not base64-encoded).

        Useful for binary storage or further processing.

        Args:
            value: Value to index
            config: Index configuration

        Returns:
            Raw index bytes
        """
        normalized = self._normalize_value(value, config)
        field_key = self._derive_field_key(config.field_name)

        h = hmac.new(
            field_key,
            normalized.encode('utf-8'),
            hashlib.sha256
        )

        return h.digest()[:config.output_length]

    def verify_index(self, value: str, index: str, config: BlindIndexConfig) -> bool:
        """
        Verify that an index matches a value.

        Args:
            value: Value to check
            index: Base64-encoded index to verify
            config: Index configuration

        Returns:
            True if index matches value, False otherwise
        """
        computed_index = self.create_index(value, config)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_index, index)

    def rotate_key(self, new_master_key: bytes):
        """
        Rotate the master key.

        After rotation, new indexes will use the new key.
        Old indexes remain valid until re-indexed.

        Args:
            new_master_key: New 256-bit master key

        Raises:
            ValueError: If key size is invalid
        """
        if len(new_master_key) != 32:
            raise ValueError("Master key must be 32 bytes (256 bits)")

        self.master_key = new_master_key
        self._field_keys.clear()  # Clear cached field keys

    def export_master_key(self) -> str:
        """
        Export master key as base64 string.

        WARNING: Store securely! Anyone with this key can generate indexes.

        Returns:
            Base64-encoded master key
        """
        return base64.b64encode(self.master_key).decode('ascii')

    @staticmethod
    def import_master_key(master_key_b64: str, tenant_id: str) -> 'BlindIndexGenerator':
        """
        Import master key from base64 string.

        Args:
            master_key_b64: Base64-encoded master key
            tenant_id: Tenant identifier

        Returns:
            BlindIndexGenerator with imported key
        """
        master_key = base64.b64decode(master_key_b64)
        return BlindIndexGenerator(tenant_id, master_key)


class BlindIndexSearch:
    """
    Helper class for searching records using blind indexes.

    Manages index generation and search operations for a tenant.

    Example:
        >>> search = BlindIndexSearch("tenant_1", master_key)
        >>> config = BlindIndexConfig(field_name="email")
        >>>
        >>> # Index records
        >>> records = {
        ...     "rec1": {"email": "alice@example.com", "name": "Alice"},
        ...     "rec2": {"email": "bob@example.com", "name": "Bob"}
        ... }
        >>> indexes = search.index_records(records, "email", config)
        >>>
        >>> # Search
        >>> results = search.search("alice@example.com", indexes, config)
        >>> print(results)  # ['rec1']
    """

    def __init__(self, tenant_id: str, master_key: bytes = None):
        """
        Initialize blind index search for a tenant.

        Args:
            tenant_id: Tenant identifier
            master_key: Master key for index generation
        """
        self.generator = BlindIndexGenerator(tenant_id, master_key)
        self.tenant_id = tenant_id

    def index_records(self, records: Dict[str, Dict], field_name: str,
                     config: BlindIndexConfig) -> Dict[str, str]:
        """
        Generate blind indexes for a set of records.

        Args:
            records: Dictionary of record_id -> record_data
            field_name: Name of field to index (must exist in records)
            config: Index configuration

        Returns:
            Dictionary of index -> record_id

        Example:
            >>> records = {
            ...     "r1": {"ssn": "123-45-6789"},
            ...     "r2": {"ssn": "987-65-4321"}
            ... }
            >>> config = BlindIndexConfig(field_name="ssn")
            >>> indexes = search.index_records(records, "ssn", config)
        """
        index_map: Dict[str, str] = {}

        for record_id, record_data in records.items():
            if field_name not in record_data:
                continue

            value = record_data[field_name]
            if value is None:
                continue

            index = self.generator.create_index(str(value), config)
            index_map[index] = record_id

        return index_map

    def search(self, query_value: str, index_map: Dict[str, str],
              config: BlindIndexConfig) -> list[str]:
        """
        Search for records matching a query value.

        Args:
            query_value: Value to search for
            index_map: Index map from index_records()
            config: Index configuration (must match indexing config)

        Returns:
            List of matching record IDs

        Example:
            >>> results = search.search("123-45-6789", index_map, config)
        """
        query_index = self.generator.create_index(query_value, config)

        if query_index in index_map:
            return [index_map[query_index]]
        else:
            return []

    def multi_search(self, query_values: list[str], index_map: Dict[str, str],
                    config: BlindIndexConfig) -> Dict[str, list[str]]:
        """
        Search for multiple values at once.

        Args:
            query_values: List of values to search for
            index_map: Index map from index_records()
            config: Index configuration

        Returns:
            Dictionary of query_value -> list of matching record IDs
        """
        results = {}
        for query_value in query_values:
            results[query_value] = self.search(query_value, index_map, config)
        return results


# Convenience functions for common use cases

def create_ssn_index(ssn: str, tenant_id: str, master_key: bytes) -> str:
    """
    Create a blind index for an SSN.

    Args:
        ssn: Social Security Number (any format)
        tenant_id: Tenant identifier
        master_key: Master key

    Returns:
        Blind index for SSN
    """
    generator = BlindIndexGenerator(tenant_id, master_key)
    config = BlindIndexConfig(
        field_name="ssn",
        case_sensitive=False,
        output_length=16
    )
    return generator.create_index(ssn, config)


def create_email_index(email: str, tenant_id: str, master_key: bytes) -> str:
    """
    Create a blind index for an email address.

    Args:
        email: Email address
        tenant_id: Tenant identifier
        master_key: Master key

    Returns:
        Blind index for email
    """
    generator = BlindIndexGenerator(tenant_id, master_key)
    config = BlindIndexConfig(
        field_name="email",
        case_sensitive=False,
        output_length=16
    )
    return generator.create_index(email, config)


def create_account_index(account_number: str, tenant_id: str, master_key: bytes) -> str:
    """
    Create a blind index for an account number.

    Args:
        account_number: Account number
        tenant_id: Tenant identifier
        master_key: Master key

    Returns:
        Blind index for account number
    """
    generator = BlindIndexGenerator(tenant_id, master_key)
    config = BlindIndexConfig(
        field_name="account_number",
        case_sensitive=True,  # Account numbers are usually case-sensitive
        output_length=16
    )
    return generator.create_index(account_number, config)
