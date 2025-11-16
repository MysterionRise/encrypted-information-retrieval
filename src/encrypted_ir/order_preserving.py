"""
Order-Preserving Encryption Module

Implements order-preserving encryption for range queries on encrypted numeric data.
Uses a simplified OPE scheme with format-preserving properties.

WARNING: OPE reveals ordering relationships and should only be used when
range queries are essential and the security trade-off is acceptable.

Use Case: Transaction amounts, dates, account balances where range queries
are required (e.g., "find transactions > $1000").

DEPRECATION NOTICE:
    This OPE implementation is DEPRECATED and will be removed in v2.0.0 (Q3 2025).

    Security Rationale:
    - Current OPE leaks global total order + frequency across all encrypted values
    - Fails to meet 2025 security standards (DORA Art. 9, PCI DSS 3.5.1)
    - Vulnerable to inference attacks in multi-tenant environments

    Migration Path:
    - Use ORE (Order-Revealing Encryption) with Lewi-Wu construction instead
    - See docs/migration/OPE_TO_ORE.md for migration guide
    - ORE provides pairwise comparison without global order leakage

    Timeline:
    - Deprecation: v1.0.0 (now)
    - Removal: v2.0.0 (Q3 2025)
"""

import os
import hmac
import hashlib
import struct
import warnings
from typing import Union

# NOTE: We use pycryptodome (>=3.19.0), NOT the deprecated pycrypto library.
# pycryptodome is actively maintained and secure. Bandit cannot distinguish between
# them because they share the same namespace, hence the nosec annotations.
from Crypto.Cipher import AES  # nosec B413
from Crypto.Util.Padding import pad, unpad  # nosec B413
import base64


class OrderPreservingEncryption:
    """
    Order-preserving encryption for numeric values.

    Encrypts numbers while preserving their order:
    if a < b, then encrypt(a) < encrypt(b)

    Note: This implementation uses a simplified approach suitable for
    demonstration. Production systems should use more sophisticated OPE schemes.
    """

    def __init__(self, key: bytes = None, plaintext_bits: int = 32, ciphertext_bits: int = 64):
        """
        Initialize order-preserving encryption.

        Args:
            key: 256-bit encryption key. If None, generates new key.
            plaintext_bits: Bit size of plaintext values (default: 32)
            ciphertext_bits: Bit size of ciphertext values (default: 64)

        .. deprecated:: 1.0.0
            OrderPreservingEncryption is deprecated and will be removed in v2.0.0.
            Use ORE (Order-Revealing Encryption) instead for improved security.
            See docs/migration/OPE_TO_ORE.md for migration guide.
        """
        # Emit deprecation warning
        warnings.warn(
            "OrderPreservingEncryption is deprecated and will be removed in v2.0.0 (Q3 2025). "
            "Current OPE leaks global order across all encrypted values, which fails "
            "2025 security standards (DORA Art. 9, PCI DSS 3.5.1). "
            "Migrate to ORE (Order-Revealing Encryption) with Lewi-Wu construction for "
            "improved security. See docs/migration/OPE_TO_ORE.md for migration guide.",
            DeprecationWarning,
            stacklevel=2,
        )

        if key is None:
            key = os.urandom(32)
        elif len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits)")

        self.key = key
        self.plaintext_bits = plaintext_bits
        self.ciphertext_bits = ciphertext_bits
        self.plaintext_max = (1 << plaintext_bits) - 1
        self.ciphertext_max = (1 << ciphertext_bits) - 1

        # Initialize mapping cache
        self._mapping_cache = {}

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new 256-bit key."""
        return os.urandom(32)

    def _deterministic_map(self, plaintext: int) -> int:
        """
        Create a deterministic order-preserving mapping.

        This is a simplified OPE scheme using PRF-based mapping.

        Args:
            plaintext: Integer value to map

        Returns:
            Order-preserving ciphertext integer
        """
        if plaintext < 0 or plaintext > self.plaintext_max:
            raise ValueError(f"Plaintext must be between 0 and {self.plaintext_max}")

        # Check cache
        if plaintext in self._mapping_cache:
            return self._mapping_cache[plaintext]

        # Use HMAC as PRF to generate deterministic but unpredictable mapping
        # We create a mapping that preserves order
        prf_input = struct.pack(">Q", plaintext)
        prf_output = hmac.new(self.key, prf_input, hashlib.sha256).digest()

        # Convert PRF output to integer
        prf_value = int.from_bytes(prf_output[:8], byteorder="big")

        # Scale to ciphertext range while preserving order
        # Simple linear scaling with noise
        base_mapping = (plaintext * self.ciphertext_max) // self.plaintext_max

        # Add small controlled noise that doesn't break ordering
        # Noise range is limited to avoid overlapping with adjacent values
        noise_range = max(1, self.ciphertext_max // (self.plaintext_max * 10))
        noise = prf_value % noise_range

        ciphertext = min(base_mapping + noise, self.ciphertext_max)

        # Cache the mapping
        self._mapping_cache[plaintext] = ciphertext

        return ciphertext

    def encrypt_int(self, plaintext: int) -> int:
        """
        Encrypt an integer value.

        Args:
            plaintext: Integer to encrypt (must be in valid range)

        Returns:
            Encrypted integer value (order-preserving)
        """
        return self._deterministic_map(plaintext)

    def encrypt_float(self, plaintext: float, precision: int = 2) -> int:
        """
        Encrypt a float value by converting to integer with fixed precision.

        Args:
            plaintext: Float value to encrypt
            precision: Number of decimal places to preserve

        Returns:
            Encrypted integer value
        """
        # Convert float to integer with fixed precision
        multiplier = 10**precision
        int_value = int(plaintext * multiplier)

        if int_value < 0:
            raise ValueError("Negative values not supported in this implementation")

        # Adjust range if needed
        if int_value > self.plaintext_max:
            raise ValueError(
                f"Value too large: {plaintext} (max: {self.plaintext_max / multiplier})"
            )

        return self.encrypt_int(int_value)

    def encrypt_amount(self, amount: float) -> int:
        """
        Encrypt a monetary amount (convenience method).

        Args:
            amount: Monetary amount (e.g., 1234.56)

        Returns:
            Encrypted integer value
        """
        return self.encrypt_float(amount, precision=2)

    def compare_encrypted(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Compare two encrypted values.

        Args:
            ciphertext1: First encrypted value
            ciphertext2: Second encrypted value

        Returns:
            -1 if ciphertext1 < ciphertext2
             0 if ciphertext1 == ciphertext2
             1 if ciphertext1 > ciphertext2
        """
        if ciphertext1 < ciphertext2:
            return -1
        elif ciphertext1 > ciphertext2:
            return 1
        else:
            return 0

    def range_query(
        self, encrypted_values: list[int], min_val: int = None, max_val: int = None
    ) -> list[int]:
        """
        Perform range query on encrypted values.

        Args:
            encrypted_values: List of encrypted values
            min_val: Minimum encrypted value (inclusive, None = no minimum)
            max_val: Maximum encrypted value (inclusive, None = no maximum)

        Returns:
            Filtered list of encrypted values within range
        """
        result = encrypted_values

        if min_val is not None:
            result = [v for v in result if v >= min_val]

        if max_val is not None:
            result = [v for v in result if v <= max_val]

        return result

    def encrypt_int_to_bytes(self, plaintext: int) -> bytes:
        """
        Encrypt integer and return as bytes.

        Args:
            plaintext: Integer to encrypt

        Returns:
            Encrypted value as bytes
        """
        ciphertext = self.encrypt_int(plaintext)
        return struct.pack(">Q", ciphertext)

    def encrypt_int_to_base64(self, plaintext: int) -> str:
        """
        Encrypt integer and encode as base64 string.

        Args:
            plaintext: Integer to encrypt

        Returns:
            Base64-encoded encrypted value
        """
        encrypted_bytes = self.encrypt_int_to_bytes(plaintext)
        return base64.b64encode(encrypted_bytes).decode("ascii")

    @staticmethod
    def decrypt_int_from_bytes(ciphertext: bytes) -> int:
        """
        Extract encrypted integer from bytes.

        Note: This doesn't actually decrypt to plaintext - OPE is one-way
        in this implementation for security. This just converts bytes to int.

        Args:
            ciphertext: Encrypted value as bytes

        Returns:
            Encrypted integer value
        """
        return struct.unpack(">Q", ciphertext)[0]

    @staticmethod
    def decrypt_int_from_base64(ciphertext_b64: str) -> int:
        """
        Extract encrypted integer from base64.

        Args:
            ciphertext_b64: Base64-encoded encrypted value

        Returns:
            Encrypted integer value
        """
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        return OrderPreservingEncryption.decrypt_int_from_bytes(ciphertext_bytes)

    def export_key(self) -> str:
        """Export key as base64 string."""
        return base64.b64encode(self.key).decode("ascii")

    @staticmethod
    def import_key(
        key_b64: str, plaintext_bits: int = 32, ciphertext_bits: int = 64
    ) -> "OrderPreservingEncryption":
        """
        Import key from base64 string.

        Args:
            key_b64: Base64-encoded key
            plaintext_bits: Bit size of plaintext values
            ciphertext_bits: Bit size of ciphertext values

        Returns:
            OrderPreservingEncryption instance with imported key
        """
        key = base64.b64decode(key_b64)
        return OrderPreservingEncryption(key, plaintext_bits, ciphertext_bits)

    def clear_cache(self):
        """Clear the mapping cache."""
        self._mapping_cache.clear()
