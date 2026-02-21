"""
Order-Revealing Encryption (ORE) Module

Implements the Lewi-Wu ORE construction for secure range queries on encrypted
numeric data. Unlike OPE (Order-Preserving Encryption), ORE does not leak
global ordering from individual ciphertexts.

Security Properties:
- Pairwise comparison only: ordering is revealed only when two ciphertexts
  are explicitly compared using the compare() method
- No global order leakage: a single ciphertext reveals nothing about the
  plaintext value's rank among all encrypted values
- Per-key isolation: ciphertexts from different keys cannot be compared

Algorithm: ore-lewi-wu (based on Lewi & Wu, 2016)
Reference: https://eprint.iacr.org/2016/612

Leakage Profile:
    Leakage(ORE) = { compare(encrypt(a), encrypt(b)) -> (a < b, a = b, a > b) }
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct


class ORE:
    """
    Order-Revealing Encryption using the Lewi-Wu construction.

    Encrypts numeric values such that pairwise comparison reveals ordering
    without leaking global order from individual ciphertexts.

    The ciphertext is split into left and right components per block position.
    Comparison works by matching left components (which encode the prefix)
    and recovering the block difference from right components using modular
    arithmetic. This ensures that only the explicit compare() call reveals
    ordering—raw ciphertext bytes are not sortable.
    """

    ALGORITHM = "ore-lewi-wu"
    KEY_SIZE = 32
    BLOCK_BITS = 8
    NUM_BLOCKS = 4  # 4 blocks of 8 bits = 32-bit plaintext
    PLAINTEXT_BITS = NUM_BLOCKS * BLOCK_BITS
    PLAINTEXT_MAX = (1 << PLAINTEXT_BITS) - 1
    LEFT_SIZE = 8  # bytes per left component (truncated HMAC-SHA256)
    MODULUS = 1 << 16  # 65536 — large enough that block diffs [−255,255] are unambiguous
    VERSION_TAG = 0x01

    def __init__(self, key: bytes = None):
        """
        Initialize ORE with a 256-bit key.

        Args:
            key: 32-byte encryption key. If None, generates a new key.

        Raises:
            ValueError: If key is not exactly 32 bytes.
        """
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        elif len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes ({self.KEY_SIZE * 8} bits)")

        self.key = key
        self._k_left = hmac.new(key, b"ore-lewi-wu-left", hashlib.sha256).digest()
        self._k_right = hmac.new(key, b"ore-lewi-wu-right", hashlib.sha256).digest()
        self._cache = {}

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new 256-bit key for ORE."""
        return os.urandom(ORE.KEY_SIZE)

    def _get_blocks(self, plaintext: int) -> list[int]:
        """Split plaintext into byte-sized blocks (MSB first)."""
        blocks = []
        for i in range(self.NUM_BLOCKS):
            shift = self.PLAINTEXT_BITS - (i + 1) * self.BLOCK_BITS
            block = (plaintext >> shift) & ((1 << self.BLOCK_BITS) - 1)
            blocks.append(block)
        return blocks

    def _prf(self, subkey: bytes, data: bytes) -> bytes:
        """Pseudorandom function based on HMAC-SHA256."""
        return hmac.new(subkey, data, hashlib.sha256).digest()

    def _encode_position_prefix(self, position: int, prefix_blocks: list[int]) -> bytes:
        """Encode block position and prefix for PRF input."""
        data = struct.pack(">B", position)
        for b in prefix_blocks:
            data += struct.pack(">B", b)
        return data

    def encrypt_int(self, plaintext: int) -> bytes:
        """
        Encrypt an integer value using ORE.

        The returned ciphertext is NOT directly comparable via byte ordering.
        Use compare() for pairwise comparison.

        Args:
            plaintext: Non-negative integer (0 to 2^32 - 1).

        Returns:
            ORE ciphertext as bytes.

        Raises:
            ValueError: If plaintext is negative or exceeds 2^32 - 1.
        """
        if plaintext < 0 or plaintext > self.PLAINTEXT_MAX:
            raise ValueError(f"Plaintext must be between 0 and {self.PLAINTEXT_MAX}")

        if plaintext in self._cache:
            return self._cache[plaintext]

        blocks = self._get_blocks(plaintext)
        left_parts = []
        right_parts = []

        for i in range(self.NUM_BLOCKS):
            prefix = blocks[:i]
            pos_prefix = self._encode_position_prefix(i, prefix)

            # Left component: truncated PRF output for prefix matching
            left_val = self._prf(self._k_left, pos_prefix)[: self.LEFT_SIZE]
            left_parts.append(left_val)

            # Right component: block value masked with PRF-derived offset
            h_bytes = self._prf(self._k_right, pos_prefix)
            h = int.from_bytes(h_bytes[:4], "big") % self.MODULUS
            right_val = (blocks[i] + h) % self.MODULUS
            right_parts.append(right_val)

        # Serialize: [version][num_blocks][left_0..left_n][right_0..right_n]
        result = struct.pack(">BB", self.VERSION_TAG, self.NUM_BLOCKS)
        for lp in left_parts:
            result += lp
        for rv in right_parts:
            result += struct.pack(">H", rv)

        self._cache[plaintext] = result
        return result

    def encrypt_float(self, plaintext: float, precision: int = 2) -> bytes:
        """
        Encrypt a float value with fixed-point precision.

        Args:
            plaintext: Non-negative float value.
            precision: Number of decimal places to preserve (default: 2).

        Returns:
            ORE ciphertext as bytes.

        Raises:
            ValueError: If value is negative or too large for the plaintext space.
        """
        multiplier = 10**precision
        int_value = int(plaintext * multiplier)

        if int_value < 0:
            raise ValueError("Negative values not supported")
        if int_value > self.PLAINTEXT_MAX:
            raise ValueError(
                f"Value too large: {plaintext} (max: {self.PLAINTEXT_MAX / multiplier})"
            )

        return self.encrypt_int(int_value)

    def encrypt_amount(self, amount: float) -> bytes:
        """
        Encrypt a monetary amount (2 decimal places).

        Args:
            amount: Non-negative monetary amount (e.g., 1234.56).

        Returns:
            ORE ciphertext as bytes.
        """
        return self.encrypt_float(amount, precision=2)

    def _deserialize(self, ciphertext: bytes):
        """Parse ciphertext into left components and right values."""
        if len(ciphertext) < 2:
            raise ValueError("Invalid ciphertext: too short")

        version, num_blocks = struct.unpack(">BB", ciphertext[:2])
        if version != self.VERSION_TAG:
            raise ValueError(f"Unknown ciphertext version: {version}")

        expected_len = 2 + num_blocks * self.LEFT_SIZE + num_blocks * 2
        if len(ciphertext) != expected_len:
            raise ValueError(
                f"Invalid ciphertext length: expected {expected_len}, got {len(ciphertext)}"
            )

        offset = 2
        left_parts = []
        for _ in range(num_blocks):
            left_parts.append(ciphertext[offset : offset + self.LEFT_SIZE])
            offset += self.LEFT_SIZE

        right_parts = []
        for _ in range(num_blocks):
            (rv,) = struct.unpack(">H", ciphertext[offset : offset + 2])
            right_parts.append(rv)
            offset += 2

        return left_parts, right_parts, num_blocks

    def compare(self, ciphertext1: bytes, ciphertext2: bytes) -> int:
        """
        Compare two ORE ciphertexts to determine plaintext ordering.

        This is the only way to determine ordering—raw ciphertext bytes are
        not sortable. Both ciphertexts must have been encrypted under the
        same key.

        Args:
            ciphertext1: First ORE ciphertext.
            ciphertext2: Second ORE ciphertext.

        Returns:
            -1 if plaintext1 < plaintext2
             0 if plaintext1 == plaintext2
             1 if plaintext1 > plaintext2

        Raises:
            ValueError: If ciphertexts are from different keys or malformed.
        """
        left1, right1, n1 = self._deserialize(ciphertext1)
        left2, right2, n2 = self._deserialize(ciphertext2)

        if n1 != n2:
            raise ValueError("Cannot compare ciphertexts with different block counts")

        for i in range(n1):
            if left1[i] != left2[i]:
                raise ValueError("Cannot compare ciphertexts encrypted under different keys")

            diff = (right1[i] - right2[i]) % self.MODULUS
            if diff == 0:
                continue
            elif diff <= self.MODULUS // 2:
                return 1  # ct1 > ct2
            else:
                return -1  # ct1 < ct2

        return 0

    def range_query(
        self,
        encrypted_values: list[bytes],
        min_val: bytes | None = None,
        max_val: bytes | None = None,
    ) -> list[bytes]:
        """
        Perform range query on ORE-encrypted values.

        Args:
            encrypted_values: List of ORE ciphertexts.
            min_val: Minimum ORE ciphertext (inclusive). None for no minimum.
            max_val: Maximum ORE ciphertext (inclusive). None for no maximum.

        Returns:
            Filtered list of ciphertexts within range.
        """
        result = []
        for v in encrypted_values:
            if min_val is not None and self.compare(v, min_val) < 0:
                continue
            if max_val is not None and self.compare(v, max_val) > 0:
                continue
            result.append(v)
        return result

    def encrypt_to_base64(self, plaintext: int) -> str:
        """
        Encrypt integer and return base64-encoded ciphertext.

        Args:
            plaintext: Non-negative integer to encrypt.

        Returns:
            Base64-encoded ORE ciphertext string.
        """
        return base64.b64encode(self.encrypt_int(plaintext)).decode("ascii")

    @staticmethod
    def decrypt_from_base64(ciphertext_b64: str) -> bytes:
        """
        Decode base64-encoded ORE ciphertext.

        Note: ORE is one-way. This recovers ciphertext bytes, not plaintext.

        Args:
            ciphertext_b64: Base64-encoded ciphertext.

        Returns:
            ORE ciphertext bytes (for use with compare()).
        """
        return base64.b64decode(ciphertext_b64)

    def export_key(self) -> str:
        """Export key as base64 string."""
        return base64.b64encode(self.key).decode("ascii")

    @staticmethod
    def import_key(key_b64: str) -> ORE:
        """
        Import key from base64 string.

        Args:
            key_b64: Base64-encoded 32-byte key.

        Returns:
            ORE instance with imported key.
        """
        key = base64.b64decode(key_b64)
        return ORE(key)

    def clear_cache(self):
        """Clear the encryption cache."""
        self._cache.clear()
