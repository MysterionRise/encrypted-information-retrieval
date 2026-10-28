"""
Order-Revealing Encryption (ORE) Module: research prototype, not audited.

What this is: a CLWW-style prefix ORE over 32-bit integers split into four
8-bit blocks (Chenette, Lewi, Weis and Wu, FSE 2016). For block i the
ciphertext stores a left value HMAC(k_left, i || prefix)[:8], where prefix is
blocks 0..i-1, and a right value (block_i + HMAC(k_right, i || prefix)) mod 2^16.

What this is not: the Lewi-Wu (2016) left/right construction. In Lewi-Wu,
stored right ciphertexts cannot be compared with each other; here they can.
The ALGORITHM identifier is "ore-clww-prototype". The HMAC subkey labels still
say "ore-lewi-wu" because they define the ciphertexts: changing them would make
every existing ciphertext incomparable with new ones.

Leakage, to anyone who holds the ciphertexts (no key is needed):
- Total order. compare() reads only the two ciphertexts and never uses the
  instance key, so an ORE instance with any key can sort another key's
  ciphertexts. This is the same order leakage as OPE.
- Block differences. For ciphertexts that share a prefix, the difference of
  the first differing right values equals the difference of the plaintext
  blocks at that position.
- Partial plaintext. right_0 is the most significant byte plus a per-key
  constant, so one known plaintext/ciphertext pair reveals the most
  significant byte of every value encrypted under that key.
- Equality, because encryption is deterministic.

Raw ciphertext bytes do not sort in plaintext order, but that is not a
protection because compare() needs no key. Treat this module as a research
demo; see docs/LEAKAGE_AND_ENDPOINTS.md and issue #34.

Fixed-point values (encrypt_float, encrypt_amount): the value is converted
through its decimal string (``Decimal(str(x))`` for floats), scaled by
10^precision and rounded half-to-even, so 0.29 encrypts as 29 and 1.15 as 115.
NaN, infinities, negative values and values above the 32-bit plaintext space
are rejected. Rounding is lossy: with precision=2, 1.005 and 1.00 both become
100 and compare as equal.

Cache: encrypt_int keeps an LRU cache of at most ``cache_size`` (default
1024) plaintext -> ciphertext entries. The cache holds plaintexts in process
memory; pass ``cache_size=0`` to disable it, and call clear_cache() to drop it.

Lewi-Wu, for comparison (not implemented here): https://eprint.iacr.org/2016/612
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from collections import OrderedDict
from decimal import ROUND_HALF_EVEN, Decimal


class ORE:
    """
    CLWW-style prefix order-revealing encryption over 32-bit integers.

    Research prototype, not audited. The ciphertext holds a left and a right
    component per 8-bit block. compare() matches left components to find the
    first differing block, then reads the order from the right components.

    Encryption is deterministic and compare() needs no key. Whoever holds the
    ciphertexts learns:
    - their total order,
    - the exact difference at the first differing block,
    - with one known pair, the most significant byte of every value.

    See the module docstring.
    """

    ALGORITHM = "ore-clww-prototype"
    KEY_SIZE = 32
    BLOCK_BITS = 8
    NUM_BLOCKS = 4  # 4 blocks of 8 bits = 32-bit plaintext
    PLAINTEXT_BITS = NUM_BLOCKS * BLOCK_BITS
    PLAINTEXT_MAX = (1 << PLAINTEXT_BITS) - 1
    LEFT_SIZE = 8  # bytes per left component (truncated HMAC-SHA256)
    MODULUS = 1 << 16  # 65536 — large enough that block diffs [−255,255] are unambiguous
    VERSION_TAG = 0x01
    DEFAULT_CACHE_SIZE = 1024

    def __init__(self, key: bytes = None, cache_size: int = DEFAULT_CACHE_SIZE):
        """
        Initialize ORE with a 256-bit key.

        Args:
            key: 32-byte encryption key. If None, generates a new key.
            cache_size: Maximum number of plaintext -> ciphertext entries kept in the
                LRU cache (default 1024). 0 disables the cache.

        Raises:
            ValueError: If key is not exactly 32 bytes or cache_size is negative.
        """
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        elif len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes ({self.KEY_SIZE * 8} bits)")
        if isinstance(cache_size, bool) or not isinstance(cache_size, int) or cache_size < 0:
            raise ValueError("cache_size must be a non-negative integer")

        self.key = key
        # The labels keep their historical "ore-lewi-wu" names: they define the ciphertexts.
        self._k_left = hmac.new(key, b"ore-lewi-wu-left", hashlib.sha256).digest()
        self._k_right = hmac.new(key, b"ore-lewi-wu-right", hashlib.sha256).digest()
        self._cache_size = cache_size
        self._cache: OrderedDict[int, bytes] = OrderedDict()

    @property
    def cache_size(self) -> int:
        """Maximum number of entries in the plaintext -> ciphertext LRU cache."""
        return self._cache_size

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

        Raw ciphertext bytes do not sort in plaintext order, but compare()
        orders ciphertexts without any key, so this is not a confidentiality
        property. See the module docstring for the full leakage.

        Args:
            plaintext: Non-negative integer (0 to 2^32 - 1).

        Returns:
            ORE ciphertext as bytes.

        Raises:
            ValueError: If plaintext is negative or exceeds 2^32 - 1.
        """
        if plaintext < 0 or plaintext > self.PLAINTEXT_MAX:
            raise ValueError(f"Plaintext must be between 0 and {self.PLAINTEXT_MAX}")

        cached = self._cache.get(plaintext)
        if cached is not None:
            self._cache.move_to_end(plaintext)
            return cached

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

        if self._cache_size > 0:
            self._cache[plaintext] = result
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)  # evict the least recently used entry
        return result

    @classmethod
    def to_fixed_point(cls, value: float | int | Decimal, precision: int = 2) -> int:
        """
        Convert a non-negative number to the integer that encrypt_float encrypts.

        Floats go through their shortest decimal representation (``str(value)``), so
        0.29 becomes 29 at precision 2 instead of 28. The scaled value is rounded
        half-to-even.

        Args:
            value: Non-negative float, int or Decimal.
            precision: Number of decimal places to keep (0 or more).

        Returns:
            round_half_even(value * 10**precision) as an int.

        Raises:
            ValueError: If precision is negative, the value is not a finite number, the
                value is negative, or the scaled value exceeds 2^32 - 1.
        """
        if isinstance(precision, bool) or not isinstance(precision, int) or precision < 0:
            raise ValueError("precision must be a non-negative integer")
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            raise ValueError(f"Value must be an int, float or Decimal, got {type(value).__name__}")

        # str() of an int or float always parses ("nan" and "inf" included).
        decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
        if not decimal_value.is_finite():
            raise ValueError(f"Value must be finite, got {value!r}")
        if decimal_value < 0:
            raise ValueError("Negative values not supported")

        scaled = (decimal_value.scaleb(precision)).to_integral_value(rounding=ROUND_HALF_EVEN)
        int_value = int(scaled)
        if int_value > cls.PLAINTEXT_MAX:
            max_value = Decimal(cls.PLAINTEXT_MAX).scaleb(-precision)
            raise ValueError(f"Value too large: {value} (max: {max_value})")
        return int_value

    def encrypt_float(self, plaintext: float | int | Decimal, precision: int = 2) -> bytes:
        """
        Encrypt a non-negative number with fixed-point precision.

        The value is scaled exactly (no binary floating-point truncation) and rounded
        half-to-even; see :meth:`to_fixed_point`.

        Args:
            plaintext: Non-negative float, int or Decimal.
            precision: Number of decimal places to preserve (default: 2).

        Returns:
            ORE ciphertext as bytes.

        Raises:
            ValueError: If the value is NaN, infinite, negative, or too large for the
                plaintext space, or precision is negative.
        """
        return self.encrypt_int(self.to_fixed_point(plaintext, precision))

    def encrypt_amount(self, amount: float | int | Decimal) -> bytes:
        """
        Encrypt a monetary amount (2 decimal places, rounded half-to-even).

        Pass a ``Decimal`` to avoid binary floating-point surprises; a float is
        converted through ``str(amount)``.

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

        This method never uses the instance key: any ORE instance, or anyone
        reimplementing it, can compare ciphertexts produced under any key.
        The "different keys" check only detects that the two ciphertexts came
        from different keys, by comparing their left components. Both
        ciphertexts must come from the same key for the result to be
        meaningful.

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

    def clear_cache(self) -> None:
        """Drop every cached plaintext -> ciphertext entry."""
        self._cache.clear()
