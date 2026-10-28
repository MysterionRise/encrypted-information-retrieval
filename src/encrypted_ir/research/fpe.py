"""
Format-Preserving Encryption (FPE) Module (research prototype, not audited)

Implements FF1 from NIST SP 800-38G Rev 1 for format-preserving encryption.
Ciphertext has the same length and alphabet as the plaintext — a 16-digit number
encrypts to a 16-digit number, a 9-digit SSN encrypts to a 9-digit string, etc.
The FF1 class reproduces the nine NIST FF1 sample vectors (AES-128/192/256,
radix 10 and 36); they are in tests/research/test_fpe.py.

Use Case: Credit card PANs, SSNs, account numbers, phone numbers, and other
fixed-format identifiers stored in columns with a fixed length and character set.
Only length and alphabet are preserved: structure inside the value (a PAN's
issuer prefix and Luhn check digit, an SSN's area number rules) is not, so the
ciphertext is not a drop-in value for systems that validate that structure.

Algorithm: FF1 (NIST SP 800-38G Rev 1)
Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

Security Properties:
- Format-preserving: ciphertext domain == plaintext domain
- Tweakable: the tweak provides domain separation (e.g., per column)
- AES-based: security reduces to AES block cipher security
- Deterministic: same (key, tweak, plaintext) always produces same ciphertext,
  so equal values are visible as equal

Tweaks:
- FormatPreservingEncryption.encrypt() and decrypt() require an explicit tweak.
- The helpers default to a fixed per-field tweak (TWEAK_CREDIT_CARD,
  TWEAK_SSN, TWEAK_ACCOUNT_NUMBER), so the same digits encrypted as an SSN and
  as an account number give unrelated ciphertexts. A tweak passed to a helper
  replaces its default; include the field name in it (for example
  b"ssn:" + customer_id) to keep the separation.
- The low-level FF1 class accepts an empty tweak, as the standard does.

Constraints (per NIST SP 800-38G):
- Radix in [2, 2^16]
- Input length n such that radix^n >= 1_000_000 (domain must be >= 10^6)
- Tweak length in [0, maxTlen]; this implementation sets maxTlen = 2^32 - 1,
  the largest length the 4-byte tweak-length field of block P can encode.
- The alphabet of FormatPreservingEncryption must not repeat a character.

Small domains: the published attacks on FF1 and FF3 target small domains
(Durak and Vaudenay 2017; Hoang, Tessaro and Trieu 2018), which is why NIST
SP 800-38G Rev 1 requires radix^n >= 10^6. Inputs near that minimum have the
least margin.
"""

from __future__ import annotations

import base64
import math
import os
from typing import cast

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class FF1:
    """
    FF1 Format-Preserving Encryption (NIST SP 800-38G Rev 1).

    Encrypts strings over an arbitrary radix alphabet while preserving
    length and character set. Uses a 10-round balanced Feistel network
    with AES-CBC-MAC as the round function.
    """

    NUM_ROUNDS = 10
    KEY_SIZES = {16, 24, 32}  # AES-128, AES-192, AES-256
    MAX_TWEAK_LEN = 2**32 - 1  # maxTlen: the tweak length is encoded in 4 bytes of P

    def __init__(self, key: bytes, radix: int = 10):
        """
        Initialize FF1 with an AES key and radix.

        Args:
            key: AES key (16, 24, or 32 bytes for AES-128/192/256).
            radix: Alphabet size (default 10 for decimal digits).

        Raises:
            ValueError: If key size is invalid or radix is out of range.
        """
        if len(key) not in self.KEY_SIZES:
            raise ValueError(f"Key must be {self.KEY_SIZES} bytes, got {len(key)}")
        if radix < 2 or radix > (1 << 16):
            raise ValueError(f"Radix must be in [2, 2^16], got {radix}")

        self.key = key
        self.radix = radix

    @staticmethod
    def generate_key(bit_length: int = 256) -> bytes:
        """
        Generate a random AES key.

        Args:
            bit_length: Key size in bits (128, 192, or 256).

        Returns:
            Random AES key bytes.
        """
        if bit_length not in {128, 192, 256}:
            raise ValueError(f"bit_length must be 128, 192, or 256, got {bit_length}")
        return os.urandom(bit_length // 8)

    def _aes_ecb_encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block with AES-ECB."""
        cipher = Cipher(algorithms.AES(self.key), modes.ECB())  # nosec B305
        enc = cipher.encryptor()
        return cast(bytes, enc.update(block) + enc.finalize())

    def _prf(self, data: bytes) -> bytes:
        """
        AES-CBC-MAC per NIST SP 800-38G Section 4.

        Computes CBC-MAC over data (must be a multiple of 16 bytes).
        """
        iv = b"\x00" * 16
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = cast(bytes, enc.update(data) + enc.finalize())
        return ct[-16:]

    @staticmethod
    def _num_to_bytes(value: int, length: int) -> bytes:
        """Convert integer to big-endian byte string of given length."""
        return value.to_bytes(length, byteorder="big")

    @staticmethod
    def _bytes_to_num(byte_string: bytes) -> int:
        """Convert big-endian byte string to integer."""
        return int.from_bytes(byte_string, byteorder="big")

    @staticmethod
    def _num_radix(digits: list[int], radix: int) -> int:
        """Convert a list of radix digits to an integer (big-endian)."""
        result = 0
        for d in digits:
            result = result * radix + d
        return result

    @staticmethod
    def _str_radix(value: int, radix: int, length: int) -> list[int]:
        """Convert integer to a list of radix digits with given length (big-endian)."""
        digits = []
        for _ in range(length):
            digits.append(value % radix)
            value //= radix
        digits.reverse()
        return digits

    def _validate_tweak(self, tweak: bytes) -> None:
        """Validate the tweak type and length (0 <= len <= maxTlen)."""
        if not isinstance(tweak, (bytes, bytearray)):
            raise ValueError(f"Tweak must be bytes, got {type(tweak).__name__}")
        if len(tweak) > self.MAX_TWEAK_LEN:
            raise ValueError(f"Tweak length {len(tweak)} exceeds maxTlen = {self.MAX_TWEAK_LEN}")

    def _validate_input(self, numerals: list[int]):
        """Validate input constraints per NIST SP 800-38G."""
        n = len(numerals)
        if n < 2:
            raise ValueError(f"Input length must be >= 2, got {n}")

        min_domain = 1_000_000
        domain_size = self.radix**n
        if domain_size < min_domain:
            raise ValueError(
                f"Domain too small: radix^n = {self.radix}^{n} = {domain_size} < {min_domain}. "
                f"Use longer input or larger radix."
            )

        for i, d in enumerate(numerals):
            if d < 0 or d >= self.radix:
                raise ValueError(f"Numeral at index {i} is {d}, must be in [0, {self.radix - 1}]")

    def _compute_p(self, n: int, u: int, t: int) -> bytes:
        """Compute the fixed P block (16 bytes) per NIST SP 800-38G step 5."""
        P = bytes([1, 2, 1]) + self.radix.to_bytes(3, "big")
        P += bytes([10, u % 256])
        P += n.to_bytes(4, "big")
        P += t.to_bytes(4, "big")
        return P

    def _compute_round(
        self, P: bytes, tweak: bytes, t: int, b: int, d: int, round_num: int, source: list[int]
    ) -> int:
        """
        Compute the Feistel round function, returning y.

        Args:
            P: Fixed 16-byte P block.
            tweak: Tweak bytes.
            t: Tweak length.
            b: Byte length for numeral encoding.
            d: Output length in bytes.
            round_num: Round index i.
            source: The numeral list fed into the PRF (B for encrypt, A for decrypt).

        Returns:
            Integer y derived from the PRF.
        """
        # Q = T || [0]^(-t-b-1 mod 16) || [i] || [NUMradix(source)]_b
        zero_pad_len = (-t - b - 1) % 16
        Q = tweak + bytes(zero_pad_len) + bytes([round_num])
        Q += self._num_to_bytes(self._num_radix(source, self.radix), b)

        # R = PRF_K(P || Q) — P||Q is already a multiple of 16 bytes
        R = self._prf(P + Q)

        # S = R || CIPH_K(R xor [1]_16) || CIPH_K(R xor [2]_16) || ...
        S = R
        extra_blocks = math.ceil(d / 16) - 1
        for j in range(1, extra_blocks + 1):
            xor_block = bytes(a ^ b_ for a, b_ in zip(R, self._num_to_bytes(j, 16)))
            S += self._aes_ecb_encrypt_block(xor_block)

        return self._bytes_to_num(S[:d])

    def encrypt(self, numerals: list[int], tweak: bytes = b"") -> list[int]:
        """
        Encrypt a sequence of numerals using FF1.

        Args:
            numerals: List of integers in [0, radix). E.g., for radix=10 and
                      PAN "4111111111111111", pass [4,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1].
            tweak: Tweak bytes for domain separation (can be empty, at most
                MAX_TWEAK_LEN bytes).

        Returns:
            Encrypted numerals (same length and radix as input).

        Raises:
            ValueError: If the numerals or the tweak violate the FF1 constraints.
        """
        self._validate_input(numerals)
        self._validate_tweak(tweak)
        tweak = bytes(tweak)

        n = len(numerals)
        t = len(tweak)
        u = n // 2
        v = n - u

        A = list(numerals[:u])
        B = list(numerals[u:])

        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        P = self._compute_p(n, u, t)

        for i in range(self.NUM_ROUNDS):
            m = u if i % 2 == 0 else v

            y = self._compute_round(P, tweak, t, b, d, i, B)
            c = (self._num_radix(A, self.radix) + y) % (self.radix**m)

            A = list(B)
            B = self._str_radix(c, self.radix, m)

        return A + B

    def decrypt(self, numerals: list[int], tweak: bytes = b"") -> list[int]:
        """
        Decrypt a sequence of numerals using FF1.

        The Feistel is reversed: PRF uses A (not B), subtraction replaces
        addition, and rounds run 9 down to 0.

        Args:
            numerals: Encrypted numerals (list of integers in [0, radix)).
            tweak: Tweak bytes (must match the tweak used for encryption).

        Returns:
            Decrypted numerals (same length and radix as input).

        Raises:
            ValueError: If the numerals or the tweak violate the FF1 constraints.
        """
        self._validate_input(numerals)
        self._validate_tweak(tweak)
        tweak = bytes(tweak)

        n = len(numerals)
        t = len(tweak)
        u = n // 2
        v = n - u

        A = list(numerals[:u])
        B = list(numerals[u:])

        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        P = self._compute_p(n, u, t)

        for i in range(self.NUM_ROUNDS - 1, -1, -1):
            m = u if i % 2 == 0 else v

            # Decrypt: PRF uses A (encrypt used B)
            y = self._compute_round(P, tweak, t, b, d, i, A)
            c = (self._num_radix(B, self.radix) - y) % (self.radix**m)

            C = self._str_radix(c, self.radix, m)
            B = list(A)
            A = C

        return A + B

    def export_key(self) -> str:
        """Export key as base64 string."""
        return base64.b64encode(self.key).decode("ascii")

    @staticmethod
    def import_key(key_b64: str, radix: int = 10) -> FF1:
        """
        Import key from base64 string.

        Args:
            key_b64: Base64-encoded AES key.
            radix: Alphabet radix (default 10).

        Returns:
            FF1 instance with imported key.
        """
        key = base64.b64decode(key_b64)
        return FF1(key, radix)


class FormatPreservingEncryption:
    """
    High-level FPE interface for common financial data formats.

    Wraps FF1 with convenience methods for credit card numbers, SSNs,
    account numbers, and other fixed-format identifiers. encrypt() and
    decrypt() need an explicit tweak; the field helpers default to a fixed
    per-field tweak (see the module docstring).
    """

    DIGITS = "0123456789"
    ALPHANUMERIC_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz"
    ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    # Default tweaks of the field helpers: one per field, so the same digits
    # encrypted as different fields give unrelated ciphertexts.
    TWEAK_CREDIT_CARD = b"encrypted-ir/fpe/credit-card"
    TWEAK_SSN = b"encrypted-ir/fpe/ssn"
    TWEAK_ACCOUNT_NUMBER = b"encrypted-ir/fpe/account-number"

    def __init__(self, key: bytes, alphabet: str = None):
        """
        Initialize FPE with an AES key and alphabet.

        Args:
            key: AES key (16, 24, or 32 bytes).
            alphabet: Character alphabet string, at least 2 distinct characters.
                Default is decimal digits.

        Raises:
            ValueError: If the alphabet repeats a character (the character-to-numeral
                mapping would not be a bijection), or the key or radix is invalid.
        """
        if alphabet is None:
            alphabet = self.DIGITS
        if not isinstance(alphabet, str):
            raise ValueError("Alphabet must be a string")
        if len(set(alphabet)) != len(alphabet):
            duplicates = sorted({c for c in alphabet if alphabet.count(c) > 1})
            raise ValueError(f"Alphabet characters must be unique; repeated: {duplicates}")
        self.alphabet = alphabet
        self._char_to_int = {c: i for i, c in enumerate(alphabet)}
        self._ff1 = FF1(key, radix=len(alphabet))

    @staticmethod
    def generate_key(bit_length: int = 256) -> bytes:
        """Generate a random AES key."""
        return FF1.generate_key(bit_length)

    def _to_numerals(self, text: str) -> list[int]:
        """Convert string to numeral list using the alphabet mapping."""
        try:
            return [self._char_to_int[c] for c in text]
        except KeyError as e:
            raise ValueError(f"Character {e} not in alphabet") from e

    def _from_numerals(self, numerals: list[int]) -> str:
        """Convert numeral list back to string."""
        return "".join(self.alphabet[n] for n in numerals)

    def encrypt(self, plaintext: str, tweak: bytes) -> str:
        """
        Encrypt a string, preserving its length and alphabet.

        Args:
            plaintext: String composed of characters from the alphabet.
            tweak: Tweak bytes for domain separation, for example the column name.
                Required; pass b"" only to interoperate with tweak-less data.

        Returns:
            Encrypted string (same length and alphabet).
        """
        numerals = self._to_numerals(plaintext)
        encrypted = self._ff1.encrypt(numerals, tweak)
        return self._from_numerals(encrypted)

    def decrypt(self, ciphertext: str, tweak: bytes) -> str:
        """
        Decrypt a string.

        Args:
            ciphertext: Encrypted string.
            tweak: Tweak bytes (must match encryption).

        Returns:
            Decrypted string.
        """
        numerals = self._to_numerals(ciphertext)
        decrypted = self._ff1.decrypt(numerals, tweak)
        return self._from_numerals(decrypted)

    def encrypt_credit_card(self, pan: str, tweak: bytes | None = None) -> str:
        """
        Encrypt a credit card PAN, preserving its length and separators.

        Every digit is encrypted, including the issuer identification number
        (BIN/IIN) and the last four digits. The result keeps the length and the
        positions of spaces or dashes, but its leading digits are random and it
        generally fails the Luhn check, so it is not a valid-looking PAN for
        systems that check the BIN or Luhn digit.

        Args:
            pan: Credit card number (digits, optionally with separators).
            tweak: Tweak bytes. Defaults to TWEAK_CREDIT_CARD; a value passed here
                replaces the default.

        Returns:
            Encrypted PAN with same format.
        """
        return self._encrypt_with_separators(pan, self._tweak(tweak, self.TWEAK_CREDIT_CARD))

    def decrypt_credit_card(self, encrypted_pan: str, tweak: bytes | None = None) -> str:
        """
        Decrypt a credit card PAN.

        Args:
            encrypted_pan: Encrypted PAN.
            tweak: Tweak bytes (must match encryption; defaults to TWEAK_CREDIT_CARD).

        Returns:
            Decrypted PAN.
        """
        return self._decrypt_with_separators(
            encrypted_pan, self._tweak(tweak, self.TWEAK_CREDIT_CARD)
        )

    def encrypt_ssn(self, ssn: str, tweak: bytes | None = None) -> str:
        """
        Encrypt a Social Security Number, preserving format.

        Handles both "123456789" and "123-45-6789" formats. The result is nine
        digits but need not be a valid SSN (area 000, 666 or 9xx can occur).

        Args:
            ssn: SSN string.
            tweak: Tweak bytes. Defaults to TWEAK_SSN; a value passed here replaces
                the default.

        Returns:
            Encrypted SSN with same format.
        """
        return self._encrypt_with_separators(ssn, self._tweak(tweak, self.TWEAK_SSN))

    def decrypt_ssn(self, encrypted_ssn: str, tweak: bytes | None = None) -> str:
        """
        Decrypt a Social Security Number.

        Args:
            encrypted_ssn: Encrypted SSN.
            tweak: Tweak bytes (must match encryption; defaults to TWEAK_SSN).

        Returns:
            Decrypted SSN.
        """
        return self._decrypt_with_separators(encrypted_ssn, self._tweak(tweak, self.TWEAK_SSN))

    def encrypt_account_number(self, account: str, tweak: bytes | None = None) -> str:
        """
        Encrypt an account number, preserving format.

        Args:
            account: Account number string (digits).
            tweak: Tweak bytes, for example b"account-number:" + routing number.
                Defaults to TWEAK_ACCOUNT_NUMBER; a value passed here replaces the
                default.

        Returns:
            Encrypted account number.
        """
        return self._encrypt_with_separators(account, self._tweak(tweak, self.TWEAK_ACCOUNT_NUMBER))

    def decrypt_account_number(self, encrypted_account: str, tweak: bytes | None = None) -> str:
        """
        Decrypt an account number.

        Args:
            encrypted_account: Encrypted account number.
            tweak: Tweak bytes (must match encryption; defaults to
                TWEAK_ACCOUNT_NUMBER).

        Returns:
            Decrypted account number.
        """
        return self._decrypt_with_separators(
            encrypted_account, self._tweak(tweak, self.TWEAK_ACCOUNT_NUMBER)
        )

    @staticmethod
    def _tweak(tweak: bytes | None, default: bytes) -> bytes:
        """Return ``tweak``, or the helper's default tweak when it is None."""
        return default if tweak is None else tweak

    def _encrypt_with_separators(self, text: str, tweak: bytes) -> str:
        """Encrypt only alphabet characters, preserving non-alphabet separators."""
        chars = []
        separators = {}

        for i, c in enumerate(text):
            if c in self._char_to_int:
                chars.append(c)
            else:
                separators[i] = c

        encrypted_chars = list(self.encrypt("".join(chars), tweak))

        for pos, sep in sorted(separators.items()):
            encrypted_chars.insert(pos, sep)

        return "".join(encrypted_chars)

    def _decrypt_with_separators(self, text: str, tweak: bytes) -> str:
        """Decrypt only alphabet characters, preserving non-alphabet separators."""
        chars = []
        separators = {}

        for i, c in enumerate(text):
            if c in self._char_to_int:
                chars.append(c)
            else:
                separators[i] = c

        decrypted_chars = list(self.decrypt("".join(chars), tweak))

        for pos, sep in sorted(separators.items()):
            decrypted_chars.insert(pos, sep)

        return "".join(decrypted_chars)

    def export_key(self) -> str:
        """Export key as base64 string."""
        return self._ff1.export_key()

    @staticmethod
    def import_key(key_b64: str, alphabet: str = None) -> FormatPreservingEncryption:
        """
        Import key from base64 string.

        Args:
            key_b64: Base64-encoded AES key.
            alphabet: Character alphabet (default: decimal digits).

        Returns:
            FormatPreservingEncryption instance.
        """
        key = base64.b64decode(key_b64)
        return FormatPreservingEncryption(key, alphabet)
