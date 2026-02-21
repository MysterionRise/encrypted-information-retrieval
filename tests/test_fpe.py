"""Tests for Format-Preserving Encryption (FF1) module."""

import pytest
from encrypted_ir.fpe import FF1, FormatPreservingEncryption


class TestFF1Basic:
    """Basic FF1 encrypt/decrypt round-trip tests."""

    def setup_method(self):
        self.key = FF1.generate_key(256)
        self.ff1 = FF1(self.key)

    def test_encrypt_decrypt_round_trip(self):
        """Encrypt then decrypt recovers original numerals."""
        plaintext = [4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        ciphertext = self.ff1.encrypt(plaintext)
        decrypted = self.ff1.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_changes_value(self):
        """Ciphertext differs from plaintext."""
        plaintext = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        ciphertext = self.ff1.encrypt(plaintext)
        assert ciphertext != plaintext

    def test_preserves_length(self):
        """Ciphertext has same length as plaintext."""
        plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        ciphertext = self.ff1.encrypt(plaintext)
        assert len(ciphertext) == len(plaintext)

    def test_preserves_radix(self):
        """All ciphertext digits are within [0, radix)."""
        plaintext = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ciphertext = self.ff1.encrypt(plaintext)
        for d in ciphertext:
            assert 0 <= d < 10

    def test_deterministic(self):
        """Same key, tweak, and plaintext produce same ciphertext."""
        plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        ct1 = self.ff1.encrypt(plaintext)
        ct2 = self.ff1.encrypt(plaintext)
        assert ct1 == ct2

    def test_different_keys_produce_different_ciphertext(self):
        """Different keys produce different ciphertexts."""
        plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        ff1_other = FF1(FF1.generate_key(256))
        ct1 = self.ff1.encrypt(plaintext)
        ct2 = ff1_other.encrypt(plaintext)
        assert ct1 != ct2


class TestFF1Tweaks:
    """Test tweak functionality."""

    def setup_method(self):
        self.key = FF1.generate_key(256)
        self.ff1 = FF1(self.key)
        self.plaintext = [4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

    def test_empty_tweak(self):
        """Encrypt/decrypt with empty tweak."""
        ct = self.ff1.encrypt(self.plaintext, tweak=b"")
        pt = self.ff1.decrypt(ct, tweak=b"")
        assert pt == self.plaintext

    def test_tweak_changes_ciphertext(self):
        """Different tweaks produce different ciphertexts."""
        ct1 = self.ff1.encrypt(self.plaintext, tweak=b"tweak1")
        ct2 = self.ff1.encrypt(self.plaintext, tweak=b"tweak2")
        assert ct1 != ct2

    def test_wrong_tweak_fails_decrypt(self):
        """Decrypting with wrong tweak does not recover plaintext."""
        ct = self.ff1.encrypt(self.plaintext, tweak=b"correct")
        pt = self.ff1.decrypt(ct, tweak=b"wrong")
        assert pt != self.plaintext

    def test_round_trip_with_tweak(self):
        """Encrypt/decrypt with non-empty tweak."""
        tweak = b"column_id_42"
        ct = self.ff1.encrypt(self.plaintext, tweak=tweak)
        pt = self.ff1.decrypt(ct, tweak=tweak)
        assert pt == self.plaintext

    def test_long_tweak(self):
        """Round-trip with long tweak value."""
        tweak = b"a" * 200
        ct = self.ff1.encrypt(self.plaintext, tweak=tweak)
        pt = self.ff1.decrypt(ct, tweak=tweak)
        assert pt == self.plaintext


class TestFF1Radix:
    """Test different radix values."""

    def test_binary_radix(self):
        """FF1 with radix=2 (binary), minimum domain 2^20 >= 10^6."""
        key = FF1.generate_key(256)
        ff1 = FF1(key, radix=2)
        plaintext = [0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1]
        ct = ff1.encrypt(plaintext)
        pt = ff1.decrypt(ct)
        assert pt == plaintext
        assert len(ct) == 20
        assert all(d in (0, 1) for d in ct)

    def test_hex_radix(self):
        """FF1 with radix=16 (hexadecimal)."""
        key = FF1.generate_key(256)
        ff1 = FF1(key, radix=16)
        plaintext = [0xA, 0xB, 0xC, 0xD, 0xE, 0xF]
        ct = ff1.encrypt(plaintext)
        pt = ff1.decrypt(ct)
        assert pt == plaintext
        assert all(0 <= d < 16 for d in ct)

    def test_radix_36(self):
        """FF1 with radix=36 (alphanumeric lower)."""
        key = FF1.generate_key(256)
        ff1 = FF1(key, radix=36)
        plaintext = [10, 11, 12, 13, 14, 15]  # a, b, c, d, e, f
        ct = ff1.encrypt(plaintext)
        pt = ff1.decrypt(ct)
        assert pt == plaintext


class TestFF1KeySizes:
    """Test different AES key sizes."""

    def test_aes_128(self):
        key = FF1.generate_key(128)
        assert len(key) == 16
        ff1 = FF1(key)
        pt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        assert ff1.decrypt(ff1.encrypt(pt)) == pt

    def test_aes_192(self):
        key = FF1.generate_key(192)
        assert len(key) == 24
        ff1 = FF1(key)
        pt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        assert ff1.decrypt(ff1.encrypt(pt)) == pt

    def test_aes_256(self):
        key = FF1.generate_key(256)
        assert len(key) == 32
        ff1 = FF1(key)
        pt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        assert ff1.decrypt(ff1.encrypt(pt)) == pt


class TestFF1Validation:
    """Test input validation."""

    def test_invalid_key_size(self):
        with pytest.raises(ValueError, match="Key must be"):
            FF1(b"short")

    def test_invalid_radix_low(self):
        with pytest.raises(ValueError, match="Radix must be"):
            FF1(FF1.generate_key(), radix=1)

    def test_invalid_radix_high(self):
        with pytest.raises(ValueError, match="Radix must be"):
            FF1(FF1.generate_key(), radix=(1 << 16) + 1)

    def test_input_too_short(self):
        ff1 = FF1(FF1.generate_key())
        with pytest.raises(ValueError, match="Input length must be >= 2"):
            ff1.encrypt([5])

    def test_domain_too_small(self):
        """radix=10, n=5 → domain = 10^5 = 100000 < 1000000."""
        ff1 = FF1(FF1.generate_key())
        with pytest.raises(ValueError, match="Domain too small"):
            ff1.encrypt([1, 2, 3, 4, 5])

    def test_numeral_out_of_range(self):
        ff1 = FF1(FF1.generate_key())
        with pytest.raises(ValueError, match="Numeral at index"):
            ff1.encrypt([1, 2, 3, 4, 5, 10, 7, 8, 9, 0])

    def test_negative_numeral(self):
        ff1 = FF1(FF1.generate_key())
        with pytest.raises(ValueError, match="Numeral at index"):
            ff1.encrypt([1, 2, -1, 4, 5, 6, 7, 8, 9, 0])

    def test_invalid_key_bit_length(self):
        with pytest.raises(ValueError, match="bit_length"):
            FF1.generate_key(64)


class TestFF1KeyExport:
    """Test key import/export."""

    def test_export_import_round_trip(self):
        ff1 = FF1(FF1.generate_key())
        plaintext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        ct = ff1.encrypt(plaintext)

        key_b64 = ff1.export_key()
        ff1_restored = FF1.import_key(key_b64)
        pt = ff1_restored.decrypt(ct)
        assert pt == plaintext

    def test_export_import_with_radix(self):
        ff1 = FF1(FF1.generate_key(), radix=16)
        plaintext = [0xA, 0xB, 0xC, 0xD, 0xE, 0xF]
        ct = ff1.encrypt(plaintext)

        key_b64 = ff1.export_key()
        ff1_restored = FF1.import_key(key_b64, radix=16)
        pt = ff1_restored.decrypt(ct)
        assert pt == plaintext


class TestFF1OddLength:
    """Test with odd-length inputs (u != v)."""

    def test_odd_length_7(self):
        ff1 = FF1(FF1.generate_key())
        pt = [1, 2, 3, 4, 5, 6, 7]  # u=3, v=4
        ct = ff1.encrypt(pt)
        assert len(ct) == 7
        assert ff1.decrypt(ct) == pt

    def test_odd_length_9(self):
        ff1 = FF1(FF1.generate_key())
        pt = [1, 2, 3, 4, 5, 6, 7, 8, 9]  # u=4, v=5
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt

    def test_odd_length_11(self):
        ff1 = FF1(FF1.generate_key())
        pt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt


class TestFormatPreservingEncryption:
    """Test the high-level FormatPreservingEncryption class."""

    def setup_method(self):
        self.key = FormatPreservingEncryption.generate_key()
        self.fpe = FormatPreservingEncryption(self.key)

    def test_encrypt_decrypt_digits(self):
        ct = self.fpe.encrypt("1234567890")
        assert len(ct) == 10
        assert ct.isdigit()
        pt = self.fpe.decrypt(ct)
        assert pt == "1234567890"

    def test_encrypt_changes_value(self):
        ct = self.fpe.encrypt("0000000000")
        assert ct != "0000000000"

    def test_deterministic(self):
        ct1 = self.fpe.encrypt("1234567890")
        ct2 = self.fpe.encrypt("1234567890")
        assert ct1 == ct2

    def test_tweak_changes_output(self):
        ct1 = self.fpe.encrypt("1234567890", tweak=b"a")
        ct2 = self.fpe.encrypt("1234567890", tweak=b"b")
        assert ct1 != ct2


class TestFPECreditCard:
    """Test credit card PAN encryption."""

    def setup_method(self):
        self.key = FormatPreservingEncryption.generate_key()
        self.fpe = FormatPreservingEncryption(self.key)

    def test_pan_round_trip(self):
        pan = "4111111111111111"
        encrypted = self.fpe.encrypt_credit_card(pan)
        assert len(encrypted) == 16
        assert encrypted.isdigit()
        decrypted = self.fpe.decrypt_credit_card(encrypted)
        assert decrypted == pan

    def test_pan_with_spaces(self):
        pan = "4111 1111 1111 1111"
        encrypted = self.fpe.encrypt_credit_card(pan)
        # Spaces should be preserved
        assert encrypted[4] == " "
        assert encrypted[9] == " "
        assert encrypted[14] == " "
        decrypted = self.fpe.decrypt_credit_card(encrypted)
        assert decrypted == pan

    def test_pan_with_dashes(self):
        pan = "4111-1111-1111-1111"
        encrypted = self.fpe.encrypt_credit_card(pan)
        assert encrypted[4] == "-"
        assert encrypted[9] == "-"
        assert encrypted[14] == "-"
        decrypted = self.fpe.decrypt_credit_card(encrypted)
        assert decrypted == pan

    def test_encrypted_pan_is_all_digits(self):
        """Only the digit positions change; separator positions stay."""
        pan = "4111-1111-1111-1111"
        encrypted = self.fpe.encrypt_credit_card(pan)
        digits_only = encrypted.replace("-", "")
        assert digits_only.isdigit()
        assert len(digits_only) == 16


class TestFPESSN:
    """Test SSN encryption."""

    def setup_method(self):
        self.key = FormatPreservingEncryption.generate_key()
        self.fpe = FormatPreservingEncryption(self.key)

    def test_ssn_plain(self):
        ssn = "123456789"
        encrypted = self.fpe.encrypt_ssn(ssn)
        assert len(encrypted) == 9
        assert encrypted.isdigit()
        decrypted = self.fpe.decrypt_ssn(encrypted)
        assert decrypted == ssn

    def test_ssn_with_dashes(self):
        ssn = "123-45-6789"
        encrypted = self.fpe.encrypt_ssn(ssn)
        assert encrypted[3] == "-"
        assert encrypted[6] == "-"
        decrypted = self.fpe.decrypt_ssn(encrypted)
        assert decrypted == ssn


class TestFPEAccountNumber:
    """Test account number encryption."""

    def setup_method(self):
        self.key = FormatPreservingEncryption.generate_key()
        self.fpe = FormatPreservingEncryption(self.key)

    def test_account_round_trip(self):
        account = "9876543210"
        encrypted = self.fpe.encrypt_account_number(account)
        assert len(encrypted) == 10
        assert encrypted.isdigit()
        decrypted = self.fpe.decrypt_account_number(encrypted)
        assert decrypted == account

    def test_account_with_tweak(self):
        account = "9876543210"
        tweak = b"routing_021000021"
        encrypted = self.fpe.encrypt_account_number(account, tweak=tweak)
        decrypted = self.fpe.decrypt_account_number(encrypted, tweak=tweak)
        assert decrypted == account


class TestFPEAlphanumeric:
    """Test alphanumeric alphabet."""

    def test_lower_alphanumeric(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key, alphabet=FormatPreservingEncryption.ALPHANUMERIC_LOWER)
        plaintext = "abc123"
        ct = fpe.encrypt(plaintext)
        assert len(ct) == 6
        assert all(c in FormatPreservingEncryption.ALPHANUMERIC_LOWER for c in ct)
        pt = fpe.decrypt(ct)
        assert pt == plaintext

    def test_full_alphanumeric(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key, alphabet=FormatPreservingEncryption.ALPHANUMERIC)
        plaintext = "AbCd12"
        ct = fpe.encrypt(plaintext)
        assert len(ct) == 6
        pt = fpe.decrypt(ct)
        assert pt == plaintext

    def test_invalid_character(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key)  # digits only
        with pytest.raises(ValueError, match="not in alphabet"):
            fpe.encrypt("12345A7890")


class TestFPEKeyExport:
    """Test FormatPreservingEncryption key import/export."""

    def test_export_import_round_trip(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key)
        ct = fpe.encrypt("1234567890")

        key_b64 = fpe.export_key()
        fpe2 = FormatPreservingEncryption.import_key(key_b64)
        pt = fpe2.decrypt(ct)
        assert pt == "1234567890"

    def test_export_import_with_alphabet(self):
        key = FormatPreservingEncryption.generate_key()
        alpha = FormatPreservingEncryption.ALPHANUMERIC_LOWER
        fpe = FormatPreservingEncryption(key, alphabet=alpha)
        ct = fpe.encrypt("abc123")

        key_b64 = fpe.export_key()
        fpe2 = FormatPreservingEncryption.import_key(key_b64, alphabet=alpha)
        pt = fpe2.decrypt(ct)
        assert pt == "abc123"


class TestFF1EdgeCases:
    """Test edge cases and boundary conditions."""

    def test_minimum_domain_radix_10(self):
        """Minimum input for radix=10: 6 digits (10^6 = 1,000,000)."""
        ff1 = FF1(FF1.generate_key())
        pt = [1, 2, 3, 4, 5, 6]
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt

    def test_minimum_domain_radix_2(self):
        """Minimum input for radix=2: 20 bits (2^20 = 1,048,576)."""
        ff1 = FF1(FF1.generate_key(), radix=2)
        pt = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt

    def test_all_zeros(self):
        ff1 = FF1(FF1.generate_key())
        pt = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt

    def test_all_nines(self):
        ff1 = FF1(FF1.generate_key())
        pt = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt

    def test_long_input(self):
        """32-digit input."""
        ff1 = FF1(FF1.generate_key())
        pt = list(range(10)) * 3 + [0, 1]
        assert len(pt) == 32
        ct = ff1.encrypt(pt)
        assert len(ct) == 32
        assert ff1.decrypt(ct) == pt

    def test_even_length(self):
        """Even-length input where u == v."""
        ff1 = FF1(FF1.generate_key())
        pt = [1, 2, 3, 4, 5, 6, 7, 8]  # u=4, v=4
        ct = ff1.encrypt(pt)
        assert ff1.decrypt(ct) == pt
