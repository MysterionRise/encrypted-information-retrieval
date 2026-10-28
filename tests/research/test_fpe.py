"""Tests for Format-Preserving Encryption (FF1) module."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from encrypted_ir.research.fpe import FF1, FormatPreservingEncryption

# NIST SP 800-38G FF1 sample vectors (NIST "FF1samples.pdf", Samples #1-#9).
# Radix-36 samples use the alphabet 0-9a-z, i.e. FormatPreservingEncryption.ALPHANUMERIC_LOWER.
NIST_KEY_128 = "2B7E151628AED2A6ABF7158809CF4F3C"
NIST_KEY_192 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"
NIST_KEY_256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
NIST_TWEAK_10 = "39383736353433323130"
NIST_TWEAK_36 = "3737373770717273373737"
NIST_FF1_SAMPLES = [
    # (sample, key, radix, tweak, plaintext, ciphertext)
    (1, NIST_KEY_128, 10, "", "0123456789", "2433477484"),
    (2, NIST_KEY_128, 10, NIST_TWEAK_10, "0123456789", "6124200773"),
    (3, NIST_KEY_128, 36, NIST_TWEAK_36, "0123456789abcdefghi", "a9tv40mll9kdu509eum"),
    (4, NIST_KEY_192, 10, "", "0123456789", "2830668132"),
    (5, NIST_KEY_192, 10, NIST_TWEAK_10, "0123456789", "2496655549"),
    (6, NIST_KEY_192, 36, NIST_TWEAK_36, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"),
    (7, NIST_KEY_256, 10, "", "0123456789", "6657667009"),
    (8, NIST_KEY_256, 10, NIST_TWEAK_10, "0123456789", "1001623463"),
    (9, NIST_KEY_256, 36, NIST_TWEAK_36, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"),
]
_NIST_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


class TestNISTFF1Vectors:
    """The nine NIST SP 800-38G FF1 sample vectors."""

    @pytest.mark.parametrize(
        "sample,key,radix,tweak,plaintext,ciphertext",
        NIST_FF1_SAMPLES,
        ids=[f"sample-{s[0]}" for s in NIST_FF1_SAMPLES],
    )
    def test_ff1_sample(self, sample, key, radix, tweak, plaintext, ciphertext):
        ff1 = FF1(bytes.fromhex(key), radix=radix)
        numerals = [_NIST_ALPHABET.index(c) for c in plaintext]
        expected = [_NIST_ALPHABET.index(c) for c in ciphertext]

        assert ff1.encrypt(numerals, bytes.fromhex(tweak)) == expected
        assert ff1.decrypt(expected, bytes.fromhex(tweak)) == numerals

    @pytest.mark.parametrize(
        "sample,key,radix,tweak,plaintext,ciphertext",
        NIST_FF1_SAMPLES,
        ids=[f"sample-{s[0]}" for s in NIST_FF1_SAMPLES],
    )
    def test_ff1_sample_through_string_api(self, sample, key, radix, tweak, plaintext, ciphertext):
        alphabet = (
            FormatPreservingEncryption.DIGITS
            if radix == 10
            else FormatPreservingEncryption.ALPHANUMERIC_LOWER
        )
        fpe = FormatPreservingEncryption(bytes.fromhex(key), alphabet=alphabet)

        assert fpe.encrypt(plaintext, tweak=bytes.fromhex(tweak)) == ciphertext
        assert fpe.decrypt(ciphertext, tweak=bytes.fromhex(tweak)) == plaintext


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
        ct = self.fpe.encrypt("1234567890", tweak=b"column")
        assert len(ct) == 10
        assert ct.isdigit()
        pt = self.fpe.decrypt(ct, tweak=b"column")
        assert pt == "1234567890"

    def test_encrypt_changes_value(self):
        ct = self.fpe.encrypt("0000000000", tweak=b"column")
        assert ct != "0000000000"

    def test_deterministic(self):
        ct1 = self.fpe.encrypt("1234567890", tweak=b"column")
        ct2 = self.fpe.encrypt("1234567890", tweak=b"column")
        assert ct1 == ct2

    def test_tweak_is_required(self):
        """Regression (#38): encrypt() defaulted to an empty tweak."""
        with pytest.raises(TypeError):
            self.fpe.encrypt("1234567890")
        with pytest.raises(TypeError):
            self.fpe.decrypt("1234567890")

    def test_empty_tweak_still_allowed_explicitly(self):
        ct = self.fpe.encrypt("1234567890", tweak=b"")
        assert ct == "".join(
            str(d) for d in FF1(self.key).encrypt([1, 2, 3, 4, 5, 6, 7, 8, 9, 0], b"")
        )
        assert self.fpe.decrypt(ct, tweak=b"") == "1234567890"

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
        fpe = FormatPreservingEncryption(
            key, alphabet=FormatPreservingEncryption.ALPHANUMERIC_LOWER
        )
        plaintext = "abc123"
        ct = fpe.encrypt(plaintext, tweak=b"t")
        assert len(ct) == 6
        assert all(c in FormatPreservingEncryption.ALPHANUMERIC_LOWER for c in ct)
        pt = fpe.decrypt(ct, tweak=b"t")
        assert pt == plaintext

    def test_full_alphanumeric(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key, alphabet=FormatPreservingEncryption.ALPHANUMERIC)
        plaintext = "AbCd12"
        ct = fpe.encrypt(plaintext, tweak=b"t")
        assert len(ct) == 6
        pt = fpe.decrypt(ct, tweak=b"t")
        assert pt == plaintext

    def test_invalid_character(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key)  # digits only
        with pytest.raises(ValueError, match="not in alphabet"):
            fpe.encrypt("12345A7890", tweak=b"t")


class TestFPEKeyExport:
    """Test FormatPreservingEncryption key import/export."""

    def test_export_import_round_trip(self):
        key = FormatPreservingEncryption.generate_key()
        fpe = FormatPreservingEncryption(key)
        ct = fpe.encrypt("1234567890", tweak=b"t")

        key_b64 = fpe.export_key()
        fpe2 = FormatPreservingEncryption.import_key(key_b64)
        pt = fpe2.decrypt(ct, tweak=b"t")
        assert pt == "1234567890"

    def test_export_import_with_alphabet(self):
        key = FormatPreservingEncryption.generate_key()
        alpha = FormatPreservingEncryption.ALPHANUMERIC_LOWER
        fpe = FormatPreservingEncryption(key, alphabet=alpha)
        ct = fpe.encrypt("abc123", tweak=b"t")

        key_b64 = fpe.export_key()
        fpe2 = FormatPreservingEncryption.import_key(key_b64, alphabet=alpha)
        pt = fpe2.decrypt(ct, tweak=b"t")
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


class TestFPEDefectRegressions:
    """Regression tests for the issue #38 FPE findings."""

    KEY = bytes(range(32))

    @pytest.mark.parametrize("alphabet", ["0123456789a1", "aab", "0123456789" + "0"])
    def test_duplicate_alphabet_characters_rejected(self, alphabet):
        """A repeated character broke the character <-> numeral bijection."""
        with pytest.raises(ValueError, match="unique"):
            FormatPreservingEncryption(self.KEY, alphabet=alphabet)

    def test_non_string_alphabet_rejected(self):
        with pytest.raises(ValueError, match="string"):
            FormatPreservingEncryption(self.KEY, alphabet=list("0123456789"))

    def test_helpers_use_distinct_default_tweaks(self):
        """The helpers defaulted to an empty tweak, so no domain separation happened."""
        fpe = FormatPreservingEncryption(self.KEY)
        digits = "123456789"
        as_ssn = fpe.encrypt_ssn(digits)
        as_account = fpe.encrypt_account_number(digits)
        as_card = fpe.encrypt_credit_card(digits)

        assert len({as_ssn, as_account, as_card, fpe.encrypt(digits, tweak=b"")}) == 4
        assert as_ssn == fpe.encrypt(digits, tweak=FormatPreservingEncryption.TWEAK_SSN)
        assert as_account == fpe.encrypt(
            digits, tweak=FormatPreservingEncryption.TWEAK_ACCOUNT_NUMBER
        )
        assert as_card == fpe.encrypt(digits, tweak=FormatPreservingEncryption.TWEAK_CREDIT_CARD)
        assert (
            len(
                {
                    FormatPreservingEncryption.TWEAK_SSN,
                    FormatPreservingEncryption.TWEAK_ACCOUNT_NUMBER,
                    FormatPreservingEncryption.TWEAK_CREDIT_CARD,
                }
            )
            == 3
        )

    def test_helper_default_tweak_golden_values(self):
        """Pin the helper defaults so a changed default cannot silently orphan data."""
        fpe = FormatPreservingEncryption(self.KEY)
        assert fpe.encrypt_credit_card("4111 1111 1111 1111") == "8827 2035 7204 3356"
        assert fpe.encrypt_ssn("123-45-6789") == "127-07-2552"
        assert fpe.encrypt_account_number("123456789") == "271824863"
        assert fpe.decrypt_ssn("127-07-2552") == "123-45-6789"

    def test_explicit_helper_tweak_replaces_default(self):
        fpe = FormatPreservingEncryption(self.KEY)
        encrypted = fpe.encrypt_ssn("123456789", tweak=b"ssn:customer-7")
        assert encrypted == fpe.encrypt("123456789", tweak=b"ssn:customer-7")
        assert fpe.decrypt_ssn(encrypted, tweak=b"ssn:customer-7") == "123456789"
        # Data written by the old empty-tweak default can still be read explicitly.
        legacy = fpe.encrypt("4111111111111111", tweak=b"")
        assert fpe.decrypt_credit_card(legacy, tweak=b"") == "4111111111111111"

    def test_credit_card_does_not_preserve_bin_or_luhn(self):
        """The docstring no longer claims a drop-in PAN: BIN, last four and Luhn change."""

        def luhn_valid(number: str) -> bool:
            total = 0
            for i, ch in enumerate(reversed(number)):
                d = int(ch)
                if i % 2 == 1:
                    d = d * 2 - 9 if d > 4 else d * 2
                total += d
            return total % 10 == 0

        pan = "4111111111111111"
        assert luhn_valid(pan)
        encrypted = FormatPreservingEncryption(self.KEY).encrypt_credit_card(pan)
        assert encrypted == "8827203572043356"
        assert encrypted[:6] != pan[:6]
        assert encrypted[-4:] != pan[-4:]
        assert not luhn_valid(encrypted)

    @pytest.mark.parametrize("tweak", ["text", 42, None])
    def test_non_bytes_tweak_rejected(self, tweak):
        ff1 = FF1(self.KEY)
        with pytest.raises(ValueError, match="Tweak must be bytes"):
            ff1.encrypt([1, 2, 3, 4, 5, 6], tweak)
        with pytest.raises(ValueError, match="Tweak must be bytes"):
            ff1.decrypt([1, 2, 3, 4, 5, 6], tweak)

    def test_tweak_length_limit_enforced(self, monkeypatch):
        """maxTlen is 2^32 - 1; lowered here so the check can be exercised."""
        assert FF1.MAX_TWEAK_LEN == 2**32 - 1
        monkeypatch.setattr(FF1, "MAX_TWEAK_LEN", 8)
        ff1 = FF1(self.KEY)
        pt = [1, 2, 3, 4, 5, 6]
        assert ff1.decrypt(ff1.encrypt(pt, b"x" * 8), b"x" * 8) == pt
        with pytest.raises(ValueError, match="maxTlen"):
            ff1.encrypt(pt, b"x" * 9)
        with pytest.raises(ValueError, match="maxTlen"):
            ff1.decrypt(pt, b"x" * 9)

    def test_bytearray_tweak_accepted(self):
        ff1 = FF1(self.KEY)
        pt = [1, 2, 3, 4, 5, 6]
        assert ff1.encrypt(pt, bytearray(b"col")) == ff1.encrypt(pt, b"col")

    @pytest.mark.parametrize("radix,length", [(10, 120), (2**16, 24)])
    def test_long_inputs_use_extra_round_blocks(self, radix, length):
        """Inputs whose half exceeds 96 bits need d > 16, i.e. more than one AES block of
        round output (the CIPH_K(R xor [j]) blocks). The NIST samples never reach this."""
        ff1 = FF1(self.KEY, radix=radix)
        v = length - length // 2
        assert v * (radix.bit_length() - 1) > 96
        pt = [(i * 7919) % radix for i in range(length)]
        ct = ff1.encrypt(pt, b"long")
        assert len(ct) == length
        assert ct != pt
        assert ff1.decrypt(ct, b"long") == pt


class TestFF1Properties:
    """Property tests: FF1 round-trips and preserves length and alphabet."""

    FPE_DIGITS = FormatPreservingEncryption(bytes(range(16)))
    FPE_ALNUM = FormatPreservingEncryption(
        bytes(range(32)), alphabet=FormatPreservingEncryption.ALPHANUMERIC
    )

    @settings(max_examples=50, deadline=None)
    @given(
        plaintext=st.text(alphabet=FormatPreservingEncryption.DIGITS, min_size=6, max_size=40),
        tweak=st.binary(max_size=40),
    )
    def test_digits_round_trip(self, plaintext, tweak):
        ciphertext = self.FPE_DIGITS.encrypt(plaintext, tweak=tweak)
        assert len(ciphertext) == len(plaintext)
        assert set(ciphertext) <= set(FormatPreservingEncryption.DIGITS)
        assert self.FPE_DIGITS.decrypt(ciphertext, tweak=tweak) == plaintext

    @settings(max_examples=50, deadline=None)
    @given(
        plaintext=st.text(
            alphabet=FormatPreservingEncryption.ALPHANUMERIC, min_size=4, max_size=40
        ),
        tweak=st.binary(max_size=40),
    )
    def test_alphanumeric_round_trip(self, plaintext, tweak):
        ciphertext = self.FPE_ALNUM.encrypt(plaintext, tweak=tweak)
        assert len(ciphertext) == len(plaintext)
        assert set(ciphertext) <= set(FormatPreservingEncryption.ALPHANUMERIC)
        assert self.FPE_ALNUM.decrypt(ciphertext, tweak=tweak) == plaintext

    @settings(max_examples=50, deadline=None)
    @given(
        radix=st.integers(min_value=2, max_value=2**16),
        data=st.data(),
    )
    def test_numeral_round_trip_any_radix(self, radix, data):
        min_len = 2
        while radix**min_len < 1_000_000:
            min_len += 1
        numerals = data.draw(
            st.lists(
                st.integers(min_value=0, max_value=radix - 1),
                min_size=min_len,
                max_size=min_len + 12,
            )
        )
        ff1 = FF1(bytes(range(24)), radix=radix)
        ciphertext = ff1.encrypt(numerals, b"prop")
        assert len(ciphertext) == len(numerals)
        assert all(0 <= d < radix for d in ciphertext)
        assert ff1.decrypt(ciphertext, b"prop") == numerals
