"""Tests for Post-Quantum Cryptography module."""

import pytest

from encrypted_ir.post_quantum import MLDSA, MLKEM, HybridKEM, PostQuantumEncryption

# ---------------------------------------------------------------------------
# ML-KEM Tests
# ---------------------------------------------------------------------------


class TestMLKEMBasic:
    """Basic ML-KEM key encapsulation tests."""

    def setup_method(self):
        self.kem = MLKEM(768)
        self.pub = self.kem.generate_keypair()

    def test_generate_keypair(self):
        """Keypair generation produces a non-empty public key."""
        assert len(self.pub) == 1184  # ML-KEM-768 public key size

    def test_encapsulate_decapsulate_round_trip(self):
        """Encapsulate then decapsulate recovers the same shared secret."""
        shared_secret, ciphertext = MLKEM.encapsulate(self.pub, 768)
        recovered = self.kem.decapsulate(ciphertext)
        assert shared_secret == recovered

    def test_shared_secret_length(self):
        """Shared secret is 32 bytes."""
        shared_secret, _ = MLKEM.encapsulate(self.pub, 768)
        assert len(shared_secret) == 32

    def test_different_keypairs_produce_different_ciphertexts(self):
        """Two encapsulations to the same public key differ (randomized)."""
        _, ct1 = MLKEM.encapsulate(self.pub, 768)
        _, ct2 = MLKEM.encapsulate(self.pub, 768)
        assert ct1 != ct2

    def test_wrong_secret_key_fails(self):
        """Decapsulation with wrong secret key yields a different shared secret."""
        shared_secret, ciphertext = MLKEM.encapsulate(self.pub, 768)
        other_kem = MLKEM(768)
        other_kem.generate_keypair()
        recovered = other_kem.decapsulate(ciphertext)
        assert shared_secret != recovered


class TestMLKEMSecurityLevels:
    """Test different ML-KEM security levels."""

    def test_level_512(self):
        kem = MLKEM(512)
        pub = kem.generate_keypair()
        assert len(pub) == 800
        ss, ct = MLKEM.encapsulate(pub, 512)
        assert len(ct) == 768
        assert kem.decapsulate(ct) == ss

    def test_level_768(self):
        kem = MLKEM(768)
        pub = kem.generate_keypair()
        assert len(pub) == 1184
        ss, ct = MLKEM.encapsulate(pub, 768)
        assert len(ct) == 1088
        assert kem.decapsulate(ct) == ss

    def test_level_1024(self):
        kem = MLKEM(1024)
        pub = kem.generate_keypair()
        assert len(pub) == 1568
        ss, ct = MLKEM.encapsulate(pub, 1024)
        assert len(ct) == 1568
        assert kem.decapsulate(ct) == ss

    def test_invalid_security_level(self):
        with pytest.raises(ValueError, match="security_level"):
            MLKEM(256)


class TestMLKEMKeyExport:
    """Test ML-KEM key import/export."""

    def test_export_import_secret_key(self):
        kem = MLKEM(768)
        pub = kem.generate_keypair()
        ss, ct = MLKEM.encapsulate(pub, 768)

        sk_b64 = kem.export_secret_key()
        restored = MLKEM.from_secret_key(sk_b64, 768)
        assert restored.decapsulate(ct) == ss

    def test_export_import_public_key(self):
        kem = MLKEM(768)
        pub = kem.generate_keypair()
        pk_b64 = kem.export_public_key()

        import base64

        restored_pub = base64.b64decode(pk_b64)
        assert restored_pub == pub

    def test_no_keypair_raises(self):
        kem = MLKEM(768)
        with pytest.raises(RuntimeError, match="No keypair"):
            kem.get_public_key()
        with pytest.raises(RuntimeError, match="No keypair"):
            kem.export_secret_key()

    def test_no_secret_key_decapsulate_raises(self):
        kem = MLKEM(768)
        with pytest.raises(RuntimeError, match="No secret key"):
            kem.decapsulate(b"\x00" * 1088)


class TestMLKEMLoadKeys:
    """Test loading keys into an MLKEM instance."""

    def test_load_secret_key(self):
        kem1 = MLKEM(768)
        pub = kem1.generate_keypair()
        ss, ct = MLKEM.encapsulate(pub, 768)

        kem2 = MLKEM(768)
        kem2.load_secret_key(kem1._secret_key)
        assert kem2.decapsulate(ct) == ss

    def test_load_public_key(self):
        kem = MLKEM(768)
        pub = kem.generate_keypair()

        kem2 = MLKEM(768)
        kem2.load_public_key(pub)
        assert kem2.get_public_key() == pub


# ---------------------------------------------------------------------------
# ML-DSA Tests
# ---------------------------------------------------------------------------


class TestMLDSABasic:
    """Basic ML-DSA signature tests."""

    def setup_method(self):
        self.dsa = MLDSA(65)
        self.pub = self.dsa.generate_keypair()

    def test_generate_keypair(self):
        """Keypair generation produces a non-empty public key."""
        assert len(self.pub) == 1952  # ML-DSA-65 public key size

    def test_sign_verify_round_trip(self):
        """Sign then verify succeeds."""
        sig = self.dsa.sign(b"hello world")
        assert MLDSA.verify(self.pub, b"hello world", sig, 65)

    def test_wrong_message_fails(self):
        """Verification fails for a different message."""
        sig = self.dsa.sign(b"hello world")
        assert not MLDSA.verify(self.pub, b"wrong message", sig, 65)

    def test_wrong_key_fails(self):
        """Verification fails with the wrong public key."""
        sig = self.dsa.sign(b"hello world")
        other_dsa = MLDSA(65)
        other_pub = other_dsa.generate_keypair()
        assert not MLDSA.verify(other_pub, b"hello world", sig, 65)

    def test_signature_is_nontrivial(self):
        """Signature is non-empty and differs from the message."""
        sig = self.dsa.sign(b"hello world")
        assert len(sig) > 0
        assert sig != b"hello world"

    def test_empty_message(self):
        """Signing and verifying an empty message works."""
        sig = self.dsa.sign(b"")
        assert MLDSA.verify(self.pub, b"", sig, 65)

    def test_large_message(self):
        """Signing and verifying a large message works."""
        msg = b"A" * 100_000
        sig = self.dsa.sign(msg)
        assert MLDSA.verify(self.pub, msg, sig, 65)


class TestMLDSASecurityLevels:
    """Test different ML-DSA security levels."""

    def test_level_44(self):
        dsa = MLDSA(44)
        pub = dsa.generate_keypair()
        assert len(pub) == 1312
        sig = dsa.sign(b"test")
        assert MLDSA.verify(pub, b"test", sig, 44)

    def test_level_65(self):
        dsa = MLDSA(65)
        pub = dsa.generate_keypair()
        assert len(pub) == 1952
        sig = dsa.sign(b"test")
        assert MLDSA.verify(pub, b"test", sig, 65)

    def test_level_87(self):
        dsa = MLDSA(87)
        pub = dsa.generate_keypair()
        assert len(pub) == 2592
        sig = dsa.sign(b"test")
        assert MLDSA.verify(pub, b"test", sig, 87)

    def test_invalid_security_level(self):
        with pytest.raises(ValueError, match="security_level"):
            MLDSA(128)


class TestMLDSAKeyExport:
    """Test ML-DSA key import/export."""

    def test_export_import_secret_key(self):
        dsa = MLDSA(65)
        pub = dsa.generate_keypair()
        dsa.sign(b"message")

        sk_b64 = dsa.export_secret_key()
        restored = MLDSA.from_secret_key(sk_b64, 65)
        # The restored instance can sign — and the original public key can verify
        sig2 = restored.sign(b"another message")
        assert MLDSA.verify(pub, b"another message", sig2, 65)

    def test_no_keypair_raises(self):
        dsa = MLDSA(65)
        with pytest.raises(RuntimeError, match="No keypair"):
            dsa.get_public_key()
        with pytest.raises(RuntimeError, match="No keypair"):
            dsa.export_secret_key()

    def test_no_secret_key_sign_raises(self):
        dsa = MLDSA(65)
        with pytest.raises(RuntimeError, match="No secret key"):
            dsa.sign(b"test")


# ---------------------------------------------------------------------------
# Hybrid KEM Tests
# ---------------------------------------------------------------------------


class TestHybridKEMBasic:
    """Test hybrid ML-KEM + X25519 key encapsulation."""

    def setup_method(self):
        self.hybrid = HybridKEM(768)
        self.kem_pub, self.x25519_pub = self.hybrid.generate_keypair()

    def test_generate_keypair(self):
        assert len(self.kem_pub) == 1184
        assert len(self.x25519_pub) == 32

    def test_encapsulate_decapsulate_round_trip(self):
        combined_ss, kem_ct, x25519_eph = HybridKEM.encapsulate(self.kem_pub, self.x25519_pub, 768)
        recovered = self.hybrid.decapsulate(kem_ct, x25519_eph)
        assert combined_ss == recovered

    def test_shared_secret_length(self):
        combined_ss, _, _ = HybridKEM.encapsulate(self.kem_pub, self.x25519_pub, 768)
        assert len(combined_ss) == 32  # SHA-256 output

    def test_different_encapsulations_differ(self):
        ss1, _, _ = HybridKEM.encapsulate(self.kem_pub, self.x25519_pub, 768)
        ss2, _, _ = HybridKEM.encapsulate(self.kem_pub, self.x25519_pub, 768)
        assert ss1 != ss2

    def test_no_keypair_decapsulate_raises(self):
        hybrid = HybridKEM(768)
        with pytest.raises(RuntimeError, match="No keypair"):
            hybrid.decapsulate(b"\x00" * 1088, b"\x00" * 32)


class TestHybridKEMSecurityLevels:
    """Test hybrid KEM with different ML-KEM security levels."""

    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_round_trip(self, level):
        hybrid = HybridKEM(level)
        kem_pub, x25519_pub = hybrid.generate_keypair()
        ss, kem_ct, x25519_eph = HybridKEM.encapsulate(kem_pub, x25519_pub, level)
        recovered = hybrid.decapsulate(kem_ct, x25519_eph)
        assert ss == recovered


# ---------------------------------------------------------------------------
# PostQuantumEncryption Tests
# ---------------------------------------------------------------------------


class TestPostQuantumEncryptionBasic:
    """Test high-level post-quantum encryption."""

    def setup_method(self):
        self.sender = PostQuantumEncryption(768, 65)
        self.sender_keys = self.sender.generate_keypair()

        self.recipient = PostQuantumEncryption(768, 65)
        self.recipient_keys = self.recipient.generate_keypair()

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"Sensitive financial data: account 12345678"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
        )
        decrypted = self.recipient.decrypt(
            encrypted["kem_ciphertext"],
            encrypted["x25519_ephemeral"],
            encrypted["nonce"],
            encrypted["ciphertext"],
        )
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_data(self):
        encrypted = self.sender.encrypt(
            b"",
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
        )
        decrypted = self.recipient.decrypt(
            encrypted["kem_ciphertext"],
            encrypted["x25519_ephemeral"],
            encrypted["nonce"],
            encrypted["ciphertext"],
        )
        assert decrypted == b""

    def test_encrypt_decrypt_large_data(self):
        plaintext = b"X" * 1_000_000  # 1 MB
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
        )
        decrypted = self.recipient.decrypt(
            encrypted["kem_ciphertext"],
            encrypted["x25519_ephemeral"],
            encrypted["nonce"],
            encrypted["ciphertext"],
        )
        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"Sensitive financial data"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
        )
        assert encrypted["ciphertext"] != plaintext

    def test_wrong_recipient_cannot_decrypt(self):
        plaintext = b"Secret data"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
        )
        # A different recipient cannot decrypt
        other = PostQuantumEncryption(768, 65)
        other.generate_keypair()
        with pytest.raises(Exception):
            other.decrypt(
                encrypted["kem_ciphertext"],
                encrypted["x25519_ephemeral"],
                encrypted["nonce"],
                encrypted["ciphertext"],
            )


class TestPostQuantumEncryptionSigned:
    """Test signed post-quantum encryption."""

    def setup_method(self):
        self.sender = PostQuantumEncryption(768, 65)
        self.sender_keys = self.sender.generate_keypair()

        self.recipient = PostQuantumEncryption(768, 65)
        self.recipient_keys = self.recipient.generate_keypair()

    def test_signed_encrypt_decrypt(self):
        plaintext = b"Signed financial document"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
            sign=True,
        )
        assert "signature" in encrypted

        decrypted = self.recipient.decrypt(
            encrypted["kem_ciphertext"],
            encrypted["x25519_ephemeral"],
            encrypted["nonce"],
            encrypted["ciphertext"],
            signature=encrypted["signature"],
            sender_dsa_public_key=self.sender_keys["dsa_public_key"],
        )
        assert decrypted == plaintext

    def test_tampered_ciphertext_fails_signature(self):
        plaintext = b"Important document"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
            sign=True,
        )
        # Tamper with the ciphertext
        tampered_ct = bytearray(encrypted["ciphertext"])
        tampered_ct[0] ^= 0xFF
        tampered_ct = bytes(tampered_ct)

        with pytest.raises(ValueError, match="Signature verification failed"):
            self.recipient.decrypt(
                encrypted["kem_ciphertext"],
                encrypted["x25519_ephemeral"],
                encrypted["nonce"],
                tampered_ct,
                signature=encrypted["signature"],
                sender_dsa_public_key=self.sender_keys["dsa_public_key"],
            )

    def test_wrong_sender_key_fails_signature(self):
        plaintext = b"Document"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
            sign=True,
        )
        # Try verifying with the wrong sender key
        other_sender = PostQuantumEncryption(768, 65)
        other_keys = other_sender.generate_keypair()

        with pytest.raises(ValueError, match="Signature verification failed"):
            self.recipient.decrypt(
                encrypted["kem_ciphertext"],
                encrypted["x25519_ephemeral"],
                encrypted["nonce"],
                encrypted["ciphertext"],
                signature=encrypted["signature"],
                sender_dsa_public_key=other_keys["dsa_public_key"],
            )

    def test_signature_without_public_key_raises(self):
        plaintext = b"Document"
        encrypted = self.sender.encrypt(
            plaintext,
            self.recipient_keys["kem_public_key"],
            self.recipient_keys["x25519_public_key"],
            sign=True,
        )
        with pytest.raises(ValueError, match="sender_dsa_public_key required"):
            self.recipient.decrypt(
                encrypted["kem_ciphertext"],
                encrypted["x25519_ephemeral"],
                encrypted["nonce"],
                encrypted["ciphertext"],
                signature=encrypted["signature"],
            )


class TestPostQuantumDocumentSigning:
    """Test standalone document signing."""

    def setup_method(self):
        self.pqe = PostQuantumEncryption(768, 65)
        self.keys = self.pqe.generate_keypair()

    def test_sign_verify(self):
        doc = b"Financial audit record 2026-Q1"
        sig = self.pqe.sign_document(doc)
        assert self.pqe.verify_document(self.keys["dsa_public_key"], doc, sig)

    def test_wrong_document_fails(self):
        doc = b"Original document"
        sig = self.pqe.sign_document(doc)
        assert not self.pqe.verify_document(self.keys["dsa_public_key"], b"Tampered", sig)

    def test_get_dsa_public_key(self):
        assert self.pqe.get_dsa_public_key() == self.keys["dsa_public_key"]


class TestPostQuantumSecurityLevels:
    """Test PostQuantumEncryption with different security levels."""

    @pytest.mark.parametrize(
        "kem_level,dsa_level",
        [(512, 44), (768, 65), (1024, 87)],
    )
    def test_encrypt_decrypt_all_levels(self, kem_level, dsa_level):
        sender = PostQuantumEncryption(kem_level, dsa_level)
        sender_keys = sender.generate_keypair()

        recipient = PostQuantumEncryption(kem_level, dsa_level)
        recipient_keys = recipient.generate_keypair()

        plaintext = b"Level test data"
        encrypted = sender.encrypt(
            plaintext,
            recipient_keys["kem_public_key"],
            recipient_keys["x25519_public_key"],
            sign=True,
        )
        decrypted = recipient.decrypt(
            encrypted["kem_ciphertext"],
            encrypted["x25519_ephemeral"],
            encrypted["nonce"],
            encrypted["ciphertext"],
            signature=encrypted["signature"],
            sender_dsa_public_key=sender_keys["dsa_public_key"],
        )
        assert decrypted == plaintext
