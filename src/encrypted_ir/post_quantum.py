"""
Post-Quantum Cryptography Module

Implements NIST PQC standards for quantum-resistant key encapsulation and
digital signatures, suitable for protecting financial data against future
quantum computing threats.

Algorithms (NIST FIPS 203 / FIPS 204):
- ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism): Hybrid key
  exchange combining ML-KEM with X25519 for defense-in-depth.
- ML-DSA (Module-Lattice-Based Digital Signature Algorithm): Quantum-resistant
  digital signatures for document integrity and non-repudiation.

Security Levels:
- ML-KEM-512  / ML-DSA-44: NIST Level 1 (~AES-128 equivalent)
- ML-KEM-768  / ML-DSA-65: NIST Level 3 (~AES-192 equivalent) [recommended]
- ML-KEM-1024 / ML-DSA-87: NIST Level 5 (~AES-256 equivalent)

Use Cases:
- Hybrid key exchange for establishing shared secrets (ML-KEM + X25519)
- Signing encrypted documents, audit records, key attestations (ML-DSA)
- Long-term data protection against "harvest now, decrypt later" attacks
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

# ---------------------------------------------------------------------------
# ML-KEM parameter set registry
# ---------------------------------------------------------------------------

_KEM_PARAMS = {
    512: ml_kem_512,
    768: ml_kem_768,
    1024: ml_kem_1024,
}

_DSA_PARAMS = {
    44: ml_dsa_44,
    65: ml_dsa_65,
    87: ml_dsa_87,
}


class MLKEM:
    """
    ML-KEM Key Encapsulation Mechanism (FIPS 203).

    Generates a shared secret between two parties using lattice-based
    cryptography resistant to quantum attacks.

    Typical workflow:
        1. Recipient generates a keypair and publishes the public key.
        2. Sender calls ``encapsulate(public_key)`` → (shared_secret, ciphertext).
        3. Recipient calls ``decapsulate(ciphertext)`` → shared_secret.
        4. Both parties derive symmetric keys from the shared secret.
    """

    SECURITY_LEVELS = {512, 768, 1024}

    def __init__(self, security_level: int = 768):
        """
        Initialize ML-KEM with a security level.

        Args:
            security_level: 512 (Level 1), 768 (Level 3, recommended), or 1024 (Level 5).

        Raises:
            ValueError: If security_level is not supported.
        """
        if security_level not in self.SECURITY_LEVELS:
            raise ValueError(
                f"security_level must be one of {sorted(self.SECURITY_LEVELS)}, "
                f"got {security_level}"
            )
        self.security_level = security_level
        self._mod = _KEM_PARAMS[security_level]
        self._public_key: bytes | None = None
        self._secret_key: bytes | None = None

    def generate_keypair(self) -> bytes:
        """
        Generate an ML-KEM keypair.

        Returns:
            Public key bytes (share with the sender).
        """
        self._public_key, self._secret_key = self._mod.generate_keypair()
        return self._public_key

    @staticmethod
    def encapsulate(public_key: bytes, security_level: int = 768) -> tuple[bytes, bytes]:
        """
        Encapsulate: produce a shared secret and ciphertext for the given public key.

        Args:
            public_key: Recipient's ML-KEM public key.
            security_level: Must match the recipient's security level.

        Returns:
            Tuple of (shared_secret, ciphertext). Send ciphertext to the recipient.
        """
        mod = _KEM_PARAMS[security_level]
        ciphertext, shared_secret = mod.encrypt(public_key)
        return shared_secret, ciphertext

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover the shared secret from a ciphertext.

        Args:
            ciphertext: Ciphertext produced by ``encapsulate``.

        Returns:
            32-byte shared secret (matches sender's shared secret).

        Raises:
            RuntimeError: If no secret key is loaded.
        """
        if self._secret_key is None:
            raise RuntimeError("No secret key — call generate_keypair() or load_secret_key() first")
        return self._mod.decrypt(self._secret_key, ciphertext)

    def get_public_key(self) -> bytes:
        """Return the public key bytes."""
        if self._public_key is None:
            raise RuntimeError("No keypair generated")
        return self._public_key

    def export_public_key(self) -> str:
        """Export the public key as base64."""
        return base64.b64encode(self.get_public_key()).decode("ascii")

    def export_secret_key(self) -> str:
        """Export the secret key as base64."""
        if self._secret_key is None:
            raise RuntimeError("No keypair generated")
        return base64.b64encode(self._secret_key).decode("ascii")

    def load_secret_key(self, secret_key: bytes):
        """Load a previously exported secret key."""
        self._secret_key = secret_key

    def load_public_key(self, public_key: bytes):
        """Load a previously exported public key."""
        self._public_key = public_key

    @classmethod
    def from_secret_key(cls, secret_key_b64: str, security_level: int = 768) -> MLKEM:
        """
        Restore an MLKEM instance from a base64-encoded secret key.

        Args:
            secret_key_b64: Base64-encoded secret key.
            security_level: Security level that produced the key.

        Returns:
            MLKEM instance ready for decapsulation.
        """
        instance = cls(security_level)
        instance._secret_key = base64.b64decode(secret_key_b64)
        return instance


class MLDSA:
    """
    ML-DSA Digital Signature Algorithm (FIPS 204).

    Provides quantum-resistant digital signatures for document integrity,
    non-repudiation, and key attestation.

    Typical workflow:
        1. Signer generates a keypair and publishes the public key.
        2. Signer calls ``sign(message)`` → signature bytes.
        3. Verifier calls ``verify(public_key, message, signature)`` → bool.
    """

    SECURITY_LEVELS = {44, 65, 87}

    def __init__(self, security_level: int = 65):
        """
        Initialize ML-DSA with a security level.

        Args:
            security_level: 44 (Level 1), 65 (Level 3, recommended), or 87 (Level 5).

        Raises:
            ValueError: If security_level is not supported.
        """
        if security_level not in self.SECURITY_LEVELS:
            raise ValueError(
                f"security_level must be one of {sorted(self.SECURITY_LEVELS)}, "
                f"got {security_level}"
            )
        self.security_level = security_level
        self._mod = _DSA_PARAMS[security_level]
        self._public_key: bytes | None = None
        self._secret_key: bytes | None = None

    def generate_keypair(self) -> bytes:
        """
        Generate an ML-DSA keypair.

        Returns:
            Public key bytes (share with verifiers).
        """
        self._public_key, self._secret_key = self._mod.generate_keypair()
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            message: Arbitrary-length message bytes.

        Returns:
            Signature bytes.

        Raises:
            RuntimeError: If no secret key is loaded.
        """
        if self._secret_key is None:
            raise RuntimeError("No secret key — call generate_keypair() or load_secret_key() first")
        return self._mod.sign(self._secret_key, message)

    @staticmethod
    def verify(
        public_key: bytes, message: bytes, signature: bytes, security_level: int = 65
    ) -> bool:
        """
        Verify a signature.

        Args:
            public_key: Signer's ML-DSA public key.
            message: The original message.
            signature: Signature to verify.
            security_level: Must match signer's security level.

        Returns:
            True if the signature is valid, False otherwise.
        """
        mod = _DSA_PARAMS[security_level]
        return mod.verify(public_key, message, signature)

    def get_public_key(self) -> bytes:
        """Return the public key bytes."""
        if self._public_key is None:
            raise RuntimeError("No keypair generated")
        return self._public_key

    def export_public_key(self) -> str:
        """Export the public key as base64."""
        return base64.b64encode(self.get_public_key()).decode("ascii")

    def export_secret_key(self) -> str:
        """Export the secret key as base64."""
        if self._secret_key is None:
            raise RuntimeError("No keypair generated")
        return base64.b64encode(self._secret_key).decode("ascii")

    def load_secret_key(self, secret_key: bytes):
        """Load a previously exported secret key."""
        self._secret_key = secret_key

    def load_public_key(self, public_key: bytes):
        """Load a previously exported public key."""
        self._public_key = public_key

    @classmethod
    def from_secret_key(cls, secret_key_b64: str, security_level: int = 65) -> MLDSA:
        """
        Restore an MLDSA instance from a base64-encoded secret key.

        Args:
            secret_key_b64: Base64-encoded secret key.
            security_level: Security level that produced the key.

        Returns:
            MLDSA instance ready for signing.
        """
        instance = cls(security_level)
        instance._secret_key = base64.b64decode(secret_key_b64)
        return instance


class HybridKEM:
    """
    Hybrid Key Encapsulation combining ML-KEM with X25519.

    Provides defense-in-depth: the shared secret is secure as long as
    *either* ML-KEM or X25519 remains unbroken. This follows the
    recommended migration strategy for transitioning to post-quantum
    cryptography (NIST SP 800-227).

    The combined shared secret is derived by concatenating the ML-KEM
    and X25519 shared secrets and hashing with SHA-256.
    """

    def __init__(self, kem_security_level: int = 768):
        """
        Initialize hybrid KEM.

        Args:
            kem_security_level: ML-KEM security level (512, 768, or 1024).
        """
        self._mlkem = MLKEM(kem_security_level)
        self._x25519_private: X25519PrivateKey | None = None
        self.kem_security_level = kem_security_level

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate hybrid keypair (ML-KEM + X25519).

        Returns:
            Tuple of (ml_kem_public_key, x25519_public_key).
        """
        kem_pub = self._mlkem.generate_keypair()
        self._x25519_private = X25519PrivateKey.generate()
        x25519_pub = self._x25519_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return kem_pub, x25519_pub

    @staticmethod
    def encapsulate(
        kem_public_key: bytes,
        x25519_public_key: bytes,
        kem_security_level: int = 768,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Hybrid encapsulation: produce a combined shared secret.

        Args:
            kem_public_key: Recipient's ML-KEM public key.
            x25519_public_key: Recipient's X25519 public key (32 bytes).
            kem_security_level: ML-KEM security level.

        Returns:
            Tuple of (combined_shared_secret, kem_ciphertext, x25519_public_key).
            Send kem_ciphertext and x25519_public_key to the recipient.
        """
        # ML-KEM encapsulation
        kem_ss, kem_ct = MLKEM.encapsulate(kem_public_key, kem_security_level)

        # X25519 key agreement
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        peer_public = X25519PublicKey.from_public_bytes(x25519_public_key)
        x25519_ss = ephemeral_private.exchange(peer_public)

        # Combine shared secrets via SHA-256
        combined = _combine_secrets(kem_ss, x25519_ss)
        return combined, kem_ct, ephemeral_public

    def decapsulate(self, kem_ciphertext: bytes, x25519_ephemeral_public: bytes) -> bytes:
        """
        Hybrid decapsulation: recover the combined shared secret.

        Args:
            kem_ciphertext: ML-KEM ciphertext from encapsulation.
            x25519_ephemeral_public: Sender's ephemeral X25519 public key (32 bytes).

        Returns:
            32-byte combined shared secret.

        Raises:
            RuntimeError: If no keypair was generated.
        """
        if self._x25519_private is None:
            raise RuntimeError("No keypair generated")

        # ML-KEM decapsulation
        kem_ss = self._mlkem.decapsulate(kem_ciphertext)

        # X25519 key agreement
        peer_public = X25519PublicKey.from_public_bytes(x25519_ephemeral_public)
        x25519_ss = self._x25519_private.exchange(peer_public)

        return _combine_secrets(kem_ss, x25519_ss)

    def export_x25519_private_key(self) -> str:
        """Export X25519 private key as base64."""
        if self._x25519_private is None:
            raise RuntimeError("No keypair generated")
        raw = self._x25519_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return base64.b64encode(raw).decode("ascii")

    def export_kem_secret_key(self) -> str:
        """Export ML-KEM secret key as base64."""
        return self._mlkem.export_secret_key()


class PostQuantumEncryption:
    """
    High-level post-quantum encryption interface.

    Combines HybridKEM (ML-KEM + X25519) for key establishment with
    AES-256-GCM for authenticated data encryption. Optionally signs
    ciphertexts with ML-DSA for integrity and non-repudiation.

    Use Case: Encrypting sensitive financial documents with quantum-resistant
    protection and optional digital signatures for audit compliance.
    """

    def __init__(
        self,
        kem_security_level: int = 768,
        dsa_security_level: int = 65,
    ):
        """
        Initialize post-quantum encryption.

        Args:
            kem_security_level: ML-KEM security level for key encapsulation.
            dsa_security_level: ML-DSA security level for signatures.
        """
        self._hybrid = HybridKEM(kem_security_level)
        self._dsa = MLDSA(dsa_security_level)
        self.kem_security_level = kem_security_level
        self.dsa_security_level = dsa_security_level

    def generate_keypair(self) -> dict:
        """
        Generate all keys (encryption + signing).

        Returns:
            Dictionary with public keys:
            - ``kem_public_key``: ML-KEM public key bytes
            - ``x25519_public_key``: X25519 public key bytes (32 bytes)
            - ``dsa_public_key``: ML-DSA public key bytes
        """
        kem_pub, x25519_pub = self._hybrid.generate_keypair()
        dsa_pub = self._dsa.generate_keypair()
        return {
            "kem_public_key": kem_pub,
            "x25519_public_key": x25519_pub,
            "dsa_public_key": dsa_pub,
        }

    def encrypt(
        self,
        plaintext: bytes,
        recipient_kem_public_key: bytes,
        recipient_x25519_public_key: bytes,
        sign: bool = False,
    ) -> dict:
        """
        Encrypt data for a recipient using hybrid PQ key exchange + AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            recipient_kem_public_key: Recipient's ML-KEM public key.
            recipient_x25519_public_key: Recipient's X25519 public key.
            sign: If True, sign the ciphertext with ML-DSA.

        Returns:
            Dictionary containing:
            - ``kem_ciphertext``: ML-KEM ciphertext for key recovery
            - ``x25519_ephemeral``: Sender's ephemeral X25519 public key
            - ``nonce``: AES-GCM nonce (12 bytes)
            - ``ciphertext``: AES-256-GCM encrypted data
            - ``signature``: ML-DSA signature (only if sign=True)
        """
        # Hybrid key exchange
        shared_secret, kem_ct, x25519_eph = HybridKEM.encapsulate(
            recipient_kem_public_key,
            recipient_x25519_public_key,
            self.kem_security_level,
        )

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(shared_secret)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        result = {
            "kem_ciphertext": kem_ct,
            "x25519_ephemeral": x25519_eph,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

        if sign:
            # Sign the ciphertext for non-repudiation
            sig_data = kem_ct + x25519_eph + nonce + ciphertext
            result["signature"] = self._dsa.sign(sig_data)

        return result

    def decrypt(
        self,
        kem_ciphertext: bytes,
        x25519_ephemeral: bytes,
        nonce: bytes,
        ciphertext: bytes,
        signature: bytes = None,
        sender_dsa_public_key: bytes = None,
    ) -> bytes:
        """
        Decrypt data using hybrid PQ key exchange + AES-256-GCM.

        Args:
            kem_ciphertext: ML-KEM ciphertext.
            x25519_ephemeral: Sender's ephemeral X25519 public key.
            nonce: AES-GCM nonce.
            ciphertext: AES-256-GCM encrypted data.
            signature: Optional ML-DSA signature to verify.
            sender_dsa_public_key: Sender's ML-DSA public key (required if signature given).

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If signature verification fails.
        """
        # Verify signature if provided
        if signature is not None:
            if sender_dsa_public_key is None:
                raise ValueError("sender_dsa_public_key required when verifying signature")
            sig_data = kem_ciphertext + x25519_ephemeral + nonce + ciphertext
            if not MLDSA.verify(
                sender_dsa_public_key, sig_data, signature, self.dsa_security_level
            ):
                raise ValueError("Signature verification failed")

        # Hybrid decapsulation
        shared_secret = self._hybrid.decapsulate(kem_ciphertext, x25519_ephemeral)

        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def sign_document(self, document: bytes) -> bytes:
        """
        Sign a document with ML-DSA.

        Args:
            document: Document bytes to sign.

        Returns:
            Signature bytes.
        """
        return self._dsa.sign(document)

    def verify_document(self, public_key: bytes, document: bytes, signature: bytes) -> bool:
        """
        Verify a document signature.

        Args:
            public_key: Signer's ML-DSA public key.
            document: Original document bytes.
            signature: Signature to verify.

        Returns:
            True if the signature is valid.
        """
        return MLDSA.verify(public_key, document, signature, self.dsa_security_level)

    def get_dsa_public_key(self) -> bytes:
        """Return the ML-DSA public key."""
        return self._dsa.get_public_key()


def _combine_secrets(kem_secret: bytes, x25519_secret: bytes) -> bytes:
    """
    Combine two shared secrets into one via SHA-256.

    This is the standard hybrid combiner: H(kem_ss || x25519_ss).
    Security holds if *either* component is secure.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(kem_secret)
    digest.update(x25519_secret)
    return digest.finalize()
