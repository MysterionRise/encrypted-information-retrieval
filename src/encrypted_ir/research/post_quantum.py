"""
Post-Quantum Cryptography Module (research prototype, not audited)

Wraps the pqcrypto bindings of ML-KEM (FIPS 203) and ML-DSA (FIPS 204), and
builds a hybrid KEM and a sign-then-encrypt helper on top of them.

Algorithms:
- ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism), via pqcrypto.
- ML-DSA (Module-Lattice-Based Digital Signature Algorithm), via pqcrypto.
- HybridKEM: ML-KEM plus an ephemeral-static X25519 exchange, combined as
  SHA-256(kem_ss || x25519_ss). This combiner is custom. It is not X-Wing,
  not the IETF hybrid key-exchange design, and no conformance to NIST
  SP 800-227 or SP 800-56C is claimed. It binds neither the ciphertexts nor
  the public keys into the hash and has no domain-separation label.

Security Levels:
- ML-KEM-512  / ML-DSA-44: NIST Level 1 (~AES-128 equivalent)
- ML-KEM-768  / ML-DSA-65: NIST Level 3 (~AES-192 equivalent) [default]
- ML-KEM-1024 / ML-DSA-87: NIST Level 5 (~AES-256 equivalent)

An unsupported security level raises ValueError everywhere, including the
static MLKEM.encapsulate, MLDSA.verify and HybridKEM.encapsulate.

Signatures: PostQuantumEncryption.decrypt() verifies a signature whenever one
is given, and refuses to decrypt without one when ``require_signature`` is
True. ``require_signature`` defaults to True when the caller passes
``sender_dsa_public_key`` (the caller expects a signed message, so a stripped
signature must fail) and to False otherwise.

Persistence: every secret (ML-KEM and ML-DSA secret keys, X25519 private key)
can be exported as base64 and loaded again, so an instance can be restored
after a restart; see HybridKEM.from_secret_keys() and
PostQuantumEncryption.export_keys() / from_keys().

Requires pqcrypto below 1.0 (1.0 renamed the API).
"""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from types import ModuleType
from typing import Any, cast

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

try:
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
    from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87
except ImportError as exc:
    raise ImportError(
        "encrypted_ir.research.post_quantum needs pqcrypto below 1.0. Install the research "
        "extra: pip install 'encrypted-information-retrieval[research]' "
        "or pip install -r requirements-research.txt"
    ) from exc

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

_X25519_KEY_SIZE = 32


def _kem_module(security_level: int) -> ModuleType:
    """Return the pqcrypto ML-KEM module for ``security_level`` or raise ValueError."""
    try:
        return cast(ModuleType, _KEM_PARAMS[security_level])
    except (KeyError, TypeError):
        raise ValueError(
            f"security_level must be one of {sorted(_KEM_PARAMS)}, got {security_level!r}"
        ) from None


def _dsa_module(security_level: int) -> ModuleType:
    """Return the pqcrypto ML-DSA module for ``security_level`` or raise ValueError."""
    try:
        return cast(ModuleType, _DSA_PARAMS[security_level])
    except (KeyError, TypeError):
        raise ValueError(
            f"security_level must be one of {sorted(_DSA_PARAMS)}, got {security_level!r}"
        ) from None


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
        self._mod = _kem_module(security_level)
        self.security_level = security_level
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

        Raises:
            ValueError: If security_level is not supported.
        """
        mod = _kem_module(security_level)
        ciphertext, shared_secret = mod.encrypt(public_key)
        return cast(bytes, shared_secret), cast(bytes, ciphertext)

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
        return cast(bytes, self._mod.decrypt(self._secret_key, ciphertext))

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
        self._mod = _dsa_module(security_level)
        self.security_level = security_level
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
        return cast(bytes, self._mod.sign(self._secret_key, message))

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

        Raises:
            ValueError: If security_level is not supported.
        """
        mod = _dsa_module(security_level)
        return bool(mod.verify(public_key, message, signature))

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
    Hybrid key encapsulation: ML-KEM plus X25519, with a custom combiner.

    Research prototype, not audited. The intent is that the shared secret stays
    secret while either ML-KEM or X25519 is unbroken.

    The combined secret is SHA-256(kem_ss || x25519_ss). This is not X-Wing,
    not the IETF hybrid key-exchange construction, and not a combiner from
    NIST SP 800-227 or SP 800-56C; no conformance to any of them is claimed.
    Unlike X-Wing it does not hash the X25519 ciphertext (the ephemeral public
    key) or the recipient's X25519 public key, and it has no domain-separation
    label. Changing the combiner would change every shared secret, so it is
    documented rather than replaced.

    Persistence: export_kem_secret_key() and export_x25519_private_key() return
    base64 secrets; from_secret_keys() restores an instance that can
    decapsulate.
    """

    def __init__(self, kem_security_level: int = 768):
        """
        Initialize hybrid KEM.

        Args:
            kem_security_level: ML-KEM security level (512, 768, or 1024).

        Raises:
            ValueError: If kem_security_level is not supported.
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
        return kem_pub, self.get_x25519_public_key()

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

        Raises:
            ValueError: If kem_security_level is not supported.
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
            RuntimeError: If no keypair was generated or loaded.
        """
        if self._x25519_private is None:
            raise RuntimeError("No keypair generated")

        # ML-KEM decapsulation
        kem_ss = self._mlkem.decapsulate(kem_ciphertext)

        # X25519 key agreement
        peer_public = X25519PublicKey.from_public_bytes(x25519_ephemeral_public)
        x25519_ss = self._x25519_private.exchange(peer_public)

        return _combine_secrets(kem_ss, x25519_ss)

    def get_x25519_public_key(self) -> bytes:
        """Return the raw 32-byte X25519 public key."""
        if self._x25519_private is None:
            raise RuntimeError("No keypair generated")
        return cast(
            bytes, self._x25519_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def get_kem_public_key(self) -> bytes:
        """Return the ML-KEM public key."""
        return self._mlkem.get_public_key()

    def export_x25519_private_key(self) -> str:
        """Export X25519 private key as base64."""
        if self._x25519_private is None:
            raise RuntimeError("No keypair generated")
        raw = self._x25519_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return base64.b64encode(raw).decode("ascii")

    def export_kem_secret_key(self) -> str:
        """Export ML-KEM secret key as base64."""
        return self._mlkem.export_secret_key()

    def export_kem_public_key(self) -> str:
        """Export ML-KEM public key as base64."""
        return self._mlkem.export_public_key()

    def load_x25519_private_key(self, private_key: bytes) -> bytes:
        """
        Load a raw 32-byte X25519 private key (as exported, after base64 decoding).

        Args:
            private_key: Raw X25519 private key.

        Returns:
            The matching raw X25519 public key.

        Raises:
            ValueError: If the key is not 32 bytes.
        """
        if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != _X25519_KEY_SIZE:
            raise ValueError(f"X25519 private key must be {_X25519_KEY_SIZE} raw bytes")
        self._x25519_private = X25519PrivateKey.from_private_bytes(bytes(private_key))
        return self.get_x25519_public_key()

    def load_kem_secret_key(self, secret_key: bytes) -> None:
        """Load a raw ML-KEM secret key."""
        self._mlkem.load_secret_key(secret_key)

    def load_kem_public_key(self, public_key: bytes) -> None:
        """Load a raw ML-KEM public key."""
        self._mlkem.load_public_key(public_key)

    @classmethod
    def from_secret_keys(
        cls,
        kem_secret_key_b64: str,
        x25519_private_key_b64: str,
        kem_security_level: int = 768,
        kem_public_key_b64: str | None = None,
    ) -> HybridKEM:
        """
        Restore a HybridKEM that can decapsulate from its exported secrets.

        Args:
            kem_secret_key_b64: Output of export_kem_secret_key().
            x25519_private_key_b64: Output of export_x25519_private_key().
            kem_security_level: ML-KEM security level that produced the key.
            kem_public_key_b64: Optional output of export_kem_public_key(), so that
                get_kem_public_key() works on the restored instance.

        Returns:
            HybridKEM instance.

        Raises:
            ValueError: If a value is not valid base64, the X25519 key is not 32 bytes,
                or the security level is not supported.
        """
        instance = cls(kem_security_level)
        instance.load_kem_secret_key(_b64decode_strict(kem_secret_key_b64))
        instance.load_x25519_private_key(_b64decode_strict(x25519_private_key_b64))
        if kem_public_key_b64 is not None:
            instance.load_kem_public_key(_b64decode_strict(kem_public_key_b64))
        return instance


class PostQuantumEncryption:
    """
    Post-quantum sign-then-encrypt helper (research prototype, not audited).

    Combines HybridKEM (ML-KEM + X25519, custom combiner) for key
    establishment with AES-256-GCM for data encryption. Optionally signs the
    ciphertext with ML-DSA.

    decrypt() verifies a signature whenever one is supplied. To make a missing
    signature an error, pass ``sender_dsa_public_key`` (require_signature then
    defaults to True) or ``require_signature=True``.
    """

    KEY_EXPORT_VERSION = 1

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

        Raises:
            ValueError: If either security level is not supported.
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

    def export_keys(self) -> dict[str, Any]:
        """
        Export every key of this instance, secret keys included, as a JSON-serialisable dict.

        The result contains the ML-KEM, X25519 and ML-DSA secret keys in the
        clear (base64). Protect it like the keys themselves.

        Returns:
            Dict for :meth:`from_keys`.

        Raises:
            RuntimeError: If the keys have not been generated or loaded.
        """
        return {
            "version": self.KEY_EXPORT_VERSION,
            "kem_security_level": self.kem_security_level,
            "dsa_security_level": self.dsa_security_level,
            "kem_secret_key": self._hybrid.export_kem_secret_key(),
            "kem_public_key": self._hybrid.export_kem_public_key(),
            "x25519_private_key": self._hybrid.export_x25519_private_key(),
            "dsa_secret_key": self._dsa.export_secret_key(),
            "dsa_public_key": self._dsa.export_public_key(),
        }

    @classmethod
    def from_keys(cls, keys: Mapping[str, Any]) -> PostQuantumEncryption:
        """
        Restore an instance from :meth:`export_keys` output.

        The restored instance can decrypt data encrypted to the original public
        keys and sign with the original ML-DSA key.

        Args:
            keys: Dict returned by export_keys(), for example after a JSON round trip.

        Returns:
            PostQuantumEncryption instance.

        Raises:
            ValueError: If the dict is malformed or has an unsupported version.
        """
        try:
            if keys["version"] != cls.KEY_EXPORT_VERSION:
                raise ValueError(f"Unsupported key export version: {keys['version']!r}")
            instance = cls(keys["kem_security_level"], keys["dsa_security_level"])
            instance._hybrid = HybridKEM.from_secret_keys(
                keys["kem_secret_key"],
                keys["x25519_private_key"],
                keys["kem_security_level"],
                kem_public_key_b64=keys["kem_public_key"],
            )
            instance._dsa.load_secret_key(_b64decode_strict(keys["dsa_secret_key"]))
            instance._dsa.load_public_key(_b64decode_strict(keys["dsa_public_key"]))
        except (KeyError, TypeError) as exc:
            raise ValueError(f"Malformed key export: {exc}") from exc
        return instance

    def get_public_keys(self) -> dict:
        """Return the public keys in the same shape as generate_keypair()."""
        return {
            "kem_public_key": self._hybrid.get_kem_public_key(),
            "x25519_public_key": self._hybrid.get_x25519_public_key(),
            "dsa_public_key": self._dsa.get_public_key(),
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
        require_signature: bool | None = None,
    ) -> bytes:
        """
        Decrypt data using hybrid PQ key exchange + AES-256-GCM.

        A supplied signature is always verified, before anything is decrypted.
        Whether a signature must be present is decided by ``require_signature``:

        - None (default): required if and only if ``sender_dsa_public_key`` is
          given. Passing the sender's key means a signed message is expected, so
          a message whose signature was stripped is rejected.
        - True: required; ``sender_dsa_public_key`` must be given too.
        - False: an unsigned message is accepted.

        Args:
            kem_ciphertext: ML-KEM ciphertext.
            x25519_ephemeral: Sender's ephemeral X25519 public key.
            nonce: AES-GCM nonce.
            ciphertext: AES-256-GCM encrypted data.
            signature: ML-DSA signature over the four fields above.
            sender_dsa_public_key: Sender's ML-DSA public key (required if a signature
                is given or required).
            require_signature: See above.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If a required signature is missing, the sender's key is
                missing, or signature verification fails.
            cryptography.exceptions.InvalidTag: If AES-GCM authentication fails.
        """
        if require_signature is None:
            require_signature = sender_dsa_public_key is not None

        if signature is None:
            if require_signature:
                raise ValueError("Signature required but none was supplied")
        else:
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
        return cast(bytes, aesgcm.decrypt(nonce, ciphertext, None))

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


def _b64decode_strict(value: str) -> bytes:
    """Decode standard base64, raising ValueError on anything else."""
    if not isinstance(value, (str, bytes)):
        raise ValueError("Expected a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:  # binascii.Error is a ValueError
        raise ValueError("Invalid base64") from exc


def _combine_secrets(kem_secret: bytes, x25519_secret: bytes) -> bytes:
    """
    Combine two shared secrets as SHA-256(kem_secret || x25519_secret).

    A custom combiner, kept because changing it would change every shared
    secret. It is not X-Wing or the IETF hybrid design: it binds no
    ciphertexts or public keys and has no domain-separation label. The
    concatenation is unambiguous only because both inputs are fixed-length
    (32 bytes each).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(kem_secret)
    digest.update(x25519_secret)
    return cast(bytes, digest.finalize())
