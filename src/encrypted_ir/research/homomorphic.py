"""
Basic Homomorphic Encryption Module

Implements basic homomorphic encryption operations using TenSEAL (CKKS scheme).
Research prototype, not audited.

Addition, subtraction, multiplication and the aggregates sum_vector,
mean_vector, dot_product and weighted_sum all run on ciphertexts and return
an encrypted result (a CKKSVector). Only the caller that holds the secret key
can decrypt it, with decrypt_value() or decrypt_vector(). A party that holds
only the public context (export_public_context()) can compute the aggregates
but cannot decrypt anything.

Keys: the default context generates relinearisation keys (for ciphertext x
ciphertext multiplication) and Galois keys. TenSEAL's CKKSVector.sum() and
dot() add the slots together with rotations, and rotations need the Galois
keys, so they are required for every aggregate here.

Context export: export_context() and export_context_to_base64() leave out the
secret key unless called with ``save_secret_key=True``. A context exported
with the secret key holds it unencrypted; protect it like any other key.

Known limitations:
- CKKS is approximate: results carry small errors (about 1e-6 relative at the
  default scale 2^40).
- The default coefficient modulus chain [60, 40, 40, 60] allows two rescaling
  levels, so only shallow computations work (for example one ciphertext
  multiplication followed by a plaintext-weighted aggregate).
- No parameter choice here has been reviewed against the Homomorphic
  Encryption Standard's security tables.

Use Case: Privacy-preserving credit scoring, encrypted risk calculations,
secure multi-party analytics, regulatory reporting on encrypted data.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from typing import cast

try:
    import tenseal as ts
except ImportError as exc:
    raise ImportError(
        "encrypted_ir.research.homomorphic needs TenSEAL. Install the research extra: "
        "pip install 'encrypted-information-retrieval[research]' "
        "or pip install -r requirements-research.txt"
    ) from exc


def _require_ckks_context(context: object) -> ts.Context:
    """Return ``context`` if it is a usable TenSEAL CKKS context, else raise ValueError."""
    if not isinstance(context, ts.Context):
        raise ValueError(f"Expected a TenSEAL context, got {type(context).__name__}")
    try:
        # BFV contexts, and CKKS contexts whose scale was never set, raise "no global scale".
        scale = context.global_scale
    except ValueError as exc:
        raise ValueError("The TenSEAL context is not a CKKS context with a global scale") from exc
    if scale <= 0:
        raise ValueError("The CKKS context has no positive global scale")
    return context


class BasicHomomorphicEncryption:
    """
    Basic homomorphic encryption using CKKS scheme (approximate arithmetic).

    Supports addition, subtraction, multiplication and slot aggregates (sum,
    mean, dot product, weighted sum) on encrypted data. Every operation returns
    a ciphertext; decrypt with decrypt_value() or decrypt_vector().
    """

    def __init__(self, context: ts.Context = None):
        """
        Initialize homomorphic encryption.

        Args:
            context: TenSEAL CKKS context. If None, creates a new context with default
                parameters (see create_context()).

        Raises:
            ValueError: If ``context`` is not a TenSEAL CKKS context.
        """
        if context is None:
            context = self.create_context()

        self.context = _require_ckks_context(context)

    @staticmethod
    def create_context(
        poly_modulus_degree: int = 8192,
        coeff_mod_bit_sizes: list[int] = None,
        global_scale: int = 2**40,
    ) -> ts.Context:
        """
        Create a new TenSEAL CKKS context with relinearisation and Galois keys.

        Relinearisation keys are needed after ciphertext x ciphertext
        multiplication. Galois keys are needed for the slot rotations that
        CKKSVector.sum() and dot() use, so every aggregate method depends on them.

        Args:
            poly_modulus_degree: Polynomial modulus degree (higher = more secure)
            coeff_mod_bit_sizes: Coefficient modulus bit sizes
            global_scale: Global scale for encoding precision

        Returns:
            TenSEAL context
        """
        if coeff_mod_bit_sizes is None:
            coeff_mod_bit_sizes = [60, 40, 40, 60]

        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=coeff_mod_bit_sizes,
        )
        context.global_scale = global_scale
        context.generate_galois_keys()
        context.generate_relin_keys()

        return context

    @property
    def has_secret_key(self) -> bool:
        """True if this instance can decrypt (its context holds the secret key)."""
        return bool(self.context.is_private())

    def encrypt_value(self, value: float | int) -> ts.CKKSVector:
        """
        Encrypt a single numeric value.

        Args:
            value: Number to encrypt

        Returns:
            Encrypted value (CKKSVector)
        """
        return ts.ckks_vector(self.context, [float(value)])

    def encrypt_vector(self, values: list[float | int]) -> ts.CKKSVector:
        """
        Encrypt a vector of numeric values.

        Args:
            values: List of numbers to encrypt

        Returns:
            Encrypted vector (CKKSVector)
        """
        float_values = [float(v) for v in values]
        return ts.ckks_vector(self.context, float_values)

    def decrypt_value(self, encrypted_value: ts.CKKSVector) -> float:
        """
        Decrypt a single encrypted value.

        Args:
            encrypted_value: Encrypted value

        Returns:
            Decrypted value (float)
        """
        decrypted = encrypted_value.decrypt()
        return float(decrypted[0] if isinstance(decrypted, list) else decrypted)

    def decrypt_vector(self, encrypted_vector: ts.CKKSVector) -> list[float]:
        """
        Decrypt an encrypted vector.

        Args:
            encrypted_vector: Encrypted vector

        Returns:
            List of decrypted values
        """
        return cast(list[float], encrypted_vector.decrypt())

    def add_encrypted(self, enc1: ts.CKKSVector, enc2: ts.CKKSVector) -> ts.CKKSVector:
        """
        Add two encrypted values (homomorphic addition).

        Args:
            enc1: First encrypted value
            enc2: Second encrypted value

        Returns:
            Encrypted sum
        """
        return enc1 + enc2

    def add_plain(self, encrypted: ts.CKKSVector, plaintext: float | int) -> ts.CKKSVector:
        """
        Add plaintext to encrypted value.

        Args:
            encrypted: Encrypted value
            plaintext: Plaintext value to add

        Returns:
            Encrypted result
        """
        return encrypted + float(plaintext)

    def subtract_encrypted(self, enc1: ts.CKKSVector, enc2: ts.CKKSVector) -> ts.CKKSVector:
        """
        Subtract two encrypted values (homomorphic subtraction).

        Args:
            enc1: First encrypted value
            enc2: Second encrypted value

        Returns:
            Encrypted difference
        """
        return enc1 - enc2

    def subtract_plain(self, encrypted: ts.CKKSVector, plaintext: float | int) -> ts.CKKSVector:
        """
        Subtract plaintext from encrypted value.

        Args:
            encrypted: Encrypted value
            plaintext: Plaintext value to subtract

        Returns:
            Encrypted result
        """
        return encrypted - float(plaintext)

    def multiply_encrypted(self, enc1: ts.CKKSVector, enc2: ts.CKKSVector) -> ts.CKKSVector:
        """
        Multiply two encrypted values (homomorphic multiplication).

        Args:
            enc1: First encrypted value
            enc2: Second encrypted value

        Returns:
            Encrypted product
        """
        return enc1 * enc2

    def multiply_plain(self, encrypted: ts.CKKSVector, plaintext: float | int) -> ts.CKKSVector:
        """
        Multiply encrypted value by plaintext.

        Args:
            encrypted: Encrypted value
            plaintext: Plaintext multiplier

        Returns:
            Encrypted result
        """
        return encrypted * float(plaintext)

    def sum_vector(self, encrypted_vector: ts.CKKSVector) -> ts.CKKSVector:
        """
        Sum the slots of an encrypted vector, homomorphically.

        Uses TenSEAL's ciphertext ``sum()`` (slot rotations with the Galois
        keys). Nothing is decrypted; the result is an encrypted scalar.

        Args:
            encrypted_vector: Encrypted vector

        Returns:
            Encrypted sum (decrypt with decrypt_value())
        """
        return encrypted_vector.sum()

    def mean_vector(self, encrypted_vector: ts.CKKSVector) -> ts.CKKSVector:
        """
        Average the slots of an encrypted vector, homomorphically.

        The encrypted sum is multiplied by the plaintext 1/n, where n is the
        vector length (ciphertext metadata, not a secret).

        Args:
            encrypted_vector: Encrypted vector (TenSEAL cannot encrypt an empty one)

        Returns:
            Encrypted mean (decrypt with decrypt_value())
        """
        return encrypted_vector.sum() * (1.0 / encrypted_vector.size())

    def dot_product(self, enc_vec1: ts.CKKSVector, enc_vec2: ts.CKKSVector) -> ts.CKKSVector:
        """
        Dot product of two encrypted vectors, homomorphically.

        Uses TenSEAL's ciphertext ``dot()``: element-wise multiplication,
        relinearisation and a slot sum. Nothing is decrypted.

        Args:
            enc_vec1: First encrypted vector
            enc_vec2: Second encrypted vector of the same length

        Returns:
            Encrypted dot product (decrypt with decrypt_value())

        Raises:
            ValueError: If the vectors have different lengths.
        """
        if enc_vec1.size() != enc_vec2.size():
            raise ValueError(f"Vector lengths differ: {enc_vec1.size()} and {enc_vec2.size()}")
        return enc_vec1.dot(enc_vec2)

    def weighted_sum(
        self, encrypted_vector: ts.CKKSVector, weights: Sequence[float]
    ) -> ts.CKKSVector:
        """
        Weighted sum of an encrypted vector with plaintext weights, homomorphically.

        Uses TenSEAL's ``dot()`` with a plaintext vector. Nothing is decrypted.

        Args:
            encrypted_vector: Encrypted vector
            weights: Plaintext weights, one per element

        Returns:
            Encrypted weighted sum (decrypt with decrypt_value())

        Raises:
            ValueError: If the number of weights differs from the vector length.
        """
        weight_list = [float(w) for w in weights]
        if len(weight_list) != encrypted_vector.size():
            raise ValueError(f"Expected {encrypted_vector.size()} weights, got {len(weight_list)}")
        return encrypted_vector.dot(weight_list)

    def serialize_encrypted(self, encrypted: ts.CKKSVector) -> bytes:
        """
        Serialize encrypted value to bytes.

        Args:
            encrypted: Encrypted value

        Returns:
            Serialized bytes
        """
        return cast(bytes, encrypted.serialize())

    def deserialize_encrypted(self, data: bytes) -> ts.CKKSVector:
        """
        Deserialize encrypted value from bytes.

        Args:
            data: Serialized encrypted value

        Returns:
            Encrypted value
        """
        return ts.ckks_vector_from(self.context, data)

    def serialize_encrypted_to_base64(self, encrypted: ts.CKKSVector) -> str:
        """
        Serialize encrypted value to base64 string.

        Args:
            encrypted: Encrypted value

        Returns:
            Base64-encoded serialized value
        """
        serialized = self.serialize_encrypted(encrypted)
        return base64.b64encode(serialized).decode("ascii")

    def deserialize_encrypted_from_base64(self, data_b64: str) -> ts.CKKSVector:
        """
        Deserialize encrypted value from base64 string.

        Args:
            data_b64: Base64-encoded serialized value

        Returns:
            Encrypted value
        """
        data = base64.b64decode(data_b64)
        return self.deserialize_encrypted(data)

    def export_context(self, save_secret_key: bool = False) -> bytes:
        """
        Export the encryption context.

        By default the secret key is left out, so the result can only encrypt
        and compute. Pass ``save_secret_key=True`` to include the secret key;
        it is serialised unencrypted, so the result must be protected like
        the key itself.

        Args:
            save_secret_key: Include the secret key (default False).

        Returns:
            Serialized context
        """
        return cast(bytes, self.context.serialize(save_secret_key=save_secret_key))

    def export_public_context(self) -> bytes:
        """
        Export public context (without secret key).

        Returns:
            Serialized public context
        """
        return self.export_context(save_secret_key=False)

    def export_context_to_base64(self, save_secret_key: bool = False) -> str:
        """
        Export context to base64 string.

        Args:
            save_secret_key: Include the secret key (default False); see export_context().

        Returns:
            Base64-encoded context
        """
        context_bytes = self.export_context(save_secret_key=save_secret_key)
        return base64.b64encode(context_bytes).decode("ascii")

    @staticmethod
    def import_context(context_bytes: bytes) -> BasicHomomorphicEncryption:
        """
        Import a context from bytes.

        A context exported without the secret key gives an instance that can
        encrypt and compute but not decrypt (``has_secret_key`` is False).

        Args:
            context_bytes: Serialized CKKS context

        Returns:
            BasicHomomorphicEncryption instance with imported context

        Raises:
            ValueError: If the bytes are not a serialized TenSEAL CKKS context.
        """
        if not isinstance(context_bytes, (bytes, bytearray)):
            raise ValueError("context_bytes must be bytes")
        try:
            context = ts.context_from(bytes(context_bytes))
        except Exception as exc:  # TenSEAL raises ValueError or RuntimeError on bad input
            raise ValueError("Not a serialized TenSEAL context") from exc
        return BasicHomomorphicEncryption(context)

    @staticmethod
    def import_context_from_base64(context_b64: str) -> BasicHomomorphicEncryption:
        """
        Import context from base64 string.

        Args:
            context_b64: Base64-encoded context

        Returns:
            BasicHomomorphicEncryption instance with imported context

        Raises:
            ValueError: If the string is not base64 of a serialized CKKS context.
        """
        try:
            context_bytes = base64.b64decode(context_b64, validate=True)
        except (binascii.Error, TypeError) as exc:
            raise ValueError("context_b64 is not valid base64") from exc
        return BasicHomomorphicEncryption.import_context(context_bytes)
