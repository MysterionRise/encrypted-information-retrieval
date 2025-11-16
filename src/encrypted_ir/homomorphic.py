"""
Basic Homomorphic Encryption Module

Implements basic homomorphic encryption operations using TenSEAL (CKKS scheme).
Allows computations on encrypted data without decryption.

Use Case: Privacy-preserving credit scoring, encrypted risk calculations,
secure multi-party analytics, regulatory reporting on encrypted data.
"""

import tenseal as ts
from typing import List, Union
import pickle
import base64


class BasicHomomorphicEncryption:
    """
    Basic homomorphic encryption using CKKS scheme (approximate arithmetic).

    Supports addition, subtraction, and multiplication on encrypted data.
    Uses CKKS for floating-point arithmetic with controlled precision.
    """

    def __init__(self, context: ts.Context = None):
        """
        Initialize homomorphic encryption.

        Args:
            context: TenSEAL context. If None, creates new context with default parameters.
        """
        if context is None:
            # Create context with CKKS scheme
            # poly_modulus_degree: security parameter (higher = more secure but slower)
            # coeff_mod_bit_sizes: coefficient modulus chain
            context = ts.context(
                ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60]
            )
            # Set scale for encoding (precision)
            context.global_scale = 2**40
            # Generate Galois keys for rotations and relinearization
            context.generate_galois_keys()
            context.generate_relin_keys()

        self.context = context

    @staticmethod
    def create_context(
        poly_modulus_degree: int = 8192,
        coeff_mod_bit_sizes: List[int] = None,
        global_scale: int = 2**40,
    ) -> ts.Context:
        """
        Create a new TenSEAL context with custom parameters.

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

    def encrypt_value(self, value: Union[float, int]) -> ts.CKKSVector:
        """
        Encrypt a single numeric value.

        Args:
            value: Number to encrypt

        Returns:
            Encrypted value (CKKSVector)
        """
        return ts.ckks_vector(self.context, [float(value)])

    def encrypt_vector(self, values: List[Union[float, int]]) -> ts.CKKSVector:
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
        return decrypted[0] if isinstance(decrypted, list) else decrypted

    def decrypt_vector(self, encrypted_vector: ts.CKKSVector) -> List[float]:
        """
        Decrypt an encrypted vector.

        Args:
            encrypted_vector: Encrypted vector

        Returns:
            List of decrypted values
        """
        return encrypted_vector.decrypt()

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

    def add_plain(self, encrypted: ts.CKKSVector, plaintext: Union[float, int]) -> ts.CKKSVector:
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

    def subtract_plain(
        self, encrypted: ts.CKKSVector, plaintext: Union[float, int]
    ) -> ts.CKKSVector:
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

    def multiply_plain(
        self, encrypted: ts.CKKSVector, plaintext: Union[float, int]
    ) -> ts.CKKSVector:
        """
        Multiply encrypted value by plaintext.

        Args:
            encrypted: Encrypted value
            plaintext: Plaintext multiplier

        Returns:
            Encrypted result
        """
        return encrypted * float(plaintext)

    def sum_vector(self, encrypted_vector: ts.CKKSVector) -> float:
        """
        Compute sum of encrypted vector (decrypt result).

        Args:
            encrypted_vector: Encrypted vector

        Returns:
            Sum of all elements
        """
        decrypted = self.decrypt_vector(encrypted_vector)
        return sum(decrypted)

    def mean_vector(self, encrypted_vector: ts.CKKSVector) -> float:
        """
        Compute mean of encrypted vector.

        Args:
            encrypted_vector: Encrypted vector

        Returns:
            Mean value
        """
        decrypted = self.decrypt_vector(encrypted_vector)
        return sum(decrypted) / len(decrypted)

    def dot_product(self, enc_vec1: ts.CKKSVector, enc_vec2: ts.CKKSVector) -> float:
        """
        Compute dot product of two encrypted vectors.

        Args:
            enc_vec1: First encrypted vector
            enc_vec2: Second encrypted vector

        Returns:
            Dot product result
        """
        product = enc_vec1 * enc_vec2
        return self.sum_vector(product)

    def weighted_sum(self, encrypted_vector: ts.CKKSVector, weights: List[float]) -> float:
        """
        Compute weighted sum of encrypted vector.

        Args:
            encrypted_vector: Encrypted vector
            weights: Plaintext weights

        Returns:
            Weighted sum
        """
        # Multiply encrypted vector by plaintext weights
        weighted = encrypted_vector * weights
        return self.sum_vector(weighted)

    def serialize_encrypted(self, encrypted: ts.CKKSVector) -> bytes:
        """
        Serialize encrypted value to bytes.

        Args:
            encrypted: Encrypted value

        Returns:
            Serialized bytes
        """
        return encrypted.serialize()

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

    def export_context(self) -> bytes:
        """
        Export the encryption context (includes keys).

        Returns:
            Serialized context
        """
        return self.context.serialize(save_secret_key=True)

    def export_public_context(self) -> bytes:
        """
        Export public context (without secret key).

        Returns:
            Serialized public context
        """
        return self.context.serialize(save_secret_key=False)

    def export_context_to_base64(self) -> str:
        """
        Export context to base64 string.

        Returns:
            Base64-encoded context
        """
        context_bytes = self.export_context()
        return base64.b64encode(context_bytes).decode("ascii")

    @staticmethod
    def import_context(context_bytes: bytes) -> "BasicHomomorphicEncryption":
        """
        Import context from bytes.

        Args:
            context_bytes: Serialized context

        Returns:
            BasicHomomorphicEncryption instance with imported context
        """
        context = ts.context_from(context_bytes)
        return BasicHomomorphicEncryption(context)

    @staticmethod
    def import_context_from_base64(context_b64: str) -> "BasicHomomorphicEncryption":
        """
        Import context from base64 string.

        Args:
            context_b64: Base64-encoded context

        Returns:
            BasicHomomorphicEncryption instance with imported context
        """
        context_bytes = base64.b64decode(context_b64)
        return BasicHomomorphicEncryption.import_context(context_bytes)
