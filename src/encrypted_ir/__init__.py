"""
Encrypted Information Retrieval for Financial Services

This package provides implementations of various encrypted information retrieval
techniques suitable for financial services applications.
"""

from .blind_index import BlindIndexConfig, BlindIndexGenerator, BlindIndexSearch
from .deterministic import DeterministicEncryption
from .fpe import FF1, FormatPreservingEncryption
from .homomorphic import BasicHomomorphicEncryption
from .key_manager import KeyManager
from .kms_provider import AWSKMSProvider, EnvelopeEncryption, KMSProvider
from .order_preserving import OrderPreservingEncryption
from .ore import ORE
from .post_quantum import MLDSA, MLKEM, HybridKEM, PostQuantumEncryption
from .searchable import BackwardPrivateIndex, BooleanQuery, SearchableEncryption
from .storage_backend import FileStorageBackend, StorageBackend

__version__ = "1.0.0"
__all__ = [
    "DeterministicEncryption",
    "SearchableEncryption",
    "BooleanQuery",
    "BackwardPrivateIndex",
    "OrderPreservingEncryption",
    "ORE",
    "BasicHomomorphicEncryption",
    "KeyManager",
    "BlindIndexGenerator",
    "BlindIndexConfig",
    "BlindIndexSearch",
    "StorageBackend",
    "FileStorageBackend",
    "KMSProvider",
    "AWSKMSProvider",
    "EnvelopeEncryption",
    "FF1",
    "FormatPreservingEncryption",
    "MLKEM",
    "MLDSA",
    "HybridKEM",
    "PostQuantumEncryption",
]
