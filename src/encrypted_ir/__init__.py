"""
Encrypted Information Retrieval for Financial Services

This package provides implementations of various encrypted information retrieval
techniques suitable for financial services applications.
"""

from .deterministic import DeterministicEncryption
from .searchable import SearchableEncryption, BooleanQuery
from .order_preserving import OrderPreservingEncryption
from .ore import ORE
from .homomorphic import BasicHomomorphicEncryption
from .key_manager import KeyManager
from .blind_index import BlindIndexGenerator, BlindIndexConfig, BlindIndexSearch
from .storage_backend import StorageBackend, FileStorageBackend
from .kms_provider import KMSProvider, AWSKMSProvider, EnvelopeEncryption
from .fpe import FF1, FormatPreservingEncryption
from .post_quantum import MLKEM, MLDSA, HybridKEM, PostQuantumEncryption

__version__ = "1.0.0"
__all__ = [
    "DeterministicEncryption",
    "SearchableEncryption",
    "BooleanQuery",
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
