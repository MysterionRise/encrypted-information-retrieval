"""
Encrypted Information Retrieval for Financial Services

This package provides implementations of various encrypted information retrieval
techniques suitable for financial services applications.
"""

from .deterministic import DeterministicEncryption
from .searchable import SearchableEncryption
from .order_preserving import OrderPreservingEncryption
from .homomorphic import BasicHomomorphicEncryption
from .key_manager import KeyManager

__version__ = "1.0.0"
__all__ = [
    "DeterministicEncryption",
    "SearchableEncryption",
    "OrderPreservingEncryption",
    "BasicHomomorphicEncryption",
    "KeyManager",
]
