"""
Encrypted Information Retrieval for Financial Services

This package provides implementations of various encrypted information retrieval
techniques suitable for financial services applications.
"""

from typing import Any as _Any

from .audit import AuditEventType, AuditLogger
from .blind_index import BlindIndexConfig, BlindIndexGenerator, BlindIndexSearch
from .deterministic import DeterministicEncryption
from .differential_privacy import (
    DPQueryInterface,
    ExponentialMechanism,
    GaussianMechanism,
    LaplaceMechanism,
    PrivacyBudgetExhaustedError,
    PrivacyBudgetTracker,
    PrivacyBudgetWarning,
)
from .document_service import DocumentRecord, DocumentService, RetrievalCandidate
from .fpe import FF1, FormatPreservingEncryption
from .key_manager import KeyLifecycleState, KeyManager
from .key_rotation import (
    KeyRotationManager,
    RotationPolicy,
    RotationProgress,
    VersionedBlob,
)
from .kms_provider import AWSKMSProvider, EnvelopeEncryption, KMSProvider
from .logging import LoggingConfig, StructuredFormatter, get_correlation_id, new_correlation_id
from .metrics import EncryptionMetrics
from .order_preserving import OrderPreservingEncryption
from .ore import ORE
from .searchable import BackwardPrivateIndex, BooleanQuery, ForwardPrivateSSE, SearchableEncryption
from .storage_backend import DatabaseStorageBackend, FileStorageBackend, StorageBackend

BasicHomomorphicEncryption: _Any
try:
    from .homomorphic import BasicHomomorphicEncryption as BasicHomomorphicEncryption
except ImportError:
    BasicHomomorphicEncryption = None

MLDSA: _Any
MLKEM: _Any
HybridKEM: _Any
PostQuantumEncryption: _Any
try:
    from .post_quantum import MLDSA, MLKEM, HybridKEM, PostQuantumEncryption
except ImportError:
    MLDSA = MLKEM = HybridKEM = PostQuantumEncryption = None

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
    "KeyLifecycleState",
    "KeyRotationManager",
    "RotationPolicy",
    "RotationProgress",
    "VersionedBlob",
    "BlindIndexGenerator",
    "BlindIndexConfig",
    "BlindIndexSearch",
    "StorageBackend",
    "FileStorageBackend",
    "DatabaseStorageBackend",
    "DocumentService",
    "DocumentRecord",
    "RetrievalCandidate",
    "KMSProvider",
    "AWSKMSProvider",
    "EnvelopeEncryption",
    "FF1",
    "ForwardPrivateSSE",
    "FormatPreservingEncryption",
    "MLKEM",
    "MLDSA",
    "HybridKEM",
    "PostQuantumEncryption",
    # Observability
    "LoggingConfig",
    "StructuredFormatter",
    "get_correlation_id",
    "new_correlation_id",
    "EncryptionMetrics",
    "AuditLogger",
    "AuditEventType",
    # Differential Privacy
    "LaplaceMechanism",
    "GaussianMechanism",
    "ExponentialMechanism",
    "PrivacyBudgetTracker",
    "PrivacyBudgetExhaustedError",
    "PrivacyBudgetWarning",
    "DPQueryInterface",
]
