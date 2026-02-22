"""
Encrypted Information Retrieval for Financial Services

This package provides implementations of various encrypted information retrieval
techniques suitable for financial services applications.
"""

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
from .fpe import FF1, FormatPreservingEncryption
from .homomorphic import BasicHomomorphicEncryption
from .key_manager import KeyLifecycleState, KeyManager
from .key_rotation import (
    KeyRotationManager,
    RotationPolicy,
    RotationProgress,
    VersionedBlob,
)
from .kms_provider import AWSKMSProvider, EnvelopeEncryption, KMSProvider
from .order_preserving import OrderPreservingEncryption
from .ore import ORE
from .post_quantum import MLDSA, MLKEM, HybridKEM, PostQuantumEncryption
from .searchable import BackwardPrivateIndex, BooleanQuery, ForwardPrivateSSE, SearchableEncryption
from .audit import AuditEventType, AuditLogger
from .logging import LoggingConfig, StructuredFormatter, get_correlation_id, new_correlation_id
from .metrics import EncryptionMetrics
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
