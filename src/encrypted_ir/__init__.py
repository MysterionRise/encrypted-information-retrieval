"""
Encrypted Information Retrieval

Tenant-scoped encrypted document storage and keyword-token retrieval for regulated AI and
RAG workloads. This top-level package exports the durable document path and the standard
constructions it is built from.

Unaudited research prototypes (ORE, FF1, CKKS, post-quantum KEM/signatures, differential
privacy, forward-private SSE and the use-case demos) live in ``encrypted_ir.research`` and
issue a :class:`ResearchPrototypeWarning` when imported. Nothing here imports them.
"""

from .audit import AuditEvent, AuditEventType, ChainVerification
from .blind_index import BlindIndexConfig, BlindIndexGenerator, BlindIndexSearch
from .deterministic import DeterministicEncryption
from .document_service import DocumentRecord, DocumentService, RetrievalCandidate
from .errors import ResearchPrototypeWarning
from .key_manager import KeyLifecycleState, KeyManager
from .key_rotation import KeyRotationManager, RotationPolicy, RotationProgress
from .kms_provider import AWSKMSProvider, EnvelopeEncryption, KMSProvider
from .logging import LoggingConfig, StructuredFormatter, get_correlation_id, new_correlation_id
from .metrics import EncryptionMetrics
from .searchable import BooleanQuery, SearchableEncryption
from .storage_backend import DatabaseStorageBackend, FileStorageBackend, StorageBackend

__version__ = "0.9.0"
__all__ = [
    # Durable document path
    "DocumentService",
    "DocumentRecord",
    "RetrievalCandidate",
    "SearchableEncryption",
    "BooleanQuery",
    # Standard constructions
    "DeterministicEncryption",
    "BlindIndexGenerator",
    "BlindIndexConfig",
    "BlindIndexSearch",
    # Key management
    "KeyManager",
    "KeyLifecycleState",
    "KeyRotationManager",
    "RotationPolicy",
    "RotationProgress",
    "StorageBackend",
    "FileStorageBackend",
    "DatabaseStorageBackend",
    "KMSProvider",
    "AWSKMSProvider",
    "EnvelopeEncryption",
    # Observability
    "LoggingConfig",
    "StructuredFormatter",
    "get_correlation_id",
    "new_correlation_id",
    "EncryptionMetrics",
    "AuditEvent",
    "AuditEventType",
    "ChainVerification",
    # Warnings
    "ResearchPrototypeWarning",
]
