"""Warnings and errors shared across the package.

This module has no package-internal imports, so callers can reference these classes, for
example in a warnings filter, without importing anything else.
"""

from __future__ import annotations

__all__ = [
    "DocumentAlreadyExistsError",
    "DocumentIntegrityError",
    "DocumentNotFoundError",
    "KeyIntegrityError",
    "ResearchPrototypeWarning",
]


class ResearchPrototypeWarning(UserWarning):
    """Issued when ``encrypted_ir.research`` is imported.

    The research modules are unaudited prototypes kept for experimentation. None of them is
    used by the durable document path. To silence the warning deliberately::

        import warnings
        from encrypted_ir.errors import ResearchPrototypeWarning

        warnings.filterwarnings("ignore", category=ResearchPrototypeWarning)
    """


class DocumentAlreadyExistsError(ValueError):
    """A document with this ID already exists for the tenant. The API maps it to 409."""

    def __init__(self, doc_id: str):
        super().__init__(f"Document '{doc_id}' already exists")
        self.doc_id = doc_id


class DocumentNotFoundError(KeyError):
    """No document with this ID exists for the tenant. The API maps it to 404."""

    def __init__(self, doc_id: str):
        super().__init__(f"Document '{doc_id}' not found")
        self.doc_id = doc_id


class DocumentIntegrityError(Exception):
    """A stored document ciphertext failed authentication or does not match its row.

    Raised for any malformed header, unexpected version, algorithm or key ID, and any
    AES-GCM tag failure. It deliberately does not subclass ``ValueError`` or ``KeyError``, so
    the API reports it as a generic server error instead of echoing details to the caller.
    """


class KeyIntegrityError(Exception):
    """A stored wrapped key failed to unwrap under its tenant, key ID, type and version."""
