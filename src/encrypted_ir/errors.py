"""Warnings and errors shared across the package.

This module has no package-internal imports, so callers can reference these classes, for
example in a warnings filter, without importing anything else.
"""

from __future__ import annotations

__all__ = ["ResearchPrototypeWarning"]


class ResearchPrototypeWarning(UserWarning):
    """Issued when ``encrypted_ir.research`` is imported.

    The research modules are unaudited prototypes kept for experimentation. None of them is
    used by the durable document path. To silence the warning deliberately::

        import warnings
        from encrypted_ir.errors import ResearchPrototypeWarning

        warnings.filterwarnings("ignore", category=ResearchPrototypeWarning)
    """
