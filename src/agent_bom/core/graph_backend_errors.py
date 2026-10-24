"""Graph backend errors, importable without the API layer."""

from __future__ import annotations


class NeptuneGraphStoreError(RuntimeError):
    """Base error for Neptune graph backend failures."""


class NeptuneGraphStoreConfigError(NeptuneGraphStoreError):
    """Raised when the Neptune backend is selected without required config."""


class NeptuneGraphStoreUnsupportedOperationError(NeptuneGraphStoreError):
    """Raised for GraphStoreProtocol operations not yet implemented by Neptune."""
