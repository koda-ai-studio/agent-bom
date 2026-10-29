"""Shared streaming export result and failure contracts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


class ExportDestinationError(RuntimeError):
    """Raised when a destination cannot be built or written to."""


class ExportPublicationIndeterminateError(ExportDestinationError):
    """Publication may still complete; callers must not classify it as failed."""


@dataclass(frozen=True)
class ExportResult:
    """Outcome of a single findings export run."""

    kind: str
    destination_uri: str
    row_count: int
    byte_count: int | None = None


@runtime_checkable
class ExportDestination(Protocol):
    """Contract every export destination adapter implements."""

    kind: str

    def write_findings(self, rows: Iterable[dict[str, Any]], *, tenant_id: str, run_id: str) -> ExportResult:
        """Stream ``rows`` to the destination and return the run outcome."""
        ...
