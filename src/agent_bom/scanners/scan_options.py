"""Per-scan controls and shared scanner output."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from rich.console import Console

from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name

console = Console(stderr=True)


_logger = logging.getLogger("agent_bom.scanners.package_scan")


@dataclass(frozen=True)
class ScanOptions:
    """Immutable per-scan scanner controls.

    The legacy module-level setters remain for CLI compatibility, but request
    handlers and concurrent scan callers should pass explicit options so tenant
    policy cannot bleed through shared module state.
    """

    offline: bool = False
    compliance_enabled: bool = False
    resolve_transitive: bool = False
    prefer_local_db: bool = False
    demo_advisories: bool = False
    # Target project directory (the ``-p`` path) for local install resolution.
    # When set, bare/floating versions are resolved against the target — its
    # virtualenv for pip, the dir itself for npm/go — never the scanner host.
    project_dir: Optional[str] = None


class IncompleteScanError(RuntimeError):
    """Raised when a scan cannot produce a trustworthy verdict."""


def _package_db_key(p: Package) -> str:
    return f"{p.ecosystem.lower()}:{normalize_package_name(p.name, p.ecosystem)}@{p.version}"
