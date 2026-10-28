"""Project scope for framework-agent ids."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def project_scope(project_root: Path, scopes: dict[str, Path]) -> str:
    """Scope ids by the project directory name, disambiguated when two projects share one.

    The bare name keeps ids stable across checkouts of one project. When a
    second project in the same scan resolves to the same name (``/teamA/app``
    and ``/teamB/app``), its ids take a short hash of the resolved path, so its
    agents are never dropped as duplicates of, or wired into, the first project.
    """
    scope = project_root.name
    owner = scopes.setdefault(scope, project_root)
    if owner == project_root:
        return scope
    suffix = hashlib.sha256(str(project_root).encode()).hexdigest()[:8]
    logger.warning(
        "Framework agent scope %r is shared by %s and %s; scoping the second as %s-%s",
        scope,
        owner,
        project_root,
        scope,
        suffix,
    )
    return f"{scope}-{suffix}"
