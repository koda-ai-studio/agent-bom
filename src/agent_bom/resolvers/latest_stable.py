"""Latest *stable* published version, selected the same way for every registry.

A registry's "latest" pointer is not always a release a user would install:
Maven Central's ``latestVersion`` can be a ``-beta``, an npm ``latest`` tag can
be pointed at a pre-release, and crates.io's ``newest_version`` may be an
``-alpha``. Every ecosystem here resolves to the newest non-pre-release version
and only falls back to the newest pre-release when the package has published
nothing else; that fallback is flagged so the caller can say so.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass

import httpx

from agent_bom import resolver, transitive, version_utils
from agent_bom.core.versions import compare_version_order, is_prerelease_version
from agent_bom.models import Package
from agent_bom.resolvers.registry_budget import latest_deadline_budget

PRERELEASE_VERSION_SOURCE = "registry_latest_prerelease"
PRERELEASE_NOTE = "pre-release; no stable release published"
# A single-package ``check`` waits longer for a registry than a bulk scan does:
# one slow Maven Central search is still a better answer than "unresolved".
CHECK_LATEST_DEADLINE = 12.0
_MAVEN_VERSION_ROWS = 20


@dataclass(frozen=True)
class LatestRelease:
    version: str
    license: str | None = None
    is_prerelease: bool = False


def check_latest_budget() -> AbstractContextManager[None]:
    """Widen the registry-latest wait to the single-package ``check`` budget."""
    return latest_deadline_budget(CHECK_LATEST_DEADLINE)


def resolved_version_source(package_version_source: str) -> str:
    """Map a resolved package's ``version_source`` onto the check-result contract."""
    if package_version_source in ("registry_fallback", PRERELEASE_VERSION_SOURCE):
        return package_version_source
    return "registry_latest"


def select_latest_stable(candidates: Iterable[str], ecosystem: str) -> LatestRelease | None:
    """Pick the newest stable version; the newest pre-release (flagged) when there is none."""
    versions = [v.strip() for v in candidates if v and v.strip()]
    if not versions:
        return None
    stable = [v for v in versions if not is_prerelease_version(v, ecosystem)]
    pool, is_prerelease = (stable, False) if stable else (versions, True)
    return LatestRelease(_highest(pool, ecosystem), is_prerelease=is_prerelease)


def _highest(versions: list[str], ecosystem: str) -> str:
    best = versions[0]
    for candidate in versions[1:]:
        order = compare_version_order(candidate, best, ecosystem)
        if order is not None and order > 0:
            best = candidate
    return best


def _flagged(version: str | None, license_id: str | None, ecosystem: str) -> LatestRelease | None:
    if not version:
        return None
    return LatestRelease(version, license_id, is_prerelease_version(version, ecosystem))


async def _npm_release(name: str, client: httpx.AsyncClient) -> LatestRelease | None:
    version, license_id = await resolver.resolve_npm_metadata(name, client)
    if not version:
        return None
    if not is_prerelease_version(version, "npm"):
        return LatestRelease(version, license_id)
    # The ``latest`` tag points at a pre-release: look for the newest stable
    # version in the packument before settling for the tag.
    packument = await transitive.fetch_npm_packument(name, client)
    selected = select_latest_stable(list((packument or {}).get("versions") or {}), "npm")
    if selected is not None and not selected.is_prerelease:
        return selected
    return LatestRelease(version, license_id, is_prerelease=True)


async def _maven_release(name: str, client: httpx.AsyncClient) -> LatestRelease | None:
    group, artifact = name.split(":", 1)
    versions = await version_utils.resolve_maven_versions(group, artifact, client, rows=_MAVEN_VERSION_ROWS)
    selected = select_latest_stable(versions, "maven")
    if selected is not None:
        return selected
    # Without the version list, ``latestVersion`` is trusted only when it is a
    # release: a pre-release there cannot prove that no stable release exists.
    version, _ = await version_utils.resolve_maven_metadata(group, artifact, client)
    if not version or is_prerelease_version(version, "maven"):
        return None
    return LatestRelease(version)


async def resolve_latest_release(pkg: Package, client: httpx.AsyncClient) -> LatestRelease | None:
    """Return the latest stable release of ``pkg`` from its registry, or ``None``.

    ``None`` means the registry did not answer or does not know the package;
    an unsupported ecosystem also yields ``None`` so the caller never guesses.
    """
    ecosystem = pkg.ecosystem.lower()
    if ecosystem == "npm":
        return await _npm_release(pkg.name, client)
    if ecosystem in ("pypi", "conda"):
        # PyPI's ``info.version`` already skips pre-releases while a final
        # release exists; a pre-release here means the project has only those.
        version, license_id = await resolver.resolve_pypi_metadata(pkg.name, client)
        return _flagged(version, license_id, "pypi")
    if ecosystem == "go":
        # proxy.golang.org ``@latest`` prefers release versions over pre-releases.
        version, license_id = await version_utils.resolve_go_metadata(pkg.name, client)
        return _flagged(version, license_id, "go")
    if ecosystem == "cargo":
        # crates.io ``max_stable_version`` is preferred; ``max_version`` only when absent.
        version, license_id = await version_utils.resolve_cargo_metadata(pkg.name, client)
        return _flagged(version, license_id, "cargo")
    if ecosystem == "maven" and ":" in pkg.name:
        return await _maven_release(pkg.name, client)
    return None
