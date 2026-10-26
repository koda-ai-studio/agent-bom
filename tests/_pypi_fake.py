"""In-memory PyPI JSON API for resolver tests (no network)."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.parsers import pypi_resolution


class FakePyPI:
    """Serve ``/pypi/<name>/json`` and ``/pypi/<name>/<version>/json`` from a dict.

    ``index`` maps a project name to ``{version: release}`` where a release may set
    ``requires_dist`` (list or ``None``), ``requires_python``, ``yanked`` and
    ``wheel`` (False for an sdist-only release).
    """

    def __init__(self, index: dict[str, dict[str, dict[str, Any]]], *, fail: set[str] | None = None) -> None:
        self.index = {re.sub(r"[-_.]+", "-", name).lower(): releases for name, releases in index.items()}
        self.fail = fail or set()
        self.requests: list[str] = []

    def _files(self, release: dict[str, Any]) -> list[dict[str, Any]]:
        packagetype = "bdist_wheel" if release.get("wheel", True) else "sdist"
        return [{"packagetype": packagetype, "requires_python": release.get("requires_python"), "yanked": release.get("yanked", False)}]

    def __call__(self, url: str) -> dict[str, Any] | None:
        self.requests.append(url)
        match = re.fullmatch(r"https://pypi\.org/pypi/([^/]+)(?:/([^/]+))?/json", url)
        assert match, url
        name, version = match.group(1), match.group(2)
        if name in self.fail:
            raise pypi_resolution.PyPIUnavailableError(f"{name}: simulated outage")
        releases = self.index.get(name)
        if releases is None or (version is not None and version not in releases):
            return None
        if version is None:
            latest = list(releases)[-1]
            return {
                "info": {"name": name, "version": latest, "requires_dist": releases[latest].get("requires_dist")},
                "releases": {v: self._files(r) for v, r in releases.items()},
            }
        release = releases[version]
        return {"info": {"name": name, "version": version, "requires_dist": release.get("requires_dist")}, "urls": self._files(release)}
