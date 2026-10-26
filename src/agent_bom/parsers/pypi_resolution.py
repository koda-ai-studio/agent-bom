"""Resolve unlocked Python declarations transitively from PyPI JSON metadata.

Used only when a project has no lockfile and no virtualenv and the scan may use
the network. Reads ``requires_dist`` from the PyPI JSON API; never downloads,
builds or executes a distribution. Environment markers are evaluated for one
documented target, :data:`TARGET_ENVIRONMENT` (CPython 3.12 on Linux x86_64),
so results do not depend on the machine running the scan. Each name gets the
newest non-yanked, non-prerelease release that satisfies every constraint
seen for it and supports the target Python; anything that cannot be resolved
inside :data:`DEFAULT_BUDGET` is returned as a named failure, never guessed.
"""

from __future__ import annotations

import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from packaging.markers import Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from agent_bom.core.settings import env_float
from agent_bom.http_client import OfflineModeError, create_sync_client, sync_request_with_retry
from agent_bom.scanners.state import scan_scoped_deadline
from agent_bom.transitive import PYPI_API, _resolve_pip_version

TARGET_ENVIRONMENT: dict[str, str] = {
    "implementation_name": "cpython",
    "implementation_version": "3.12.0",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_system": "Linux",
    "platform_version": "",
    "python_full_version": "3.12.0",
    "python_version": "3.12",
    "sys_platform": "linux",
}
_TARGET_PYTHON = Version(TARGET_ENVIRONMENT["python_full_version"])
_MAX_ROUNDS = 3


@dataclass
class ResolutionBudget:
    max_packages: int = 500
    max_depth: int = 15
    max_seconds: float = 15.0
    workers: int = 8


DEFAULT_BUDGET = ResolutionBudget()


def scan_resolution_deadline() -> float:
    """The deadline every unlocked manifest in this scan shares (``AGENT_BOM_PYPI_RESOLUTION_BUDGET_SECONDS``)."""
    seconds = env_float("AGENT_BOM_PYPI_RESOLUTION_BUDGET_SECONDS", DEFAULT_BUDGET.max_seconds)
    return scan_scoped_deadline(seconds, time.monotonic())


class PyPIUnavailableError(RuntimeError):
    """The registry could not answer (network error, offline mode, bad payload)."""


def fetch_pypi_json(url: str) -> dict[str, Any] | None:
    """GET a PyPI JSON document; ``None`` when the project/release does not exist."""
    try:
        with create_sync_client(timeout=15.0) as client:
            response = sync_request_with_retry(client, "GET", url)
    except OfflineModeError as exc:
        raise PyPIUnavailableError(str(exc)) from exc
    if response is None:
        raise PyPIUnavailableError("registry unreachable")
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise PyPIUnavailableError(f"registry returned HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise PyPIUnavailableError("registry returned malformed JSON") from exc
    return data if isinstance(data, dict) else None


@dataclass
class _Project:
    name: str
    releases: dict[str, dict[str, Any]]
    latest: str
    latest_requires: list[str] | None


@dataclass
class ResolvedDistribution:
    name: str
    version: str
    constraint: str
    parent: str | None
    depth: int


@dataclass
class ResolutionResult:
    resolved: dict[str, ResolvedDistribution] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)


def _release_info(files: Any) -> dict[str, Any] | None:
    """Summarize one release's files; ``None`` when every file is yanked or none exist."""
    if not isinstance(files, list) or not files:
        return None
    live = [f for f in files if isinstance(f, dict) and not f.get("yanked")]
    if not live:
        return None
    requires_python = next((f.get("requires_python") for f in live if f.get("requires_python")), None)
    return {"requires_python": requires_python, "wheel": any(f.get("packagetype") == "bdist_wheel" for f in live)}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _supports_target(release: dict[str, Any]) -> bool:
    spec = release.get("requires_python")
    if not spec:
        return True
    try:
        return SpecifierSet(str(spec)).contains(_TARGET_PYTHON, prereleases=True)
    except InvalidSpecifier:
        return True


class _Index:
    """Cached PyPI JSON reads; safe to prefetch from worker threads."""

    def __init__(self) -> None:
        self.projects: dict[str, _Project | None] = {}
        self.errors: dict[str, str] = {}
        self.requires: dict[tuple[str, str], list[str] | None] = {}

    def _get(self, url: str) -> dict[str, Any] | None:
        return fetch_pypi_json(url)

    def load_project(self, name: str) -> None:
        if name in self.projects or name in self.errors:
            return
        try:
            data = self._get(f"{PYPI_API}/{name}/json")
        except PyPIUnavailableError as exc:
            self.errors[name] = f"registry unavailable ({exc})"
            return
        if data is None or not isinstance(data.get("releases"), dict):
            self.projects[name] = None
            return
        info = _mapping(data.get("info"))
        releases = {str(v): r for v, files in data["releases"].items() if (r := _release_info(files)) is not None}
        requires = info.get("requires_dist")
        self.projects[name] = _Project(
            name=name,
            releases=releases,
            latest=str(info.get("version") or ""),
            latest_requires=list(requires) if isinstance(requires, list) else None,
        )

    def load_requires(self, name: str, version: str) -> None:
        key = (name, version)
        project = self.projects.get(name)
        if key in self.requires or project is None:
            return
        if version == project.latest:
            self.requires[key] = project.latest_requires
            return
        try:
            data = self._get(f"{PYPI_API}/{name}/{version}/json")
        except PyPIUnavailableError as exc:
            self.errors[name] = f"registry unavailable ({exc})"
            return
        requires = _mapping((data or {}).get("info")).get("requires_dist")
        self.requires[key] = list(requires) if isinstance(requires, list) else None


def _pick(project: _Project, spec: SpecifierSet) -> str | None:
    candidates = {v: r for v, r in project.releases.items() if _supports_target(r)}
    resolved = _resolve_pip_version(str(spec), candidates)
    return None if resolved == "unknown" else resolved


def _applies(marker: Marker | None, extras: set[str]) -> bool:
    if marker is None:
        return True
    try:
        return any(marker.evaluate({**TARGET_ENVIRONMENT, "extra": extra}) for extra in (extras or {""}))
    except (UndefinedComparison, UndefinedEnvironmentName):
        return True


@dataclass
class _Edge:
    requirement: Requirement
    parent: str | None
    depth: int
    parent_extras: frozenset[str] = frozenset()


class _Round:
    """One breadth-first resolution pass under fixed extra constraints."""

    def __init__(self, index: _Index, budget: ResolutionBudget, pinned: dict[str, SpecifierSet], deadline: float) -> None:
        self.index, self.budget, self.pinned, self.deadline = index, budget, pinned, deadline
        self.result = ResolutionResult()
        self.constraints: dict[str, SpecifierSet] = defaultdict(SpecifierSet)
        self.extras: dict[str, set[str]] = defaultdict(set)
        self.expanded: dict[str, set[str]] = defaultdict(set)

    def run(self, roots: list[Requirement]) -> ResolutionResult:
        frontier = [_Edge(req, None, 0) for req in roots]
        with ThreadPoolExecutor(max_workers=max(1, self.budget.workers)) as pool:
            while frontier:
                frontier = self._step(frontier, pool)
        return self.result

    def _fail(self, name: str, reason: str) -> None:
        self.result.failures.setdefault(name, reason)

    def _step(self, frontier: list[_Edge], pool: ThreadPoolExecutor) -> list[_Edge]:
        if time.monotonic() > self.deadline:
            for edge in frontier:
                self._fail(canonicalize_name(edge.requirement.name), "time budget exhausted")
            return []
        live = [edge for edge in frontier if _applies(edge.requirement.marker, set(edge.parent_extras))]
        list(pool.map(self.index.load_project, {canonicalize_name(e.requirement.name) for e in live}))
        chosen = [edge for edge in live if self._choose(edge)]
        wanted = {
            (canonicalize_name(e.requirement.name), self.result.resolved[canonicalize_name(e.requirement.name)].version) for e in chosen
        }
        list(pool.map(lambda key: self.index.load_requires(*key), wanted))
        return [child for edge in chosen for child in self._expand(edge)]

    def _choose(self, edge: _Edge) -> bool:
        """Record the edge's constraint; return True when its dependencies need expanding."""
        req = edge.requirement
        name = canonicalize_name(req.name)
        self.constraints[name] &= req.specifier
        self.extras[name] |= set(req.extras)
        if name in self.result.resolved:
            return bool(self.extras[name] - self.expanded[name])
        if name in self.result.failures:
            return False
        if len(self.result.resolved) >= self.budget.max_packages or edge.depth > self.budget.max_depth:
            self._fail(name, "resolution budget exhausted")
            return False
        project = self.index.projects.get(name)
        if project is None:
            self._fail(name, self.index.errors.get(name, "not found on PyPI"))
            return False
        version = _pick(project, req.specifier & self.pinned.get(name, SpecifierSet()))
        if version is None:
            self._fail(name, f"no release satisfies {req.specifier or 'any version'} for CPython 3.12")
            return False
        self.result.resolved[name] = ResolvedDistribution(name, version, str(req.specifier), edge.parent, edge.depth)
        return True

    def _expand(self, edge: _Edge) -> list[_Edge]:
        name = canonicalize_name(edge.requirement.name)
        version = self.result.resolved[name].version
        done = set(self.expanded[name])
        todo = ({""} | self.extras[name]) - done
        if not todo:
            return []
        self.expanded[name] |= todo
        if name in self.index.errors:
            self._fail(name, self.index.errors[name])
            return []
        requires = self.index.requires.get((name, version))
        project = self.index.projects.get(name)
        if requires is None:
            if "" in todo and project is not None and not project.releases[version]["wheel"]:
                self._fail(name, f"{version} publishes no dependency metadata (sdist only; not built)")
            return []
        children = []
        for raw in requires:
            try:
                child = Requirement(str(raw))
            except InvalidRequirement:
                continue
            if not _applies(child.marker, todo) or (done and _applies(child.marker, done)):
                continue
            children.append(_Edge(child, name, edge.depth + 1, frozenset(todo)))
        return children


def resolve_requirements(roots: list[Requirement], budget: ResolutionBudget | None = None) -> ResolutionResult:
    """Resolve *roots* and their runtime dependencies for :data:`TARGET_ENVIRONMENT`."""
    budget = budget or DEFAULT_BUDGET
    index = _Index()
    deadline = min(time.monotonic() + budget.max_seconds, scan_resolution_deadline())
    pinned: dict[str, SpecifierSet] = {}
    result = ResolutionResult()
    conflicts: dict[str, SpecifierSet] = {}
    for _ in range(_MAX_ROUNDS):
        round_ = _Round(index, budget, pinned, deadline)
        result = round_.run(roots)
        conflicts = {
            name: round_.constraints[name]
            for name, dist in result.resolved.items()
            if not round_.constraints[name].contains(dist.version, prereleases=True)
        }
        if not conflicts:
            return result
        pinned = {**pinned, **conflicts}
    for name in conflicts:
        result.resolved.pop(name, None)
        result.failures.setdefault(name, f"conflicting constraints {conflicts[name]}")
    return result


def requirement_applies(requirement: Requirement) -> bool:
    """Whether a declared requirement's marker holds for the documented target."""
    return _applies(requirement.marker, set())
