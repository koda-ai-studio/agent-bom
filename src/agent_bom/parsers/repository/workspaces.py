"""First-party package declarations from npm/yarn/pnpm, uv, Cargo and Go workspaces."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import posixpath
import re
import shlex
import tomllib
from functools import lru_cache
from itertools import islice
from typing import Any

from agent_bom.core.packages import normalize_package_name
from agent_bom.core.repository_identity import relative_path, repository_id
from agent_bom.domain.codeowners import CodeOwnerRule, owner_for_path
from agent_bom.parsers.repository.artifacts import RepositoryReader

MAX_PACKAGES = 500
_MANIFESTS = {"npm": "package.json", "pypi": "pyproject.toml", "cargo": "Cargo.toml", "go": "go.mod"}


def _yaml(text: str) -> Any:
    import yaml

    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid workspace YAML") from exc


def _declaration_limits(reader: RepositoryReader, path: str, value: dict[str, Any]) -> None:
    pending: list[Any] = [value]
    seen: set[int] = set()
    remaining = 5000
    while pending and remaining > 0:
        item = pending.pop()
        if not isinstance(item, (dict, list)) or id(item) in seen:
            continue
        seen.add(id(item))
        if len(item) > 1000:
            reader.note(path, "declaration_limit")
        children = list(islice(item.values() if isinstance(item, dict) else item, min(1000, remaining)))
        pending.extend(child for child in children if isinstance(child, (dict, list)))
        remaining -= len(children)
    if pending:
        reader.note(path, "declaration_limit")


def _document(reader: RepositoryReader, path: str) -> tuple[dict[str, Any], str]:
    text = reader.read(path)
    if text is None:
        return {}, ""
    digest = hashlib.sha256(text.encode()).hexdigest()
    try:
        if path.endswith(".json"):
            value = json.loads(text)
        elif path.endswith(".toml"):
            value = tomllib.loads(text)
        elif path.endswith(".yaml"):
            value = _yaml(text)
        else:
            module = re.search(r"^module\s+([^\s]+)", text, re.M)
            value = {
                "name": module.group(1).strip('"') if module else "",
                "dependencies": re.findall(r"^\s*(?:require\s+)?([^\s()]+)\s+v[\d][^\s]*", text, re.M),
            }
        if not isinstance(value, dict):
            raise ValueError("mapping expected")
        _declaration_limits(reader, path, value)
        return value, digest
    except (ValueError, RecursionError):
        reader.note(path, "invalid_or_unreadable_artifact")
        return {}, digest


def _strings(value: object) -> list[str]:
    return [v for v in value[:1000] if isinstance(v, str) and len(v) <= 512] if isinstance(value, list) else []


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _matches(path: str, pattern: str) -> bool:
    # Segment matching prevents apps/* from also selecting apps/a/nested.
    parts, glob = path.split("/"), pattern.removeprefix("./").rstrip("/").split("/")

    @lru_cache(maxsize=4096)
    def match(pi: int, gi: int) -> bool:
        if gi == len(glob):
            return pi == len(parts)
        if glob[gi] == "**":
            return match(pi, gi + 1) or (pi < len(parts) and match(pi + 1, gi))
        return pi < len(parts) and fnmatch.fnmatchcase(parts[pi], glob[gi]) and match(pi + 1, gi + 1)

    return match(0, 0)


def _patterns(reader: RepositoryReader, roots: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    npm = roots["npm"].get("workspaces")
    npm = npm.get("packages") if isinstance(npm, dict) else npm
    pnpm, _ = _document(reader, "pnpm-workspace.yaml")
    uv = _mapping(_mapping(_mapping(roots["pypi"].get("tool")).get("uv")).get("workspace"))
    cargo = _mapping(roots["cargo"].get("workspace"))
    patterns = {
        "npm": _strings(npm) + _strings(pnpm.get("packages")),
        "pypi": _strings(uv.get("members")) + ["!" + p for p in _strings(uv.get("exclude"))],
        "cargo": _strings(cargo.get("members")) + ["!" + p for p in _strings(cargo.get("exclude"))],
        "go": [],
    }
    go = reader.read("go.work") or ""
    for block in re.findall(r"\buse\s*\(([^)]*)\)", go):
        patterns["go"] += [s.split("//", 1)[0].strip().strip('"') for s in block.splitlines() if s.split("//", 1)[0].strip()]
    patterns["go"] += re.findall(r"^use\s+([^\s(]+)", go, re.M)
    for ecosystem, values in patterns.items():
        safe = []
        for value in values:
            if relative_path(value.removeprefix("!").strip('"')) is None:
                reader.note("<invalid path>", "invalid_workspace_path")
            else:
                safe.append(value.strip('"'))
        patterns[ecosystem] = safe
    return patterns


def _owners(reader: RepositoryReader) -> tuple[str, list[CodeOwnerRule]]:
    for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
        text = reader.read(path, max_bytes=256 * 1024)
        if text is None:
            continue
        rules = []
        for line in text.splitlines()[:2000]:
            try:
                parts = shlex.split(line, comments=True)
            except ValueError:
                continue
            if len(parts) >= 2:
                owners = tuple(p for p in parts[1:21] if p.startswith("@") or "@" in p)
                if owners:
                    rules.append(CodeOwnerRule(parts[0], owners))
        return path, rules
    return "", []


def _package(data: dict[str, Any], ecosystem: str) -> tuple[str, list[str]]:
    section = _mapping(data.get("project" if ecosystem == "pypi" else "package")) if ecosystem in {"pypi", "cargo"} else data
    name = section.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 256:
        return "", []
    deps: set[str] = set()
    if ecosystem == "pypi":
        for declaration in _strings(section.get("dependencies")):
            match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", declaration)
            if match:
                deps.add(normalize_package_name(match.group(), ecosystem))
    elif ecosystem == "go":
        deps.update(_strings(data.get("dependencies")))
    else:
        for key in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "dev-dependencies",
            "build-dependencies",
        ):
            deps.update(k for k in islice(_mapping(data.get(key)), 1000) if isinstance(k, str) and len(k) <= 256)
    return normalize_package_name(name.strip(), ecosystem), sorted(deps)[:1000]


def _workspace_dependencies(data: dict[str, Any], ecosystem: str) -> list[str]:
    """Name coincidence is not local resolution; require an explicit workspace declaration."""
    if ecosystem == "npm":
        return sorted(
            {
                name
                for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                for name, spec in islice(_mapping(data.get(key)).items(), 1000)
                if isinstance(name, str) and isinstance(spec, str) and spec.startswith("workspace:")
            }
        )[:1000]
    if ecosystem == "pypi":
        sources = _mapping(_mapping(_mapping(data.get("tool")).get("uv")).get("sources"))
        return sorted(
            normalize_package_name(name, "pypi")
            for name, spec in islice(sources.items(), 1000)
            if isinstance(name, str) and isinstance(spec, dict) and spec.get("workspace") is True
        )[:1000]
    return []


def _local_dependencies(data: dict[str, Any], ecosystem: str, directory: str) -> dict[str, str]:
    result = {}
    for key in ("dependencies", "devDependencies", "dev-dependencies", "build-dependencies", "optionalDependencies"):
        for name, spec in islice(_mapping(data.get(key)).items(), 1000):
            raw = spec.get("path") if ecosystem == "cargo" and isinstance(spec, dict) else None
            if ecosystem == "npm" and isinstance(spec, str) and spec.startswith(("file:", "link:")):
                raw = spec.split(":", 1)[1]
            if not isinstance(name, str) or not isinstance(raw, str) or raw.startswith("/") or "\\" in raw or len(raw) > 512:
                continue
            path = relative_path(posixpath.normpath(posixpath.join(directory, raw)))
            if path is not None:
                result[name] = path
    return dict(sorted(result.items())[:1000])


def workspace_context(reader: RepositoryReader) -> dict[str, Any]:
    roots = {eco: _document(reader, file)[0] for eco, file in _MANIFESTS.items()}
    patterns = _patterns(reader, roots)
    directories = reader.directories() if any(patterns.values()) else ["."]
    owner_source, rules = _owners(reader)
    packages: list[dict[str, Any]] = []
    for eco, manifest in _MANIFESTS.items():
        includes = [p for p in patterns[eco] if not p.startswith("!")]
        excludes = [p[1:] for p in patterns[eco] if p.startswith("!")]
        for pattern in includes:
            if not any(_matches(d, pattern) for d in directories):
                reader.note(pattern, "unmatched_workspace_pattern")
        for directory in directories:
            if directory != "." and (not any(_matches(directory, p) for p in includes) or any(_matches(directory, p) for p in excludes)):
                continue
            artifact = manifest if directory == "." else f"{directory}/{manifest}"
            data, digest = _document(reader, artifact)
            name, deps = _package(data, eco)
            if not name:
                continue
            if len(packages) >= MAX_PACKAGES:
                reader.note(".", "workspace_package_limit")
                break
            rule = owner_for_path(artifact, rules)
            owners = rule.owners if rule else ()
            packages.append(
                {
                    "id": repository_id(reader.scope, "workspace_package", f"{eco}:{directory}:{name}"),
                    "name": name,
                    "path": directory,
                    "ecosystem": eco,
                    "first_party": True,
                    "manifest": artifact,
                    "manifest_digest": digest,
                    "declared_dependencies": deps,
                    "workspace_dependencies": deps
                    if eco == "go" and any(_matches(directory, p) for p in includes)
                    else _workspace_dependencies(data, eco),
                    "local_dependency_paths": _local_dependencies(data, eco, directory),
                    "owners": list(owners),
                    "owner_source": owner_source if owners else "",
                    "evidence_tier": "static_scan",
                }
            )
    nx = reader.read("nx.json")
    turbo = reader.read("turbo.json")
    return {
        "version": 1,
        "scope_id": reader.scope,
        "identity_basis": "local_root",
        "ref": "unrecorded",
        "status": "partial" if reader.unresolved else "complete",
        "workspace_packages": packages,
        "unresolved": reader.unresolved,
        "coverage": {
            "npm_yarn": "package_manifests",
            "pnpm": "package_manifests",
            "uv": "project_manifests",
            "cargo": "package_manifests",
            "go": "module_manifests",
            "nx": "package_manifests_only" if nx is not None else "not_present",
            "turbo": "package_manifests_only" if turbo is not None else "not_present",
        },
    }
