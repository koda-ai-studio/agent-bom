"""Cargo lock inventory, explicit dependency edges, and local manifest roots."""

from __future__ import annotations

import tomllib
from collections import defaultdict
from pathlib import Path

from agent_bom.checksums import add_checksum, crates_io_download_url
from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.lockfile_topology import apply_topology


def _locked_crate(row: dict) -> Package:
    name, version = row["name"], row["version"]
    checksums: dict[str, str] = {}
    checksum = row.get("checksum")
    add_checksum(checksums, "sha256", checksum if isinstance(checksum, str) else "")
    return Package(
        name=name,
        version=version,
        ecosystem="cargo",
        purl=f"pkg:cargo/{name}@{version}",
        is_direct=None,
        checksums=checksums,
        download_url=crates_io_download_url(name, version, row.get("source")) if checksums else None,
    )


def _resolver(keys: set[tuple[str, str]]):
    def resolve(value: str):
        tokens = value.split()
        candidates = [key for key in keys if key[0] == tokens[0] and (len(tokens) < 2 or key[1] == tokens[1])]
        return candidates[0] if len(candidates) == 1 else None

    return resolve


def _lock_edges(rows: list[dict], keys: set[tuple[str, str]]) -> dict[tuple, set[tuple[str, str]]]:
    resolve = _resolver(keys)
    edges: dict[tuple, set[tuple[str, str]]] = defaultdict(set)
    for row in rows:
        parent = (row.get("name"), row.get("version"))
        for value in row.get("dependencies", []) if isinstance(row.get("dependencies", []), list) else []:
            if isinstance(value, str) and value.strip() and (child := resolve(value)):
                edges[parent].add(child)
    return edges


def _closure(starts: set[tuple[str, str]], edges: dict[tuple, set[tuple[str, str]]]) -> set[tuple[str, str]]:
    seen = set(starts)
    stack = list(starts)
    while stack:
        for child in edges.get(stack.pop(), ()):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


def parse_cargo_lock(directory: Path, member: str | None = None) -> list[Package]:
    """Registry/git crates of ``directory/Cargo.lock``.

    Rows without ``source`` are workspace or path members (first-party code):
    they are never emitted, and the registry crates they depend on are the
    direct dependencies. ``member`` restricts the result to the closure of
    that first-party crate.
    """
    lock = directory / "Cargo.lock"
    try:
        rows = tomllib.loads(read_text_limited(lock)).get("package", [])
        manifest = tomllib.loads(read_text_limited(directory / "Cargo.toml")) if (directory / "Cargo.toml").exists() else {}
    except (OSError, ValueError):
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo lock or manifest could not be read or parsed; dependency coverage is partial"
        )
        return []
    if not isinstance(rows, list) or not isinstance(manifest, dict):
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo input shape is unsupported; dependency coverage is partial"
        )
        return []
    invalid_rows = [
        row for row in rows if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("version"), str)
    ]
    if invalid_rows:
        record_manifest_parse_warning(
            ecosystem="cargo", path=str(lock), detail="Cargo package entries are malformed; dependency coverage is partial"
        )
    rows = [row for row in rows if row not in invalid_rows]
    first_party = {(row["name"], row["version"]) for row in rows if not row.get("source")}
    packages = [_locked_crate(row) for row in rows if row.get("source")]
    keys = {(p.name, p.version) for p in packages}
    edges = _lock_edges(rows, keys | first_party)
    selected: set[tuple[str, str]] = set()
    if member is not None:
        selected = _closure({key for key in first_party if key[0] == member}, edges)
        packages = [p for p in packages if (p.name, p.version) in selected]
        keys = {(p.name, p.version) for p in packages}
    roots: dict[tuple[str, str], str] = {}
    root_package = manifest.get("package", {}) if member is None else {}
    root_package = root_package if isinstance(root_package, dict) else {}
    root_key = (root_package.get("name"), root_package.get("version"))
    for field, scope in [("dev-dependencies", "dev"), ("build-dependencies", "build"), ("dependencies", "runtime")]:
        declarations = manifest.get(field, {}) if member is None else {}
        if not isinstance(declarations, dict):
            record_manifest_parse_warning(ecosystem="cargo", path=str(lock), detail="Cargo dependency declarations are malformed")
            continue
        for name, spec in declarations.items():
            name = spec.get("package", name) if isinstance(spec, dict) else name
            # Root lock edges disambiguate parallel versions when present.
            candidates = [key for key in edges.get(root_key, keys) if key[0] == name]
            if len(candidates) == 1:
                roots[candidates[0]] = scope
    for parent in first_party:
        if member is None or parent[0] == member or parent in selected:
            for child in edges.get(parent, ()):
                if child in keys:
                    roots.setdefault(child, "unknown")
    apply_topology(packages, {k: v for k, v in edges.items() if k not in first_party}, roots, lock)
    return packages


def ancestor_cargo_lock_owner(directory: Path, max_depth: int = 12) -> tuple[Path, str] | None:
    """``(workspace_dir, crate_name)`` when an ancestor ``Cargo.lock`` resolves this crate as a first-party member."""
    try:
        manifest = tomllib.loads(read_text_limited(directory / "Cargo.toml"))
    except (OSError, ValueError):
        return None
    package = manifest.get("package")
    name = package.get("name") if isinstance(package, dict) else None
    if not isinstance(name, str):
        return None
    for depth, parent in enumerate(directory.parents):
        if depth >= max_depth:
            return None
        lock = parent / "Cargo.lock"
        if not lock.is_file():
            continue
        try:
            rows = tomllib.loads(read_text_limited(lock)).get("package", [])
        except (OSError, ValueError):
            return None
        owned = isinstance(rows, list) and any(isinstance(row, dict) and row.get("name") == name and not row.get("source") for row in rows)
        return (parent, name) if owned else None
    return None
