"""Lockfile parsers for the real-repository accuracy measurement.

These are deliberately separate from agent-bom's own parsers, so the ground
truth does not inherit a parser bug from the tool being measured. Each parser
returns OSV ``(ecosystem, name, version)`` triples plus the entries it skipped
because they do not come from a public registry.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ParsedLockfile:
    packages: set[tuple[str, str, str]] = field(default_factory=set)
    skipped: list[str] = field(default_factory=list)


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_GO_REQUIRE = re.compile(r"^(\S+)\s+(v\S+)")
_GO_REPLACE = re.compile(r"^(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?")


def _go_directives(text: str, keyword: str) -> list[str]:
    """Return the bodies of single-line and block ``require``/``replace`` directives."""
    lines: list[str] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if in_block:
            if line == ")":
                in_block = False
            elif line:
                lines.append(line)
        elif line == f"{keyword} (":
            in_block = True
        elif line.startswith(f"{keyword} "):
            lines.append(line[len(keyword) + 1 :].strip())
    return lines


def parse_go_mod(path: Path) -> ParsedLockfile:
    """Modules in the ``require`` directives, with ``replace`` applied (Go 1.17+ lists the full build list)."""
    text = path.read_text(encoding="utf-8")
    result = ParsedLockfile()
    replacements: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    for line in _go_directives(text, "replace"):
        match = _GO_REPLACE.match(line)
        if match:
            old, old_version, new, new_version = match.groups()
            replacements[(old, old_version)] = (new, new_version)
    for line in _go_directives(text, "require"):
        match = _GO_REQUIRE.match(line)
        if not match:
            continue
        module, version = match.groups()
        target = replacements.get((module, version)) or replacements.get((module, None))
        if target is None:
            result.packages.add(("Go", module, version))
        elif target[1] is None:
            result.skipped.append(f"{module}@{version} (replaced by local path {target[0]})")
        else:
            result.packages.add(("Go", target[0], target[1]))
    return result


def _split_pnpm_key(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/")
    key = key.split("(", 1)[0]
    at = key.rfind("@")
    if at <= 0:
        return None
    return key[:at], key[at + 1 :]


_SEMVER_LIKE = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-+]+)?$")


def parse_pnpm_lock(path: Path) -> ParsedLockfile:
    """Registry packages under ``packages:`` (pnpm lockfile v6 and v9 keys)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    result = ParsedLockfile()
    for key in data.get("packages") or {}:
        split = _split_pnpm_key(str(key))
        if split and _SEMVER_LIKE.match(split[1]):
            result.packages.add(("npm", split[0], split[1]))
        else:
            result.skipped.append(str(key))
    return result


def parse_cargo_lock(path: Path) -> ParsedLockfile:
    """Crates whose ``source`` is the crates.io registry; workspace and git crates are skipped."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result = ParsedLockfile()
    for package in data.get("package", []):
        name, version, source = package["name"], package["version"], package.get("source")
        if source is None:
            result.skipped.append(f"{name}@{version} (workspace)")
        elif source.startswith("registry+https://github.com/rust-lang/crates.io-index") or source.startswith(
            "sparse+https://index.crates.io/"
        ):
            result.packages.add(("crates.io", name, version))
        else:
            result.skipped.append(f"{name}@{version} ({source.split('+', 1)[0]})")
    return result


def parse_uv_lock(path: Path) -> ParsedLockfile:
    """Packages resolved from a registry; editable, virtual, path and git sources are skipped."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result = ParsedLockfile()
    for package in data.get("package", []):
        name, version = package["name"], package.get("version", "")
        source = package.get("source") or {}
        if "registry" in source and version:
            result.packages.add(("PyPI", _pep503(name), version))
        else:
            kind = next(iter(source), "unknown")
            result.skipped.append(f"{name}@{version} ({kind})")
    return result


PARSERS = {
    "go.mod": parse_go_mod,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "Cargo.lock": parse_cargo_lock,
    "uv.lock": parse_uv_lock,
}


def parse_lockfile(path: Path, fmt: str) -> ParsedLockfile:
    try:
        parser = PARSERS[fmt]
    except KeyError as exc:
        raise ValueError(f"no independent parser for format {fmt!r}") from exc
    return parser(path)
