"""Conservative package-install parsing for commands an agent actually ran.

Only a command word in executable position counts (``echo npm install x`` does
not). Flags that take a value reuse the pre-install guard's tables.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from agent_bom.guard import _NPM_VALUE_FLAGS, _PIP_VALUE_FLAGS

_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")
_NAME = re.compile(r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._/-]*$")
_PIP_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:==([A-Za-z0-9.+!_-]+))?(?:[<>=!~;].*)?$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NPM_MANAGERS = {"npm": {"install", "i", "add"}, "pnpm": {"add", "install", "i"}, "yarn": {"add"}, "bun": {"add", "install", "i"}}
_NPM_RUNNERS = {"npx", "bunx"}


@dataclass(frozen=True)
class InstalledPackage:
    ecosystem: str
    name: str
    version: str | None
    manager: str
    kind: str  # "install" or "run"


def _tokens(segment: str) -> list[str]:
    try:
        tokens = shlex.split(segment, comments=True)
    except ValueError:
        tokens = segment.split()
    while tokens and (_ENV_ASSIGN.match(tokens[0]) or tokens[0] in {"sudo", "env", "command", "exec"}):
        tokens.pop(0)
    return tokens


def _operands(tokens: list[str], value_flags: frozenset[str] | set[str]) -> list[str]:
    operands, skip = [], False
    for token in tokens:
        if skip:
            skip = False
        elif token.startswith("-"):
            skip = token in value_flags
        else:
            operands.append(token)
    return operands


def _npm(spec: str, manager: str, kind: str) -> InstalledPackage | None:
    scoped = spec.startswith("@")
    name, _, version = spec[1:].partition("@") if scoped else spec.partition("@")
    name = ("@" + name) if scoped else name
    if not _NAME.match(name) or name.startswith((".", "/")) or ":" in spec:
        return None
    return InstalledPackage("npm", name, version or None, manager, kind)


def _pypi(spec: str, manager: str, kind: str) -> InstalledPackage | None:
    match = _PIP_SPEC.match(spec.split("@", 1)[0] if kind == "run" else spec)
    if not match or spec.startswith((".", "/")) or "://" in spec:
        return None
    version = match.group(2) or (spec.split("@", 1)[1] if kind == "run" and "@" in spec else None)
    return InstalledPackage("pypi", match.group(1), version, manager, kind)


def _pip_args(tokens: list[str]) -> list[str] | None:
    if tokens[:1] and tokens[0].rsplit("/", 1)[-1] in {"pip", "pip3"}:
        rest = tokens[1:]
    elif len(tokens) > 3 and tokens[0].rsplit("/", 1)[-1].startswith("python") and tokens[1:3] == ["-m", "pip"]:
        rest = tokens[3:]
    elif tokens[:2] == ["uv", "pip"]:
        rest = tokens[2:]
    else:
        return None
    return rest[1:] if rest[:1] == ["install"] else None


def _segment_packages(tokens: list[str]) -> list[InstalledPackage]:
    if not tokens:
        return []
    head = tokens[0].rsplit("/", 1)[-1]
    pip = _pip_args(tokens)
    if pip is not None:
        return [p for spec in _operands(pip, _PIP_VALUE_FLAGS | {"-r", "--requirement"}) if (p := _pypi(spec, "pip", "install"))]
    if head in _NPM_MANAGERS and len(tokens) > 1 and tokens[1] in _NPM_MANAGERS[head]:
        return [p for spec in _operands(tokens[2:], _NPM_VALUE_FLAGS) if (p := _npm(spec, head, "install"))]
    if head in _NPM_RUNNERS or (head in {"pnpm", "yarn"} and tokens[1:2] == ["dlx"]):
        operands = _operands(tokens[2:] if head in {"pnpm", "yarn"} else tokens[1:], {"-p", "--package"})
        return [p for p in [_npm(operands[0], head, "run")] if p] if operands else []
    if head == "uv" and tokens[1:2] == ["add"]:
        return [p for spec in _operands(tokens[2:], {"--group", "--extra", "--optional"}) if (p := _pypi(spec, "uv", "install"))]
    if head == "uvx" or (head == "uv" and tokens[1:3] in (["tool", "run"], ["tool", "install"])):
        operands = _operands(tokens[1:] if head == "uvx" else tokens[3:], {"--from", "--with", "--python"})
        kind = "install" if tokens[1:3] == ["tool", "install"] else "run"
        return [p for p in [_pypi(operands[0], "uv", kind)] if p] if operands else []
    if head == "cargo" and tokens[1:2] in (["install"], ["add"]):
        return [
            InstalledPackage("cargo", spec, None, "cargo", "install")
            for spec in _operands(tokens[2:], {"--version", "--git", "--path"})
            if _NAME.match(spec)
        ]
    if head == "go" and tokens[1:2] in (["install"], ["get"]):
        found = []
        for spec in _operands(tokens[2:], set()):
            name, _, version = spec.partition("@")
            if "." in name.split("/", 1)[0] and _NAME.match(name):
                found.append(InstalledPackage("go", name, version or None, "go", "install"))
        return found
    return []


def packages_from_command(command: str) -> list[InstalledPackage]:
    found: list[InstalledPackage] = []
    for segment in _SEGMENT_SPLIT.split(command or ""):
        for package in _segment_packages(_tokens(segment.strip())):
            if package not in found:
                found.append(package)
    return found
