"""Packages named by npx, bunx, uvx and uv tool run, in commands and MCP configs."""

from __future__ import annotations

import re

from agent_bom.models import Package

_NPX_RE = re.compile(
    r"(?:npx|bunx)[ \t]+(?:(?:-[yYp]|--yes)[ \t]+)*(?!-)(@?[\w./-]+(?:@[\w.^~<>=+-]+)?)",
)
_UVX_RE = re.compile(
    r"(?:uvx|uv[ \t]+tool[ \t]+run)[ \t]+([\w][\w.-]*(?:(?:==|@)[\w.+-]+)?)",
)
_LAUNCHER_COMMANDS = {"npx", "bunx", "uvx", "uv"}


def _parse_pkg_spec(spec: str, version_sep: str) -> tuple[str, str]:
    """Parse a package spec like '@scope/pkg@1.0.0' or 'pkg==1.0.0'.

    Returns (name, version). Version may be empty string.
    """
    spec = spec.strip("'\"")
    if not spec:
        return ("", "")

    if version_sep == "@":
        # Handle scoped npm packages: @scope/name@version
        if spec.startswith("@"):
            # Find the second @ (version separator)
            rest = spec[1:]
            if "@" in rest:
                idx = rest.index("@")
                return (spec[: idx + 1], rest[idx + 1 :])
            return (spec, "")
        # Non-scoped: name@version
        if "@" in spec:
            parts = spec.split("@", 1)
            return (parts[0], parts[1])
        return (spec, "")
    else:
        # pip-style: name==version or name>=version
        if version_sep in spec:
            parts = spec.split(version_sep, 1)
            return (parts[0], parts[1])
        return (spec, "")


def collect_launcher_packages(text: str, packages: list[Package], seen: set[tuple[str, str]]) -> None:
    """Add the packages named by npx, bunx and uvx commands in ``text``."""
    for match in _NPX_RE.finditer(text):
        name, version = _parse_pkg_spec(match.group(1), "@")
        if (name.lower(), "npm") not in seen:
            seen.add((name.lower(), "npm"))
            packages.append(Package(name=name, version=version or "latest", ecosystem="npm"))
    for match in _UVX_RE.finditer(text):
        raw = match.group(1)
        name, version = _parse_pkg_spec(raw, "==" if "==" in raw else "@")
        if (name.lower(), "pypi") not in seen:
            seen.add((name.lower(), "pypi"))
            packages.append(Package(name=name, version=version or "latest", ecosystem="pypi"))


def collect_mcp_launcher_packages(command: str, args: list, packages: list[Package], seen: set[tuple[str, str]]) -> None:
    """Add the package an MCP server's launcher command and arguments name."""
    launcher = re.split(r"[\\/]", command)[-1].lower().removesuffix(".cmd").removesuffix(".exe")
    if launcher in _LAUNCHER_COMMANDS:
        collect_launcher_packages(" ".join([launcher, *(arg for arg in args if isinstance(arg, str))]), packages, seen)
