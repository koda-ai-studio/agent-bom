"""Packages and requirement files named by install commands in shell text.

Each command segment (split on ``&&``, ``||``, ``;``, ``|``, ``&``, newlines
and inline-code backticks) is tokenized on its own, so every install on a line
is read. Options that take a value consume it; ``-r`` values are requirement
files, recorded as manifest references rather than packages. Redirects with
their targets, environment assignments, ``$VAR`` and ``$(...)`` never become
packages.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

_REDIRECT_RE = re.compile(r"^\d*(?:>>?|<<?|>&|&>>?)")
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=(?!=)")
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NPM_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*$")
_FILE_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".zip", ".txt", ".toml", ".cfg", ".in", ".py", ".lock", ".json")

_PIP_VALUE_OPTIONS = frozenset(
    {
        *("-r", "--requirement", "--requirements", "-c", "--constraint", "--constraints", "-e", "--editable"),
        *("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root"),
        *("-C", "--config-settings", "--src", "--platform", "--python-version", "--implementation", "--abi"),
        *("--no-binary", "--only-binary", "--progress-bar", "--upgrade-strategy", "--trusted-host", "--proxy"),
        *("--cert", "--client-cert", "--cache-dir", "--timeout", "--retries", "--exists-action", "--log"),
        *("--report", "--root-user-action", "--keyring-provider", "--group", "--python", "--build-constraint"),
        *("--use-feature", "--use-deprecated", "--global-option", "--install-option"),
        # uv pip install
        *("--overrides", "--excludes", "-b", "--build-constraints", "--extra", "--index", "--default-index"),
        *("--index-strategy", "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "-p"),
        *("--python-platform", "--torch-backend", "--directory", "--project", "--config-file", "--color"),
        *("--allow-insecure-host", "--reinstall-package", "--refresh-package", "--output-format"),
    }
)
_UV_ADD_VALUE_OPTIONS = frozenset(
    {
        *("-r", "--requirements", "-c", "--constraints", "-m", "--marker", "--optional", "--group", "--bounds"),
        *("--rev", "--tag", "--branch", "--extra", "--package", "--script", "--index", "--default-index"),
        *("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index-strategy", "--resolution"),
        *("--prerelease", "--exclude-newer", "--link-mode", "--cache-dir", "-p", "--python", "--color"),
        *("--directory", "--project", "--config-file", "--allow-insecure-host", "--keyring-provider"),
    }
)
_PIPX_VALUE_OPTIONS = frozenset(
    {"--suffix", "--python", "--preinstall", "--app", "--lock", "--pip-args", "--index-url", "-i", "--include-resources-from"}
)
_NPM_VALUE_OPTIONS = frozenset(
    {
        *("--registry", "--tag", "--prefix", "-w", "--workspace", "--omit", "--include", "--install-strategy"),
        *("--cache", "--userconfig", "--before", "--loglevel", "--cpu", "--os", "--libc", "--save-prefix"),
    }
)
_YARN_VALUE_OPTIONS = frozenset({"--registry", "--network-timeout", "--cache-folder", "--modules-folder", "--cwd"})
_PNPM_VALUE_OPTIONS = frozenset({"--filter", "-F", "--dir", "-C", "--registry", "--save-catalog-name", "--store-dir"})

_MANIFEST_OPTIONS = frozenset({"-r", "--requirement", "--requirements"})

# command -> (subcommands that install, ecosystem, options that take a value)
_INSTALLERS: dict[str, tuple[frozenset[str], str, frozenset[str]]] = {
    "pip": (frozenset({"install"}), "pypi", _PIP_VALUE_OPTIONS),
    "pip3": (frozenset({"install"}), "pypi", _PIP_VALUE_OPTIONS),
    "uv": (frozenset({"add"}), "pypi", _UV_ADD_VALUE_OPTIONS),
    "pipx": (frozenset({"install"}), "pypi", _PIPX_VALUE_OPTIONS),
    "npm": (frozenset({"install", "i", "add"}), "npm", _NPM_VALUE_OPTIONS),
    "yarn": (frozenset({"add"}), "npm", _YARN_VALUE_OPTIONS),
    "pnpm": (frozenset({"add"}), "npm", _PNPM_VALUE_OPTIONS),
}


@dataclass
class InstallCommands:
    """``(ecosystem, spec)`` pairs in text order, and requirement files named by ``-r``."""

    packages: list[tuple[str, str]] = field(default_factory=list)
    manifest_references: list[str] = field(default_factory=list)


def parse_install_commands(text: str) -> InstallCommands:
    found = InstallCommands()
    for segment in _command_segments(text):
        _parse_segment(segment, found)
    return found


def _command_segments(text: str) -> list[str]:
    """Split shell text on control operators, newlines and backticks, outside quotes."""
    segments: list[str] = []
    current: list[str] = []
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            elif char == "\n":
                quote = ""
            i += 1
            continue
        if char in "'\"" and (i == 0 or text[i - 1] in " \t=("):
            quote = char
            current.append(char)
        elif char in "\n;`|" or (char == "&" and not _is_redirect_ampersand(text, i)):
            segments.append("".join(current))
            current = []
            if text[i : i + 2] in ("&&", "||"):
                i += 1
        else:
            current.append(char)
        i += 1
    segments.append("".join(current))
    return segments


def _is_redirect_ampersand(text: str, index: int) -> bool:
    return (index > 0 and text[index - 1] in "<>") or text[index + 1 : index + 2] == ">"


def _tokens(segment: str) -> list[str]:
    segment = segment.split("$(", 1)[0]
    try:
        lexer = shlex.shlex(segment, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return [token.strip("'\"") for token in segment.split("#", 1)[0].split()]


def _parse_segment(segment: str, found: InstallCommands) -> None:
    tokens = _tokens(segment)
    for index, token in enumerate(tokens[:-1]):
        installer = _INSTALLERS.get(token)
        if installer is None or tokens[index + 1] not in installer[0]:
            continue
        _subcommands, ecosystem, value_options = installer
        _parse_arguments(tokens[index + 2 :], ecosystem, value_options, found)
        return


def _parse_arguments(tokens: list[str], ecosystem: str, value_options: frozenset[str], found: InstallCommands) -> None:
    skip_next = False
    manifest_next = False
    options_done = False
    for token in tokens:
        if skip_next:
            skip_next = False
            if manifest_next:
                _add_manifest(token, found)
                manifest_next = False
            continue
        redirect = _REDIRECT_RE.match(token)
        if redirect:
            skip_next = redirect.end() == len(token)
            continue
        if token == "--" and not options_done:
            options_done = True
            continue
        if token.startswith("-") and not options_done:
            skip_next, manifest_next = _option(token, value_options, found)
            continue
        if not token or token.startswith("$") or _ENV_ASSIGNMENT_RE.match(token):
            continue
        if _is_package_spec(token, ecosystem):
            found.packages.append((ecosystem, token))


def _option(token: str, value_options: frozenset[str], found: InstallCommands) -> tuple[bool, bool]:
    """Return ``(consumes_next_token, next_token_is_a_manifest)`` for one option token."""
    name, eq, value = token.partition("=")
    if eq and name.startswith("--"):
        if name in _MANIFEST_OPTIONS:
            _add_manifest(value, found)
        return False, False
    if token in value_options:
        return True, token in _MANIFEST_OPTIONS
    short = token[:2]
    if not token.startswith("--") and len(token) > 2 and short in value_options:
        if short in _MANIFEST_OPTIONS:
            _add_manifest(token[2:], found)
    return False, False


def _add_manifest(value: str, found: InstallCommands) -> None:
    if value and not value.startswith("$") and value not in found.manifest_references:
        found.manifest_references.append(value)


def _is_package_spec(spec: str, ecosystem: str) -> bool:
    if spec.startswith((".", "/", "~")):
        return False
    if ecosystem == "npm":
        if ":" in spec:
            return False
        name = spec[: spec.index("@", 1)] if "@" in spec[1:] else spec
        return bool(_NPM_NAME_RE.match(name)) and not name.lower().endswith(_FILE_SUFFIXES)
    name = re.split(r"[><=!~;]", spec)[0].split("[")[0]
    return len(name) >= 2 and bool(_PYPI_NAME_RE.match(name)) and not name.lower().endswith(_FILE_SUFFIXES)
