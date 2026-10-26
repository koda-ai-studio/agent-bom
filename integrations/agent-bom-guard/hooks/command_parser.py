"""Bounded, passive extraction of named registry installs; never execute shell text."""

from __future__ import annotations

import re
import shlex
from collections import namedtuple

# Plain tuples rather than dataclasses: importing dataclasses (and inspect) costs
# more than the whole check on a stock interpreter, and this runs on every Bash call.
Package = namedtuple("Package", ["ecosystem", "name", "version"], defaults=[None])


class InstallPlan:
    def __init__(self) -> None:
        self.packages: list[Package] = []
        self.requirement_files: list[str] = []
        self.pipe_to_shell: list[str] = []
        self.custom_indexes: list[str] = []
        self.incomplete = False


_VALUES = {
    "--registry",
    "--index-url",
    "--extra-index-url",
    "--trusted-host",
    "--group",
    "-G",
    "--features",
    "-F",
    "--target",
    "--prefix",
    "--cache",
    "--python",
    "-p",
    "--directory",
    "--cwd",
    "--config",
    "--config-settings",
    "--find-links",
    "-f",
    "--proxy",
    "--timeout",
    "--cert",
    "--client-cert",
    "--platform",
    "--implementation",
    "--abi",
    "--python-version",
}
_INDEX_OPTIONS = {"--registry", "--index-url", "--extra-index-url", "-i"}


def _index_host(url: str) -> str:
    """Host of a registry URL, without any user name or token in it."""
    rest = url.partition("://")[2] or url
    return rest.split("/", 1)[0].rpartition("@")[2][:253]


_EXACT = re.compile(r"v?\d[0-9A-Za-z.+_-]*\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SCOPED = re.compile(r"@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\Z")
_GO = re.compile(r"[A-Za-z0-9.-]+\.[A-Za-z]+/[A-Za-z0-9._~/-]+\Z")


def _package(spec: str, ecosystem: str) -> Package | None:
    if len(spec) > 256 or any(c in spec for c in (":", "$", "`", "\\")) or spec.startswith((".", "/", "-")):
        return None
    if ecosystem == "pypi":
        spec = re.sub(r"\[[^]]*\]", "", spec)
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:(==|@)([^ ]+)|[<>!~=].*)?", spec)
        if not match:
            return None
        name, op, version = match.groups()
        name = re.sub(r"[-_.]+", "-", name).lower()
    else:
        name, sep, version = spec.rpartition("@")
        if not sep or not name:
            name, version = spec, None
        valid = _GO.fullmatch(name) if ecosystem == "go" else (_NAME.fullmatch(name) or (ecosystem == "npm" and _SCOPED.fullmatch(name)))
        if not valid:
            return None
    return Package(ecosystem, name, version.removeprefix("v") if version and _EXACT.fullmatch(version) else None)


_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_PREFIXES = {"sudo", "doas", "env", "nohup", "time", "command", "exec"}
_PREFIX_VALUE_FLAGS = {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}
_FAMILY = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "npx": "npm",
    "pip": "pypi",
    "pip3": "pypi",
    "uv": "pypi",
    "uvx": "pypi",
    "pipx": "pypi",
    "poetry": "pypi",
    "cargo": "cargo",
    "go": "go",
}
_RUNNERS = {"npx", "uvx"}
_INSTALL_VERBS = {"install", "i", "add", "get"}


def _strip_prefixes(tokens: list[str]) -> list[str]:
    """Drop env assignments and wrappers such as ``sudo -u x`` or ``env -i``."""
    while tokens:
        head = tokens[0]
        if _ASSIGNMENT.fullmatch(head):
            tokens = tokens[1:]
            continue
        if head.rsplit("/", 1)[-1] not in _PREFIXES:
            break
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            flag, tokens = tokens[0], tokens[1:]
            if flag in _PREFIX_VALUE_FLAGS and tokens:
                tokens = tokens[1:]
    return tokens


def _canonical(tokens: list[str]) -> list[str]:
    """Rewrite ``python -m pip``, ``uv pip`` and ``uv tool run`` to the tool they invoke."""
    executable = tokens[0].rsplit("/", 1)[-1]
    if executable.startswith("python") and tokens[1:3] == ["-m", "pip"]:
        return ["pip", *tokens[3:]]
    if executable == "uv" and tokens[1:2] == ["pip"]:
        return ["pip", *tokens[2:]]
    if executable == "uv" and tokens[1:3] == ["tool", "run"]:
        return ["uvx", *tokens[3:]]
    return [executable, *tokens[1:]]


def _option_value(args: list[str], i: int) -> tuple[str, int]:
    """Value of the option at ``args[i]`` (``--opt=v`` or ``--opt v``) and the next index."""
    _, equals, inline = args[i].partition("=")
    if equals:
        return inline, i + 1
    return (args[i + 1] if i + 1 < len(args) else ""), i + 2


def _scan_args(args: list[str], ecosystem: str, executable: str, plan: InstallPlan) -> list[Package]:
    runner = executable in _RUNNERS
    packages: list[Package] = []
    version = None
    i = 0
    while i < len(args):
        arg = args[i]
        option = arg.partition("=")[0]
        if option in {"-r", "--requirement", "-c", "--constraint"}:
            value, i = _option_value(args, i)
            if value:
                plan.requirement_files.append(value)
            continue
        if option in {"--from", "--package"} and runner:
            value, i = _option_value(args, i)
            pkg = _package(value, ecosystem)
            if pkg:
                packages.append(pkg)
            if executable == "uvx":
                break
            continue
        if option == "--version" and executable == "cargo":
            version, i = _option_value(args, i)
            continue
        if option in {"-e", "--editable", "--path", "--git"}:
            plan.incomplete = True
            _, i = _option_value(args, i)
            continue
        if option in _INDEX_OPTIONS:
            value, i = _option_value(args, i)
            host = _index_host(value)
            if host:
                plan.custom_indexes.append(f"{option} {host}")
            continue
        if option in _VALUES:
            _, i = _option_value(args, i)
            continue
        if arg.startswith("-"):
            i += 1
            continue
        pkg = _package(arg, ecosystem)
        if pkg:
            packages.append(pkg)
        else:
            plan.incomplete = True
        if runner:
            break
        i += 1
    if version and _EXACT.fullmatch(version):
        packages = [Package(p.ecosystem, p.name, version.removeprefix("v")) for p in packages]
    return packages


def _install(tokens: list[str], plan: InstallPlan, depth: int) -> None:
    tokens = _strip_prefixes(tokens)
    if not tokens:
        return
    executable = tokens[0].rsplit("/", 1)[-1]
    if executable in {"sh", "bash", "zsh"} and len(tokens) == 3 and tokens[1] in {"-c", "-lc"}:
        if depth < 3:
            _parse(tokens[2], plan, depth + 1)
        else:
            plan.incomplete = True
        return
    tokens = _canonical(tokens)
    executable = tokens[0]
    ecosystem = _FAMILY.get(executable)
    if ecosystem is None:
        return
    runner = executable in _RUNNERS
    if not runner and (len(tokens) < 2 or tokens[1] not in _INSTALL_VERBS):
        return
    args = tokens[1:] if runner else tokens[2:]
    plan.packages.extend(_scan_args(args, ecosystem, executable, plan))


def _parse(command: str, plan: InstallPlan, depth: int) -> None:
    # Backslash-newline is a continuation; an unquoted newline separates commands.
    command = command.replace("\\\n", "")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        plan.incomplete = True
        return
    segment: list[str] = []
    previous: list[str] = []
    operator = ""
    for token in [*tokens, ";"]:
        if token and all(c in ";&|\n" for c in token):
            _install(segment, plan, depth)
            if operator == "|" and _is_pipe_to_shell(previous, segment):
                plan.pipe_to_shell.append(f"{_executable(previous)} ... | {_executable(segment)}")
            previous, operator, segment = segment, token, []
        else:
            segment.append(token)


_DOWNLOADERS = {"curl", "wget"}
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "perl", "ruby", "pwsh"}


def _executable(tokens: list[str]) -> str:
    stripped = _strip_prefixes(tokens)
    return stripped[0].rsplit("/", 1)[-1] if stripped else ""


def _is_pipe_to_shell(left: list[str], right: list[str]) -> bool:
    """``curl URL | sh``: a download fed straight into an interpreter, unread."""
    return _executable(left) in _DOWNLOADERS and _executable(right) in _INTERPRETERS


def parse_command(command: str) -> InstallPlan:
    plan = InstallPlan()
    if not isinstance(command, str) or len(command) > 65536:
        plan.incomplete = True
        return plan
    _parse(command, plan, 0)
    plan.packages = list(dict.fromkeys(plan.packages))
    if len(plan.packages) > 50:
        plan.packages = plan.packages[:50]
        plan.incomplete = True
    return plan
