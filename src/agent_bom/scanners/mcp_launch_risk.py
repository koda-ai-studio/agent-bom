"""Static checks over a configured MCP launch recipe and its environment.

The recipe is text to read, never to run: nothing here starts a process, opens a
connection or touches the filesystem. Each check is a heuristic over the
configuration, so findings describe what the recipe would do when launched, not
that it has been launched. No function returns or stores a secret value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_bom.enforcement import EnforcementFinding
from agent_bom.security import env_key_is_credential

if TYPE_CHECKING:
    from agent_bom.models import MCPServer

_MAX_INSPECTED_CHARS = 16_384

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "cmd", "powershell", "pwsh"})
_LANGUAGE_RUNTIMES = frozenset({"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"})
_WRAPPERS = frozenset({"env", "sudo", "doas", "nohup", "nice", "time", "exec", "command", "stdbuf", "busybox", "caffeinate", "timeout"})

_INLINE_SHELL_FLAG_RE = re.compile(r"^(?:-[a-zA-Z]*c[a-zA-Z]*|/c|/k|-command)$", re.IGNORECASE)
_ENCODED_COMMAND_FLAG_RE = re.compile(r"^-(?:e|ec|enc|encoded|encodedcommand)$", re.IGNORECASE)
_INLINE_CODE_FLAG_RE = re.compile(r"^(?:-[a-zA-Z]*[ceE]|-r|--eval|--exec|--print|-p)$")
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_]\w*=")

_FETCHER = r"(?<![\w-])(?:curl|wget|fetch|aria2c|iwr|irm|invoke-webrequest|invoke-restmethod)(?:\.exe)?(?![\w-])"
_INTERPRETER = (
    r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:[\w./\\-]*[/\\])?"
    r"(?:sh|bash|zsh|dash|ksh|ash|fish|python[\d.]*|perl|ruby|node|deno|bun|php|pwsh|powershell|iex|invoke-expression)(?:\.exe)?"
)
# ``| sh`` reads stdin as a program; ``| python -m json.tool`` runs another program on stdin as data.
_INTERPRETER_READS_STDIN = rf"{_INTERPRETER}(?:\s+-s\b|(?:\s+-(?!c\b|e\b|m\b)[\w-]*)*\s*(?:$|[;&|)'\"]))"
_SEGMENT = r"[^|;&\n]{0,2048}"

_FETCH_PIPED_RE = re.compile(rf"{_FETCHER}{_SEGMENT}(?:\|(?!\|){_SEGMENT}){{0,4}}?\|(?!\|)\s*{_INTERPRETER_READS_STDIN}", re.IGNORECASE)
_DECODE_PIPED_RE = re.compile(
    rf"(?:base64\s+(?:-d|-D|--decode)|openssl\s+(?:enc\s+)?(?:-d|base64\s+-d)){_SEGMENT}(?:\|(?!\|){_SEGMENT}){{0,4}}?\|(?!\|)\s*{_INTERPRETER_READS_STDIN}",
    re.IGNORECASE,
)
_SUBSTITUTED_FETCH_RE = re.compile(
    rf"(?:(?:^|[;&|]\s*)[\"']?\$\(\s*{_FETCHER}"
    rf"|<\(\s*{_FETCHER}"
    rf"|(?<![\w-])(?:eval|exec|source|\.|sh|bash|zsh|dash|ksh|python[\d.]*|perl|ruby|node|php)\s+(?:-\w+\s+)*[\"']?(?:\$\(|`)\s*{_FETCHER})",
    re.IGNORECASE,
)
_POWERSHELL_FETCH_EVAL_RE = re.compile(
    r"(?<![\w-])(?:iex|invoke-expression)\b.{0,2048}?(?:downloadstring|downloadfile|webclient|iwr|irm|invoke-webrequest|invoke-restmethod)",
    re.IGNORECASE,
)
_SAVED_TO_RE = re.compile(r"(?:\s-[a-zA-Z]*[oO]\s*|\s--output[= ]\s*|\s--output-document[= ]\s*|>\s*)([^\s;&|'\"]+)")
_REMOTE_NAME_RE = re.compile(r"(?:^|\s)-[a-zA-Z]*O\b|--remote-name|^wget\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"|;&]+", re.IGNORECASE)
_RUN_WORD_RE = re.compile(r"(?<![\w-])(?:sh|bash|zsh|dash|ksh|python[\d.]*|node|perl|ruby|php|source|chmod|\.)(?![\w-])")
_STATEMENT_SPLIT_RE = re.compile(r"&&|;|\n")

_INLINE_EVAL_RE = re.compile(r"(?<![\w.])(?:exec|compile|Function|system|popen|spawn|execSync)\b|\beval\b")
_INLINE_NETWORK_RE = re.compile(
    r"https?://|urlopen|urllib|requests\.get|httpx\.get|\bfetch\s*\(|https?\.get|Net::HTTP|LWP::|open-uri|file_get_contents|(?<![\w-])(?:curl|wget)(?![\w-])"
)
_INLINE_DECODE_EVAL_RE = re.compile(r"(?:exec|eval)\s*\(.{0,512}(?:b64decode|atob|base64)", re.IGNORECASE)

_REMOTE_SOURCE_RE = re.compile(r"^(?:https?://|git\+|git://|git@|github:|gitlab:|bitbucket:)", re.IGNORECASE)
_PINNED_SOURCE_RE = re.compile(r"(?:[@#][0-9a-f]{40}\b|#sha(?:256|384|512)[=-][0-9a-f]{32,})", re.IGNORECASE)
_SOURCE_OPTIONS = frozenset({"--from", "--with", "--spec", "--package", "-p"})
_DIRECT_RUNNERS = frozenset({"npx", "bunx", "uvx", "pipx"})

_FILESYSTEM_NAME_RE = re.compile(r"(?i)file[-_]?system|mcp[-_]fs\b|\bfs[-_]mcp")
_ROOT_VALUE = r"(?:/+\.?\*?|[A-Za-z]:[\\/]*\*?|\\\\?|file:///?)"
_ROOT_ARGUMENT_RE = re.compile(rf"^(?:--?[\w-]+=)?(?:[^,=]*,)*{_ROOT_VALUE}(?:,.*)?$")
_ROOT_VOLUME_RE = re.compile(rf"^(?:--?[\w-]+=)?{_ROOT_VALUE}:[^:]")
_ROOT_MOUNT_RE = re.compile(r"(?:^|,)(?:source|src)=/+(?:,|$)")

_ENV_REFERENCE_RE = re.compile(
    r"^(?:\$\{?[A-Za-z_]\w*\}?|\$\(.*\)|%[A-Za-z_]\w*%|\{\{.*\}\}|<[^>]*>"
    r"|(?:op://|vault:|sops:|secretref:|keyring:|azure-keyvault://|arn:aws:(?:secretsmanager|ssm):).*|env:[A-Za-z_]\w*)$",
    re.IGNORECASE,
)
_NON_SECRET_LITERAL_RE = re.compile(r"^(?:\d+(?:\.\d+)?|true|false|yes|no|on|off|none|null)$", re.IGNORECASE)
_MIN_CREDENTIAL_LITERAL_CHARS = 8
_CREDENTIAL_NAMED = "credential-named variable"


@dataclass(frozen=True)
class RemoteCodeLaunch:
    """How a launch recipe would obtain and run code it does not pin."""

    technique: str
    severity: str
    launcher: str


def _base_name(token: str) -> str:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _unwrapped(tokens: list[str]) -> list[str]:
    """Drop ``env``, ``sudo`` and similar prefixes, with their flags and assignments."""
    remaining = list(tokens)
    while remaining and _base_name(remaining[0]) in _WRAPPERS:
        remaining = remaining[1:]
        while remaining and (remaining[0].startswith("-") or _ENV_ASSIGNMENT_RE.match(remaining[0]) or remaining[0].isdigit()):
            remaining = remaining[1:]
    return remaining


def _download_then_run(text: str) -> bool:
    """A statement saves a download and a later statement runs that same file."""
    statements = [statement.strip() for statement in _STATEMENT_SPLIT_RE.split(text)]
    for index, statement in enumerate(statements):
        if not re.search(_FETCHER, statement, re.IGNORECASE):
            continue
        saved = {match.group(1) for match in _SAVED_TO_RE.finditer(statement)}
        if _REMOTE_NAME_RE.search(statement):
            saved |= {url.group(0).rstrip("/").rsplit("/", 1)[-1] for url in _URL_RE.finditer(statement)}
        saved -= {"", "/dev/null", "NUL", "-"}
        for later in statements[index + 1 :]:
            if any(path in later for path in saved) and (
                _RUN_WORD_RE.search(later) or any(re.match(rf"(?:\./)?{re.escape(path)}(?:\s|$)", later) for path in saved)
            ):
                return True
    return False


def _shell_technique(text: str) -> str | None:
    if _FETCH_PIPED_RE.search(text):
        return "download_piped_to_interpreter"
    if _SUBSTITUTED_FETCH_RE.search(text) or _POWERSHELL_FETCH_EVAL_RE.search(text):
        return "download_evaluated_inline"
    if _download_then_run(text):
        return "download_then_run"
    if _DECODE_PIPED_RE.search(text):
        return "decoded_payload_piped_to_interpreter"
    return None


def _inline_code_technique(code: str) -> str | None:
    if _INLINE_DECODE_EVAL_RE.search(code):
        return "decoded_payload_evaluated_inline"
    if _INLINE_EVAL_RE.search(code) and _INLINE_NETWORK_RE.search(code):
        return "download_evaluated_inline"
    return _shell_technique(code)


def _direct_runner_technique(runner: str, args: list[str]) -> str | None:
    """A package runner handed a remote source rather than a registry package."""
    if runner in {"deno", "bun"}:
        candidates = [arg for arg in args if not arg.startswith("-")]
        if not candidates or candidates[0] not in {"run", "x"}:
            return None
    elif runner not in _DIRECT_RUNNERS:
        return None
    for arg in args:
        option, separator, value = arg.partition("=")
        source = value if separator and option in _SOURCE_OPTIONS else arg
        if _REMOTE_SOURCE_RE.match(source) and not _PINNED_SOURCE_RE.search(source):
            return "unpinned_remote_source"
    return None


def remote_code_launch(command: str, args: list[str]) -> RemoteCodeLaunch | None:
    """Return how this recipe would fetch and run remote code, if it would."""
    tokens = _unwrapped([str(command or ""), *(str(arg) for arg in args or [])])
    if not tokens or not tokens[0]:
        return None
    if any(char.isspace() for char in tokens[0]):
        technique = _shell_technique(" ".join(tokens)[:_MAX_INSPECTED_CHARS])
        return RemoteCodeLaunch(technique, "critical", "command string") if technique else None

    launcher = _base_name(tokens[0])
    rest = tokens[1:]
    if launcher in _SHELLS:
        if launcher in {"powershell", "pwsh"} and any(_ENCODED_COMMAND_FLAG_RE.match(arg) for arg in rest):
            return RemoteCodeLaunch("encoded_command", "critical", launcher)
        flag_at = next((index for index, arg in enumerate(rest) if _INLINE_SHELL_FLAG_RE.match(arg)), None)
        # ``bash <(curl ...)`` carries the substitution as a plain argument.
        text = " ".join(rest[flag_at + 1 :] if flag_at is not None else [arg for arg in rest if arg.startswith(("<(", "$("))])
        technique = _shell_technique(text[:_MAX_INSPECTED_CHARS])
        return RemoteCodeLaunch(technique, "critical", launcher) if technique else None

    if launcher.rstrip("0123456789.") in _LANGUAGE_RUNTIMES:
        flag_at = next((index for index, arg in enumerate(rest) if _INLINE_CODE_FLAG_RE.match(arg)), None)
        if flag_at is not None:
            technique = _inline_code_technique(" ".join(rest[flag_at + 1 :])[:_MAX_INSPECTED_CHARS])
            if technique:
                return RemoteCodeLaunch(technique, "critical", launcher)

    technique = _direct_runner_technique(launcher, rest)
    return RemoteCodeLaunch(technique, "high", launcher) if technique else None


def filesystem_root_argument(name: str, command: str, args: list[str]) -> str | None:
    """Return the host-root path a filesystem server is pointed at, if any."""
    tokens = [str(arg) for arg in args or []]
    if not any(_FILESYSTEM_NAME_RE.search(text) for text in (name or "", command or "", *tokens)):
        return None
    for token in tokens:
        if _ROOT_ARGUMENT_RE.match(token) or _ROOT_VOLUME_RE.match(token) or _ROOT_MOUNT_RE.search(token):
            return _root_label(token)
    return None


def _root_label(token: str) -> str:
    match = re.search(r"[A-Za-z]:[\\/]*", token)
    return match.group(0) if match and "=" not in token else "/"


def plaintext_env_secrets(raw_env: Any) -> dict[str, str]:
    """Map env names holding a literal secret to the format found; values never leave."""
    from agent_bom.scanners.secret_lines import is_placeholder_value, is_sample_value, match_credential

    if not isinstance(raw_env, dict):
        return {}
    found: dict[str, str] = {}
    for key, value in raw_env.items():
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or _ENV_REFERENCE_RE.match(text):
            continue
        # Some formats are only recognizable beside their key, so judge the pair too.
        credential = match_credential(text) or match_credential(f"{key}={text}")
        if credential is not None:
            if not is_sample_value(credential[1]):
                found[str(key)] = credential[0]
            continue
        if is_placeholder_value(text) or _NON_SECRET_LITERAL_RE.match(text) or len(text) < _MIN_CREDENTIAL_LITERAL_CHARS:
            continue
        if env_key_is_credential(str(key)):
            found[str(key)] = _CREDENTIAL_NAMED
    return found


def _server_finding(
    server: MCPServer, *, severity: str, category: str, reason: str, recommendation: str, evidence: dict[str, Any]
) -> EnforcementFinding:
    return EnforcementFinding(
        severity=severity,
        category=category,
        server_name=server.name,
        surface_type="mcp_server",
        surface_name=server.name,
        reason=reason,
        recommendation=recommendation,
        evidence={"basis": "configuration", "asset_identifier": server.canonical_id, **evidence},
    )


def launch_recipe_findings(server: MCPServer) -> list[EnforcementFinding]:
    """Findings from what the configuration says, without running any of it."""
    findings: list[EnforcementFinding] = []
    launch = remote_code_launch(server.command, server.args)
    if launch is not None:
        findings.append(
            _server_finding(
                server,
                severity=launch.severity,
                category="remote_code_launcher",
                reason=(
                    f"Launching MCP server {server.name!r} would fetch or decode code and run it through {launch.launcher} "
                    f"({launch.technique.replace('_', ' ')}). The code that runs is decided outside this configuration."
                ),
                recommendation="Install a pinned package from a registry, or a verified local build, and launch that directly.",
                evidence={"technique": launch.technique, "launcher": launch.launcher, "owasp_mcp_tags": ["MCP04", "MCP05"]},
            )
        )
    if server.plaintext_env_secrets:
        named_format = any(kind != _CREDENTIAL_NAMED for kind in server.plaintext_env_secrets.values())
        names = sorted(server.plaintext_env_secrets)
        findings.append(
            _server_finding(
                server,
                severity="critical" if named_format else "high",
                category="plaintext_secret",
                reason=f"MCP server {server.name!r} holds a literal secret value in its configured environment: {', '.join(names)}.",
                recommendation="Rotate the value, then reference it from a secret store or an environment variable set outside the config.",
                evidence={
                    "plaintext_env_refs": names,
                    "detected_formats": sorted(set(server.plaintext_env_secrets.values())),
                    "owasp_mcp_tags": ["MCP01"],
                },
            )
        )
    root = filesystem_root_argument(server.name, server.command, server.args)
    if root is not None:
        findings.append(
            _server_finding(
                server,
                severity="high",
                category="unscoped_filesystem",
                reason=f"Filesystem MCP server {server.name!r} is rooted at {root}, which exposes the whole host to every tool call.",
                recommendation="Point the server at the specific project or data directories it needs.",
                evidence={"root_kind": "host_root", "owasp_mcp_tags": ["MCP02"]},
            )
        )
    return findings
