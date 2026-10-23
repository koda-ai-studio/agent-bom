"""Environment secrets flowing into a network sink in skill and instruction files.

``env | curl``, ``printenv | nc host``, ``$AWS_SECRET_ACCESS_KEY`` in a request
body or URL, and ``os.environ`` posted from a Python block all ship the
caller's credentials off-host. A finding needs both halves: a secret source
(the whole environment, or a secret-named variable) and a network sink it
flows into. A sink alone, a source alone, and a credential sent as an
authentication header to the API it belongs to are not findings.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agent_bom.ast.source_reader import parse_python_source
from agent_bom.parsers.skill_audit_code import _PYTHON_FENCED_BLOCK_RE, _call_name, _line_column
from agent_bom.parsers.skill_audit_context import _is_prohibition_context
from agent_bom.parsers.skill_audit_types import SkillFinding
from agent_bom.runtime.text_normalize import reveal_hidden_text

_SINK_WORDS = r"curl|wget|nc|ncat|netcat|socat|telnet|Invoke-WebRequest|Invoke-RestMethod"
_SINK_START_RE = re.compile(rf"^\s*(?:sudo\s+)?(?:{_SINK_WORDS})(?![\w-])|^\s*(?:cat|tee)\s+>\s*/dev/(?:tcp|udp)/", re.IGNORECASE)
_SINK_RE = re.compile(
    rf"(?:^|(?<=[\s(]))(?:{_SINK_WORDS})(?![\w-])|/dev/(?:tcp|udp)/"
    r"|\b(?:fetch|requests\.(?:post|put|patch|get)|httpx\.(?:post|put|patch|get)|axios\.(?:post|put|patch|get)|sendBeacon)\s*\(",
    re.IGNORECASE,
)
_ENV_COMMAND_RE = re.compile(r"(?:^|\s)(?:env|printenv|export\s+-p)\s*$|/proc/(?:self|\d+|\$\$)/environ")
_ENV_SUBSTITUTION_RE = re.compile(r"\$\(\s*(?:env|printenv|export\s+-p|cat\s+/proc/\S+/environ)\s*\)")
_WHOLE_ENV_CODE_RE = re.compile(r"\bos\.environ\b(?!\s*(?:\[|\.get\b))|\bprocess\.env\b(?!\s*(?:\[|\.\w))")
_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|\bprocess\.env\.([A-Za-z_]\w*)")
_SECRET_PARTS = frozenset(
    {"KEY", "KEYS", "APIKEY", "SECRET", "SECRETS", "TOKEN", "TOKENS", "PASSWORD", "PASSWD", "PASS", "CREDENTIAL", "CREDENTIALS"}
    | {"CREDS", "PAT", "AUTH", "COOKIE", "SESSION", "PRIVATE"}
)
_AUTH_HEADER_PREFIX_RE = re.compile(
    r"""(?ix)
    (?: (?:-H|--header) \s+ ["']? [\w-]+ : \s* (?:bearer|token|basic)? \s*
      | authorization ["']? \s* [:=] \s* f? ["']? \s* (?:bearer|token|basic)? \s*
      | (?:-u|--user) \s+ ["']? [^\s:]* :
    ) \$? \{? $
    """
)
_COMMAND_BREAK_RE = re.compile(r"`|;|&&|\|\|")
_NETWORK_CALL_PREFIXES = ("requests.", "httpx.", "aiohttp.", "urllib.request.", "http.client.")
_NETWORK_CALL_ATTRS = frozenset({"post", "patch", "urlopen", "sendall", "sendto", "Request"})
_CREDENTIAL_KEYWORDS = frozenset({"headers", "auth", "cookies"})

_TITLE = "Environment secrets sent to a network destination"
_RECOMMENDATION = (
    "Remove the instruction. Never send environment variables or credentials to a third-party endpoint; "
    "pass a credential only as an authentication header to the service that issued it."
)


def is_secret_name(name: str) -> bool:
    upper = name.upper()
    return bool(_SECRET_PARTS & set(upper.split("_"))) or upper.endswith(("KEY", "TOKEN", "SECRET", "PASSWORD"))


def _pieces(line: str, offset: int) -> Iterator[tuple[str, int]]:
    """Split a line into commands at ``;``, ``&&``, ``||`` and backticks."""
    start = 0
    for brk in _COMMAND_BREAK_RE.finditer(line):
        yield line[start : brk.start()], offset + start
        start = brk.end()
    yield line[start:], offset + start


def _secret_after(segment: str, position: int) -> re.Match | None:
    """A secret source after ``position`` that is not an auth-header value."""
    whole = _ENV_SUBSTITUTION_RE.search(segment, position) or _WHOLE_ENV_CODE_RE.search(segment, position)
    if whole:
        return whole
    variables = (match for match in _VAR_RE.finditer(segment, position) if is_secret_name(match.group(1) or match.group(2)))
    return next((match for match in variables if not _AUTH_HEADER_PREFIX_RE.search(segment[: match.start()])), None)


def _segment_is_source(segment: str) -> bool:
    command = segment.rsplit("(", 1)[-1]
    if _ENV_COMMAND_RE.search(command):
        return True
    return any(is_secret_name(m.group(1) or m.group(2)) for m in _VAR_RE.finditer(command))


def _command_flows(piece: str) -> tuple[int, int] | None:
    """Return the (start, end) span of a source-to-sink flow inside one command."""
    segments = piece.split("|")
    cursor = 0
    bounds = []
    for segment in segments:
        bounds.append((cursor, cursor + len(segment)))
        cursor += len(segment) + 1
    for index, segment in enumerate(segments[:-1]):
        if _segment_is_source(segment) and any(_SINK_START_RE.match(later) for later in segments[index + 1 :]):
            return bounds[index][0], len(piece)
    for (start, _end), segment in zip(bounds, segments):
        sink = _SINK_RE.search(segment)
        source = _secret_after(segment, sink.end()) if sink else None
        if sink and source:
            return start + sink.start(), start + source.end()
    return None


def _logical_lines(content: str) -> Iterator[tuple[str, int]]:
    """Yield ``(line, offset)`` with backslash continuations joined."""
    offset = 0
    pending: list[str] = []
    pending_start = 0
    for raw in content.split("\n"):
        if not pending:
            pending_start = offset
        offset += len(raw) + 1
        if raw.endswith("\\"):
            pending.append(raw[:-1] + " ")
            continue
        yield "".join(pending) + raw, pending_start
        pending = []
    if pending:
        yield "".join(pending), pending_start


def _shell_flows(content: str) -> Iterator[tuple[int, int]]:
    for line, line_offset in _logical_lines(content):
        if line.lstrip().startswith("|"):
            continue
        for piece, piece_offset in _pieces(line, line_offset):
            span = _command_flows(piece)
            if span is not None:
                yield piece_offset + span[0], piece_offset + span[1]


def _secret_key(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and is_secret_name(node.value)


def _env_sources(node: ast.AST, tainted: set[str]) -> bool:
    """True when an expression reads the whole environment, a secret variable, or a tainted name."""
    children = list(ast.walk(node))
    keyed = {id(child.value) for child in children if isinstance(child, ast.Subscript)}
    keyed |= {id(child.value) for child in children if isinstance(child, ast.Attribute) and child.attr == "get"}
    for child in children:
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
        if isinstance(child, ast.Subscript) and _call_name(child.value) == "os.environ" and _secret_key(child.slice):
            return True
        if isinstance(child, ast.Call) and _call_name(child.func) in {"os.getenv", "os.environ.get"}:
            if _secret_key(child.args[0] if child.args else None):
                return True
        if isinstance(child, ast.Attribute) and _call_name(child) == "os.environ" and id(child) not in keyed:
            return True
    return False


def _tainted_names(tree: ast.AST) -> set[str]:
    tainted: set[str] = set()
    assigns = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    for _ in range(3):
        for node in assigns:
            if _env_sources(node.value, tainted):
                tainted |= {target.id for target in node.targets if isinstance(target, ast.Name)}
    return tainted


def _is_network_call(call: ast.Call) -> bool:
    name = _call_name(call.func)
    return name.startswith(_NETWORK_CALL_PREFIXES) or name.rsplit(".", 1)[-1] in _NETWORK_CALL_ATTRS


def _python_flows(content: str) -> Iterator[int]:
    """Yield file line numbers of network calls that carry environment secrets."""
    for block_match in _PYTHON_FENCED_BLOCK_RE.finditer(content):
        try:
            tree = parse_python_source(block_match.group(1))
        except SyntaxError:
            continue
        if "environ" not in block_match.group(1) and "getenv" not in block_match.group(1):
            continue
        tainted = _tainted_names(tree)
        block_line, _column = _line_column(content, block_match.start(1))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call) and _is_network_call(node)):
            payload = [*call.args, *(kw.value for kw in call.keywords if kw.arg not in _CREDENTIAL_KEYWORDS)]
            if any(_env_sources(arg, tainted) for arg in payload):
                yield block_line + call.lineno - 1


def _finding(filename: str, line: int, snippet: str, evidence_source: str, demoted: bool) -> SkillFinding:
    where = filename if evidence_source == "static_text" else f"{filename} after revealing hidden Unicode text"
    detail = f'Detected in {where}: "{snippet}". A secret from the environment flows into a network request.'
    if demoted:
        detail += " Reported at reduced severity: the surrounding prose reads as policy or documentation. Confirm before dismissing."
    return SkillFinding(
        severity="low" if demoted else "high",
        category="credential_exfiltration",
        title=_TITLE,
        detail=detail,
        source_file=filename,
        recommendation=_RECOMMENDATION,
        context="possibly_documentation" if demoted else "behavioral",
        evidence_source=evidence_source,
        confidence="low" if demoted else "high",
        source_line=line,
        source_column=1,
    )


def _scan_text(filename: str, content: str, evidence_source: str) -> SkillFinding | None:
    demoted: SkillFinding | None = None
    for start, end in _shell_flows(content):
        line, _column = _line_column(content, start)
        snippet = content[start:end].strip()
        snippet = snippet if len(snippet) <= 120 else snippet[:117] + "..."
        if not _is_prohibition_context(content, start, end):
            return _finding(filename, line, snippet, evidence_source, False)
        demoted = demoted or _finding(filename, line, snippet, evidence_source, True)
    for line in _python_flows(content):
        return _finding(filename, line, content.split("\n")[line - 1].strip()[:120], evidence_source, False)
    return demoted


def scan_env_exfiltration(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Report the first environment-to-network flow in each file."""
    findings: list[SkillFinding] = []
    for filename, content in raw_content.items():
        finding = _scan_text(filename, content, "static_text")
        revealed = reveal_hidden_text(content)
        if (finding is None or finding.context == "possibly_documentation") and revealed != content:
            finding = _scan_text(filename, revealed, "normalized_text") or finding
        if finding is not None:
            findings.append(finding)
    return findings
