"""Line-level secret matching shared by the file scanner and text surfaces.

``agent_bom.secret_scanner`` walks a project and scans each file. Instruction
files (skills, ``CLAUDE.md``, ``AGENTS.md``) reach the skill audit as text, not
as a tree. Both go through the matchers here, so a credential format the file
scanner learns is detected in instruction text too, with the same placeholder
handling. No matcher returns or stores the secret value.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from agent_bom.runtime.patterns import CODE_CALL_ASSIGNMENT, CREDENTIAL_PATTERNS

# Additional patterns specific to file scanning (not in runtime patterns)
FILE_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hardcoded password", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
    ("Hardcoded secret", re.compile(r'(?:secret|secret_key)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
    (
        ".env password",
        re.compile(r"^(?:DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|MYSQL_PASSWORD)\s*=\s*\S+", re.MULTILINE | re.IGNORECASE),
    ),
    (".env token", re.compile(r"^(?:AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|SESSION_SECRET)\s*=\s*\S+", re.MULTILINE | re.IGNORECASE)),
]

# Obvious non-secrets to skip even when assigned to a secret-named key.
ENTROPY_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:your[-_][a-z0-9_.-]+|x{3,}|placeholder(?:[-_][a-z0-9_.-]+)?|"
    r"example(?:[-_][a-z0-9_.-]+)?|changeme(?:[-_]?\d*)?|none|null|true|false|"
    r"enabled|disabled|\$\{[^}]*\}|\{\{[^}]*\}\}|<[a-z][^>]*>|/[a-z][^\s]*|"
    r"https?://[^\s]+)$"
)
ASSIGNED_VALUE_RE = re.compile(r"[=:]\s*['\"]?([^'\"\s,;#]+)")
# The credential body of an assignment or header; skips a ``Bearer`` scheme
# so ``Authorization: Bearer your-token-here`` judges the token, not "Bearer".
_CREDENTIAL_BODY_RE = re.compile(r"(?i)[=:]\s*['\"]?(?:bearer[ \t]+)?([^'\"\s,;#]+)")
# Template fillers a real credential never is. Each alternative must cover the
# whole value, so a random key that happens to contain "your" still reports.
_FILLER_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:"
    r"(?:insert|enter|add|put|paste|set)?[-_]?(?:replace[-_]?(?:with|me)|your)[-_][a-z0-9_.-]*"
    r"|[a-z0-9_.-]*[-_]here"
    r"|(?:dummy|sample|fake)(?:[-_][a-z0-9_.-]+)?"
    r"|(?:changeme|replaceme)(?:[-_.]?(?:changeme|replaceme))*(?:[-_.]?\d+)?"
    r"|x{3,}[a-z0-9_.-]*"
    r"|(.)\1{7,}"
    r"|\*{3,}|\.{3,}|<[^>]+>"
    r")$"
)


# A value the renderer fills in later: a Go/Jinja/Helm ``{{ ... }}`` action, a
# shell/Terraform ``${...}`` or ``$VAR`` reference, or a Python/Rust ``{name}``
# field. Each alternative is bounded and has one way to match.
_TEMPLATE_EXPR_RE = re.compile(
    r"^(?:\{\{[^{}]{0,400}\}\}|\$\{[^{}]{0,200}\}|\$[A-Za-z_][A-Za-z0-9_]{0,120}|\{[A-Za-z0-9_]{0,64}\})$",
)
# printf-family verbs (Go ``%v`` ``%q``, C ``%s`` ``%d``, Python ``%(name)s``).
_FORMAT_VERB = r"%[-+ #0]{0,2}\d{0,3}(?:\.\d{1,3})?[vsdqxXtTfgbo]|%\([A-Za-z_][A-Za-z0-9_]{0,63}\)[sdr]"
# A value made only of format verbs and URL/DSN punctuation (``%v:%v@%v``). Each
# alternative starts with a distinct character, so the repeat is linear.
_FORMAT_ONLY_RE = re.compile(rf"^(?:{_FORMAT_VERB}|\{{[A-Za-z0-9_]{{0,64}}\}}|[:@/?&=.,;-])+$")
# The literal word that names the key (``password = "password"``, ``token: token``).
_KEY_NAME_LITERAL_RE = re.compile(
    r"(?i)^(?:password|passwd|pwd|secret|secret[_-]?key|token|api[_-]?key|apikey|"
    r"access[_-]?(?:token|key)|auth[_-]?token|client[_-]?secret|credentials?|private[_-]?key)$"
)


def is_template_expression(value: str) -> bool:
    """Whether a value is rendered or formatted later rather than held literally."""
    if _TEMPLATE_EXPR_RE.fullmatch(value):
        return True
    return ("%" in value or "{" in value) and bool(_FORMAT_ONLY_RE.fullmatch(value))


def is_placeholder_value(value: str) -> bool:
    """Whether an assigned credential value is an obvious template placeholder."""
    return bool(
        ENTROPY_PLACEHOLDER_RE.fullmatch(value)
        or _FILLER_PLACEHOLDER_RE.fullmatch(value)
        or _KEY_NAME_LITERAL_RE.fullmatch(value)
        or is_template_expression(value)
    )


# ``key: "{{ default .Env.X "" }}"`` — the template action may hold spaces and
# quotes, so it is judged from the key to the line's closing delimiter rather
# than as the first whitespace-free token.
_TEMPLATE_OPEN_RE = re.compile(r"^[^=:]{0,64}[=:]\s*(?:bearer[ \t]+)?['\"]?(\{\{|\$\{)", re.IGNORECASE)
_DSN_USERINFO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+]{0,24}://([^:@\s/]{1,200}):([^@\s/]{1,200})@")


def _assignment_opens_template(tail: str) -> bool:
    opened = _TEMPLATE_OPEN_RE.match(tail)
    if not opened:
        return False
    closer = "}}" if opened.group(1) == "{{" else "}"
    return closer in tail[opened.end() :]


def _dsn_password_is_placeholder(matched: str) -> bool:
    userinfo = _DSN_USERINFO_RE.match(matched)
    return bool(userinfo and is_placeholder_value(userinfo.group(2)))


# Markers that make a credential-shaped value a documentation sample: vendor
# sample values carry EXAMPLE, and docs pad or elide the body (xxxx, ****, ...).
_SAMPLE_MARKER_RE = re.compile(
    r"(?i)example|x{4,}|\*{4,}|\.{3}|<[^>]*>|\byour[-_]|placeholder|redacted|dummy|changeme|replace[-_]?me|0{12,}",
)


class TextSecret(NamedTuple):
    """A secret found in text: its type and line, never its value."""

    line_number: int
    secret_type: str
    severity: str
    sample: bool


def matched_assignment_is_placeholder(match: re.Match, line: str | None = None) -> bool:
    """Return whether a secret-pattern match is an explicit sample or template value.

    ``line`` lets a template action that holds spaces (``{{ default .X "" }}``)
    be judged up to its closing delimiter, which lies past the match itself.
    """
    matched = match.group(0)
    if matched == "AKIAIOSFODNN7EXAMPLE":
        return True
    if _assignment_opens_template(line[match.start() :] if line is not None else matched):
        return True
    if _dsn_password_is_placeholder(matched):
        return True
    assigned = _CREDENTIAL_BODY_RE.search(matched)
    return bool(assigned and is_placeholder_value(assigned.group(1)))


def is_comment_line(line: str) -> bool:
    return line.strip().startswith(("#", "//", "/*", "*"))


def match_credential(line: str) -> tuple[str, re.Match] | None:
    """Return the first credential pattern a line holds as a literal.

    A secret-named variable assigned to a function/method call (e.g. OAuth
    token minting: ``access_token = self.signing_key.sign(claims)``) is derived
    code, not a hardcoded literal. A real literal passed as a call argument
    (``k = load("AKIA...")``) still matches on the literal itself, whose match
    is not call-shaped, so it is preserved.
    """
    for name, pattern in CREDENTIAL_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        if matched_assignment_is_placeholder(match, line):
            return None
        if line[match.end() :].lstrip().startswith("(") and CODE_CALL_ASSIGNMENT.search(line):
            return None
        return name, match
    return None


def match_file_secret(line: str) -> tuple[str, re.Match] | None:
    """Return the first file-specific secret pattern that is not a placeholder."""
    for name, pattern in FILE_SECRET_PATTERNS:
        match = pattern.search(line)
        if match and not matched_assignment_is_placeholder(match, line):
            return name, match
    return None


def is_sample_value(match: re.Match) -> bool:
    """A credential-shaped match whose value carries a documentation marker."""
    assigned = ASSIGNED_VALUE_RE.search(match.group(0))
    return bool(_SAMPLE_MARKER_RE.search(assigned.group(1) if assigned else match.group(0)))


def scan_text(content: str) -> Iterator[TextSecret]:
    """Yield at most one secret per line: a credential, else a file secret."""
    for line_number, line in enumerate(content.split("\n"), 1):
        if is_comment_line(line):
            continue
        credential = match_credential(line)
        if credential is not None:
            yield TextSecret(line_number, credential[0], "critical", is_sample_value(credential[1]))
            continue
        file_secret = match_file_secret(line)
        if file_secret is not None:
            yield TextSecret(line_number, file_secret[0], "high", is_sample_value(file_secret[1]))
