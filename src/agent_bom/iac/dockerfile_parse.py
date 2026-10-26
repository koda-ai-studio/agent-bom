"""Dockerfile parsing into logical instructions and build stages.

Rules evaluate whole instructions, the way BuildKit reads them: an instruction
continued with the escape character (``\\`` or the ``# escape=`` directive's
character) is one instruction reported at its first line, comment lines inside
a continuation are dropped, and a ``RUN``/``COPY``/``ADD`` heredoc body belongs
to the instruction that opens it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$")
_HEREDOC_RE = re.compile(r"<<-?([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
_HEREDOC_KEYWORDS = frozenset({"RUN", "COPY", "ADD"})
_ARG_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


class Instruction(NamedTuple):
    """One logical Dockerfile instruction."""

    keyword: str
    text: str
    line: int


@dataclass
class Stage:
    """One ``FROM`` build stage and the runtime settings it ends with."""

    from_line: int
    image: str | None
    alias: str | None = None
    parent: Stage | None = None
    user: str | None = None
    user_line: int = 0
    cmd_lines: list[int] = field(default_factory=list)
    entrypoint_lines: list[int] = field(default_factory=list)

    def effective_user(self) -> tuple[str | None, int]:
        """The user a container of this stage runs as, inherited through ``FROM <stage>``."""
        stage: Stage | None = self
        while stage is not None:
            if stage.user is not None:
                return stage.user, stage.user_line
            stage = stage.parent
        return None, 0

    def base_image(self) -> str | None:
        stage: Stage | None = self
        while stage is not None and stage.parent is not None:
            stage = stage.parent
        return stage.image if stage is not None else None


def _escape_char(lines: list[str]) -> str:
    """The ``# escape=`` parser directive, read only from the leading directive block."""
    escape = "\\"
    for raw in lines:
        match = _DIRECTIVE_RE.match(raw.strip())
        if not match:
            break
        if match.group(1).lower() == "escape" and match.group(2) in ("\\", "`"):
            escape = match.group(2)
    return escape


def _is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def parse_instructions(content: str) -> list[Instruction]:
    """Split Dockerfile ``content`` into logical instructions."""
    lines = content.splitlines()
    escape = _escape_char(lines)
    instructions: list[Instruction] = []
    i, total = 0, len(lines)
    while i < total:
        if _is_blank_or_comment(lines[i]):
            i += 1
            continue
        start = i + 1
        parts: list[str] = []
        current = lines[i].strip()
        while True:
            i += 1
            if not current.endswith(escape):
                parts.append(current)
                break
            parts.append(current[:-1].rstrip())
            while i < total and _is_blank_or_comment(lines[i]):
                i += 1
            if i >= total:
                break
            current = lines[i].strip()
        text = " ".join(part for part in parts if part)
        keyword = text.split(None, 1)[0].upper()
        if keyword in _HEREDOC_KEYWORDS:
            body: list[str] = []
            for _, delimiter in _HEREDOC_RE.findall(text):
                end = next((j for j in range(i, total) if lines[j].strip() == delimiter), None)
                if end is None:
                    break  # not a heredoc after all (e.g. "<<" inside a quoted string)
                body.extend(line.strip() for line in lines[i:end])
                i = end + 1
            if body:
                text = text + "\n" + "\n".join(body)
        instructions.append(Instruction(keyword=keyword, text=text, line=start))
    return instructions


def resolve_args(value: str, args: dict[str, str]) -> str | None:
    """Substitute ``$NAME`` / ``${NAME}`` from ``args``; ``None`` when a reference has no default."""
    unresolved = False

    def _sub(match: re.Match[str]) -> str:
        nonlocal unresolved
        name = match.group(1) or match.group(2)
        if name in args and args[name]:
            return args[name]
        unresolved = True
        return ""

    resolved = _ARG_REF_RE.sub(_sub, value)
    if unresolved or "$" in resolved:
        return None
    return resolved


def parse_arg(text: str) -> tuple[str, str]:
    """``ARG NAME[=default]`` → ``(NAME, default)``."""
    body = text.split(None, 1)[1].strip() if len(text.split(None, 1)) > 1 else ""
    name, _, default = body.partition("=")
    return name.strip(), default.strip().strip("'\"")


def parse_from(text: str) -> tuple[str, str | None]:
    """``FROM [--flag=...] image [AS alias]`` → ``(image, alias)``."""
    tokens = [token for token in text.split()[1:] if not token.startswith("--")]
    image = tokens[0] if tokens else ""
    alias = tokens[2] if len(tokens) >= 3 and tokens[1].upper() == "AS" else None
    return image, alias
