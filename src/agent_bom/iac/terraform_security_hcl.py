"""Depth-aware attribute and nested-block lookups over comment-stripped HCL bodies.

The AWS rules match attributes with ad-hoc regexes; the Azure and GCP rules
share these helpers so a nested ``enabled = false`` (say, inside a
``retention_policy`` block) is never mistaken for the resource's own flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource, extract_block, line_number

_ATTR_LINE_RE = re.compile(r'^[ \t]*"?([A-Za-z_][A-Za-z0-9_-]*)"?[ \t]*=[ \t]*(?!\{)(.*?)[ \t]*$')
_HEREDOC_RE = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
_QUOTED_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
_LIST_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_PORT_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")


@dataclass(frozen=True)
class Attr:
    """One top-level ``name = value`` assignment inside a block body."""

    name: str
    raw: str
    offset: int

    @property
    def string(self) -> str | None:
        """The literal when the value is a plain quoted string, else ``None``."""
        m = _QUOTED_RE.match(self.raw)
        return m.group(1) if m else None

    @property
    def boolean(self) -> bool | None:
        lowered = self.raw.strip().lower()
        return {"true": True, "false": False}.get(lowered)

    @property
    def strings(self) -> list[str] | None:
        """Quoted items of a list literal, else ``None``."""
        if not self.raw.startswith("["):
            return None
        return _LIST_ITEM_RE.findall(self.raw)


def _depth_delta(line: str) -> int:
    return line.count("{") - line.count("}") + line.count("[") - line.count("]")


def _split_statements(block: str) -> str:
    """Turn ``;`` separators outside quotes into newlines, keeping every offset stable."""
    if ";" not in block:
        return block
    out: list[str] = []
    in_string = False
    escaped = False
    for ch in block:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ";":
            ch = "\n"
        out.append(ch)
    return "".join(out)


def top_level_attrs(block: str) -> dict[str, Attr]:
    """Attributes assigned directly in ``block`` (nested blocks are skipped)."""
    attrs: dict[str, Attr] = {}
    depth = 0
    offset = 0
    heredoc: str | None = None
    pending: tuple[str, int, list[str]] | None = None
    for line in _split_statements(block).splitlines(keepends=True):
        stripped = line.strip()
        if heredoc is not None:
            if stripped == heredoc:
                heredoc = None
        elif pending is not None:
            pending[2].append(stripped)
            if _depth_delta(stripped) + depth <= 0:
                name, start, parts = pending
                attrs.setdefault(name, Attr(name, " ".join(parts), start))
                pending = None
                depth = 0
            else:
                depth += _depth_delta(stripped)
        elif depth == 0 and (m := _ATTR_LINE_RE.match(line)) is not None:
            name, raw = m.group(1), m.group(2)
            start = offset + m.start(1)
            if (h := _HEREDOC_RE.search(raw)) is not None:
                heredoc = h.group(1)
                attrs.setdefault(name, Attr(name, raw, start))
            elif raw.startswith("[") and _depth_delta(raw) > 0:
                pending = (name, start, [raw])
                depth = _depth_delta(raw)
            else:
                attrs.setdefault(name, Attr(name, raw, start))
        else:
            depth = max(0, depth + _depth_delta(line))
        offset += len(line)
    return attrs


def attr(block: str, name: str) -> Attr | None:
    return top_level_attrs(block).get(name)


def attr_string(block: str, name: str) -> str | None:
    found = attr(block, name)
    return found.string if found is not None else None


def attr_bool(block: str, name: str) -> bool | None:
    found = attr(block, name)
    return found.boolean if found is not None else None


def attr_strings(block: str, name: str) -> list[str] | None:
    found = attr(block, name)
    return found.strings if found is not None else None


def nested_blocks(block: str, name: str) -> list[tuple[int, str]]:
    """``(body_offset, body)`` for every ``name {`` or ``name = {`` block directly or deeper in ``block``.

    ``body_offset`` is the index just past the opening brace, so attribute
    offsets inside ``body`` add to it directly.
    """
    out: list[tuple[int, str]] = []
    for m in re.finditer(rf"(?m)^[ \t]*\"?{re.escape(name)}\"?[ \t]*(?:=[ \t]*)?\{{", block):
        out.append((m.end(), extract_block(block, m.end())))
    return out


def nested_block(block: str, name: str) -> tuple[int, str] | None:
    found = nested_blocks(block, name)
    return found[0] if found else None


def port_spec_covers(spec: str, port: int) -> bool:
    """Whether an NSG/firewall port spec (``*``, ``22``, ``20-25``, ``all``) includes ``port``."""
    text = spec.strip().lower()
    if text in {"*", "all", "0-65535"}:
        return True
    if text.isdigit():
        return int(text) == port
    m = _PORT_RANGE_RE.match(text)
    if m is None:
        return False
    return int(m.group(1)) <= port <= int(m.group(2))


def port_specs_only_web(specs: list[str]) -> bool:
    """True when every spec is exactly a web port (80/443), the one exposure the AWS rule also tolerates."""
    return bool(specs) and all(s.strip() in {"80", "443"} for s in specs)


def tf_finding(
    res: TfResource,
    *,
    rule_id: str,
    severity: str,
    title: str,
    message: str,
    compliance: list[str],
    remediation: str,
    offset: int | None = None,
) -> IaCFinding:
    """Build a Terraform finding; ``offset`` (relative to the resource body) pins the line."""
    line = res.block_start_line if offset is None else line_number(res.content, res.block_offset + offset)
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=res.rel_path,
        line_number=line,
        category="terraform",
        compliance=compliance,
        remediation=remediation,
    )
