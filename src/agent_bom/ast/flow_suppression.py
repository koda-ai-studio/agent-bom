"""Reviewer suppression markers for local Python flow rules.

A finding is suppressed only by a marker on one of the sink's lines (or, for
SQL, on a line that built the query) that names the sink class, or by a bare
``# nosec``. Recognized markers are the ones Python reviewers already write:

* ``# nosec`` optionally followed by bandit test ids and a reason, e.g.
  ``# nosec B608 - callers pass static table names``;
* ``# noqa: <codes>`` naming the matching ruff ``S`` code, optionally with a
  trailing reason.

Suppressed findings are never dropped: the analyzer keeps them in
``suppressed_flow_findings`` with the marker text, so a reviewer can audit what
was waived and why. A marker without a reason is recorded as unreasoned.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass

CATEGORY_RULE_IDS: dict[str, frozenset[str]] = {
    "sql_string_construction": frozenset({"B608", "S608"}),
    "ssrf_url_construction": frozenset({"B310", "S310"}),
    "unsafe_deserialization": frozenset({"B301", "B506", "S301", "S506"}),
    "command_string_construction": frozenset({"B602", "B604", "B605", "S602", "S604", "S605"}),
}

_NOSEC_RE = re.compile(r"\bnosec\b(?P<rest>.*)", re.IGNORECASE)
_NOQA_RE = re.compile(r"\bnoqa\s*:(?P<rest>.*)", re.IGNORECASE)
_BANDIT_ID_RE = re.compile(r"\s*,?\s*(B\d{3})\b", re.IGNORECASE)
_NOQA_CODE_RE = re.compile(r"\s*,?\s*([A-Z]+\d+)\b")
_REASON_STRIP = " \t-:–—"
_MAX_REASON = 200


@dataclass(frozen=True)
class InlineMarker:
    """One parsed ``nosec`` / ``noqa`` marker."""

    kind: str
    rule_ids: frozenset[str]
    reason: str

    def covers(self, category: str) -> bool:
        if self.kind == "nosec" and not self.rule_ids:
            return True
        return bool(self.rule_ids & CATEGORY_RULE_IDS.get(category, frozenset()))

    def text(self) -> str:
        ids = " ".join(sorted(self.rule_ids))
        head = f"noqa: {ids}" if self.kind == "noqa" else f"nosec {ids}".rstrip()
        return f"{head} - {self.reason}" if self.reason else f"{head} (no reason given)"


def _leading_ids(rest: str, pattern: re.Pattern[str]) -> tuple[frozenset[str], str]:
    ids: set[str] = set()
    rest = rest.lstrip(" :")
    while match := pattern.match(rest):
        ids.add(match.group(1).upper())
        rest = rest[match.end() :]
    return frozenset(ids), rest.strip(_REASON_STRIP)[:_MAX_REASON]


def parse_markers(comment: str) -> list[InlineMarker]:
    """Every marker in one comment token (``# noqa: S310  # nosec B310 - why``)."""
    markers: list[InlineMarker] = []
    for segment in comment.split("#"):
        if nosec := _NOSEC_RE.search(segment):
            ids, reason = _leading_ids(nosec.group("rest"), _BANDIT_ID_RE)
            markers.append(InlineMarker("nosec", ids, reason))
        elif noqa := _NOQA_RE.search(segment):
            ids, reason = _leading_ids(noqa.group("rest"), _NOQA_CODE_RE)
            if ids:
                markers.append(InlineMarker("noqa", ids, reason))
    return markers


def _node_lines(node: ast.AST) -> range:
    start = getattr(node, "lineno", 0)
    return range(start, (getattr(node, "end_lineno", None) or start) + 1)


@dataclass(frozen=True)
class FlowSuppressions:
    """Markers per 1-based source line."""

    by_line: dict[int, tuple[InlineMarker, ...]]

    @classmethod
    def from_source(cls, source: str) -> FlowSuppressions:
        lowered = source.lower()
        if "nosec" not in lowered and "noqa" not in lowered:
            return cls({})
        by_line: dict[int, tuple[InlineMarker, ...]] = {}
        try:
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type == tokenize.COMMENT and (markers := parse_markers(token.string)):
                    by_line[token.start[0]] = tuple(markers)
        except (tokenize.TokenError, SyntaxError):
            return cls({})
        return cls(by_line)

    def lines_for(self, category: str) -> frozenset[int]:
        return frozenset(line for line, markers in self.by_line.items() if any(m.covers(category) for m in markers))

    def marker_at(self, category: str, line: int) -> str | None:
        for marker in self.by_line.get(line, ()):
            if marker.covers(category):
                return marker.text()
        return None

    def marker_for(self, category: str, node: ast.AST) -> str | None:
        """The first covering marker on any line of ``node``."""
        for line in _node_lines(node):
            if (text := self.marker_at(category, line)) is not None:
                return text
        return None
