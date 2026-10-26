"""Shared resource context and block helpers for the Terraform security rules."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from agent_bom.iac.models import IaCFinding

PITR_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)


@dataclass(frozen=True)
class TfResource:
    """One ``resource`` block and the comment-stripped file it came from."""

    rtype: str
    rname: str
    block: str
    block_start_line: int
    rel_path: str
    content: str
    block_offset: int = 0


TfCheck = Callable[[TfResource], list[IaCFinding]]


def provider_compliance(rtype: str, *, aws: tuple[str, ...], neutral: tuple[str, ...]) -> list[str]:
    """Compliance IDs for a rule that applies to every provider's resources.

    Provider benchmark controls only describe that provider's resources, so
    they are attached only when the resource type belongs to it.
    """
    return [*aws, *neutral] if rtype.startswith("aws_") else list(neutral)


def extract_block(content: str, start: int) -> str:
    """Extract the body of a brace-delimited block starting at ``start`` (after ``{``)."""
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1
    return content[start : pos - 1]


def line_number(content: str, pos: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return content[:pos].count("\n") + 1
