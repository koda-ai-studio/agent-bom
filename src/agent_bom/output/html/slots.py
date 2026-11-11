"""Assemble a large report from a small skeleton plus held blocks.

Whole-document rewrites (tab tagging, offline mode) copy the document each
time they run. They run on the skeleton, where the finding lists and graph
data are short tokens, and the document is joined once at the end, so its
largest blocks are never copied more than once.
"""

from __future__ import annotations

import re
from typing import TextIO

from agent_bom.output.html._common import ascii_html

_TOKEN = re.compile(r"\x00agent-bom-slot-(\d+)\x00")
_WRITE_SLICE = 1 << 20


class Slots:
    def __init__(self) -> None:
        self._parts: list[str] = []

    def hold(self, markup: str) -> str:
        """Keep *markup* aside and return the token that stands for it."""
        self._parts.append(ascii_html(markup))
        return f"\x00agent-bom-slot-{len(self._parts) - 1}\x00"

    def hold_section(self, section: str) -> str:
        """Hold a ``<section>``'s content, leaving its tags for the rewrites to find."""
        opening_end = section.find(">") + 1
        if not section.startswith("<section") or not section.endswith("</section>") or opening_end <= 0:
            return self.hold(section)
        return section[:opening_end] + self.hold(section[opening_end : -len("</section>")]) + "</section>"

    def _pieces(self, skeleton: str) -> list[str]:
        pieces = _TOKEN.split(skeleton)
        # Odd positions are slot numbers; a block a rewrite removed is simply never joined.
        pieces[1::2] = [self._parts[int(index)] for index in pieces[1::2]]
        return pieces

    def fill(self, skeleton: str) -> str:
        return "".join(self._pieces(skeleton))

    def write(self, skeleton: str, handle: TextIO) -> None:
        """Write the document without ever holding it, or its encoded bytes, as one string.

        A text handle encodes each write whole, so large pieces go out in slices.
        """
        for piece in self._pieces(skeleton):
            for start in range(0, len(piece), _WRITE_SLICE):
                handle.write(piece[start : start + _WRITE_SLICE])
