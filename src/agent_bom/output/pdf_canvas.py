"""A small, dependency-free PDF layout writer for the executive report.

The repository's license policy rules out HTML-to-PDF renderers, so this
writes PDF 1.4 directly: the two standard Helvetica faces (no embedding),
filled rectangles, wrapped paragraphs, simple tables, automatic page breaks
and a numbered footer. Text is limited to the WinAnsi (Latin-1) range; other
characters are transliterated or replaced.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from io import BytesIO

from agent_bom.output.finding_views import sanitize_output_text
from agent_bom.output.pdf_font_metrics import BOLD, REGULAR

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 48
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN
_TOP = PAGE_HEIGHT - MARGIN
_BOTTOM = MARGIN + 24


_TRANSLIT = {
    "—": "-",
    "–": "-",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "•": "*",
    "→": "->",
    " ": " ",
    "…": "...",
    "·": "·",
}

Color = tuple[float, float, float]
INK: Color = (0.06, 0.09, 0.16)
MUTED: Color = (0.39, 0.45, 0.55)
RULE: Color = (0.82, 0.85, 0.89)


def hex_color(value: str) -> Color:
    value = value.lstrip("#")
    return (int(value[0:2], 16) / 255, int(value[2:4], 16) / 255, int(value[4:6], 16) / 255)


def clean(value: object) -> str:
    text = sanitize_output_text(value)
    for old, new in _TRANSLIT.items():
        text = text.replace(old, new)
    return " ".join(text.encode("latin-1", "replace").decode("latin-1").split())


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_width(text: str, size: float, bold: bool = False) -> float:
    widths = BOLD if bold else REGULAR
    return sum(widths[ord(char) - 32] if 32 <= ord(char) <= 126 else 1020 for char in text) * size / 1000


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[str]:
    words, lines, line = clean(text).split(" "), [], ""
    for word in words:
        if line and text_width(f"{line} {word}", size, bold) > width:
            lines.append(line)
            line = ""
        while text_width(word, size, bold) > width and len(word) > 1:
            stop = 1
            while stop < len(word) and text_width(word[: stop + 1], size, bold) <= width:
                stop += 1
            lines.append(word[:stop])
            word = word[stop:]
        line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return lines or [""]


@dataclass
class PdfDocument:
    footer: str = ""
    pages: list[list[str]] = field(default_factory=list)
    y: float = _TOP

    def __post_init__(self) -> None:
        self.new_page()

    def new_page(self) -> None:
        self.pages.append([])
        self.y = _TOP

    def ensure(self, height: float) -> None:
        if self.y - height < _BOTTOM:
            self.new_page()

    def text(self, x: float, y: float, value: str, *, size: float = 10, bold: bool = False, color: Color = INK) -> None:
        font = "F2" if bold else "F1"
        r, g, b = color
        self.pages[-1].append(f"BT {r:.3f} {g:.3f} {b:.3f} rg /{font} {size:g} Tf {x:.1f} {y:.1f} Td ({_escape(clean(value))}) Tj ET")

    def rect(self, x: float, y: float, w: float, h: float, color: Color) -> None:
        r, g, b = color
        self.pages[-1].append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def rule(self) -> None:
        self.rect(MARGIN, self.y, CONTENT_WIDTH, 0.6, RULE)
        self.y -= 10

    def space(self, height: float) -> None:
        self.y -= height

    def heading(self, value: str, *, size: float = 13) -> None:
        self.ensure(size + 30)
        self.y -= 8
        self.text(MARGIN, self.y - size, value, size=size, bold=True)
        self.y -= size + 6
        self.rule()

    def paragraph(self, value: str, *, size: float = 9.5, bold: bool = False, color: Color = INK, indent: float = 0) -> None:
        leading = size * 1.4
        for line in wrap(value, CONTENT_WIDTH - indent, size, bold):
            self.ensure(leading)
            self.text(MARGIN + indent, self.y - size, line, size=size, bold=bold, color=color)
            self.y -= leading
        self.y -= 3

    def table(self, columns: Sequence[tuple[str, float]], rows: Sequence[Sequence[str]], *, size: float = 8.5) -> None:
        """``columns`` are (title, fraction of the content width); cells wrap within their column."""
        widths = [CONTENT_WIDTH * fraction for _, fraction in columns]
        leading = size * 1.35

        def draw_row(cells: Sequence[str], *, bold: bool, shade: Color | None) -> None:
            wrapped = [wrap(cell, width - 6, size, bold) for cell, width in zip(cells, widths)]
            height = max(len(lines) for lines in wrapped) * leading + 4
            if self.y - height < _BOTTOM:
                self.new_page()
                if not bold:
                    draw_row([title for title, _ in columns], bold=True, shade=RULE)
            if shade:
                self.rect(MARGIN, self.y - height, CONTENT_WIDTH, height, shade)
            x: float = MARGIN
            for lines, width in zip(wrapped, widths):
                for index, line in enumerate(lines):
                    self.text(x + 3, self.y - 2 - size - index * leading, line, size=size, bold=bold)
                x += width
            self.y -= height

        draw_row([title for title, _ in columns], bold=True, shade=RULE)
        for index, row in enumerate(rows):
            draw_row(list(row), bold=False, shade=(0.97, 0.98, 0.99) if index % 2 else None)
        self.y -= 8

    def _footer_commands(self, number: int, total: int) -> str:
        r, g, b = MUTED
        label = _escape(clean(f"{self.footer}  |  page {number} of {total}"))
        return f"BT {r:.3f} {g:.3f} {b:.3f} rg /F1 7.5 Tf {MARGIN} {MARGIN - 6} Td ({label}) Tj ET"

    def build(self) -> bytes:
        total = len(self.pages)
        objects: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        ]
        page_ids: list[int] = []
        for number, commands in enumerate(self.pages, start=1):
            stream = "\n".join([*commands, self._footer_commands(number, total)]).encode("latin-1")
            content_id = len(objects) + 2
            page_ids.append(content_id - 1)
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
                ).encode("latin-1")
            )
            objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[1] = f"<< /Type /Pages /Count {total} /Kids [{kids}] >>".encode("latin-1")

        buffer = BytesIO()
        buffer.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, body in enumerate(objects, start=1):
            offsets.append(buffer.tell())
            buffer.write(f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n")
        xref = buffer.tell()
        buffer.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
        for offset in offsets[1:]:
            buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
        buffer.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
        return buffer.getvalue()


__all__ = [
    "CONTENT_WIDTH",
    "INK",
    "MARGIN",
    "MUTED",
    "PAGE_HEIGHT",
    "PAGE_WIDTH",
    "PdfDocument",
    "clean",
    "hex_color",
    "text_width",
    "wrap",
]
