"""Keep long finding lists out of the live document while the file still carries every record.

The first page of a list renders as ordinary markup. The remaining records are
stored one per line inside ``<noscript>``. With scripting on, the HTML parser
reads a ``noscript`` element as raw text, so the stored rows cost no DOM; the
paginator mounts them a page at a time, and search, filters, sorting and
printing read the stored records. With scripting off, the same element parses
as markup, so every row is shown and printed under a note that says so.
"""

from __future__ import annotations

import re

from agent_bom.output.html._common import _PAGE_SIZE

_BREAKOUT = re.compile(r"</noscript|<!--", re.IGNORECASE)


def _one_line(row: str) -> str:
    # A character reference parses to the same newline, so the stored row mounts unchanged.
    return row.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "&#10;")


def bounded_rows(
    list_id: str,
    rows: list[str],
    noun: str = "rows",
    page_size: int = _PAGE_SIZE,
    *,
    frame: tuple[str, str] = ("<div>", "</div>"),
) -> tuple[list[str], list[str]]:
    """Return ``(mounted, stored)`` markup pieces for *rows*.

    The pieces are joined once by the caller together with the markup around
    them, so a long list is copied once rather than at every nesting level.

    ``frame`` wraps the stored rows so a browser without scripting lays them
    out, for a table a ``<table>`` with its own header. The note, the frame's
    opening and its closing each sit on a line of their own, so the paginator
    reads the rows as every line between the first and the last.

    Rendered values are escaped, so a stored row cannot close its element.
    If one ever could, every row stays mounted rather than being lost.
    """
    if len(rows) <= page_size:
        return rows, []
    stored = [_one_line(row) for row in rows[page_size:]]
    if any(_BREAKOUT.search(row) for row in stored) or any(_BREAKOUT.search(part) for part in frame):
        return rows, []
    total = len(rows)
    opening, closing = frame
    pieces = [
        f'<noscript class="deferred-rows" data-rows-for="{list_id}">'
        f'<div class="hint-box deferred-note">JavaScript is off, so rows {page_size + 1}&ndash;{total} '
        f"of {total} {noun} follow without paging.</div>{opening}"
    ]
    for row in stored:
        pieces.extend(("\n", row))
    pieces.append(f"\n{closing}</noscript>")
    return rows[:page_size], pieces


_PAGER_LABELS = {
    "vulnTable": "Vulnerability",
    "policyFindingsTable": "Policy finding",
    "blastTable": "Blast radius",
    "remediationList": "Upgrade",
    "remediationNoFix": "No-fix finding",
}


def _table_frame(headers: list[str], classes: str = "data-table") -> tuple[str, str]:
    """The table a browser without scripting lays stored rows out in, styled like the list's own table."""
    head = "".join(f"<th>{header}</th>" for header in headers)
    return f'<table class="{classes} deferred-table"><thead><tr>{head}</tr></thead><tbody>', "</tbody></table>"


def _pager_controls(table_id: str, total: int, page_size: int = _PAGE_SIZE) -> str:
    """Server-rendered pagination bar bound to a table by ``data-pager``.

    Rendered for every findings table so the controls exist in the static file
    (and in tests); the paginator JS wires the buttons and hides the whole bar
    when the filtered set fits on a single page.
    """
    label = _PAGER_LABELS.get(table_id, table_id)
    return (
        f'<div class="pager" data-pager="{table_id}" data-page-size="{page_size}" role="navigation" aria-label="{label} pages">'
        '<button type="button" class="pager-btn" data-act="first" title="First page" aria-label="First page">&laquo;</button>'
        '<button type="button" class="pager-btn" data-act="prev" title="Previous page" aria-label="Previous page">&lsaquo; Prev</button>'
        f'<span class="pager-info" aria-live="polite">1&ndash;{min(page_size, total)} of {total}</span>'
        '<button type="button" class="pager-btn" data-act="next" title="Next page" aria-label="Next page">Next &rsaquo;</button>'
        '<button type="button" class="pager-btn" data-act="last" title="Last page" aria-label="Last page">&raquo;</button>'
        '<span class="pager-sep"></span>'
        '<label class="pager-size-label">Rows'
        '<select class="pager-size" aria-label="Rows per page">'
        '<option value="25">25</option>'
        f'<option value="50"{" selected" if page_size == 50 else ""}>50</option>'
        '<option value="100">100</option>'
        '<option value="250">250</option>'
        "</select></label>"
        "</div>"
    )
