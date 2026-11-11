"""Keep long finding lists out of the live document while the file still carries every record.

The first page of a list renders as ordinary markup. The remaining records are
stored, one per line, as inert text in a ``<script type="text/html">`` block that
the paginator mounts a page at a time; search, filters, sorting and printing
read the stored records, so nothing is dropped from the offline file.
"""

from __future__ import annotations

from agent_bom.output.html._common import _PAGE_SIZE


def _one_line(row: str) -> str:
    # A character reference parses to the same newline, so the stored row mounts unchanged.
    return row.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "&#10;")


def bounded_rows(list_id: str, rows: list[str], noun: str = "rows", page_size: int = _PAGE_SIZE) -> tuple[str, str]:
    """Return ``(mounted_markup, deferred_markup)`` for *rows*.

    Rendered values are escaped, so a stored row cannot close its script block.
    If one ever could, every row stays in the document rather than being lost.
    """
    if len(rows) <= page_size:
        return "".join(rows), ""
    deferred = "\n".join(_one_line(row) for row in rows[page_size:])
    if "</script" in deferred.lower() or "<!--" in deferred:
        return "".join(rows), ""
    stored = len(rows) - page_size
    return "".join(rows[:page_size]), (
        f'<script type="text/html" class="deferred-rows" data-rows-for="{list_id}">{deferred}</script>'
        f'<noscript><div class="hint-box">Showing the first {page_size} of {len(rows)} {noun}. '
        f"The other {stored} are stored in this file and appear when JavaScript is enabled.</div></noscript>"
    )
