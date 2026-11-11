"""Large HTML exports build each finding projection once, stay one byte per character and print every row without JavaScript."""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest

import agent_bom.finding as finding_module
from agent_bom.output.html import _PAGE_SIZE, to_html
from tests.html_report_scale_fixtures import scale_report

_FINDINGS = 600
_LISTS = ("vulnTable", "policyFindingsTable", "blastTable", "remediationList", "remediationNoFix")


_GLYPHS = "naïve ≥ — \U0001f512"


@pytest.fixture(scope="module")
def document() -> str:
    report, radii = scale_report(_FINDINGS)
    radii[0].vulnerability.summary = f"Advisory {_GLYPHS}"
    return to_html(report, radii)


def test_export_converts_each_blast_radius_once_per_projection(monkeypatch):
    report, radii = scale_report(_FINDINGS)
    calls = 0
    original = finding_module.blast_radius_to_finding

    def counted(blast_radius):
        nonlocal calls
        calls += 1
        return original(blast_radius)

    monkeypatch.setattr(finding_module, "blast_radius_to_finding", counted)
    monkeypatch.setattr("agent_bom.output.finding_views.blast_radius_to_finding", counted)
    to_html(report, radii)
    # One CVE projection for the tables and graphs, one unified stream for policy findings.
    assert calls == 2 * len(radii)


def test_document_is_ascii_so_python_stores_one_byte_per_character(document):
    assert document.isascii(), sorted({ch for ch in document if ord(ch) > 127})[:10]
    # Recorded text survives as character references, astral characters included.
    assert "Advisory na&#239;ve &#8805; &#8212; &#128274;" in document


class _NoScriptParse(HTMLParser):
    """Collect what a browser with scripting disabled renders from each row store."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stores: dict[str, list[str]] = {}
        self._current: str | None = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "noscript" and "deferred-rows" in (values.get("class") or ""):
            self._current = values.get("data-rows-for") or ""
            self.stores[self._current] = []
        elif self._current is not None:
            self.stores[self._current].append(tag)

    def handle_endtag(self, tag):
        if tag == "noscript":
            self._current = None


def test_rows_beyond_the_first_page_render_as_markup_without_javascript(document):
    parser = _NoScriptParse()
    parser.feed(document)
    assert set(parser.stores) == set(_LISTS)
    for list_id in ("vulnTable", "policyFindingsTable", "blastTable"):
        tags = parser.stores[list_id]
        # A table of its own, so a browser without scripting lays the rows out instead of dropping the tags.
        assert tags[:2] == ["div", "table"], list_id
        assert "thead" in tags and "tbody" in tags, list_id
    assert 'class="deferred-rows"' in document
    assert '<script type="text/html"' not in document


def test_noscript_store_states_the_rows_it_adds(document):
    store = re.search(r'<noscript class="deferred-rows" data-rows-for="vulnTable">(.*?)</noscript>', document, flags=re.DOTALL)
    assert store is not None
    total = _FINDINGS - _FINDINGS // 10
    assert f"rows {_PAGE_SIZE + 1}&ndash;{total} of {total}" in store.group(1)


def test_largest_sections_are_ascii_before_assembly():
    from agent_bom.output.finding_views import cve_findings
    from agent_bom.output.html import sections

    report, radii = scale_report(_FINDINGS)
    radii[0].vulnerability.summary = f"Advisory {_GLYPHS}"
    cve = cve_findings(report, radii)
    for name, markup in {
        "vulns": sections._vuln_table(report, radii, findings=cve),
        "blast": sections._blast_table(report, radii, findings=cve),
        "remediation": sections._remediation_list(cve),
        "policy": sections._policy_findings_section(sections._non_cve_findings(report)),
    }.items():
        assert markup.isascii(), name


def test_script_and_style_sources_are_ascii():
    from agent_bom.output.html.scripts import SCALE_REPORT_SCRIPT, render_graph_script
    from agent_bom.output.html.styles import render_styles

    for name, source in {
        "scale": SCALE_REPORT_SCRIPT,
        "graph": render_graph_script("{}", "[]", "[]"),
        "styles": render_styles("#dc2626"),
    }.items():
        assert source.isascii(), name


def test_slots_join_held_blocks_once_and_skip_removed_ones():
    from agent_bom.output.html.slots import Slots

    slots = Slots()
    kept = slots.hold("<p>café</p>")
    dropped = slots.hold("<p>gone</p>")
    section = slots.hold_section('<section id="blast"><div>rows</div></section>')
    assert section.startswith('<section id="blast">') and section.endswith("</section>") and "rows" not in section
    skeleton = f"<main>{kept}\x00 stray NUL{section}</main>"
    assert dropped not in skeleton
    assert slots.fill(skeleton) == '<main><p>caf&#233;</p>\x00 stray NUL<section id="blast"><div>rows</div></section></main>'


def test_export_html_streams_the_same_bytes_without_a_joined_copy(tmp_path, monkeypatch):
    from agent_bom.output.html import export_html
    from agent_bom.output.html.slots import Slots

    report, radii = scale_report(_FINDINGS)
    expected = to_html(report, radii)
    path = tmp_path / "report.html"

    def no_join(self, skeleton):
        raise AssertionError("export_html joined the whole document")

    # Writing piece by piece never holds the whole document as one more string.
    monkeypatch.setattr(Slots, "fill", no_join)
    export_html(report, str(path), radii)
    assert path.read_text(encoding="utf-8") == expected
