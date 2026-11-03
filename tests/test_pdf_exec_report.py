"""The executive PDF carries posture, risks with owner/SLA, fixes, controls, coverage and trend."""

from __future__ import annotations

import re

from click.testing import CliRunner

from agent_bom.models import AIBOMReport
from agent_bom.output.pdf import _build_report_lines, to_pdf
from agent_bom.output.pdf_canvas import PdfDocument, wrap


def _demo_pdf(tmp_path) -> bytes:
    from agent_bom.cli import main

    out = tmp_path / "demo.pdf"
    CliRunner().invoke(main, ["scan", "--demo", "--offline", "-f", "pdf", "-o", str(out)], catch_exceptions=False)
    return out.read_bytes()


def _text(data: bytes) -> str:
    return " ".join(match.decode("latin-1") for match in re.findall(rb"\((.*?)\) Tj", data))


def test_demo_pdf_has_every_executive_section_and_is_well_formed(tmp_path) -> None:
    data = _demo_pdf(tmp_path)
    text = _text(data)
    for section in (
        "Posture",
        "Executive summary",
        "Top risks",
        "Top package vulnerabilities by blast radius",
        "Fix first",
        "Technical control evidence",
        "Coverage and caveats",
    ):
        assert section in text, section
    assert "Posture grade:" in text and "CRITICAL FINDINGS" in text
    assert "Unassigned" in text  # owner column is explicit, never blank
    assert "OWASP Top 10 for LLM" in text and "not a compliance attestation" in text
    pages = int(re.search(rb"/Type /Pages /Count (\d+)", data).group(1))
    assert pages >= 2 and f"page {pages} of {pages}".encode() in data
    # Every object offset in the xref table points at its object header.
    xref = data[data.rindex(b"xref") :]
    offsets = [int(line[:10]) for line in xref.splitlines()[3:] if line.endswith(b" n ")]
    assert all(data[offset:].split(b" ", 1)[0].isdigit() and b" 0 obj" in data[offset : offset + 16] for offset in offsets)


def test_ungraded_and_empty_reports_say_so_instead_of_scoring_zero() -> None:
    text = " ".join(_build_report_lines(AIBOMReport(agents=[])))
    assert "0/100" not in text
    assert "NO FINDINGS IN COLLECTED SCOPE" in text or "PARTIAL COVERAGE" in text or "not graded" in text


def test_trend_appears_when_the_previous_scan_was_remembered() -> None:
    report = AIBOMReport(agents=[])
    report.since_last_scan = {"previous_at": "2026-11-01T10:00:00", "new": 0, "resolved": 3, "partial": False}
    assert "Better than the last scan: 0 new, 3 resolved." in _text(to_pdf(report, []))


def test_long_cells_wrap_and_tables_repeat_their_header_on_new_pages() -> None:
    assert all(len(line) <= 40 for line in wrap("x" * 200, 40 * 9 * 0.48, 9))
    doc = PdfDocument(footer="f")
    doc.table([("Name", 0.5), ("Value", 0.5)], [[f"row {i}", "v"] for i in range(120)])
    assert len(doc.pages) > 1
    assert any("(Name) Tj" in command for command in doc.pages[1])
