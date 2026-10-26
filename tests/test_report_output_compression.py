"""Reports written to ``*.gz`` are gzip, stream per item, and read back everywhere."""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.output import json_writer

DOCUMENTS = [
    {},
    {"empty_list": [], "empty_obj": {}, "scalars": [1, "two", None, True, 2.5]},
    {"findings": [{"id": i, "nested": {"tags": ["a", "ü", " "], "rows": [[1, 2], []]}} for i in range(5)], "n": 3},
    {"blast_radius": [{"x": "y"}], "text": 'line\nbreak "quoted"'},
]


@pytest.mark.parametrize("document", DOCUMENTS)
def test_streamed_pretty_document_is_byte_identical_to_json_dumps(document: dict) -> None:
    buffer = io.StringIO()
    json_writer.write_json_document(document, buffer)
    assert buffer.getvalue() == json.dumps(document, indent=2) + "\n"


@pytest.mark.parametrize("document", DOCUMENTS)
def test_streamed_compact_document_is_byte_identical_to_json_dumps(document: dict) -> None:
    buffer = io.StringIO()
    json_writer.write_compact_json_document(document, buffer)
    assert buffer.getvalue() == json.dumps(document, separators=(",", ":"))


def test_large_lists_are_encoded_one_item_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"id": i, "payload": "x" * 100} for i in range(50)]
    largest: list[int] = []
    real_dumps = json.dumps

    def spy(value, *args, **kwargs):
        text = real_dumps(value, *args, **kwargs)
        largest.append(len(text))
        return text

    monkeypatch.setattr(json_writer.json, "dumps", spy)
    json_writer.write_json_document({"findings": rows}, io.StringIO())
    assert max(largest) < len(real_dumps(rows, indent=2)) / 10


def test_gz_path_writes_deterministic_gzip_with_the_same_document(tmp_path: Path) -> None:
    document = DOCUMENTS[2]
    plain, packed, again = tmp_path / "r.json", tmp_path / "r.json.gz", tmp_path / "again" / "r.json.gz"
    again.parent.mkdir()
    for path in (plain, packed, again):
        json_writer.write_json_file(document, str(path))
    assert packed.read_bytes()[:2] == b"\x1f\x8b"
    assert gzip.decompress(packed.read_bytes()).decode() == plain.read_text()
    assert packed.read_bytes() == again.read_bytes()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["again", "r.json", "r.json.gz"]


def _cli(tmp_path: Path, fmt: str, name: str):
    from agent_bom.cli import main

    out = tmp_path / name
    result = CliRunner().invoke(main, ["agents", "--demo", "--offline", "--exit-zero", "-f", fmt, "-o", str(out)])
    return result, out


@pytest.mark.parametrize(
    ("fmt", "gz_name", "plain_name"),
    [
        ("json", "report.json.gz", "report.json"),
        ("sarif", "report.sarif.gz", "report.sarif"),
        ("cyclonedx", "bom.cdx.json.gz", "bom.cdx.json"),
    ],
)
def test_cli_writes_gzip_for_gz_outputs(tmp_path: Path, fmt: str, gz_name: str, plain_name: str) -> None:
    result, packed = _cli(tmp_path, fmt, gz_name)
    assert result.exit_code == 0, result.output
    assert packed.read_bytes()[:2] == b"\x1f\x8b"
    document = json.loads(gzip.decompress(packed.read_bytes()))
    plain_result, plain = _cli(tmp_path, fmt, plain_name)
    assert plain_result.exit_code == 0
    plain_document = json.loads(plain.read_text())
    if fmt == "json":
        for volatile in ("generated_at", "scan_id", "scan_run", "scan_performance", "vuln_data_freshness"):
            document.pop(volatile, None)
            plain_document.pop(volatile, None)
        assert document.keys() == plain_document.keys()
        assert [f["id"] for f in document["findings"]] == [f["id"] for f in plain_document["findings"]]
    else:
        assert document.keys() == plain_document.keys()
    assert len(packed.read_bytes()) * 5 < len(plain.read_bytes())


def test_cli_rejects_gz_with_a_mismatched_inner_suffix(tmp_path: Path) -> None:
    result, out = _cli(tmp_path, "json", "report.txt.gz")
    assert result.exit_code == 2
    assert ".json.gz" in result.output
    assert not out.exists()


def test_report_diff_and_sbom_intake_read_gzip(tmp_path: Path) -> None:
    from agent_bom.history import load_report, load_report_or_sbom
    from agent_bom.sbom import load_sbom

    report = {"blast_radius": [], "ai_bom_version": "1", "agents": []}
    json_writer.write_json_file(report, str(tmp_path / "r.json.gz"))
    assert load_report(tmp_path / "r.json.gz") == report
    assert load_report_or_sbom(tmp_path / "r.json.gz") == report
    sbom = Path(__file__).parent / "fixtures" / "sbom_ingest" / "syft-like.cdx.json"
    (tmp_path / "bom.cdx.json.gz").write_bytes(gzip.compress(sbom.read_bytes()))
    assert [p.name for p in load_sbom(str(tmp_path / "bom.cdx.json.gz"))[0]] == [p.name for p in load_sbom(str(sbom))[0]]


def test_gzip_sbom_decompression_is_bounded() -> None:
    from agent_bom.sbom_formats.decode import decode_sbom_document

    bomb = gzip.compress(b"{" + b" " * (11 * 1024 * 1024) + b"}")
    with pytest.raises(ValueError, match="10 MiB"):
        decode_sbom_document(bomb)
