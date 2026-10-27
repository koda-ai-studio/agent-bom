"""Large JSON reports are encoded and redacted piece by piece, byte-identical to the one-shot path.

A 40k-package report repeats its package list in several sections. Encoding a
section with one ``json.dumps`` call, or redacting the whole report into a copy
before writing, held hundreds of MiB at once; these tests pin the output bytes
to the one-shot encoders and bound the extra memory the export may hold.
"""

from __future__ import annotations

import io
import json
import tracemalloc

from agent_bom.models import AIBOMReport
from agent_bom.output import json_fmt
from agent_bom.output.json_writer import write_compact_json_document, write_json_document
from agent_bom.redaction.payload import StreamingRedaction
from agent_bom.security import sanitize_sensitive_payload


class _CountingSink(io.TextIOBase):
    def __init__(self) -> None:
        self.size = 0

    def write(self, text: str) -> int:
        self.size += len(text)
        return len(text)


def _package(i: int) -> dict:
    return {
        "name": f"bench-pkg-{i}",
        "version": f"1.{i % 50}.{i % 7}",
        "ecosystem": "npm",
        "purl": f"pkg:npm/bench-pkg-{i}@1.{i % 50}.{i % 7}",
        "vulnerabilities": [],
        "evidence": {"source": "package-lock.json", "paths": [f"node_modules/bench-pkg-{i}"]},
    }


def _large_report(count: int) -> dict:
    packages = [_package(i) for i in range(count)]
    return {
        "document_type": "AI-BOM",
        "agents": [{"name": "project", "mcp_servers": [{"name": "srv", "packages": packages}]}],
        "packages": packages,
        "summary": {"total_packages": count},
    }


def _varied_document() -> dict:
    nested_empty: dict = {"a": {}, "b": [], "c": [{}], "d": [[]]}
    return {
        "unicode": 'café ☃ \U0001f600 "quoted" \\ back\nslash',
        "numbers": [0, -1, 1.5, 1e300, True, False, None],
        "tuple": (1, "two", (3,)),
        "int_keys": {1: "one", 2.5: "float", False: "bool", None: "none"},
        "large_int_keys": {i: f"v{i}" for i in range(700)},
        "empty": nested_empty,
        "large": [_package(i) for i in range(1_500)],
        "deep": {"x": [{"y": [{"z": list(range(800))}]}]},
    }


def _streamed(document: dict, **kwargs) -> str:
    buffer = io.StringIO()
    write_json_document(document, buffer, **kwargs)
    return buffer.getvalue()


def test_streamed_document_is_byte_identical_to_json_dump() -> None:
    document = _varied_document()
    assert _streamed(document) == json.dumps(document, indent=2) + "\n"
    assert _streamed({}) == "{}\n"


def test_streamed_compact_document_is_byte_identical_to_compact_dumps() -> None:
    document = _varied_document()
    buffer = io.StringIO()
    write_compact_json_document(document, buffer)
    assert buffer.getvalue() == json.dumps(document, separators=(",", ":"))
    empty = io.StringIO()
    write_compact_json_document({}, empty)
    assert empty.getvalue() == "{}"


def test_writer_never_encodes_a_large_section_in_one_piece() -> None:
    document = _large_report(40_000)
    sink = _CountingSink()
    tracemalloc.start()
    try:
        write_json_document(document, sink)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert sink.size > 10_000_000
    assert peak < sink.size // 10, f"writer held {peak:,} bytes while emitting {sink.size:,}"


def _secretive_payload() -> dict:
    token = "ghp_" + "Z" * 36
    deep: object = "bottom"
    for _ in range(30):
        deep = {"level": deep}
    return {
        "api_key": "plain-secret-value",
        "env": {"OPENAI_API_KEY": "sk-" + "q" * 40, "PATH": "/usr/bin"},
        "notes": [f"token {token}", "nothing to see"],
        "tags": ("one", "two"),
        "unique": {"only"},
        "collide\x00": "first",
        "collide": "second",
        3: "non-string key",
        "deep": deep,
        "rows": [{"password": f"pw-{i}", "name": f"row-{i}", "values": list(range(3))} for i in range(900)],
        "home": "/Users/someone/project/package.json",
    }


def test_streamed_redaction_matches_whole_report_redaction() -> None:
    payload = _secretive_payload()
    expected = json.dumps(sanitize_sensitive_payload(payload), indent=2) + "\n"
    assert _streamed(payload, expand=StreamingRedaction().expand) == expected
    assert "plain-secret-value" not in expected


def test_export_json_matches_redact_then_dump(tmp_path) -> None:
    payload = _secretive_payload()
    payload["iac_findings"] = {"findings": [{"file_path": "/Users/someone/infra/main.tf", "rule_id": "IAC-1"}]}
    output = tmp_path / "report.json"
    json_fmt.export_json(AIBOMReport(), str(output), report_json=payload)
    assert output.read_text(encoding="utf-8") == json.dumps(json_fmt.redact_json_payload(payload), indent=2) + "\n"


def test_export_json_never_holds_a_redacted_copy_of_the_report(tmp_path) -> None:
    tracemalloc.start()
    try:
        report = _large_report(40_000)
        report_bytes, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        json_fmt.export_json(AIBOMReport(), str(tmp_path / "report.json"), report_json=report)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The redaction memo cache (one entry per distinct field value) is the only
    # allowance; a redacted copy of the report alone would exceed it.
    extra = peak - report_bytes
    assert extra < report_bytes // 2, f"export held {extra:,} extra bytes over a {report_bytes:,}-byte report"
    written = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert written["summary"]["total_packages"] == 40_000
    assert written["agents"][0]["mcp_servers"][0]["packages"][39_999]["name"] == "bench-pkg-39999"


def test_stdout_json_matches_redact_then_dump() -> None:
    payload = _secretive_payload()
    buffer = io.StringIO()
    json_fmt.write_redacted_json(AIBOMReport(), buffer, report_json=payload, newline=False)
    assert buffer.getvalue() == json.dumps(json_fmt.to_redacted_json(AIBOMReport(), report_json=payload), indent=2)
