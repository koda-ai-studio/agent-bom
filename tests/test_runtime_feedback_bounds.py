"""Feedback reads stay bounded and preserve gaps in graph analysis status."""

import json
from pathlib import Path

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.runtime import incident_feedback as feedback


def line():
    return json.dumps(feedback.RuntimeIncidentRecord(agent_id="a", kind="kill_switch", observed_at="2026-10-25T10:00:00Z").to_dict()) + "\n"


def test_loader_streams_without_reading_whole_file(tmp_path, monkeypatch):
    path = tmp_path / "feedback.jsonl"
    path.write_text(line() * 3)

    def forbidden(*args, **kwargs):
        raise AssertionError("whole-file read is forbidden")

    monkeypatch.setattr(Path, "read_text", forbidden)
    assert len(feedback.load_incident_records(path)) == 3


def test_record_cap_is_visible_in_graph_and_does_not_modify_evidence(tmp_path, monkeypatch):
    path = tmp_path / "feedback.jsonl"
    original = line() * 3
    path.write_text(original)
    monkeypatch.setattr(feedback, "MAX_FEEDBACK_RECORDS", 2, raising=False)
    assert len(feedback.load_incident_records(path)) == 2
    graph = build_unified_graph_from_report({"runtime_incident_feedback_path": str(path)})
    status = graph.analysis_status["runtime_incident_feedback"]
    assert status.status.value == "limited"
    assert "feedback_record_limit" in status.reason_codes
    assert path.read_text() == original


def test_oversized_line_is_bounded_and_reports_gap(tmp_path, monkeypatch):
    path = tmp_path / "feedback.jsonl"
    path.write_bytes(b"x" * 300 + b"\n" + line().encode())
    monkeypatch.setattr(feedback, "MAX_FEEDBACK_LINE_BYTES", 100, raising=False)
    graph = build_unified_graph_from_report({"runtime_incident_feedback_path": str(path)})
    status = graph.analysis_status["runtime_incident_feedback"]
    assert "feedback_line_limit" in status.reason_codes
    assert status.observed["bytes_read"] <= 101


def test_total_byte_limit_is_visible_even_with_no_valid_records(tmp_path, monkeypatch):
    path = tmp_path / "feedback.jsonl"
    path.write_bytes(b"\n" * 300)
    monkeypatch.setattr(feedback, "MAX_FEEDBACK_BYTES", 100, raising=False)
    graph = build_unified_graph_from_report({"runtime_incident_feedback_path": str(path)})
    status = graph.analysis_status["runtime_incident_feedback"]
    assert "feedback_byte_limit" in status.reason_codes
    assert status.observed["bytes_read"] <= 101
