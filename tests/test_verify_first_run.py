"""First-use qualification must reject incomplete or unrelated evidence."""

from __future__ import annotations

import pytest

from scripts import verify_first_run
from scripts.verify_first_run import validate_graph, validate_report


def report(**updates):
    return {"scan_id": "sample-1", "scan_run": {"outcome": "complete"}, "agents": [{"name": "sample"}], **updates}


def test_first_run_rejects_partial_report_even_when_inventory_exists():
    with pytest.raises(ValueError, match="complete"):
        validate_report(report(scan_run={"outcome": "partial"}))


@pytest.mark.parametrize("field", ["scan_id", "agents"])
def test_first_run_requires_inventory_and_snapshot_identity(field):
    with pytest.raises(ValueError):
        validate_report(report(**{field: None}))


def test_first_run_does_not_require_cves_from_offline_inventory():
    assert validate_report(report()) == "sample-1"


@pytest.mark.parametrize(
    "graph",
    [
        {"scan_id": "other", "nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "a"}]},
        {"scan_id": "sample-1", "nodes": [], "edges": []},
        {"scan_id": "sample-1", "nodes": [{"id": "a"}], "edges": []},
        {"scan_id": "sample-1", "nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "missing"}]},
    ],
)
def test_first_run_rejects_wrong_empty_or_dangling_graph(graph):
    with pytest.raises(ValueError):
        validate_graph(graph, "sample-1")


def test_first_run_accepts_connected_snapshot():
    graph = {"scan_id": "sample-1", "nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"source": "a", "target": "b"}]}
    assert validate_graph(graph, "sample-1") == {"nodes": 2, "edges": 1}


def test_failed_run_keeps_receipt_and_cannot_overwrite_evidence(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(verify_first_run.importlib.metadata, "distribution", lambda _: SimpleNamespace(version="0.0.1"))
    output = tmp_path / "run"
    with pytest.raises(ValueError, match="version"):
        verify_first_run.run(output, "0.0.2")
    original = (output / "receipt.json").read_bytes()
    assert json.loads(original)["status"] == "failed"
    with pytest.raises(FileExistsError):
        verify_first_run.run(output, "0.0.2")
    assert (output / "receipt.json").read_bytes() == original
