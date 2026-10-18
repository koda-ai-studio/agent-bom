"""Qualification never upgrades missing collectors to universal support."""

import json

import pytest

from scripts import qualify_endpoint_collectors as qualification
from scripts.qualify_endpoint_collectors import ALL, assess


def payload():
    return {
        "platform": {"system": "Linux"},
        "privacy": {"process_arguments_collected": False},
        "collectors": [{"name": name, "status": "complete", "item_count": 0, "message": "private-message"} for name in ALL],
        **{name: [] for name in ALL},
    }


def test_receipt_excludes_rows_and_messages():
    data = payload()
    data["processes"] = [{"username": "private-user", "name": "private-process"}]
    result = assess(data, system="Linux", max_items=64)
    assert result["passed"]
    assert "private" not in str(result)


def test_core_failure_is_preserved_and_optional_runtime_is_not_required():
    data = payload()
    for row in data["collectors"]:
        if row["name"] in {"containers", "images"}:
            row.update(status="unavailable", item_count=None)
    result = assess(data, system="Linux", max_items=64)
    assert result["passed"] and not result["all_collectors_complete"]
    next(row for row in data["collectors"] if row["name"] == "services")["status"] = "permission_denied"
    assert not assess(data, system="Linux", max_items=64)["passed"]


def test_simulated_os_missing_collector_and_unbounded_output_cannot_pass():
    data = payload()
    assert not assess(data, system="Windows", max_items=64)["passed"]
    data["collectors"].pop()
    assert not assess(data, system="Linux", max_items=64)["passed"]
    data = payload()
    data["applications"] = [{}] * 65
    assert not assess(data, system="Linux", max_items=64)["passed"]


@pytest.mark.parametrize("observed", [True, False])
def test_native_harness_requires_owned_listener_and_records_deadline(tmp_path, monkeypatch, observed):
    class Listener:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            assert address == ("127.0.0.1", 0)

        def listen(self, backlog):
            assert backlog == 1

        def getsockname(self):
            return ("127.0.0.1", 43210)

    def collect(**kwargs):
        assert kwargs["timeout_seconds"] == 30 and kwargs["max_items"] == 64
        data = payload()
        data["listeners"] = [{"port": 43210 if observed else 1}]
        return data

    output = tmp_path / "receipt.json"
    monkeypatch.setattr("sys.argv", ["qualification", "--output", str(output), "--timeout-seconds", "30"])
    monkeypatch.setattr(qualification.socket, "socket", Listener)
    monkeypatch.setattr(qualification.platform, "system", lambda: "Linux")
    monkeypatch.setattr(qualification, "collect_endpoint_inventory", collect)
    assert qualification.main() == (0 if observed else 1)
    receipt = json.loads(output.read_text())
    assert receipt["fixture_listener_observed"] is observed
    assert receipt["command_timeout_seconds"] == 30
    assert "43210" not in output.read_text()
