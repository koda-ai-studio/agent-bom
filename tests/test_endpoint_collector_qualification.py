"""Qualification never upgrades missing collectors to universal support."""

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
