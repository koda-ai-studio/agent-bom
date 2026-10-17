"""The qualification runner rejects remote targets and preserves failed receipts."""

import argparse
import json

import pytest

from scripts import qualify_clickhouse_analytics as qualification


@pytest.mark.parametrize(
    "url", ["https://production.example", "http://example.com", "http://127.0.0.1@evil.test", "http://127.0.0.1/?query=DROP"]
)
def test_only_disposable_loopback_origins(url):
    with pytest.raises(argparse.ArgumentTypeError):
        qualification.loopback_url(url)


def test_failed_qualification_is_retained_without_exception_text(tmp_path, monkeypatch):
    def fail(**kwargs):
        raise RuntimeError("secret-fixture")

    monkeypatch.setattr(qualification, "ClickHouseAnalyticsStore", fail)
    output = tmp_path / "receipt.json"
    result = qualification.run("http://127.0.0.1:8123", output)
    assert not result["passed"] and result["error_type"] == "RuntimeError"
    assert "secret-fixture" not in output.read_text()
    assert json.loads(output.read_text()) == result
    with pytest.raises(FileExistsError):
        qualification.run("http://127.0.0.1:8123", output)
