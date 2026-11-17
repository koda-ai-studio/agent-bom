"""Inventory must remain honest when OpenAI pages are incomplete."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.openai_provider import discover


def job(identifier="fixture-job"):
    return SimpleNamespace(id=identifier, model="fixture-base", fine_tuned_model="fixture-tuned", status="succeeded", training_file=None)


def scan(pages):
    sdk = MagicMock()
    client = sdk.OpenAI.return_value
    client.fine_tuning.jobs.list.side_effect = pages
    with patch.dict(sys.modules, {"openai": sdk}):
        agents, warnings = discover(api_key="fixture-credential")
    return agents, warnings, client


def test_retired_assistants_endpoint_is_not_called():
    agents, warnings, client = scan([SimpleNamespace(data=[], has_more=False)])
    client.beta.assistants.list.assert_not_called()
    assert agents == []
    assert any("retired" in warning.lower() for warning in warnings)


@pytest.mark.parametrize("status", [403, 429, 503])
def test_failed_later_page_retains_inventory_and_classifies(status):
    error = RuntimeError("fixture-sensitive-provider-message")
    error.status_code = status
    agents, warnings, _ = scan([SimpleNamespace(data=[job()], has_more=True), error])
    assert len(agents) == 1
    assert not any("fixture-sensitive-provider-message" in warning for warning in warnings)
    expected = {403: "denied", 429: "throttled", 503: "unavailable"}[status]
    assert any(expected in warning.lower() for warning in warnings)


@pytest.mark.parametrize("data", [None, {}, "invalid"])
def test_invalid_page_is_not_empty_success(data):
    _, warnings, _ = scan([SimpleNamespace(data=data, has_more=False)])
    assert any("malformed" in warning.lower() for warning in warnings)


def test_repeated_cursor_stops_without_duplicate_inventory():
    page = SimpleNamespace(data=[job()], has_more=True)
    agents, warnings, client = scan([page, page])
    assert len(agents) == 1
    assert client.fine_tuning.jobs.list.call_count == 2
    assert any("cursor" in warning.lower() for warning in warnings)


def test_malformed_job_does_not_hide_later_valid_job():
    invalid = job("invalid-job")
    invalid.fine_tuned_model = {"invalid": "model"}
    agents, warnings, _ = scan([SimpleNamespace(data=[invalid, job()], has_more=False)])
    assert len(agents) == 1
    assert agents[0].config_path == "openai://fine-tuning/fixture-job"
    assert any("malformed" in warning.lower() for warning in warnings)


def test_page_limit_is_reported():
    pages = [SimpleNamespace(data=[job(f"job-{index}")], has_more=True) for index in range(100)]
    agents, warnings, client = scan(pages)
    assert len(agents) == 100
    assert client.fine_tuning.jobs.list.call_count == 100
    assert any("safety limit" in warning for warning in warnings)
