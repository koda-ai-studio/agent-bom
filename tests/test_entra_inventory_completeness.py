"""Bounded directory reads retain rows without claiming truncated scans complete."""

from agent_bom import http_client
from agent_bom.cloud import azure_inventory
from agent_bom.identity import entra_nhi


def test_missing_page_is_not_an_empty_success(monkeypatch):
    monkeypatch.setattr(http_client, "fetch_json", lambda *args, **kwargs: None)
    client = entra_nhi.EntraClient("inert")
    warnings, users = [], []
    azure_inventory._discover_entra_directory(client=client, warnings=warnings, users=users)
    assert warnings
    assert users == []


def test_cap_keeps_bounded_rows_and_reports_truncation(monkeypatch):
    monkeypatch.setattr(entra_nhi, "_MAX_RESULTS", 2)
    monkeypatch.setattr(http_client, "fetch_json", lambda *args, **kwargs: {"value": [{"id": str(i)} for i in range(3)]})
    client = entra_nhi.EntraClient("inert")
    assert len(client.list_users()) == 2
    assert client.coverage_warnings


def test_repeated_empty_cursor_is_bounded_and_partial(monkeypatch):
    calls = []

    def page(url, **kwargs):
        calls.append(url)
        assert len(calls) <= 2
        return {"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?cursor=repeat"}

    monkeypatch.setattr(http_client, "fetch_json", page)
    client = entra_nhi.EntraClient("inert")
    assert client.list_users() == []
    assert client.coverage_warnings
