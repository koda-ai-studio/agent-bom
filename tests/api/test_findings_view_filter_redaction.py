"""View filters on ``GET /v1/findings`` redact only the rows they return.

``?reachability=`` walks the canonical finding stream page by page and keeps
the matching rows. Profiled on the demo estate (2,725 findings) it took
2.0-3.3 s warm because every walked row, including all the rows it discarded
and every row of the counting pass, went through response redaction first
(``safe_finding_response_payload``: ~160k ``sanitize_text`` calls per request).
Redaction is a per-row projection, so filtering first and redacting the
emitted rows returns the same body for a fraction of the work.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from agent_bom import finding_scope
from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401


def _all_findings(client: TestClient) -> list[dict]:
    rows: list[dict] = []
    cursor = ""
    while True:
        params = {"limit": 500, **({"cursor": cursor} if cursor else {})}
        page = client.get("/v1/findings", headers=VIEWER, params=params).json()
        rows.extend(page["findings"])
        cursor = page.get("next_cursor") or ""
        if not cursor:
            return rows


def test_reachability_view_redacts_only_emitted_rows(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    client = demo_estate_client
    expected = [row for row in _all_findings(client) if row.get("graph_reachable") is True]
    assert len(expected) > 5, "the demo estate has too few reachable findings to prove anything"

    calls = {"n": 0}
    original = finding_scope.safe_finding_response_payload

    def counting(row):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return original(row)

    monkeypatch.setattr(finding_scope, "safe_finding_response_payload", counting)
    body = client.get("/v1/findings", headers=VIEWER, params={"reachability": "reachable", "limit": 5}).json()

    assert body["findings"] == expected[:5]
    assert body["total"] == len(expected)
    assert calls["n"] <= 5, f"redacted {calls['n']} rows to return 5"


def test_reachability_view_keeps_triage_fields_unredacted(demo_estate_client: TestClient) -> None:  # noqa: F811
    body = demo_estate_client.get(
        "/v1/findings", headers=VIEWER, params={"reachability": "reachable", "triage": "untriaged", "limit": 3}
    ).json()
    assert body["findings"], "no untriaged reachable findings on the demo estate"
    for row in body["findings"]:
        assert row["graph_reachable"] is True
        assert "triage_decision" in row and row["triage_decision"] is None


@pytest.mark.parametrize("triage", ["untriaged", "affected"])
def test_triage_view_without_triage_entries_redacts_only_emitted_rows(
    demo_estate_client: TestClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    triage: str,
) -> None:
    """With no active triage entry every decision is None whatever redaction rewrites, so filtering raw rows is exact."""
    from agent_bom.api import finding_page_read

    client = demo_estate_client
    params = {"triage": triage, "limit": 5}
    monkeypatch.setattr(finding_page_read, "redacts_after_filter", lambda *, redact_page, triage, **_: redact_page and triage is None)
    redact_first = client.get("/v1/findings", headers=VIEWER, params=params)
    monkeypatch.undo()

    calls = {"n": 0}
    original = finding_scope.safe_finding_response_payload

    def counting(row):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return original(row)

    monkeypatch.setattr(finding_scope, "safe_finding_response_payload", counting)
    fast = client.get("/v1/findings", headers=VIEWER, params=params)
    assert fast.status_code == redact_first.status_code == 200
    # The rolling window's ``since`` is clock-relative; every other byte must match.
    first, second = (re.sub(r'"since":"[^"]+"', '"since":""', body.content.decode()) for body in (fast, redact_first))
    assert first == second, next((first[i - 80 : i + 80], second[i - 80 : i + 80]) for i in range(len(first)) if first[i] != second[i])
    assert calls["n"] <= 5, f"redacted {calls['n']} rows to return {len(fast.json()['findings'])}"


@pytest.fixture()
def leftover_triage_entry():
    """A triage decision another test left in the process-wide exception store."""
    from agent_bom.api import stores as api_stores
    from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException

    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-0000-0001", package_name="leftover", server_name="*", reason="[finding_triage] {}", status=ExceptionStatus.ACTIVE
        ),
        tenant_id="default",
    )
    original = api_stores._exception_store
    api_stores._exception_store = store
    yield
    api_stores._exception_store = original


def test_demo_client_starts_from_an_empty_exception_store(
    leftover_triage_entry,
    demo_estate_client: TestClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}
    original = finding_scope.safe_finding_response_payload

    def counting(row):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return original(row)

    monkeypatch.setattr(finding_scope, "safe_finding_response_payload", counting)
    body = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"triage": "untriaged", "limit": 5})
    assert body.status_code == 200
    assert calls["n"] <= 5, f"a leftover triage entry leaked into the demo client: redacted {calls['n']} rows"
