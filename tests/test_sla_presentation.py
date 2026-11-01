"""One shared SLA status/policy presentation for the brief, the API and the MCP tool."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom.core.sla import SLA_POLICY_SOURCE, annotate_sla_presentation, sla_policy_label, sla_status
from tests import test_api_read_contracts
from tests.auth_helpers import proxy_headers

NOW = datetime(2026, 11, 1, 18, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("due", "expected"),
    [
        ("2026-11-08T18:32:07.903891+00:00", "due_soon"),
        ("2026-11-01T17:59:00+00:00", "overdue"),
        ("2026-12-15T00:00:00+00:00", "on_track"),
        (None, "unknown"),
        ("not-a-date", "unknown"),
    ],
)
def test_sla_status_is_derived_from_the_same_timestamp(due: str | None, expected: str) -> None:
    assert sla_status(due, now=NOW) == expected


def test_policy_source_ids_get_display_names_and_unknown_sources_pass_through() -> None:
    assert sla_policy_label(SLA_POLICY_SOURCE) == "Severity and KEV policy (v1)"
    assert sla_policy_label("explicit") == "Explicit due date"
    assert sla_policy_label("unavailable") == "No deadline derivable"
    assert sla_policy_label(None) == "Not recorded"
    assert sla_policy_label("vendor-x/v9") == "vendor-x/v9"


def test_annotation_keeps_raw_iso_and_adds_status_and_policy() -> None:
    row = {"vulnerability_id": "CVE-1", "sla_due_at": "2026-11-08T18:32:07.903891+00:00", "sla_due_at_source": SLA_POLICY_SOURCE}
    out = annotate_sla_presentation(row, now=NOW)
    assert out["sla_due_at"] == "2026-11-08T18:32:07.903891+00:00"
    assert out["sla_status"] == "due_soon"
    assert out["sla_policy"] == "Severity and KEV policy (v1)"
    assert row.get("sla_status") is None, "input row is not mutated"


empty_estate_client = test_api_read_contracts.empty_estate_client


def test_brief_priorities_carry_the_shared_sla_presentation(empty_estate_client, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from agent_bom.api import exec_brief

    real_overview = exec_brief.get_overview

    async def overview_with_priority(request):  # noqa: ANN001
        body = await real_overview(request)
        body["top_risks"] = [
            {
                "vulnerability_id": "CVE-1",
                "severity": "critical",
                "sla_due_at": "2026-11-08T18:32:07.903891+00:00",
                "sla_due_at_source": SLA_POLICY_SOURCE,
            }
        ]
        return body

    monkeypatch.setattr(exec_brief, "get_overview", overview_with_priority)
    response = empty_estate_client.get("/v1/brief", headers=proxy_headers())
    assert response.status_code == 200, response.text
    row = response.json()["remediation_priorities"][0]
    assert row["sla_status"] in {"due_soon", "overdue", "on_track"}
    assert row["sla_policy"] == "Severity and KEV policy (v1)"
    assert row["sla_due_at"] == "2026-11-08T18:32:07.903891+00:00"
