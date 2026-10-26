"""Every Fix First priority says why, so P3 beside a HIGH CVE reads as a decision, not a contradiction."""

from __future__ import annotations

import pytest

from agent_bom.output.console_remediation import priority_tier


def _group(**overrides) -> dict:
    return {"has_kev": False, "critical_count": 0, "high_count": 0, "creds": [], **overrides}


@pytest.mark.parametrize(
    ("group", "expected"),
    [
        (_group(has_kev=True, high_count=1), ("P1", "known exploited (KEV)")),
        (_group(critical_count=3), ("P1", "3 critical vulnerabilities")),
        (_group(critical_count=1), ("P2", "critical severity")),
        (_group(high_count=2, creds=["DB_PASSWORD"]), ("P2", "high severity with credential reach")),
        (_group(high_count=4), ("P3", "high severity; not known exploited, no credential reach")),
        (_group(), ("P4", "medium or lower severity")),
    ],
)
def test_priority_tier_carries_its_reason(group: dict, expected: tuple[str, str]) -> None:
    assert priority_tier(group) == expected
