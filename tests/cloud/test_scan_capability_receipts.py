"""Completed jobs must not manufacture provider-read capability receipts."""

import pytest

from agent_bom.cloud.capability_probe import scan_verified_capabilities


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "snowflake", "databricks"])
def test_provider_name_alone_verifies_nothing(provider: str) -> None:
    assert scan_verified_capabilities(provider) == ()


def test_successful_inventory_does_not_claim_managed_ai_discovery() -> None:
    assert scan_verified_capabilities("aws", summary={"inventory": {"status": "ok", "warnings": []}}) == ("aws:inventory",)


@pytest.mark.parametrize(
    "inventory",
    [
        {"status": "partial"},
        {"status": "ok", "warnings": ["denied"]},
        {"status": "ok", "accounts": []},
        {"status": "ok", "account_count": 2, "accounts": [{"status": "ok"}]},
        {"status": "ok", "account_count": 2, "accounts": [{"status": "ok"}, {"status": "partial"}]},
    ],
)
def test_partial_or_incomplete_inventory_is_not_verified(inventory: dict) -> None:
    assert scan_verified_capabilities("aws", summary={"inventory": inventory}) == ()


def test_all_account_receipt_requires_each_account() -> None:
    summary = {"inventory": {"status": "ok", "account_count": 2, "accounts": [{"status": "ok"}, {"status": "ok"}]}}
    assert scan_verified_capabilities("aws", summary=summary) == ("aws:inventory",)


@pytest.mark.parametrize("completeness,errored,expected", [("complete", 0, ("aws:cis-read",)), ("partial", 0, ()), ("complete", 1, ())])
def test_cis_receipt_uses_observed_completeness(completeness: str, errored: int, expected: tuple) -> None:
    summary = {"cis_benchmark": {"completeness": completeness, "errored": errored, "evaluated": 2, "total": 2}}
    assert scan_verified_capabilities("aws", summary=summary) == expected
