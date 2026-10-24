"""Object-store bucket names are one global namespace per cloud, not per account.

S3 and Cloud Storage refuse a bucket name another account already holds, so a
demo where ``audit-evidence-staging`` exists in two AWS accounts shows an
estate no real cloud would allow.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate


@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_each_bucket_name_lives_in_exactly_one_account(provider: str) -> None:
    estate = build_demo_estate(tenant_id="default")
    accounts_by_name: dict[str, set[str]] = defaultdict(set)
    for asset in estate.assets:
        if asset.provider == provider and asset.resource_type == "bucket":
            accounts_by_name[asset.display_name].add(asset.account_scope)

    assert len(accounts_by_name) > 1
    shared = {name: sorted(scopes) for name, scopes in accounts_by_name.items() if len(scopes) > 1}
    assert shared == {}, f"{len(shared)} of {len(accounts_by_name)} {provider} bucket names span accounts: {shared}"


def test_external_stage_locations_name_the_bucket_as_inventoried() -> None:
    estate = build_demo_estate(tenant_id="default")
    bucket_names = {a.display_name for a in estate.assets if a.provider == "aws" and a.resource_type == "bucket"}
    locations = [
        location.removeprefix("s3://").rstrip("/")
        for asset in estate.assets
        if asset.resource_type == "storage_integration"
        for location in [asset.tags.get("storage_allowed_locations", "")]
        if location
    ]

    assert locations
    assert set(locations) <= bucket_names


def test_azure_storage_account_names_are_unique_and_valid() -> None:
    import re

    estate = build_demo_estate(tenant_id="default")
    accounts_by_name: dict[str, set[str]] = defaultdict(set)
    for asset in estate.assets:
        if asset.provider == "azure" and asset.resource_type == "storage_account":
            accounts_by_name[asset.display_name].add(asset.account_scope)

    assert len(accounts_by_name) > 1
    shared = {name: sorted(scopes) for name, scopes in accounts_by_name.items() if len(scopes) > 1}
    assert shared == {}, f"{len(shared)} of {len(accounts_by_name)} storage account names span subscriptions"
    invalid = [name for name in accounts_by_name if not re.fullmatch(r"[a-z0-9]{3,24}", name)]
    assert invalid == [], f"names break Azure's 3-24 lowercase letters-and-digits rule: {invalid[:5]}"
