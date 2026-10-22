"""Finding asset identity, with recorded scope for provider-local identifiers."""

from __future__ import annotations

from agent_bom.canonical_ids import canonical_id


def _provider_account(provider: str | None, account_ref: str | None) -> tuple[str, str]:
    scope_provider = (provider or "").strip().casefold()
    account = (account_ref or "").strip()
    prefix, separator, local = account.partition(":")
    if separator and (not scope_provider or prefix.casefold() == scope_provider):
        scope_provider = scope_provider or prefix.casefold()
        account = local.strip()
    return scope_provider, account


def canonical_asset_id(
    asset_type: str,
    identifier: str,
    *,
    provider: str | None = None,
    account_ref: str | None = None,
    region: str | None = None,
) -> str:
    """Keep qualified and unscoped legacy IDs; qualify local provider IDs.

    Environment is mutable classification, not an identity boundary. Tenant
    isolation remains the store's composite key. Previously recorded IDs must
    never be auto-aliased: one unscoped legacy ID may refer to several accounts.
    """
    qualified = identifier.startswith(("pkg:", "arn:", "/subscriptions/", "/tenants/", "projects/", "folders/", "organizations/"))
    qualified = qualified or identifier.startswith(
        ("https://www.googleapis.com/", "https://compute.googleapis.com/", "//compute.googleapis.com/")
    )
    scope_provider, account = _provider_account(provider, account_ref)
    if qualified or not (scope_provider or account or region):
        return canonical_id(asset_type, identifier)
    return canonical_id("scoped-asset/v1", asset_type, scope_provider, account, (region or "").strip(), identifier)


def finding_asset_occurrence_id(
    asset_id: str,
    identifier: str | None,
    *,
    provider: str | None = None,
    account_ref: str | None = None,
    region: str | None = None,
) -> str:
    """Scope package finding occurrences without changing global artifact IDs.

    A PURL identifies a package artifact, not its installation in an account.
    Recorded owner scope separates workflow records while the graph can still
    share the artifact node. Unscoped legacy records retain their identity.
    """
    if not isinstance(identifier, str) or not identifier.startswith("pkg:"):
        return asset_id
    scope_provider, account = _provider_account(provider, account_ref)
    scope_region = (region or "").strip()
    if not (scope_provider or account or scope_region):
        return asset_id
    return canonical_id("scoped-package-occurrence/v1", asset_id, scope_provider, account, scope_region)
