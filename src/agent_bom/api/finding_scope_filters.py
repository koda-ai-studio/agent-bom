"""Finding scope filters."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_identity import finding_identity
from agent_bom.api.finding_rank import compute_effective_reach_score
from agent_bom.api.finding_row_shapes import _package_identity, _row_vuln_id


def _finding_identity(finding: dict[str, Any]) -> str:
    """Stable identity used to collapse the default findings view.

    Prefers the finding ``id`` (what Postgres' ``hub_findings_current`` keys on)
    and falls back to the vuln:package content key when a scan row omits ``id``.
    """

    return finding_identity(finding)


def _canonical_group_key(finding: dict[str, Any]) -> str:
    """Collapse the three per-CVE representations onto one grouping key.

    Findings that carry a CVE/advisory id group by
    ``(vuln_id, package_name, version, ecosystem, asset)`` so the unified,
    ``blast_radius`` and ``package_vulnerability`` rows for the *same
    vulnerability on the same asset* merge into a single list row. Non-CVE
    findings (posture, malicious-package, etc.) fall back to their stable
    identity so distinct findings stay distinct.

    ``asset`` is in the key, and its absence was a real under-count. The three
    representations this function exists to merge all describe one vulnerability
    on **one** asset, so the asset was never needed to merge them — but leaving
    it out also merged the same package version across *different* assets. A
    scan of one repository never noticed, because a package appears once. An
    estate does: the demo ships fifteen advisories across 768 inventoried
    package rows in 129 container images, and ``/v1/findings`` reported 1,833 of
    2,616 rows — the entire vulnerability lane folded to fifteen — while every
    surface described the result as the total. A dedup key that omits the scope
    of the thing it dedupes is the same defect class that once dropped a second
    tenant's rows here.
    """
    vuln = _row_vuln_id(finding)
    if vuln:
        name, version, ecosystem = _package_identity(finding)
        return f"vuln:{vuln.lower()}:{name}:{version}:{ecosystem}:{_row_asset_key(finding)}"
    return f"id:{_finding_identity(finding)}"


def _row_asset_key(finding: dict[str, Any]) -> str:
    """The asset a row is about, in whichever spelling its representation uses.

    Empty when a representation names no asset — which keeps the merge working:
    a blast-radius row that identifies no asset still folds onto the unified row
    for the same vulnerability and package rather than splitting off on its own.
    """
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    for value in (
        asset.get("identifier"),
        asset.get("canonical_id"),
        asset.get("stable_id"),
        finding.get("resource_id"),
    ):
        text = str(value or "").strip()
        if text:
            return text.lower()
    return ""


def _canonical_scope_filters(
    provider: str | None,
    account: str | None,
    environment: str | None,
    domain: str | None,
    finding_class: str | None = None,
    q: str | None = None,
    kev: bool | None = None,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    lane: str | None = None,
) -> dict[str, str]:
    """Normalize the optional scope/domain filters into an active-filter map.

    Server-side canonicalization (issue #3946): values are lowercased/trimmed
    and empty inputs dropped. Unknown values are kept (not rejected) so the
    endpoint never raises on ad-hoc input — an unmatched value simply returns no
    findings. ``account`` maps to the finding's ``account_ref``.

    ``framework`` / ``control`` power the compliance drill-through (epic #4790):
    the framework identifier (a UI section id such as ``nist-csf`` / ``iso27001``)
    is resolved once here to the finding's ``*_tags`` field and canonical slug so
    the per-row predicate stays a cheap containment check. An unresolved
    framework is stored raw so the predicate returns an honest empty match.
    ``control`` is only meaningful alongside a framework and is dropped otherwise.
    """
    filters: dict[str, str] = {}
    if framework and framework.strip():
        from agent_bom.compliance_coverage import resolve_framework_filter

        meta = resolve_framework_filter(framework)
        if meta is not None:
            filters["framework_tag_field"] = meta.tag_field
            filters["framework_slug"] = meta.slug
        else:
            filters["framework"] = framework.strip().lower()
        if control and control.strip():
            filters["control"] = control.strip()
    if provider and provider.strip():
        filters["provider"] = provider.strip().lower()
    if account and account.strip():
        filters["account_ref"] = account.strip().lower()
    if environment and environment.strip():
        filters["environment"] = environment.strip().lower()
    if domain and domain.strip():
        # Map the pre-rename ``appsec_sca`` alias to ``aspm`` so historical
        # deep-links keep resolving; unknown values pass through untouched.
        from agent_bom.finding_scope import _LEGACY_DOMAIN_ALIASES

        key = domain.strip().lower()
        filters["domain"] = _LEGACY_DOMAIN_ALIASES.get(key, key)
    if lane and lane.strip():
        filters["lane"] = lane.strip().lower()
    if finding_class:
        filters["finding_class"] = finding_class
    if kev is not None:
        filters["kev"] = "true" if kev else "false"
    if q and q.strip():
        filters["q"] = q.strip()
    if owner and owner.strip():
        filters["owner"] = owner.strip().lower()
    if sla and sla.strip():
        filters["sla"] = sla.strip().lower()
    return filters


def _row_matches_scope(row: dict[str, Any], filters: dict[str, str]) -> bool:
    """Scope/domain predicate for a finding row.

    Thin wrapper over :func:`agent_bom.finding_scope.row_matches_scope` — the one
    source of truth shared with the hub store's scope-filtered keyset path so the
    in-memory scan-finding filter and the bulk-ingest store filter can never
    diverge on the overlapping-lens semantics. Retained under this name because
    ``routes/cloud.py`` imports it.
    """
    from agent_bom.finding_scope import row_matches_scope

    return row_matches_scope(row, filters)


def _finding_sort_key(row: dict[str, Any], sort: str) -> tuple[float, float, float]:
    """Stable sort key — descending order on the requested signal,
    with CVSS + severity-rank tiebreakers so the order is fully
    deterministic for a given input.
    """
    from agent_bom.core.severity import severity_policy_rank

    sev_rank = severity_policy_rank(str(row.get("severity", "")))
    from agent_bom.api.finding_cursor import cvss_sort_value

    cvss = cvss_sort_value(row.get("cvss_score"))
    reach_val = compute_effective_reach_score(row)

    if sort == "cvss":
        primary = cvss
    elif sort == "severity":
        primary = float(sev_rank)
    else:  # default — effective_reach
        primary = reach_val
    # Descending: negate, with cvss + severity as deterministic tiebreakers.
    return (-primary, -cvss, -float(sev_rank))


_ECHOED_SCOPE_FILTERS = (("provider", "provider"), ("account", "account_ref"), ("environment", "environment"), ("domain", "domain"))


def _finding_list_filters(
    finding_class: str | None,
    q: str | None,
    framework: str | None,
    control: str | None,
    owner: str | None,
    sla: str | None,
    *,
    severity: str | None = None,
    scope: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Echo every filter the request applied, under its query-parameter name."""

    def _clean(value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None

    scope = scope or {}
    filters = {
        "severity": severity,
        "kev": scope["kev"] == "true" if "kev" in scope else None,
        **{key: scope.get(scope_key) for key, scope_key in _ECHOED_SCOPE_FILTERS},
        "lane": scope.get("lane"),
        "finding_class": finding_class,
        "q": _clean(q),
        "framework": _clean(framework),
        "control": _clean(control),
        "owner": cleaned_owner.lower() if (cleaned_owner := _clean(owner)) else None,
        "sla": sla,
    }
    return {key: value for key, value in filters.items() if value is not None}


def normalize_export_filters(values: dict[str, Any]) -> dict[str, Any]:
    """Drop absent filters while preserving explicitly false boolean predicates."""
    return {
        key: value.strip() if isinstance(value, str) else value
        for key, value in values.items()
        if value is not None and not (isinstance(value, str) and not value.strip())
    }
