"""Tenant-scoped store for hub-ingested findings (#1044 PR C + persistence).

Backends share the same tenant-scoped protocol:

- ``InMemoryComplianceHubStore`` — process-local; ephemeral; the test default.
- ``SQLiteComplianceHubStore`` — single-node persistence behind
  ``AGENT_BOM_DB``. Survives restarts; not safe for multi-replica.
- ``PostgresComplianceHubStore`` — multi-replica; required behind
  ``AGENT_BOM_POSTGRES_URL`` for clustered self-hosted deployments.

Selection honors ``AGENT_BOM_DB`` and ``AGENT_BOM_POSTGRES_URL``.

Schema is denormalised on the framework slugs: a CSV column
``applicable_frameworks_csv`` lets posture aggregation filter at the SQL
layer instead of decoding every payload. Each finding is also tagged
with ``ingested_at`` so future expiry / TTL work has a key.
"""

from __future__ import annotations

import os
from importlib import import_module
from typing import TYPE_CHECKING, Any

from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score
from agent_bom.api.storage.hub_contract import ComplianceHubStore as ComplianceHubStore
from agent_bom.api.storage_schema import postgres_deployment_configured

if TYPE_CHECKING:
    from agent_bom.api.storage.hub_contract import _LEDGER_ORDINAL_SENTINEL as _LEDGER_ORDINAL_SENTINEL
    from agent_bom.api.storage.hub_contract import _LIST_PAGE_SORTS as _LIST_PAGE_SORTS
    from agent_bom.api.storage.hub_contract import _LIVE_STATUSES as _LIVE_STATUSES
    from agent_bom.api.storage.hub_contract import _REACH_SORT_KEY as _REACH_SORT_KEY
    from agent_bom.api.storage.hub_contract import _SCHEMA_KEY as _SCHEMA_KEY
    from agent_bom.api.storage.hub_contract import _SCHEMA_VERSION as _SCHEMA_VERSION
    from agent_bom.api.storage.hub_contract import _SCOPE_FILTER_DEADLINE_SECONDS as _SCOPE_FILTER_DEADLINE_SECONDS
    from agent_bom.api.storage.hub_contract import _SCOPE_FILTER_MAX_BATCH as _SCOPE_FILTER_MAX_BATCH
    from agent_bom.api.storage.hub_contract import _SCOPE_FILTER_MIN_BATCH as _SCOPE_FILTER_MIN_BATCH
    from agent_bom.api.storage.hub_contract import _SCOPE_FILTER_SCAN_BUDGET as _SCOPE_FILTER_SCAN_BUDGET
    from agent_bom.api.storage.hub_contract import IN_MEMORY_SORT_CEILING as IN_MEMORY_SORT_CEILING
    from agent_bom.api.storage.hub_contract import RECONCILE_ABSENT_CHUNK as RECONCILE_ABSENT_CHUNK
    from agent_bom.api.storage.hub_contract import STATUS_FILTERS as STATUS_FILTERS
    from agent_bom.api.storage.hub_contract import ComplianceHubStore as ComplianceHubStore
    from agent_bom.api.storage.hub_contract import FindingCursorPage as FindingCursorPage
    from agent_bom.api.storage.hub_contract import FindingPage as FindingPage
    from agent_bom.api.storage.hub_contract import _CurrentPageSortKey as _CurrentPageSortKey
    from agent_bom.api.storage.hub_contract import _HubFindingRows as _HubFindingRows
    from agent_bom.api.storage.hub_contract import _logger as _logger
    from agent_bom.api.storage.hub_filters import _current_kev_count_from_rows as _current_kev_count_from_rows
    from agent_bom.api.storage.hub_filters import _current_page_sort_key as _current_page_sort_key
    from agent_bom.api.storage.hub_filters import _cvss_value as _cvss_value
    from agent_bom.api.storage.hub_filters import _desc_tie_break as _desc_tie_break
    from agent_bom.api.storage.hub_filters import _filter_current_rows as _filter_current_rows
    from agent_bom.api.storage.hub_filters import _filter_hub_rows as _filter_hub_rows
    from agent_bom.api.storage.hub_filters import _framework_slug_counts_from_rows as _framework_slug_counts_from_rows
    from agent_bom.api.storage.hub_filters import _kev_json_cond_sqlite as _kev_json_cond_sqlite
    from agent_bom.api.storage.hub_filters import _page_signal as _page_signal
    from agent_bom.api.storage.hub_filters import _page_sort_key as _page_sort_key
    from agent_bom.api.storage.hub_filters import _payload_is_kev as _payload_is_kev
    from agent_bom.api.storage.hub_filters import _postgres_current_order_clause as _postgres_current_order_clause
    from agent_bom.api.storage.hub_filters import _redact_finding as _redact_finding
    from agent_bom.api.storage.hub_filters import _redact_findings as _redact_findings
    from agent_bom.api.storage.hub_filters import _severity_breakdown_from_current_rows as _severity_breakdown_from_current_rows
    from agent_bom.api.storage.hub_filters import _severity_breakdown_from_rows as _severity_breakdown_from_rows
    from agent_bom.api.storage.hub_filters import _severity_rank as _severity_rank
    from agent_bom.api.storage.hub_filters import _sqlite_current_order_clause as _sqlite_current_order_clause
    from agent_bom.api.storage.hub_filters import _strip_reach_sort as _strip_reach_sort
    from agent_bom.api.storage.hub_filters import collect_scope_filtered_page as collect_scope_filtered_page
    from agent_bom.api.storage.hub_filters import normalize_status_filter as normalize_status_filter
    from agent_bom.api.storage.hub_filters import scope_filter_batch_size as scope_filter_batch_size
    from agent_bom.api.storage.hub_filters import scope_filter_deadline_seconds as scope_filter_deadline_seconds
    from agent_bom.api.storage.hub_filters import scope_filter_scan_budget as scope_filter_scan_budget
    from agent_bom.api.storage.hub_filters import status_matches as status_matches
    from agent_bom.api.storage.hub_filters import status_sql_predicate as status_sql_predicate
    from agent_bom.api.storage.hub_memory import InMemoryComplianceHubStore as InMemoryComplianceHubStore
    from agent_bom.api.storage.hub_schema import _bump_overview_revision_sqlite as _bump_overview_revision_sqlite
    from agent_bom.api.storage.hub_schema import _ensure_current_lifecycle_sqlite as _ensure_current_lifecycle_sqlite
    from agent_bom.api.storage.hub_schema import _ensure_current_scale_indexes_sqlite as _ensure_current_scale_indexes_sqlite
    from agent_bom.api.storage.hub_schema import _ensure_overview_revision_sqlite as _ensure_overview_revision_sqlite
    from agent_bom.api.storage.hub_schema import _fetch_ledger_payloads_sqlite as _fetch_ledger_payloads_sqlite
    from agent_bom.api.storage.hub_schema import _frameworks_csv as _frameworks_csv
    from agent_bom.api.storage.hub_schema import _hub_findings_current_has_ledger_col as _hub_findings_current_has_ledger_col
    from agent_bom.api.storage.hub_schema import _hydrate_sqlite_current_rows as _hydrate_sqlite_current_rows
    from agent_bom.api.storage.hub_schema import _migrate_current_ledger_ordinal_sqlite as _migrate_current_ledger_ordinal_sqlite
    from agent_bom.api.storage.hub_schema import _migrate_current_ledger_ref_sqlite as _migrate_current_ledger_ref_sqlite
    from agent_bom.api.storage.hub_schema import _migrate_current_origin_col_sqlite as _migrate_current_origin_col_sqlite
    from agent_bom.api.storage.hub_schema import _migrate_current_scan_id_col_sqlite as _migrate_current_scan_id_col_sqlite
    from agent_bom.api.storage.hub_schema import _migrate_lifecycle_observations_l2_sqlite as _migrate_lifecycle_observations_l2_sqlite
    from agent_bom.api.storage.hub_schema import _now_utc_iso as _now_utc_iso
    from agent_bom.api.storage.hub_schema import _sqlite_current_row_from_db as _sqlite_current_row_from_db
    from agent_bom.api.storage.hub_schema import resolve_current_ledger_ordinal_sqlite as resolve_current_ledger_ordinal_sqlite
    from agent_bom.api.storage.hub_sqlite import SQLiteComplianceHubStore as SQLiteComplianceHubStore

_HUB_STORE: ComplianceHubStore | None = None


def get_compliance_hub_store() -> ComplianceHubStore:
    """Return the active hub store, lazily picking the configured backend.

    Resolution order:
      1. ``AGENT_BOM_POSTGRES_URL`` -> Postgres (multi-replica safe)
      2. ``AGENT_BOM_DB`` -> SQLite (single-node persistent)
      3. neither -> in-memory (ephemeral)
    """

    global _HUB_STORE
    if _HUB_STORE is not None:
        return _HUB_STORE

    if postgres_deployment_configured():
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

        _HUB_STORE = PostgresComplianceHubStore()
    elif os.environ.get("AGENT_BOM_DB"):
        from agent_bom.api.storage.hub_sqlite import SQLiteComplianceHubStore

        _HUB_STORE = SQLiteComplianceHubStore(os.environ["AGENT_BOM_DB"])
    else:
        from agent_bom.api.storage.hub_memory import InMemoryComplianceHubStore

        _HUB_STORE = InMemoryComplianceHubStore()
    return _HUB_STORE


def set_compliance_hub_store(store: ComplianceHubStore | None) -> None:
    """Override the hub store. Used by tests to inject a clean backend."""
    global _HUB_STORE
    _HUB_STORE = store


def reset_compliance_hub_store() -> None:
    """Reset to lazy-init. Used by tests; never call from production code."""
    global _HUB_STORE
    _HUB_STORE = None


_EXPORTS = {
    "_logger": "agent_bom.api.storage.hub_contract",
    "RECONCILE_ABSENT_CHUNK": "agent_bom.api.storage.hub_contract",
    "IN_MEMORY_SORT_CEILING": "agent_bom.api.storage.hub_contract",
    "FindingPage": "agent_bom.api.storage.hub_contract",
    "FindingCursorPage": "agent_bom.api.storage.hub_contract",
    "_HubFindingRows": "agent_bom.api.storage.hub_contract",
    "_CurrentPageSortKey": "agent_bom.api.storage.hub_contract",
    "_LIST_PAGE_SORTS": "agent_bom.api.storage.hub_contract",
    "_REACH_SORT_KEY": "agent_bom.api.storage.hub_contract",
    "_SCOPE_FILTER_MIN_BATCH": "agent_bom.api.storage.hub_contract",
    "_SCOPE_FILTER_MAX_BATCH": "agent_bom.api.storage.hub_contract",
    "_SCOPE_FILTER_SCAN_BUDGET": "agent_bom.api.storage.hub_contract",
    "_SCOPE_FILTER_DEADLINE_SECONDS": "agent_bom.api.storage.hub_contract",
    "scope_filter_batch_size": "agent_bom.api.storage.hub_filters",
    "scope_filter_scan_budget": "agent_bom.api.storage.hub_filters",
    "scope_filter_deadline_seconds": "agent_bom.api.storage.hub_filters",
    "_LIVE_STATUSES": "agent_bom.api.storage.hub_contract",
    "STATUS_FILTERS": "agent_bom.api.storage.hub_contract",
    "normalize_status_filter": "agent_bom.api.storage.hub_filters",
    "status_sql_predicate": "agent_bom.api.storage.hub_filters",
    "status_matches": "agent_bom.api.storage.hub_filters",
    "collect_scope_filtered_page": "agent_bom.api.storage.hub_filters",
    "_severity_rank": "agent_bom.api.storage.hub_filters",
    "_cvss_value": "agent_bom.api.storage.hub_filters",
    "_page_signal": "agent_bom.api.storage.hub_filters",
    "_page_sort_key": "agent_bom.api.storage.hub_filters",
    "_strip_reach_sort": "agent_bom.api.storage.hub_filters",
    "_filter_hub_rows": "agent_bom.api.storage.hub_filters",
    "_severity_breakdown_from_rows": "agent_bom.api.storage.hub_filters",
    "_severity_breakdown_from_current_rows": "agent_bom.api.storage.hub_filters",
    "_payload_is_kev": "agent_bom.api.storage.hub_filters",
    "_kev_json_cond_sqlite": "agent_bom.api.storage.hub_filters",
    "_current_kev_count_from_rows": "agent_bom.api.storage.hub_filters",
    "_framework_slug_counts_from_rows": "agent_bom.api.storage.hub_filters",
    "_redact_finding": "agent_bom.api.storage.hub_filters",
    "_redact_findings": "agent_bom.api.storage.hub_filters",
    "ComplianceHubStore": "agent_bom.api.storage.hub_contract",
    "_fetch_ledger_payloads_sqlite": "agent_bom.api.storage.hub_schema",
    "_sqlite_current_row_from_db": "agent_bom.api.storage.hub_schema",
    "_hydrate_sqlite_current_rows": "agent_bom.api.storage.hub_schema",
    "_hub_findings_current_has_ledger_col": "agent_bom.api.storage.hub_schema",
    "_migrate_current_ledger_ref_sqlite": "agent_bom.api.storage.hub_schema",
    "_migrate_current_ledger_ordinal_sqlite": "agent_bom.api.storage.hub_schema",
    "_migrate_current_origin_col_sqlite": "agent_bom.api.storage.hub_schema",
    "_migrate_current_scan_id_col_sqlite": "agent_bom.api.storage.hub_schema",
    "_ensure_current_scale_indexes_sqlite": "agent_bom.api.storage.hub_schema",
    "_ensure_current_lifecycle_sqlite": "agent_bom.api.storage.hub_schema",
    "_migrate_lifecycle_observations_l2_sqlite": "agent_bom.api.storage.hub_schema",
    "InMemoryComplianceHubStore": "agent_bom.api.storage.hub_memory",
    "_SCHEMA_KEY": "agent_bom.api.storage.hub_contract",
    "_SCHEMA_VERSION": "agent_bom.api.storage.hub_contract",
    "_frameworks_csv": "agent_bom.api.storage.hub_schema",
    "_now_utc_iso": "agent_bom.api.storage.hub_schema",
    "_ensure_overview_revision_sqlite": "agent_bom.api.storage.hub_schema",
    "_bump_overview_revision_sqlite": "agent_bom.api.storage.hub_schema",
    "_LEDGER_ORDINAL_SENTINEL": "agent_bom.api.storage.hub_contract",
    "resolve_current_ledger_ordinal_sqlite": "agent_bom.api.storage.hub_schema",
    "_sqlite_current_order_clause": "agent_bom.api.storage.hub_filters",
    "_postgres_current_order_clause": "agent_bom.api.storage.hub_filters",
    "_desc_tie_break": "agent_bom.api.storage.hub_filters",
    "_current_page_sort_key": "agent_bom.api.storage.hub_filters",
    "_filter_current_rows": "agent_bom.api.storage.hub_filters",
    "SQLiteComplianceHubStore": "agent_bom.api.storage.hub_sqlite",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
