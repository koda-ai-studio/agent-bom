"""Current-state columns that make KEV and issue counts sargable.

Hub payloads of 512 bytes or more are zstd-wrapped at rest, so SQL cannot read
keys inside them. Counts, filters and facets therefore read these columns, which
are computed from the same hydrated payload the findings drill serves:

``issue_group_id``  hash of the issue-group key; NULL marks a row not yet backfilled
``kev_direct``      the finding's own KEV flag (rows with no CVE reference)
``intel_ref``       the tenant CVE reference holding the KEV flag for CVE rows
``lens_mask``       coverage lanes the row counts under, plus the Vuln / SCA card
``frameworks_csv``  the ledger's framework slugs, so failing frameworks need no ledger join
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from agent_bom.api.finding_group_key import _finding_group_identity
from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.hub_reference_payload import extract_reference_blobs, payload_is_kev, resolve_cve_id
from agent_bom.api.overview_cve_counts import VULN_CARD_FILTERS
from agent_bom.api.storage.finding_current import columns, hydrate_rows, parse_row
from agent_bom.api.storage.sql import Dialect, SqlSession
from agent_bom.canonical_ids import canonical_id
from agent_bom.config import HUB_REFERENCE_NORMALIZE
from agent_bom.finding_scope import SECURITY_DOMAINS, lenses_for_row, row_matches_scope

MATERIALIZED_COLUMNS = ("issue_group_id", "kev_direct", "intel_ref", "lens_mask", "frameworks_csv")
LENS_BITS: dict[str, int] = {domain: 1 << offset for offset, domain in enumerate(SECURITY_DOMAINS)}
VULN_CARD_BIT = 1 << len(SECURITY_DOMAINS)


MATERIALIZED_POSTGRES_COLUMNS: tuple[str, ...] = (
    "ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS issue_group_id TEXT",
    "ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS kev_direct BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS intel_ref TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS lens_mask INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS frameworks_csv TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE hub_cve_intel ADD COLUMN IF NOT EXISTS is_kev BOOLEAN NOT NULL DEFAULT FALSE",
)
# Partial indexes stay tiny: only pending rows, KEV rows and rows carrying a CVE reference.
PENDING_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_materialize_pending "
    "ON hub_findings_current(tenant_id, canonical_id) WHERE issue_group_id IS NULL"
)
READ_INDEXES: tuple[str, ...] = (
    # Covers the count predicates so aggregates scan this index, not the heap. Client-sized
    # text such as frameworks_csv stays out: an oversized btree entry would fail the ingest.
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_issue_group "
    "ON hub_findings_current(tenant_id, issue_group_id, severity, lens_mask, origin, status, last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_kev_direct ON hub_findings_current(tenant_id, canonical_id) WHERE kev_direct",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_intel_ref ON hub_findings_current(tenant_id, intel_ref) WHERE intel_ref <> ''",
    "CREATE INDEX IF NOT EXISTS idx_hub_cve_intel_kev ON hub_cve_intel(tenant_id, cve_id) WHERE is_kev",
)
INTEL_KEV_BACKFILL_POSTGRES = (
    "UPDATE hub_cve_intel SET is_kev = TRUE WHERE NOT is_kev AND ("
    "payload->>'is_kev' IN ('true', 't', '1', 'True') OR payload->>'cisa_kev' IN ('true', 't', '1', 'True'))"
)
MATERIALIZED_POSTGRES_DDL: tuple[str, ...] = (*MATERIALIZED_POSTGRES_COLUMNS, PENDING_INDEX, *READ_INDEXES)


class MaterializedFinding(NamedTuple):
    issue_group_id: str
    kev_direct: bool
    intel_ref: str
    lens_mask: int
    frameworks_csv: str


def group_id_for_key(group_key: str) -> str:
    """Fixed-size group id, so a long package name can never overflow an index row."""
    return canonical_id("finding-group", group_key)


def issue_group_id(row: dict[str, Any]) -> str:
    return group_id_for_key(_finding_group_identity(row)[1])


def lens_mask(row: dict[str, Any]) -> int:
    mask = 0
    for domain in lenses_for_row(row):
        mask |= LENS_BITS.get(domain, 0)
    if row_matches_scope(dict(row), VULN_CARD_FILTERS):
        mask |= VULN_CARD_BIT
    return mask


def materialized_fields(
    payload: Mapping[str, Any], *, canonical: str, frameworks_csv: str = "", stored_intel_ref: str | None = None
) -> MaterializedFinding:
    """Derive the columns from a hydrated finding payload.

    CVE findings keep their KEV flag in the tenant's ``hub_cve_intel`` row, so the
    flag can change for every occurrence of that CVE; ``intel_ref`` lets the count
    read the current value instead of a copy that would go stale.
    """
    row = {**payload, "canonical_id": canonical}
    if HUB_REFERENCE_NORMALIZE:
        slim, _, _ = extract_reference_blobs(payload)
    else:
        slim = dict(payload)
    intel_ref = stored_intel_ref if stored_intel_ref is not None else str(slim.get("intel_ref") or "")
    return MaterializedFinding(issue_group_id(row), payload_is_kev(slim), intel_ref, lens_mask(row), frameworks_csv)


def _pending_tuples(tx: SqlSession, tenant: str, rows: Sequence[Any], *, has_ledger: bool) -> list[tuple[Any, ...]]:
    parsed = [parse_row(row, has_ledger_col=has_ledger) for row in rows]
    ledger_ids = sorted({str(row.get("ledger_finding_id") or "") for row in parsed} - {""})
    stored: dict[str, tuple[str, str]] = {}
    for start in range(0, len(ledger_ids), 500):
        batch = ledger_ids[start : start + 500]
        markers = ",".join("?" for _ in batch)
        found = tx.execute(
            "SELECT finding_id, payload, applicable_frameworks_csv FROM compliance_hub_findings "
            f"WHERE tenant_id = ? AND finding_id IN ({markers})",  # nosec B608
            (tenant, *batch),
        ).fetchall()
        for item in found:
            ledger = decode_hub_payload(item[1])
            # Rows written before every CVE finding carried a link still name their CVE.
            ref = str(ledger.get("intel_ref") or "") or (resolve_cve_id(ledger) if HUB_REFERENCE_NORMALIZE else "")
            stored[str(item[0])] = (ref, str(item[2] or ""))
    tuples: list[tuple[Any, ...]] = []
    for row in hydrate_rows(tx, tenant, parsed):
        intel_ref, frameworks = stored.get(str(row.get("ledger_finding_id") or ""), (None, ""))
        fields = materialized_fields(
            row["payload"], canonical=str(row["canonical_id"]), frameworks_csv=frameworks, stored_intel_ref=intel_ref
        )
        tuples.append((*fields, tenant, row["canonical_id"]))
    return tuples


def backfill_batch(tx: SqlSession, dialect: Dialect, *, limit: int, bump_revision: Any) -> int:
    """Materialize up to ``limit`` pending rows in the caller's transaction.

    Resumable by construction: a row leaves the pending set once written, so a
    crash loses at most one uncommitted batch. Postgres skips rows a writer holds,
    and the UPDATE keeps ``issue_group_id IS NULL`` so a concurrent ingest's fresher
    values always win.
    """
    lock = " FOR UPDATE SKIP LOCKED" if dialect == "postgres" else ""
    rows = tx.execute(
        f"SELECT tenant_id, {columns(True)} FROM hub_findings_current WHERE issue_group_id IS NULL "  # nosec B608
        f"ORDER BY tenant_id, canonical_id LIMIT ?{lock}",
        (int(limit),),
    ).fetchall()
    by_tenant: dict[str, list[Any]] = {}
    for row in rows:
        by_tenant.setdefault(str(row[0]), []).append(row[1:])
    for tenant, tenant_rows in by_tenant.items():
        updates = _pending_tuples(tx, tenant, tenant_rows, has_ledger=True)
        tx.executemany(
            "UPDATE hub_findings_current SET issue_group_id = ?, kev_direct = ?, intel_ref = ?, lens_mask = ?, frameworks_csv = ? "
            "WHERE tenant_id = ? AND canonical_id = ? AND issue_group_id IS NULL",
            updates,
        )
        # Cached counts computed while these rows were pending are lower bounds.
        bump_revision(tx, tenant)
    return len(rows)
