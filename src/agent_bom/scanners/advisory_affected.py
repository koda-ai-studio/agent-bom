"""Which stored assets an advisory affects: one transport-neutral answer.

The REST route, the MCP tool and the CLI all page this same answer, so they
can never disagree. Every package occurrence whose identity the advisory names
gets exactly one verdict:

- ``affected`` — the version is inside an affected range (or the
  distribution's own record says so); ``fixed_version`` is the patch target.
- ``possibly_affected`` — the version cannot be decided here. A distro package
  of a CPE product (Debian ``php8.2-cli`` for ``php:php``) is never compared
  against upstream ranges because distributions backport fixes; until the
  distribution's record is in the local DB it stays possibly affected, never
  clean. Possibly-affected rows are not confirmed vulnerabilities.
- ``not_affected`` — the product is present at a version outside every range.

``clean_scanned`` counts examined assets with no affected or possibly-affected
package. It means "not found in what was scanned", never "safe".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable
from typing import Any

from agent_bom.advisory_ids import derive_cve_from_advisory_id
from agent_bom.core.severity import normalize_severity, severity_rank
from agent_bom.core.timestamps import parse_timestamp
from agent_bom.db.advisory_aliases import alias_index_ready
from agent_bom.graph.image_projection import carrier_node_id
from agent_bom.scanners.advisory_feed_severity import feed_severity
from agent_bom.scanners.advisory_graph_ids import occurrence_graph_ids
from agent_bom.scanners.advisory_merge import self_consistent_aliases
from agent_bom.scanners.advisory_occurrences import asset_key
from agent_bom.scanners.distro_cpe_verdict import DistroVerdictFn
from agent_bom.scanners.operator_advisory import (
    DISTRO_BACKPORT_UNVERIFIED,
    OPERATOR_ADVISORY_PROVENANCE,
    AdvisoryMatchResult,
    AffectedProduct,
    FeedAffectedRange,
    OperatorAdvisory,
    iter_report_packages,
    match_advisories_against_reports,
)

SCHEMA_VERSION = "advisory-affected.v1"
VERDICTS = ("affected", "possibly_affected", "not_affected")
VERDICT_FILTERS = ("all", *VERDICTS)
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
_CURSOR_PREFIX = "a1."
_MAX_CURSOR = 512


class AffectedCursorError(ValueError):
    """``kind`` is ``malformed`` (422) or ``stale`` (409: the answer changed since the cursor was issued)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def _version_key(value: str) -> tuple:
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"[.\-+~:]", value))


def _fixed_versions(advisory: OperatorAdvisory) -> list[str]:
    fixed = {item.fixed for product in advisory.affected for item in product.ranges if item.fixed}
    return sorted(fixed, key=_version_key)


AFFECTED_COUNT_BASIS = "package_occurrence_per_holding_asset"
AFFECTED_COUNT_BASIS_NOTE = (
    "One row per package occurrence on each holding asset (MCP server, container image or standalone package). "
    "Findings group one occurrence across the servers that hold it, so their total for the same advisory can be lower."
)


def _advisory_view(advisory: OperatorAdvisory, source: str) -> dict[str, Any]:
    return {
        "id": advisory.id,
        "aliases": list(advisory.aliases),
        "summary": advisory.summary,
        "severity": advisory.severity,
        "severity_source": advisory.severity_source or ("operator_advisory" if source == "operator_advisory" else None),
        "cvss_score": advisory.cvss_score,
        "source": source,
        "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
        "fixed_versions": _fixed_versions(advisory),
    }


def _row_order(row: dict[str, Any]) -> tuple:
    package = row["package"]
    return (VERDICTS.index(row["verdict"]), row["asset_label"], package.get("name", ""), row["installed_version"], row["id"])


def _with_graph_ids(row: dict[str, Any]) -> dict[str, Any]:
    """Add the graph node ids plus the asset's type and node id (a server, an image carrier or a standalone asset)."""
    owners = row.pop("_owners")
    if owners is None:
        node_id = row["asset"].get("node_id") or None
        graph: dict[str, str | None] = {"package_node_id": node_id, "server_node_id": None, "agent_node_id": None}
        return {**row, "asset_type": row["asset"].get("asset_type") or "package", "asset_node_id": node_id, "graph": graph}
    agent, server = owners
    ids = occurrence_graph_ids(agent, server, row["package"])
    image = carrier_node_id(agent)
    asset_type = "container_image" if image else "mcp_server"
    return {**row, "asset_type": asset_type, "asset_node_id": image or ids["server_node_id"], "graph": ids}


UNEXAMINED_SECTIONS_REASON = "a stored report section could not be read; see coverage.unexamined_sections"


def _coverage(result: AdvisoryMatchResult) -> dict[str, Any]:
    return {
        "agent_packages": result.packages_examined - result.standalone_packages_examined,
        "standalone_packages": result.standalone_packages_examined,
        "unexamined_sections": sorted(result.unexamined_sections),
    }


def affected_answer(
    advisory: OperatorAdvisory,
    reports: Iterable[dict[str, Any]],
    *,
    source: str = "operator_advisory",
    distro_verdict: DistroVerdictFn | None = None,
) -> dict[str, Any]:
    """The whole answer for one advisory over the newest stored scans; ``rows`` are unpaged."""
    provenance = {"feed": "feed", "scan": "scan"}.get(source, "operator_advisory")
    result = match_advisories_against_reports([advisory], reports, provenance=provenance, distro_verdict=distro_verdict)
    rows = sorted((_with_graph_ids(row) for row in result.rows), key=_row_order)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict) for verdict in VERDICTS}
    flagged = {asset_key(row["scan_id"] or "", row["asset"]) for row in rows if row["verdict"] != "not_affected"}
    retryable = [row for row in rows if row["verdict"] == "possibly_affected" and row["verdict_reason"] != DISTRO_BACKPORT_UNVERIFIED]
    unexamined = sorted(result.unexamined_sections)
    answer: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "advisory": _advisory_view(advisory, source),
        "summary": {
            **counts,
            "clean_scanned": len(result.assets_examined - flagged),
            "assets_examined": len(result.assets_examined),
            "reports_examined": result.reports_examined,
            "count_basis": AFFECTED_COUNT_BASIS,
            "count_basis_note": AFFECTED_COUNT_BASIS_NOTE,
        },
        "coverage": _coverage(result),
        "complete": result.reports_examined > 0 and not retryable and not unexamined,
        "generation": _generation(advisory.id, rows),
        "rows": rows,
    }
    if unexamined:
        answer["incomplete_reason"] = UNEXAMINED_SECTIONS_REASON
        answer["warnings"] = [UNEXAMINED_SECTIONS_REASON]
    return answer


STORED_FINDINGS_REASON = "no advisory feed record; answered from stored findings"


def _referencing_findings(wanted: str, reports: list[dict[str, Any]]) -> Iterable[tuple[dict[str, Any], dict[str, Any], set[str]]]:
    """``(package, vuln, ids)`` for every stored scan finding whose id or alias is ``wanted``."""
    for report in reports:
        for _asset, package, _owners in iter_report_packages(report):
            for vuln in package.get("vulnerabilities") or []:
                if not isinstance(vuln, dict) or vuln.get("provenance") == OPERATOR_ADVISORY_PROVENANCE:
                    continue
                ids = {str(vuln.get("id") or ""), *(str(alias) for alias in vuln.get("aliases") or [])} - {""}
                if wanted in {identifier.upper() for identifier in ids}:
                    yield package, vuln, ids


def stored_findings_answer(
    advisory_id: str, reports: Iterable[dict[str, Any]], *, distro_verdict: DistroVerdictFn | None = None
) -> dict[str, Any] | None:
    """The answer from the stored scans' own findings when no declaration or feed record knows the id.

    Each package version a stored finding names is ``affected`` with the
    finding's fix as the patch target. With no range record nothing can be
    called ``not_affected``, so the answer is never complete. ``None`` when no
    stored finding references the id.
    """
    report_list = list(reports)
    wanted = advisory_id.strip().upper()
    products: dict[tuple[str, str], AffectedProduct] = {}
    spellings: set[str] = set()
    severities: list[tuple[str, str | None, float | None]] = []
    fixed: set[str] = set()
    summary = ""
    for package, vuln, ids in _referencing_findings(wanted, report_list):
        spellings |= ids
        cvss = vuln.get("cvss_score")
        severities.append(
            (normalize_severity(vuln.get("severity")), vuln.get("severity_source"), cvss if isinstance(cvss, (int, float)) else None)
        )
        if vuln.get("fixed_version"):
            fixed.add(str(vuln["fixed_version"]))
        summary = summary or str(vuln.get("summary") or vuln.get("description") or "")
        key = (str(package.get("ecosystem") or ""), str(package["name"]))
        product = products.setdefault(
            key, AffectedProduct.model_construct(ecosystem=key[0], name=key[1], cpe_product=None, ranges=[], versions=[])
        )
        if str(package["version"]) not in product.versions:
            product.versions.append(str(package["version"]))
    if not products:
        return None
    canonical = next((spelling for spelling in sorted(spellings) if spelling.upper() == wanted), advisory_id.strip())
    # The stored findings already applied the scan's severity policy; the worst recorded verdict speaks for the advisory.
    severity, severity_source, cvss_score = max(severities, key=lambda item: severity_rank(item[0]))
    advisory = OperatorAdvisory.model_construct(
        id=canonical,
        aliases=sorted(spellings - {canonical}),
        summary=summary or f"{canonical}, as recorded by the stored scan findings",
        severity=severity,
        severity_source=severity_source or "scan",
        cvss_score=cvss_score,
        published_at=None,
        references=[],
        affected=list(products.values()),
    )
    answer = affected_answer(advisory, report_list, source="scan", distro_verdict=distro_verdict)
    rows = [row for row in answer["rows"] if row["verdict"] != "not_affected"]
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict) for verdict in VERDICTS}
    return {
        **answer,
        "advisory": {**answer["advisory"], "fixed_versions": sorted(fixed, key=_version_key)},
        "summary": {**answer["summary"], **counts},
        "complete": False,
        "incomplete_reason": STORED_FINDINGS_REASON,
        "warnings": [STORED_FINDINGS_REASON],
        "generation": _generation(advisory.id, rows),
        "rows": rows,
    }


def _generation(advisory_id: str, rows: list[dict[str, Any]]) -> str:
    identity = [advisory_id, *[(r["id"], r["verdict"], r["fixed_version"], r["scan_id"]) for r in rows]]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:20]


def _filter_key(verdict: str, q: str | None) -> str:
    return hashlib.sha256(json.dumps([verdict, q or ""]).encode()).hexdigest()[:12]


def _encode_cursor(tenant_id: str, generation: str, offset: int, filters: str) -> str:
    raw = json.dumps({"t": tenant_id, "g": generation, "o": offset, "f": filters}, separators=(",", ":")).encode()
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any]:
    if len(cursor) > _MAX_CURSOR or not cursor.startswith(_CURSOR_PREFIX):
        raise AffectedCursorError("malformed", "Invalid cursor for this query; restart from the first page.")
    encoded = cursor[len(_CURSOR_PREFIX) :]
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, binascii.Error, UnicodeError) as exc:
        raise AffectedCursorError("malformed", "Invalid cursor for this query; restart from the first page.") from exc
    shape = {"t": str, "g": str, "o": int, "f": str}
    if not isinstance(value, dict) or any(type(value.get(key)) is not kind for key, kind in shape.items()) or value["o"] < 0:
        raise AffectedCursorError("malformed", "Invalid cursor for this query; restart from the first page.")
    return value


def _matches(row: dict[str, Any], verdict: str, needle: str) -> bool:
    if verdict != "all" and row["verdict"] != verdict:
        return False
    if not needle:
        return True
    package = row["package"]
    haystack = " ".join([row["asset_label"], *row["asset"].values(), str(package.get("name", "")), row["installed_version"]])
    return needle in haystack.lower()


def page_answer(
    answer: dict[str, Any],
    *,
    tenant_id: str,
    verdict: str = "all",
    q: str | None = None,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    """One page of an answer; ``summary`` always describes the whole answer, not the page."""
    if verdict not in VERDICT_FILTERS:
        raise ValueError(f"verdict must be one of: {', '.join(VERDICT_FILTERS)}")
    if isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    needle = (q or "").strip().lower()
    filters = _filter_key(verdict, needle)
    rows = [row for row in answer["rows"] if _matches(row, verdict, needle)]
    offset = 0
    if cursor:
        value = _decode_cursor(cursor)
        if value["f"] != filters or value["t"] != tenant_id:
            raise AffectedCursorError("malformed", "Cursor belongs to a different filter; restart from the first page.")
        if value["g"] != answer["generation"] or value["o"] > len(rows):
            raise AffectedCursorError("stale", "Affected assets changed since this cursor was issued; restart from the first page.")
        offset = value["o"]
    page = rows[offset : offset + limit]
    end = offset + len(page)
    has_more = end < len(rows)
    body = {key: value for key, value in answer.items() if key != "rows"}
    return {
        **body,
        "tenant_id": tenant_id,
        "rows": page,
        "count": len(page),
        "limit": limit,
        "has_more": has_more,
        "next_cursor": _encode_cursor(tenant_id, answer["generation"], end, filters) if has_more else None,
        "warnings": list(answer.get("warnings") or []),
    }


# --- feed records (OSV/GHSA/distro rows and NVD CPE ranges) from the local DB ----------------


_VULN_COLUMNS = "id, summary, severity, aliases, published, cvss_score, cvss_vector, source"
_MAX_ALIAS_RECORDS = 32


def _id_spellings(advisory_id: str) -> list[str]:
    """Stored spellings of one id: OSV keeps a GHSA body lowercase, every other scheme upper."""
    upper = advisory_id.strip().upper()
    spellings = [upper]
    if upper.startswith("GHSA-"):
        spellings.append("GHSA-" + upper[5:].lower())
    return spellings


def _split_aliases(value: Any) -> list[str]:
    return [alias.strip() for alias in str(value or "").split(",") if alias.strip()]


def _names_only(row: sqlite3.Row | tuple, cve: str | None) -> bool:
    """Whether a record names no CVE other than ``cve`` (any record is fine when ``cve`` is unknown)."""
    named = {found for value in [str(row[0]), *_split_aliases(row[3])] if (found := derive_cve_from_advisory_id(value))}
    return cve is None or named <= {cve}


def _alias_records(conn: sqlite3.Connection, advisory_id: str) -> list[sqlite3.Row | tuple]:
    """Every feed record for one vulnerability: the id's own row, its aliases' rows and rows naming it.

    OSV splits one vulnerability across records (a CVE row with distro ranges,
    a GHSA row with the PyPI range), so no single row is the whole advisory.
    The requested id's own row comes first.
    """
    spellings = _id_spellings(advisory_id)
    marks = ",".join("?" * len(spellings))
    own = conn.execute(f"SELECT {_VULN_COLUMNS} FROM vulns WHERE id IN ({marks})", spellings).fetchall()  # nosec B608 - fixed projection
    if alias_index_ready(conn):
        naming = conn.execute(
            f"SELECT {_VULN_COLUMNS} FROM vulns WHERE id IN "  # nosec B608 - fixed projection
            "(SELECT vuln_id FROM vuln_aliases WHERE alias_id = ? ORDER BY vuln_id LIMIT ?) ORDER BY id",
            (spellings[0], _MAX_ALIAS_RECORDS),
        ).fetchall()
    else:
        naming = conn.execute(
            f"SELECT {_VULN_COLUMNS} FROM vulns WHERE ',' || upper(aliases) || ',' LIKE ? ORDER BY id LIMIT ?",  # nosec B608 - fixed projection
            (f"%,{spellings[0]},%", _MAX_ALIAS_RECORDS),
        ).fetchall()
    wanted_cve = derive_cve_from_advisory_id(advisory_id)
    # A stale record aliasing several CVEs (a fused upstream group) keeps its own ranges but is
    # never followed to another CVE's records, as in the scanner (self_consistent_aliases).
    records = {str(row[0]): row for row in [*own, *naming]}
    named = {alias for row in records.values() for alias in self_consistent_aliases(str(row[0]), _split_aliases(row[3]))}
    missing = sorted(spelling for alias in named for spelling in _id_spellings(alias) if spelling not in records)[:_MAX_ALIAS_RECORDS]
    if missing:
        marks = ",".join("?" * len(missing))
        for row in conn.execute(f"SELECT {_VULN_COLUMNS} FROM vulns WHERE id IN ({marks})", missing).fetchall():  # nosec B608
            if _names_only(row, wanted_cve):
                records.setdefault(str(row[0]), row)
    ordered = [*own, *sorted((row for key, row in records.items() if row not in own), key=lambda row: str(row[0]))]
    return ordered


def _cpe_products(conn: sqlite3.Connection, cve_id: str) -> list[AffectedProduct]:
    rows = conn.execute(
        "SELECT vendor, product, version, version_start, version_start_op, version_end, version_end_op "
        "FROM cpe_matches WHERE cve_id = ? ORDER BY vendor, product, version_start, version_end",
        (cve_id,),
    ).fetchall()
    grouped: dict[str, AffectedProduct] = {}
    for vendor, product, version, start, _start_op, end, end_op in rows:
        key = f"{vendor}:{product}".lower()
        entry = grouped.setdefault(key, AffectedProduct.model_construct(ecosystem=None, name=None, cpe_product=key, ranges=[], versions=[]))
        if version and version not in {"*", "-"}:
            entry.versions.append(str(version))
            continue
        including_end = end_op == "including"
        entry.ranges.append(
            FeedAffectedRange.model_construct(
                introduced=start or "0",
                fixed=None if including_end else (end or None),
                last_affected=end if including_end else None,
                limit_version="",
            )
        )
    return list(grouped.values())


def _limit_column(conn: sqlite3.Connection) -> str:
    """Projection of the range limit; a DB built before limits were stored has none."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(affected)").fetchall()}
    return "limit_version" if "limit_version" in columns else "''"


def _package_products(conn: sqlite3.Connection, vuln_id: str, limit: str) -> list[AffectedProduct]:
    rows = conn.execute(
        f"SELECT ecosystem, package_name, introduced, fixed, last_affected, {limit} FROM affected WHERE vuln_id = ?",  # nosec B608
        (vuln_id,),
    ).fetchall()
    return [
        AffectedProduct.model_construct(
            ecosystem=eco,
            name=name,
            cpe_product=None,
            versions=[],
            ranges=[
                FeedAffectedRange.model_construct(
                    introduced=introduced or None, fixed=fixed or None, last_affected=last or None, limit_version=lim or ""
                )
            ],
        )
        for eco, name, introduced, fixed, last, lim in rows
    ]


def _merged_products(products: Iterable[AffectedProduct]) -> list[AffectedProduct]:
    """One product per package identity, with each distinct range once, whichever record carried it."""
    merged: dict[tuple, AffectedProduct] = {}
    for product in products:
        key = (product.ecosystem, product.name, product.cpe_product)
        entry = merged.setdefault(
            key,
            AffectedProduct.model_construct(
                ecosystem=product.ecosystem, name=product.name, cpe_product=product.cpe_product, ranges=[], versions=[]
            ),
        )
        for item in product.ranges:
            if item not in entry.ranges:
                entry.ranges.append(item)
        entry.versions.extend(version for version in product.versions if version not in entry.versions)
    return list(merged.values())


def feed_advisory_from_db(conn: sqlite3.Connection, advisory_id: str) -> OperatorAdvisory | None:
    """The local feed record for an id or alias in the matcher's shape; ``None`` when the DB has none.

    The advisory is the union of every alias record, so a CVE row that carries
    only distribution ranges still answers for the PyPI range on its GHSA row.
    """
    records = _alias_records(conn, advisory_id)
    if not records:
        return None
    products: list[AffectedProduct] = []
    limit = _limit_column(conn)
    for record in records:
        products.extend(_package_products(conn, str(record[0]), limit))
        products.extend(_cpe_products(conn, str(record[0])))
    if not products:
        return None
    primary = records[0]
    vuln_id, summary, published = str(primary[0]), primary[1], primary[4]
    # The findings policy: the primary record's CVSS decides the band, its own label applies without one,
    # and alias records (a GHSA copy of a CVE) are consulted only when the primary rates nothing.
    severity, severity_source, cvss_score = feed_severity(records)
    identities = [str(record[0]) for record in records] + [
        alias for record in records for alias in self_consistent_aliases(str(record[0]), _split_aliases(record[3]))
    ]
    aliases = list(dict.fromkeys(identity for identity in identities if identity != vuln_id))
    return OperatorAdvisory.model_construct(
        id=vuln_id,
        aliases=aliases,
        summary=str(summary or "No description available"),
        severity=severity,
        severity_source=severity_source,
        cvss_score=cvss_score,
        published_at=parse_timestamp(str(published)) if published else None,
        references=[],
        affected=_merged_products(products),
    )
