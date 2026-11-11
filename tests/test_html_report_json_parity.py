"""Every HTML finding row, mounted or stored, says what the canonical JSON export says, field by field.

Fixture: ``tests.html_report_scale_fixtures`` at 600 findings, which rotates
through missing advisory text, CVSS, EPSS, fix and KEV status, unverified
version ranges, KEV due dates, shared agents and exposed credentials.
"""

from __future__ import annotations

import html as html_lib
import re
from collections import Counter

import pytest

from agent_bom.output import to_json
from agent_bom.output.html import to_html
from tests.html_report_scale_fixtures import scale_report

_FINDINGS = 600
_KEV_STATUS = {"not_listed": "Not listed in recorded catalog", "unknown": "Unavailable", "listed": "Listed"}


def _text(markup: str) -> str:
    return " ".join(html_lib.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


def _rows(document: str, list_id: str) -> list[str]:
    start = document.index(f'id="{list_id}"')
    body = document.index("<tbody>", start)
    mounted = re.findall(r"<tr\b.*?</tr>", document[body : document.index("</tbody>", body)], flags=re.DOTALL)
    store = re.search(rf'<noscript class="deferred-rows" data-rows-for="{list_id}">(.*?)</noscript>', document, flags=re.DOTALL)
    stored = [line for line in store.group(1).split("\n")[1:-1] if line] if store else []
    return mounted + stored


def _attr(row: str, name: str) -> str | None:
    found = re.search(rf'\s{name}="([^"]*)"', row[: row.index(">")])
    return html_lib.unescape(found.group(1)) if found else None


def _vuln_fields(row: str) -> dict[str, object]:
    package = re.search(r'<div class="finding-package">(.*?)<span>@(.*?)</span></div>', row)
    cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, flags=re.DOTALL)
    evidence = {_text(dt): _text(dd) for dt, dd in re.findall(r"<div><dt>(.*?)</dt><dd>(.*?)</dd></div>", row)}
    description = re.search(r'<div class="finding-description">(.*?)</div></details>', row)
    assert package and description
    summary, _, workflow = description.group(1).partition('<div class="finding-workflow"')
    return {
        "id": _text(re.search(r'<code class="vuln-id">(.*?)</code>', row).group(1)),
        "package": _text(package.group(1)),
        "version": _text(package.group(2)),
        "severity": _attr(row, "data-severity"),
        "kev": _attr(row, "data-kev"),
        "kev_due": _attr(row, "data-kev-due"),
        "tier": _attr(row, "data-match-tier"),
        "fix": _text(cells[2]),
        "evidence": evidence,
        "description": _text(summary),
        "workflow": _text(workflow.split(">", 1)[1]) if workflow else "",
    }


def _expected_vuln(finding: dict) -> dict[str, object]:
    evidence = finding["evidence"]
    cvss, epss = finding["cvss_score"], finding["epss_score"]
    provenance = evidence["package_version_provenance"]
    kev_due = (finding.get("kev_due_date") or "")[:10] or None
    return {
        "id": finding["cve_id"],
        "package": finding["asset"]["name"],
        "version": evidence["package_version"],
        "severity": finding["effective_severity"],
        "kev": "1" if finding["is_kev"] else "0",
        "kev_due": kev_due if finding["is_kev"] else None,
        "tier": finding["match_confidence_tier"] or "",
        "fix": finding["fixed_version"] or "No fix recorded",
        "evidence": {
            "CVSS score": f"{cvss:.1f}" if cvss else "No score recorded",
            "EPSS probability": f"{epss:.1%}" if epss is not None else "No score recorded",
            "CISA KEV catalog": "Listed" if finding["is_kev"] else _KEV_STATUS.get(evidence["kev_status"], "Not checked"),
            "Exploitation signal": f"KEV due {kev_due}" if finding["is_kev"] and kev_due else ("KEV" if finding["is_kev"] else None),
            "Agent / asset context": ", ".join(finding["affected_agents"]) or "None recorded",
            "Exposed credentials": " ".join(finding["exposed_credentials"]) or "None recorded",
            "Asset": finding["asset"]["identifier"],
            "Provenance": (f"{finding['source']}; version source {provenance['version_source']}, confidence {provenance['confidence']}"),
        },
        "description": " ".join(finding["description"].split()) if finding["description"] else "Run --enrich",
        "workflow": " \u00b7 ".join(
            part
            for part in (
                f"Owner: {finding['owner']}" if finding["owner"] else "",
                f"SLA: {finding['sla_due_at']}" if finding["sla_due_at"] else "",
                f"Status: {finding['lifecycle_status']}" if finding["lifecycle_status"] else "",
            )
            if part
        ),
    }


@pytest.fixture(scope="module")
def exported():
    report, radii = scale_report(_FINDINGS)
    return to_json(report)["findings"], to_html(report, radii)


def test_every_vulnerability_row_matches_its_json_finding_field_by_field(exported):
    canonical, document = exported
    cve = [finding for finding in canonical if finding["finding_type"] == "CVE"]
    rows = {(fields["id"], fields["package"], fields["version"]): fields for fields in map(_vuln_fields, _rows(document, "vulnTable"))}
    assert len(rows) == len(cve) == len(_rows(document, "vulnTable"))
    mismatches = []
    for finding in cve:
        expected = _expected_vuln(finding)
        actual = rows[(expected["id"], expected["package"], expected["version"])]
        for key, value in expected.items():
            if key != "evidence" and actual[key] != value:
                mismatches.append((expected["id"], key, actual[key], value))
        for label, value in expected["evidence"].items():
            if value is not None and actual["evidence"].get(label) != value:
                mismatches.append((expected["id"], label, actual["evidence"].get(label), value))
    assert not mismatches, mismatches[:5]
    # The fixture exercises each kind of missing or uncertain evidence.
    assert {finding["match_confidence_tier"] for finding in cve} >= {None, "unverified_range"}
    assert any(finding["cvss_score"] is None for finding in cve) and any(finding["epss_score"] is None for finding in cve)
    assert any(not finding["fixed_version"] for finding in cve) and any(finding["is_kev"] for finding in cve)


def test_every_policy_row_matches_its_json_finding_field_by_field(exported):
    canonical, document = exported
    policy = [finding for finding in canonical if finding["finding_type"] != "CVE"]
    rows = _rows(document, "policyFindingsTable")
    assert len(rows) == len(policy)
    actual = Counter()
    for row in rows:
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, flags=re.DOTALL)
        actual[
            (
                _attr(row, "data-severity"),
                _attr(row, "data-type"),
                _attr(row, "data-source"),
                _attr(row, "data-asset-type"),
                _text(cells[2]),
                _text(cells[3]),
                _text(cells[5]),
                _text(cells[6]),
            )
        ] += 1
    expected = Counter()
    for finding in policy:
        items = [f"{key}={value}" for key, value in finding["evidence"].items() if value not in (None, "", [], {})][:4]
        description = finding["description"] or finding["remediation_guidance"] or ""
        expected[
            (
                finding["severity"],
                finding["finding_type"],
                finding["source"],
                finding["asset"]["asset_type"],
                " ".join(filter(None, [finding["asset"]["name"], finding["asset"]["asset_type"], finding["asset"]["location"]])),
                " ".join(" ".join(filter(None, [finding["title"], description])).split()),
                " ".join(items) or "—",
                finding["remediation_guidance"] or "—",
            )
        ] += 1
    assert actual == expected
