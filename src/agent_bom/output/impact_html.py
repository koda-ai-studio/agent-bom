"""Self-contained, scriptless impact briefs with expandable sanitized receipts."""

from __future__ import annotations

import json
from html import escape
from typing import Any

_STYLE = """
:root{color-scheme:light dark;--bg:#f5f7fa;--card:#fff;--ink:#182535;--muted:#526276;--line:#cbd5e1;--accent:#086f68}
@media(prefers-color-scheme:dark){:root{--bg:#111923;--card:#1a2635;--ink:#edf3fa;--muted:#b4c3d5;--line:#425268;--accent:#70d9c5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:40px 24px}header{border-top:5px solid var(--accent);padding-top:24px}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:var(--accent)}
h1{font-size:clamp(30px,5vw,46px);line-height:1.15;margin:12px 0}h2{font-size:23px;margin:30px 0 12px}h3{font-size:19px;margin:8px 0}
p{margin:8px 0 16px}.muted,small{color:var(--muted)}.boundary{border-left:3px solid var(--accent);padding:12px 16px;background:var(--card)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
.metric,.risk,.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}
.metric strong{display:block;font-size:32px;line-height:1.2}.metric span{font-size:14px;color:var(--muted)}
.risk{margin:16px 0}.rank{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--accent)}
dl{display:grid;grid-template-columns:170px minmax(0,1fr);gap:8px 20px}dt{font-weight:650}dd{margin:0;overflow-wrap:anywhere}
details{border-top:1px solid var(--line);margin-top:18px;padding-top:14px}summary{cursor:pointer;font-weight:650}
summary:focus-visible{outline:3px solid var(--accent);outline-offset:4px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.55 ui-monospace,monospace}
code{overflow-wrap:anywhere;font-size:.85em}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}.table-wrap{overflow-x:auto}li{margin:8px 0}
@media(max-width:600px){main{padding:24px 16px}.risk,.panel{padding:16px}
dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:10px}
.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media print{body{background:white;color:black}
main{max-width:none;padding:0}.risk,.panel{break-inside:avoid}
details:not([open])>:not(summary){display:block}
pre{font-size:10px}.muted,small{color:#333}}
"""


def _text(value: Any) -> str:
    return escape(str(value if value is not None else "Unknown"), quote=True)


def _receipt(value: Any) -> str:
    return f"<pre>{_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False))}</pre>"


def _fields(pairs: list[tuple[str, Any]]) -> str:
    return "<dl>" + "".join(f"<dt>{_text(label)}</dt><dd>{_text(value)}</dd>" for label, value in pairs) + "</dl>"


def _risk(row: dict[str, Any], index: int) -> str:
    fields = [
        ("Affected asset", row["asset_name"]),
        ("Asset ID", row["asset_id"]),
        ("Linked agent IDs", ", ".join(row["agent_ids"]) or "Not recorded"),
        ("Reported condition", row["reported_condition"]),
        ("Potential consequence", row["potential_consequence"]),
        ("Confidence basis", row["confidence_basis"]),
        ("Recommended action", row["recommended_action"]),
        ("Owner", row["owner"]),
    ]
    return (
        f'<article class="risk"><div class="rank">Priority {index} · {_text(row["severity"])}</div>'
        f"<h3>{_text(row['title'])}</h3>{_fields(fields)}"
        "<details><summary>Inspect source receipt</summary>"
        f"<p>Source JSON pointer: <code>{_text(row['receipt_pointer'])}</code>. "
        f"Finding occurrence: <code>{_text(row['id'])}</code>.</p>{_receipt(row['receipt'])}</details></article>"
    )


def _metrics(current: dict[str, Any]) -> str:
    counts = current["counts"]
    labels = [
        ("asset_ids", "Affected asset IDs"),
        ("agent_ids", "Linked agent IDs"),
        ("finding_occurrences", "Finding occurrences"),
        ("finding_groups", "Finding groups"),
        ("recorded_paths", "Recorded paths"),
    ]
    return (
        '<section class="metrics" aria-label="Distinct evidence counts">'
        + "".join(f'<div class="metric"><strong>{_text(counts[key])}</strong><span>{label}</span></div>' for key, label in labels)
        + "</section>"
    )


def _comparison(brief: dict[str, Any]) -> str:
    comparison = brief["comparison"]
    if comparison is None:
        return (
            "<section><h2>Change since baseline</h2><p>No baseline supplied. Add --before to compare retained scan records.</p></section>"
        )
    before, after = brief["baseline"], brief["current"]
    labels = [
        ("asset_ids", "Asset IDs"),
        ("agent_ids", "Linked agent IDs"),
        ("finding_occurrences", "Finding occurrences"),
        ("recorded_paths", "Recorded paths"),
    ]
    rows = "".join(
        f'<tr><th scope="row">{label}</th><td>{_text(before["counts"][key])}</td><td>{_text(after["counts"][key])}</td></tr>'
        for key, label in labels
    )
    counts = comparison["counts"]
    return (
        '<section><h2>Change since baseline</h2><div class="panel">'
        f"<p>{_text(comparison['claim_boundary'])}</p>"
        '<div class="table-wrap"><table><thead><tr><th>Recorded metric</th><th>Before</th><th>After</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div><p>{counts['newly_recorded']} newly recorded · "
        f"{counts['not_observed']} not observed · {counts['retained']} retained "
        f"(including {counts['changed']} changed records).</p>"
        f"<p>Scope comparison: {_text(comparison['scope_status'].replace('_', ' '))}. Verified fixes: not evaluated.</p>"
        "<details><summary>Inspect bounded change records</summary>" + _receipt(comparison) + "</details></div></section>"
    )


def render_impact_brief(brief: dict[str, Any]) -> str:
    """Render a brief returned by build_impact_brief; all data is escaped."""
    current = brief["current"]
    priorities = "".join(_risk(row, index) for index, row in enumerate(current["priorities"], 1))
    if not priorities:
        priorities = (
            '<p class="boundary">No findings recorded in this input. Unscanned or unavailable sources are not established as clean.</p>'
        )
    provenance = {key: value for key, value in current.items() if key != "priorities"}
    missing = current["counts"]
    baseline = (
        ""
        if brief["baseline"] is None
        else "<details><summary>Baseline source and bounded receipts</summary>" + _receipt(brief["baseline"]) + "</details>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\';'
        " style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>Agent-Bom · Impact brief</title><style>" + _STYLE + "</style></head><body><main>"
        '<header><div class="eyebrow">Agent-Bom / Retained scan evidence</div><h1>Impact brief</h1>'
        f'<p class="muted">Scan <code>{_text(current["scan_id"])}</code> · {_text(current["generated_at"])}</p>'
        f'<p class="boundary">{_text(brief["claim_boundary"])}</p></header>{_metrics(current)}'
        f'<p class="muted">{missing["finding_rows"]} source rows. Missing identity evidence: '
        f"{missing['occurrences_without_asset_id']} occurrences without an asset ID; "
        f"{missing['occurrences_without_agent_id']} without linked agent IDs; "
        f"{missing['occurrences_without_group_id']} without a group ID. Names are never used to merge assets.</p>"
        f'<section class="panel"><h2>Evidence coverage</h2><p>Recorded execution outcome: {_text(current["coverage"]["outcome"])}.</p>'
        "<details><summary>Inspect scope, gaps and source digest</summary>"
        + _receipt(provenance)
        + "</details></section>"
        + _comparison(brief)
        + '<section><h2>What to review first</h2><p class="muted">Ordered by recorded severity, then occurrence ID. '
        "Applicability and action approval still require review.</p>"
        + priorities
        + f"<p>{current['omitted_occurrences']} additional occurrences omitted from this brief. "
        "Full counts remain above; consult the source scan.</p></section>"
        + baseline
        + "<section><h2>Limits and next step</h2><ul>"
        + "".join(f"<li>{_text(item)}</li>" for item in brief["limitations"])
        + "</ul><p>Review the receipts, approve the change separately, repeat collection "
        "in the same scope, and retain remediation verification evidence.</p></section>"
        "</main></body></html>\n"
    )
