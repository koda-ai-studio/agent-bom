"""Standalone graph HTML helpers: risk summaries, safe script JSON and offline rendering."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agent_bom.output.finding_views import package_graph_node_id as _package_node_id
from agent_bom.output.graph_html_template_body import _GRAPH_HTML_TEMPLATE_BODY
from agent_bom.output.graph_html_template_head import _GRAPH_HTML_TEMPLATE_HEAD

if TYPE_CHECKING:
    from agent_bom.finding import Finding


def _graph_priority_summary(findings: list["Finding"], *, collapse_cves: bool = False) -> list[dict]:
    """Summarize the highest-value blast-radius paths for the HTML graph.

    The standalone graph needs an operator-facing starting point, not just raw
    nodes. These summaries drive the top-risk sidebar and focus behavior.
    """
    from agent_bom.output.finding_views import package_ecosystem, package_name, package_version, severity_value

    priorities: list[dict] = []
    for finding in sorted(findings, key=lambda item: float(item.risk_score or 0.0), reverse=True)[:8]:
        is_policy = not finding.cve_id
        vuln_id = finding.cve_id or finding.title
        node_id = f"finding:{finding.id}" if is_policy else f"cve:{vuln_id}"
        if not is_policy and collapse_cves and finding.affected_agents and finding.affected_servers:
            node_id = _package_node_id(
                package_name(finding),
                package_ecosystem(finding),
                package_version(finding),
                agent_name=finding.affected_agents[0],
                server_name=finding.affected_servers[0],
                scoped=True,
            )
        priorities.append(
            {
                "nodeId": node_id,
                "vulnerabilityId": vuln_id,
                "packageName": package_name(finding),
                "packageVersion": package_version(finding),
                "packageEcosystem": package_ecosystem(finding),
                "severity": severity_value(finding),
                "riskScore": round(float(finding.risk_score or 0.0), 1),
                "agentCount": len(finding.affected_agents),
                "serverCount": len(finding.affected_servers),
                "credentialCount": len(finding.exposed_credentials),
                "toolCount": len(finding.exposed_tools),
                "fixVersion": finding.fixed_version or "",
                "reachability": finding.reachability,
                "summary": finding.description or finding.title or "",
                "agents": list(finding.affected_agents[:6]),
                "servers": list(finding.affected_servers[:6]),
                "credentials": list(finding.exposed_credentials)[:8],
                "tools": list(finding.exposed_tools)[:10],
                "owaspTags": list(finding.owasp_tags),
                "atlasTags": list(finding.atlas_tags),
                "owaspMcpTags": list(finding.owasp_mcp_tags),
                "owaspAgenticTags": list(finding.owasp_agentic_tags),
            }
        )
    return priorities


def _json_for_script(value: object, *, indent: int | None = 2) -> str:
    """Serialize already-projected data without allowing HTML breakout."""
    return (
        json.dumps(value, indent=indent)
        .replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("\u2028", r"\u2028")
        .replace("\u2029", r"\u2029")
    )


def _sanitize_graph_reference_payload(value: object, id_map: dict[str, str]) -> object:
    """Sanitize graph side-panel data and remap its node references."""
    from agent_bom.security import sanitize_sensitive_payload

    sanitized = sanitize_sensitive_payload(value, max_str_len=10_000)
    if not isinstance(value, list) or not isinstance(sanitized, list):
        return sanitized
    projected: list[object] = []
    for raw, safe in zip(value, sanitized, strict=False):
        if isinstance(raw, dict) and isinstance(safe, dict) and "nodeId" in raw:
            safe["nodeId"] = id_map.get(str(raw["nodeId"]), safe.get("nodeId"))
        projected.append(safe)
    return projected


def _graph_overview(findings: list["Finding"]) -> dict[str, int]:
    """Aggregate the key counts operators need before drilling into a path."""
    from agent_bom.output.finding_views import severity_value

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    exposed_credentials: set[str] = set()
    exposed_tools: set[str] = set()
    affected_servers: set[str] = set()
    affected_agents: set[str] = set()

    for finding in findings:
        severity = severity_value(finding)
        if severity in counts:
            counts[severity] += 1
        exposed_credentials.update(finding.exposed_credentials)
        exposed_tools.update(finding.exposed_tools)
        affected_servers.update(finding.affected_servers)
        affected_agents.update(finding.affected_agents)

    return {
        **counts,
        "credentialCount": len(exposed_credentials),
        "toolCount": len(exposed_tools),
        "affectedServerCount": len(affected_servers),
        "affectedAgentCount": len(affected_agents),
    }


#: Pinned vendor bundles inlined into the standalone graph HTML so the export
#: renders with no network access (an ``--offline`` scan must not produce an
#: artifact that needs a CDN). Versions match the upstream npm releases:
#: cytoscape 3.30.2, dagre 0.8.5, cytoscape-dagre 2.5.0.
_VENDOR_JS_FILES = ("cytoscape.min.js", "dagre.min.js", "cytoscape-dagre.js")

_CDN_FALLBACK_TAGS = (
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"'
    ' onerror="graphAssetLoadFailed()"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"'
    ' onerror="graphAssetLoadFailed()"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.js"'
    ' onerror="graphAssetLoadFailed()"></script>'
)


def _vendor_script_tags() -> str:
    """Return inline ``<script>`` blocks for the pinned graph libraries.

    Falls back to the pinned CDN URLs — with a visible failure notice instead
    of a silent blank canvas — only if the vendored files are missing from the
    installed package.
    """
    from importlib import resources

    try:
        blocks = []
        vendor = resources.files("agent_bom.output").joinpath("vendor")
        for name in _VENDOR_JS_FILES:
            js = vendor.joinpath(name).read_text(encoding="utf-8")
            blocks.append(f"<script>\n{js}\n</script>")
        return "\n".join(blocks)
    except Exception:  # noqa: BLE001 — degrade to CDN + explicit offline notice
        notice = (
            "<script>function graphAssetLoadFailed(){document.getElementById('cy').innerHTML="
            '\'<p style="padding:24px;color:#ffd33d">This graph export requires internet access to render '
            "(CDN graph libraries could not be loaded).</p>';}</script>"
        )
        return notice + "\n" + _CDN_FALLBACK_TAGS


def _html_escape(value: object) -> str:
    from agent_bom.output.finding_views import sanitize_output_text

    return sanitize_output_text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _to_offline_graph_html(
    *,
    total_agents: int,
    total_servers: int,
    total_pkgs: int,
    total_vulns: int,
    top_risks: list[dict[str, Any]],
    overview: dict[str, Any],
) -> str:
    risk_items = []
    for item in top_risks[:12]:
        risk_items.append(
            "<li>"
            f"<strong>{_html_escape(item.get('title', 'Risk path'))}</strong>"
            f"<span>risk {_html_escape(item.get('riskScore', 0))}</span>"
            f"<p>{_html_escape(item.get('summary', ''))}</p>"
            "</li>"
        )
    risk_html = "\n".join(risk_items) or "<li>No vulnerable paths were present in this graph export.</li>"
    sev = {key: overview.get(key, 0) for key in ("critical", "high", "medium", "low")} if isinstance(overview, dict) else {}
    sev_rows = ""
    if isinstance(sev, dict):
        sev_rows = "\n".join(f"<tr><th>{_html_escape(k)}</th><td>{_html_escape(v)}</td></tr>" for k, v in sorted(sev.items()))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-bom Supply Chain Graph — Offline</title>
<style>
  body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0f1419;color:#e7e9ea;margin:0;padding:32px;line-height:1.55}}
  main{{max-width:1040px;margin:0 auto}}
  h1{{font-size:28px;margin-bottom:8px}}
  .muted{{color:#9ba1a6}}
  .banner{{border:1px solid #2f3336;background:#11161c;border-radius:12px;padding:14px 16px;margin:18px 0}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}}
  .card{{border:1px solid #2f3336;background:#151b22;border-radius:12px;padding:14px}}
  .card strong{{display:block;font-size:28px;color:#d9ecff}}
  ol{{padding-left:24px}}
  li{{margin-bottom:12px;border-bottom:1px solid #242b33;padding-bottom:12px}}
  li span{{float:right;color:#ffd33d;font-weight:700}}
  li p{{margin:6px 0 0;color:#c6ccd3}}
  table{{border-collapse:collapse;width:100%;max-width:440px}}
  th,td{{border:1px solid #2f3336;padding:8px;text-align:left}}
  th{{color:#9ba1a6;font-weight:600}}
</style>
</head>
<body>
<main>
  <h1>agent-bom Supply Chain Graph</h1>
  <p class="muted">
    Static offline export for air-gapped review. Interactive Cytoscape rendering is disabled
    because external JavaScript assets were omitted.
  </p>
  <div class="banner">
    <strong>Offline HTML mode</strong> keeps the graph evidence readable without network access.
    Use the default graph-html export when interactive zoom, filtering, and PNG export are required.
  </div>
  <div class="cards">
    <div class="card"><strong>{total_agents}</strong>agents</div>
    <div class="card"><strong>{total_servers}</strong>servers</div>
    <div class="card"><strong>{total_pkgs}</strong>packages</div>
    <div class="card"><strong>{total_vulns}</strong>CVEs</div>
  </div>
  <h2>Top Risk Paths</h2>
  <ol>{risk_html}</ol>
  <h2>Severity Counts</h2>
  <table>{sev_rows}</table>
</main>
</body>
</html>"""


_GRAPH_HTML_TEMPLATE = _GRAPH_HTML_TEMPLATE_HEAD + _GRAPH_HTML_TEMPLATE_BODY
