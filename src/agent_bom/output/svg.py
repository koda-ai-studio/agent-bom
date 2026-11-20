"""SVG supply chain diagram generator.

Produces a self-contained SVG file showing the full AI supply chain hierarchy:
    Source/Provider --> Agent --> MCP Server --> Package (with CVE indicators)

Pure Python implementation — no external rendering dependencies required.
Output is viewable in any browser, image viewer, or embedded in HTML/markdown.

Usage:
    agent-bom scan --format svg -o supply-chain.svg
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.core.packages import canonical_package_key
from agent_bom.output.finding_views import cve_findings, sanitize_output_text, severity_value, topology_package_key

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius, MCPServer

# ── Layout constants ──────────────────────────────────────────────────────────

_COL_PROVIDER = 50
_COL_AGENT = 320
_COL_SERVER = 590
_COL_PACKAGE = 860
_COL_CVE = 1130

_NODE_W = 200
_NODE_H = 44
_NODE_RX = 8
_ROW_GAP = 14
_HEADER_H = 80
_ROWS_PER_PAGE = 50
_PAGE_HEADER_H = 34
_PAGE_GAP = 28
_DEFAULT_MAX_ROWS_PER_COLUMN = _ROWS_PER_PAGE

# ── Color palette ─────────────────────────────────────────────────────────────

_COLORS = {
    "provider": ("#1e3a5f", "#e8f0fe", "#90b4d6"),
    "agent": ("#1b5e20", "#e8f5e9", "#81c784"),
    "server_clean": ("#37474f", "#eceff1", "#90a4ae"),
    "server_vuln": ("#b71c1c", "#fbe9e7", "#ef9a9a"),
    "server_cred": ("#e65100", "#fff3e0", "#ffcc80"),
    "pkg_clean": ("#455a64", "#eceff1", "#b0bec5"),
    "pkg_vuln": ("#c62828", "#ffebee", "#ef9a9a"),
    "cve_critical": ("#d32f2f", "#ffcdd2", "#ef5350"),
    "cve_high": ("#e65100", "#ffe0b2", "#ff9800"),
    "cve_medium": ("#f9a825", "#fff9c4", "#ffee58"),
    "cve_low": ("#2e7d32", "#c8e6c9", "#66bb6a"),
    "omitted": ("#92400e", "#fffbeb", "#f59e0b"),
}

_FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"


@dataclass
class _Columns:
    """Rendered nodes per column plus the edges between adjacent columns."""

    providers: list[dict] = field(default_factory=list)
    agents: list[dict] = field(default_factory=list)
    servers: list[dict] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)
    provider_to_agents: list[tuple[str, str]] = field(default_factory=list)
    agent_to_servers: list[tuple[str, str]] = field(default_factory=list)
    server_to_packages: list[tuple[str, str]] = field(default_factory=list)
    package_to_cves: list[tuple[str, str]] = field(default_factory=list)

    def ordered(self) -> list[list[dict]]:
        return [self.providers, self.agents, self.servers, self.packages, self.cves]

    def all_edges(self) -> list[tuple[str, str]]:
        return self.provider_to_agents + self.agent_to_servers + self.server_to_packages + self.package_to_cves


@dataclass
class _Canvas:
    total_w: int
    total_h: int
    page_count: int
    page_h: int
    node_y: dict[str, float]
    node_page: dict[str, int]


def to_svg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
    *,
    max_rows_per_column: int | None = _DEFAULT_MAX_ROWS_PER_COLUMN,
) -> str:
    """Generate a self-contained SVG supply chain diagram.

    Shows hierarchical layout: Provider -> Agent -> MCP Server -> Package -> CVE
    Color-coded by severity and status.

    Args:
        report: The AI-BOM report.
        blast_radii: List of BlastRadius objects for CVE indicators.
        max_rows_per_column: Maximum rendered rows per SVG column. ``None``
            renders the full graph. The default keeps static SVG exports
            readable in browsers and reports by adding an explicit omission
            marker for oversized columns.

    Returns:
        Complete SVG document as a string.
    """
    if max_rows_per_column is not None and max_rows_per_column < 2:
        raise ValueError("max_rows_per_column must be at least 2 or None")

    cols = _collect_columns(report, blast_radii)
    # Deduplicate packages/servers (same ID can appear under multiple parents)
    cols.packages = _dedup_by_id(cols.packages)
    cols.servers = _dedup_by_id(cols.servers)
    graph_counts = {"agents": len(cols.agents), "servers": len(cols.servers), "packages": len(cols.packages), "cves": len(cols.cves)}
    omitted_counts = _bound_columns(cols, max_rows_per_column)
    omitted_nodes = sum(omitted_counts.values())

    canvas = _layout_canvas(cols)
    visible_node_ids = {item["id"] for column in cols.ordered() for item in column}
    unique_edges = set(cols.all_edges())
    rendered_edges = {edge for edge in unique_edges if edge[0] in visible_node_ids and edge[1] in visible_node_ids}
    omitted_edges = len(unique_edges) - len(rendered_edges)

    parts = _header_parts(canvas, graph_counts, omitted_counts, omitted_nodes, omitted_edges)
    parts.extend(_column_header_parts(has_cves=bool(cols.cves)))
    parts.extend(_page_frame_parts(canvas))
    parts.extend(_edge_parts(cols, canvas))
    for items, col_x, color_key in zip(cols.ordered(), _COLUMN_X, _COLUMN_COLOR_KEYS):
        parts.extend(_node_parts(items, col_x, color_key, canvas.node_y))

    if not report.agents:
        x, y = canvas.total_w / 2, canvas.total_h / 2
        parts.append(f'<text x="{x}" y="{y}" text-anchor="middle" font-size="16" fill="#999">No agents discovered</text>')

    parts.append("</svg>")
    return "\n".join(parts)


_COLUMN_X = (_COL_PROVIDER, _COL_AGENT, _COL_SERVER, _COL_PACKAGE, _COL_CVE)
_COLUMN_COLOR_KEYS = ("provider", "agent", "server_clean", "pkg_clean", "cve_medium")


def _collect_columns(report: AIBOMReport, blast_radii: list[BlastRadius]) -> _Columns:
    """Walk agents -> servers -> packages -> CVEs into per-column node lists."""
    findings = cve_findings(report, blast_radii)
    vuln_pkg_keys: set[tuple[str, str, str]] = {topology_package_key(finding) for finding in findings}
    pkg_cve_map: dict[tuple[str, str, str], list[dict]] = {}
    for finding in findings:
        pkg_cve_map.setdefault(topology_package_key(finding), []).append(
            {"id": finding.cve_id or finding.title, "severity": severity_value(finding)}
        )

    cols = _Columns()
    provider_set: set[str] = set()
    cve_set: set[str] = set()
    for agent in report.agents:
        source = agent.source or "local"
        if source not in provider_set:
            provider_set.add(source)
            cols.providers.append({"id": f"p:{source}", "label": _provider_label(source)})

        aid = f"a:{agent.name}"
        cols.agents.append({"id": aid, "label": agent.name, "type": agent.agent_type.value, "servers": len(agent.mcp_servers)})
        cols.provider_to_agents.append((f"p:{source}", aid))
        for srv in agent.mcp_servers:
            _collect_server(cols, aid, agent.name, srv, vuln_pkg_keys, pkg_cve_map, cve_set)
    return cols


def _collect_server(
    cols: _Columns,
    aid: str,
    agent_name: str,
    srv: MCPServer,
    vuln_pkg_keys: set[tuple[str, str, str]],
    pkg_cve_map: dict[tuple[str, str, str], list[dict]],
    cve_set: set[str],
) -> None:
    sid = f"s:{agent_name}:{srv.name}"
    has_vuln = any((p.name, p.ecosystem, p.version) in vuln_pkg_keys for p in srv.packages)
    has_cred = srv.has_credentials
    stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")
    cred_label = f" [{len(srv.credential_names)} cred]" if has_cred else ""
    cols.servers.append(
        {
            "id": sid,
            "label": srv.name + cred_label,
            "type": stype,
            "pkg_count": len(srv.packages),
            "tool_count": len(srv.tools) if srv.tools else 0,
        }
    )
    cols.agent_to_servers.append((aid, sid))

    for pkg in srv.packages:
        pkg_key = (pkg.name, pkg.ecosystem, pkg.version)
        pid = f"pkg:{canonical_package_key(pkg.name, pkg.version, pkg.ecosystem)}"
        is_vuln = pkg_key in vuln_pkg_keys
        cols.packages.append(
            {
                "id": pid,
                "label": f"{pkg.name}@{pkg.version}",
                "type": "pkg_vuln" if is_vuln else "pkg_clean",
                "ecosystem": pkg.ecosystem,
                "version_provenance": package_version_provenance(pkg),
            }
        )
        cols.server_to_packages.append((sid, pid))
        if is_vuln and pkg_key in pkg_cve_map:
            for cve_info in pkg_cve_map[pkg_key]:
                cve_id = f"cve:{cve_info['id']}"
                if cve_info["id"] not in cve_set:
                    cve_set.add(cve_info["id"])
                    cols.cves.append(
                        {"id": cve_id, "label": cve_info["id"], "type": f"cve_{cve_info['severity']}", "severity": cve_info["severity"]}
                    )
                cols.package_to_cves.append((pid, cve_id))


def _bound_columns(cols: _Columns, max_rows: int | None) -> dict[str, int]:
    omitted: dict[str, int] = {}
    cols.providers, omitted["sources"] = _bound_column(cols.providers, "sources", max_rows)
    cols.agents, omitted["agents"] = _bound_column(cols.agents, "agents", max_rows)
    cols.servers, omitted["servers"] = _bound_column(cols.servers, "servers", max_rows)
    cols.packages, omitted["packages"] = _bound_column(cols.packages, "packages", max_rows)
    cols.cves, omitted["CVEs"] = _bound_column(cols.cves, "CVEs", max_rows)
    return omitted


def _layout_canvas(cols: _Columns) -> _Canvas:
    """Assign every node a page and a Y position; size the document."""
    columns = cols.ordered()
    max_rows = max(len(col) for col in columns) if columns else 1
    page_count = max(1, (max_rows + _ROWS_PER_PAGE - 1) // _ROWS_PER_PAGE)
    page_h = _PAGE_HEADER_H + min(max_rows, _ROWS_PER_PAGE) * (_NODE_H + _ROW_GAP) + _PAGE_GAP
    total_h = _HEADER_H + page_count * page_h + 40

    node_y: dict[str, float] = {}
    node_page: dict[str, int] = {}
    for col_items in columns:
        for i, item in enumerate(col_items):
            page_idx = i // _ROWS_PER_PAGE
            page_top = _HEADER_H + page_idx * page_h
            node_y[item["id"]] = page_top + _PAGE_HEADER_H + (i % _ROWS_PER_PAGE) * (_NODE_H + _ROW_GAP)
            node_page[item["id"]] = page_idx

    total_w = _COL_CVE + _NODE_W + 60 if cols.cves else _COL_PACKAGE + _NODE_W + 60
    return _Canvas(total_w, total_h, page_count, page_h, node_y, node_page)


def _header_parts(
    canvas: _Canvas, graph_counts: dict[str, int], omitted_counts: dict[str, int], omitted_nodes: int, omitted_edges: int
) -> list[str]:
    total_w, total_h = canvas.total_w, canvas.total_h
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w} {total_h}" '
        f'width="{total_w}" height="{total_h}" '
        f'preserveAspectRatio="xMinYMin meet" '
        f'style="font-family: {_FONT}; font-size: 12px; background: #fafafa;">'
    ]
    if omitted_nodes or omitted_edges:
        omitted_label = ", ".join(f"{count} {kind}" for kind, count in omitted_counts.items() if count)
        parts.append(
            "<metadata>"
            f"Bounded SVG export: omitted {html.escape(omitted_label or '0 nodes')} "
            f"and {omitted_edges} edges. Export JSON, DOT, GraphML, or Cypher for the full graph."
            "</metadata>"
        )
    parts.append(_ARROW_DEFS)
    parts.append(
        f'<text x="{total_w / 2}" y="30" text-anchor="middle" '
        f'font-size="18" font-weight="bold" fill="#1a1a1a">'
        f"AI Supply Chain — agent-bom</text>"
    )
    parts.append(
        f'<text x="{total_w / 2}" y="52" text-anchor="middle" '
        f'font-size="13" fill="#666">'
        f"{graph_counts['agents']} agents | {graph_counts['servers']} servers | "
        f"{graph_counts['packages']} packages | {graph_counts['cves']} CVEs</text>"
    )
    if omitted_nodes or omitted_edges:
        parts.append(
            f'<text x="{total_w / 2}" y="70" text-anchor="middle" '
            f'font-size="11" fill="#92400e">'
            f"Bounded view: {omitted_nodes} nodes and {omitted_edges} edges omitted; export JSON/DOT/GraphML/Cypher for full graph</text>"
        )
    return parts


_ARROW_DEFS = """<defs>
  <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3"
    markerWidth="8" markerHeight="6" orient="auto-start-reverse">
    <path d="M 0 0 L 10 3 L 0 6 z" fill="#999"/>
  </marker>
</defs>"""


def _column_header_parts(*, has_cves: bool) -> list[str]:
    headers = [(_COL_PROVIDER, "Sources"), (_COL_AGENT, "Agents"), (_COL_SERVER, "MCP Servers"), (_COL_PACKAGE, "Packages")]
    if has_cves:
        headers.append((_COL_CVE, "CVEs"))
    return [
        f'<text x="{x + _NODE_W / 2}" y="{_HEADER_H - 12}" text-anchor="middle" font-size="13" font-weight="600" fill="#444">{label}</text>'
        for x, label in headers
    ]


def _page_frame_parts(canvas: _Canvas) -> list[str]:
    if canvas.page_count <= 1:
        return []
    parts = []
    for page_idx in range(canvas.page_count):
        page_top = _HEADER_H + page_idx * canvas.page_h
        parts.append(
            f'<g id="page-{page_idx + 1}">'
            f'<rect x="20" y="{page_top + 2}" width="{canvas.total_w - 40}" height="{canvas.page_h - _PAGE_GAP / 2}" '
            f'fill="none" stroke="#d7dde3" stroke-width="1" stroke-dasharray="6 6"/>'
            f'<text x="34" y="{page_top + 23}" font-size="12" font-weight="600" fill="#59636e">'
            f"Page {page_idx + 1} of {canvas.page_count}</text></g>"
        )
    return parts


def _edge_parts(cols: _Columns, canvas: _Canvas) -> list[str]:
    """Same-page edges as curves (drawn before nodes); cross-page edges summarized."""
    col_x_map: dict[str, int] = {}
    for items, col_x in zip(cols.ordered(), _COLUMN_X):
        for item in items:
            col_x_map[item["id"]] = col_x

    parts: list[str] = []
    seen_edges: set[tuple[str, str]] = set()
    skipped_cross_page_edges = 0
    for src, tgt in cols.all_edges():
        if (src, tgt) in seen_edges:
            continue
        seen_edges.add((src, tgt))
        if src not in canvas.node_y or tgt not in canvas.node_y:
            continue
        if canvas.node_page.get(src, 0) != canvas.node_page.get(tgt, 0):
            skipped_cross_page_edges += 1
            continue
        sx = col_x_map.get(src, 0) + _NODE_W
        sy = canvas.node_y[src] + _NODE_H / 2
        tx = col_x_map.get(tgt, 0)
        ty = canvas.node_y[tgt] + _NODE_H / 2
        mid = (sx + tx) / 2
        parts.append(
            f'<path d="M {sx} {sy} C {mid} {sy}, {mid} {ty}, {tx} {ty}" '
            f'fill="none" stroke="#ccc" stroke-width="1.5" marker-end="url(#arrow)"/>'
        )

    if skipped_cross_page_edges:
        parts.append(
            f'<text x="{canvas.total_w / 2}" y="{canvas.total_h - 18}" text-anchor="middle" font-size="12" fill="#6b7280">'
            f"{skipped_cross_page_edges} cross-page relationships summarized to keep dense SVG pages readable</text>"
        )
    return parts


def _node_parts(items: list[dict], col_x: int, color_key: str, node_y: dict[str, float]) -> list[str]:
    parts: list[str] = []
    for item in items:
        y = node_y.get(item["id"], 0)
        ctype = item.get("type", color_key)
        colors = _COLORS.get(ctype, _COLORS.get(color_key, ("#333", "#f5f5f5", "#999")))
        text_color, bg_color, border_color = colors
        label = html.escape(sanitize_output_text(item["label"])[:28])
        version_attrs = ""
        version_provenance = item.get("version_provenance")
        if isinstance(version_provenance, dict):
            source = html.escape(sanitize_output_text(version_provenance.get("version_source", "unknown")), quote=True)
            confidence = html.escape(sanitize_output_text(version_provenance.get("confidence", "unknown")), quote=True)
            version_attrs = f' data-version-source="{source}" data-version-confidence="{confidence}"'

        parts.append(
            f'<rect x="{col_x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" '
            f'rx="{_NODE_RX}" fill="{bg_color}" stroke="{border_color}" stroke-width="1.5"{version_attrs}/>'
        )
        parts.append(
            f'<text x="{col_x + _NODE_W / 2}" y="{y + _NODE_H / 2 + 4}" '
            f'text-anchor="middle" font-size="11" font-weight="500" fill="{text_color}">'
            f"{label}</text>"
        )
    return parts


def export_svg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
    output_path: str,
) -> None:
    """Generate and write SVG supply chain diagram to a file."""
    from pathlib import Path

    svg = to_svg(report, blast_radii)
    Path(output_path).write_text(svg, encoding="utf-8")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _dedup_by_id(items: list[dict]) -> list[dict]:
    """Deduplicate items by their 'id' key, keeping first occurrence."""
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        if item["id"] not in seen:
            seen.add(item["id"])
            result.append(item)
    return result


def _bound_column(items: list[dict], label: str, max_rows: int | None) -> tuple[list[dict], int]:
    """Bound a rendered SVG column and append a visible omission marker."""
    if max_rows is None or len(items) <= max_rows:
        return items, 0

    visible = items[: max_rows - 1]
    omitted = len(items) - len(visible)
    return [
        *visible,
        {
            "id": f"omitted:{label}",
            "label": f"{omitted} more {label} omitted",
            "type": "omitted",
        },
    ], omitted


def _provider_label(source: str) -> str:
    """Human-readable label for a provider source."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "aws-sagemaker": "AWS SageMaker",
        "azure-container-apps": "Azure Container Apps",
        "azure-ai-foundry": "Azure AI Foundry",
        "gcp-vertex-ai": "GCP Vertex AI",
        "gcp-cloud-run": "GCP Cloud Run",
        "databricks": "Databricks",
        "snowflake-cortex": "Snowflake Cortex",
        "snowflake-streamlit": "Snowflake Streamlit",
        "snowflake": "Snowflake",
        "mcp-registry": "MCP Registry",
        "smithery": "Smithery",
        "huggingface": "Hugging Face",
        "openai": "OpenAI",
        "mlflow": "MLflow",
        "wandb": "W&B",
    }
    return labels.get(source, source.replace("-", " ").title())
