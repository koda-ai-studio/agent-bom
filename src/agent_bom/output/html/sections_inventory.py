"""Output html sections inventory helpers."""

from __future__ import annotations

from agent_bom.models import AIBOMReport, MCPServer
from agent_bom.output.html._common import (
    _PKG_PREVIEW,
    _SEV_COLOR,
    _esc,
    _sev_badge,
)
from agent_bom.security import sanitize_launch_command, sanitize_path_label


def _skill_audit_section(report: "AIBOMReport") -> str:
    """Build the skill audit findings section if data is available."""
    data = getattr(report, "skill_audit_data", None)
    if not data:
        return ""

    findings = data.get("findings", [])
    passed = data.get("passed", True)
    pkgs_checked = data.get("packages_checked", 0)
    servers_checked = data.get("servers_checked", 0)
    creds_checked = data.get("credentials_checked", 0)
    ai_summary = data.get("ai_skill_summary", "")
    ai_risk = data.get("ai_overall_risk_level", "")

    status_color = "#16a34a" if passed else "#dc2626"
    status_text = "PASSED" if passed else "FAILED"

    summary_html = ""
    if ai_summary:
        summary_html = (
            f'<div class="hint-box" style="border-color:#818cf840;background:#1e1b4b40">'
            f'<strong style="color:#c7d2fe">AI Analysis:</strong> {_esc(ai_summary)}'
            f"</div>"
        )

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f'<span>Status: <strong style="color:{status_color}">{status_text}</strong></span>'
        f"<span>Packages checked: <strong>{pkgs_checked}</strong></span>"
        f"<span>Servers checked: <strong>{servers_checked}</strong></span>"
        f"<span>Credentials checked: <strong>{creds_checked}</strong></span>"
        + (
            f'<span>AI risk level: <strong style="color:{_SEV_COLOR.get(ai_risk, "#64748b")}">{_esc(ai_risk).upper()}</strong></span>'
            if ai_risk
            else ""
        )
        + "</div>"
    )

    if not findings:
        return (
            f'<section id="skillaudit">'
            f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit</div>'
            f'<div class="panel">{stats_html}{summary_html}'
            f'<div class="empty-state">&#x2705; No security findings in skill files.</div>'
            f"</div></section>"
        )

    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(f.get("title", ""))}</td>'
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(f.get("category", ""))}</code></td>'
            f'<td style="font-size:.78rem;color:#94a3b8;max-width:300px">{_esc(f.get("detail", ""))}</td>'
            f'<td style="font-size:.75rem;color:#64748b">{_esc(f.get("source_file", ""))}</td>'
            f'<td style="font-size:.75rem;color:#4ade80">{_esc(f.get("recommendation", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Finding", "Category", "Detail", "Source", "Recommendation"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="skillaudit">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">{stats_html}{summary_html}{table_html}</div>'
        f"</section>"
    )


def _ai_inventory_section(report: "AIBOMReport") -> str:
    """Build the AI component inventory section if data is available."""
    data = getattr(report, "ai_inventory_data", None)
    if not data:
        return ""

    components = data.get("components", [])
    total = data.get("total_components", 0)
    files_scanned = data.get("files_scanned", 0)
    shadow_count = data.get("shadow_ai_count", 0)
    deprecated_count = data.get("deprecated_models_count", 0)
    unique_sdks = data.get("unique_sdks", [])
    unique_models = data.get("unique_models", [])

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f"<span>Files scanned: <strong>{files_scanned}</strong></span>"
        f"<span>Components: <strong>{total}</strong></span>"
        f"<span>SDKs: <strong>{len(unique_sdks)}</strong></span>"
        f"<span>Models: <strong>{len(unique_models)}</strong></span>"
        + (f'<span>Shadow AI: <strong style="color:#eab308">{shadow_count}</strong></span>' if shadow_count else "")
        + (f'<span>Deprecated: <strong style="color:#f97316">{deprecated_count}</strong></span>' if deprecated_count else "")
        + "</div>"
    )

    if not components:
        return (
            f'<section id="aiinventory">'
            f'<div class="sec-title">&#x1f916; AI Component Inventory</div>'
            f'<div class="panel">{stats_html}'
            f'<div class="empty-state">&#x2705; No AI components detected.</div>'
            f"</div></section>"
        )

    rows = []
    for c in components:
        sev = c.get("severity", "info")
        comp_type = c.get("type", "").replace("_", " ")
        # Redact API key values — never render credential fragments in HTML
        raw_name = c.get("name", "")
        name = "[REDACTED]" if c.get("type") == "api_key" else _esc(raw_name)
        shadow_tag = ' <span style="color:#eab308;font-size:.7rem">(shadow)</span>' if c.get("is_shadow") else ""
        replacement = c.get("deprecated_replacement", "")
        repl_tag = f'<br><span style="color:#64748b;font-size:.7rem">&rarr; {_esc(replacement)}</span>' if replacement else ""
        file_loc = f"{_esc(c.get('file', ''))}:{c.get('line', '')}"
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(comp_type)}</code></td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{name}{shadow_tag}{repl_tag}</td>'
            f'<td style="font-size:.75rem;color:#64748b">{file_loc}</td>'
            f'<td style="font-size:.75rem;color:#67e8f9">{_esc(c.get("language", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Type", "Name", "File", "Language"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="aiinventory">'
        f'<div class="sec-title">&#x1f916; AI Component Inventory'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{total}</sup></div>'
        f'<div class="panel">{stats_html}{table_html}</div>'
        f"</section>"
    )


def _inventory_cards(report: "AIBOMReport") -> str:
    cards = []
    for agent in report.agents:
        total_vulns = agent.total_vulnerabilities
        total_creds = sum(len(s.credential_names) for s in agent.mcp_servers)
        agent_badges = []
        if total_vulns:
            agent_badges.append(f'<span class="badge-vuln">{total_vulns} vuln{"s" if total_vulns != 1 else ""}</span>')
        if total_creds:
            agent_badges.append(f'<span class="badge-cred">{total_creds} credential{"s" if total_creds != 1 else ""}</span>')
        badges_html = " ".join(agent_badges)

        servers_html = [_server_inventory_card(srv) for srv in agent.mcp_servers]

        servers_content = (
            "".join(servers_html) if servers_html else ('<p style="color:#334155;font-size:.85rem">No MCP servers configured.</p>')
        )

        cards.append(
            f'<details class="agent-card" open>'
            f'<summary class="agent-summary">'
            f"<span>&#x1f916; {_esc(agent.name)}</span>"
            f'<span style="display:flex;align-items:center;gap:8px">'
            f"{badges_html}"
            f'<span style="font-size:.72rem;color:#475569">'
            f"{agent.total_mcp_servers} server(s) &middot; {agent.total_packages} pkg(s)"
            f"</span>"
            f"</span>"
            f"</summary>"
            f'<div class="agent-detail">'
            f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">'
            f"{_esc(agent.agent_type.value)} &middot; {_esc(sanitize_path_label(agent.config_path) if agent.config_path else '')}"
            f"</div>"
            f"{servers_content}"
            f"</div>"
            f"</details>"
        )
    return "".join(cards)


def _server_package_preview(srv: MCPServer) -> tuple[str, int]:
    # Packages — preview first N, collapse rest
    pkgs = srv.packages
    pkg_count = len(pkgs)
    preview = pkgs[:_PKG_PREVIEW]
    rest = pkgs[_PKG_PREVIEW:]

    def pkg_row(p: object) -> str:
        from agent_bom.models import Package

        if not isinstance(p, Package):
            return ""
        color = "#f87171" if p.has_vulnerabilities else "#38bdf8"
        vuln_mark = " &#x26a0;" if p.has_vulnerabilities else ""
        return (
            f'<div class="pkg-row">'
            f'<span><code style="color:{color};font-size:.72rem">{_esc(p.ecosystem)}</code>'
            f' <span class="pkg-name">{_esc(p.name)}</span></span>'
            f'<span class="pkg-ver">{_esc(p.version)}{vuln_mark}</span>'
            f"</div>"
        )

    pkg_html = ""
    if pkgs:
        preview_rows = "".join(pkg_row(p) for p in preview)
        if rest:
            uid = f"pkgs_{id(srv)}"
            rest_rows = "".join(pkg_row(p) for p in rest)
            pkg_html = (
                f'<div style="margin-top:8px">'
                f"{preview_rows}"
                f'<div id="{uid}" style="display:none">{rest_rows}</div>'
                f'<button class="toggle-btn" onclick="togglePkgs(\'{uid}\',this)">'
                f"Show {len(rest)} more packages &#x25bc;</button>"
                f"</div>"
            )
        else:
            pkg_html = f'<div style="margin-top:8px">{preview_rows}</div>'
    return pkg_html, pkg_count


def _server_inventory_card(srv: MCPServer) -> str:
    vuln_pkgs = [p for p in srv.packages if p.has_vulnerabilities]
    accent = "#ef4444" if vuln_pkgs else ("#f59e0b" if srv.has_credentials else "#334155")
    srv_badges = []
    if vuln_pkgs:
        srv_badges.append('<span class="badge-vuln">VULN</span>')
    if srv.has_credentials:
        srv_badges.append('<span class="badge-cred">CREDS</span>')

    cmd = ""
    if srv.command:
        cmd = _esc(sanitize_launch_command(srv.command, srv.args, max_args=3))
        if srv.args and len(srv.args) > 3:
            cmd += f' <span style="color:#334155">&hellip;+{len(srv.args) - 3} args</span>'

    # Credentials section
    creds_html = ""
    if srv.credential_names:
        creds_html = (
            '<div style="margin-top:8px">'
            + "".join(
                f'<div style="font-size:.74rem;color:#fbbf24;padding:2px 0">&#x1f511; <code>{_esc(c)}</code></div>'
                for c in srv.credential_names
            )
            + "</div>"
        )

    pkg_html, pkg_count = _server_package_preview(srv)

    srv_badges_html = " ".join(srv_badges)
    srv_header = (
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
        f'<div style="font-weight:600;color:#e2e8f0;font-size:.9rem">&#x2699;&#xfe0f; {_esc(srv.name)} {srv_badges_html}</div>'
        f'<div style="font-size:.72rem;color:#475569">{pkg_count} pkg{"s" if pkg_count != 1 else ""}</div>'
        f"</div>"
    )
    cmd_html = (
        f'<div style="font-size:.72rem;color:#475569;font-family:monospace;margin-bottom:6px;word-break:break-all">{cmd}</div>'
        if cmd
        else ""
    )

    return f'<div class="server-card" style="border-left-color:{accent}">{srv_header}{cmd_html}{creds_html}{pkg_html}</div>'
