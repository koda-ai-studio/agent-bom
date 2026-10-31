"""Embedded CSS/theme for the HTML report."""

from __future__ import annotations

_REPORT_LAYOUT_CSS = """
    .row-detail-toggle{display:none}
    [hidden]{display:none!important}
    .graph-view-switch{display:flex;gap:8px;margin-bottom:12px}
    .graph-view-switch button,.graph-relationships button{background:#1e293b;color:#cbd5e1;border:1px solid #475569;border-radius:7px;padding:8px 12px;cursor:pointer;font:inherit;font-size:.8rem}
    .graph-view-switch button[aria-pressed="true"]{background:#064e3b;color:#d1fae5;border-color:#10b981}
    .graph-relationships{border:1px solid #334155;border-radius:12px;padding:16px}
    .graph-relationships ol{list-style:none;margin:0;padding:0}
    .graph-relationships li{display:grid;grid-template-columns:minmax(0,1fr) 110px minmax(0,1fr);gap:12px;padding:12px 0;border-bottom:1px solid #334155;font-size:.83rem;overflow-wrap:anywhere}
    .graph-relationships li span{color:#94a3b8;font-size:.75rem}
    .graph-relationships button:disabled{opacity:.4;cursor:default}
    .graph-container{display:flex;flex-direction:column}
    .small-graph .cy-minimap{display:none}
    .graph-filter-bar{order:-1}
    .headline-risks{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:12px;list-style:none;padding:0;margin:16px 0 0}
    .headline-risk{min-width:0;padding:16px;border:1px solid #334155;border-radius:10px;background:#0f172a}
    .headline-risk h3{font-size:.88rem;line-height:1.5;margin:0;overflow-wrap:anywhere}
    .headline-risk-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    .headline-risk summary{cursor:pointer;font-size:.78rem;color:#cbd5e1;margin-top:14px}
    .headline-risk dl{font-size:.78rem;line-height:1.5;margin:12px 0 0}
    .headline-risk dt{color:#94a3b8;margin-top:8px}
    .headline-risk dd{margin:0;overflow-wrap:anywhere;color:#e2e8f0}
    .headline-risk-note{font-size:.7rem;color:#94a3b8;margin:10px 0 0}
    .report-disclosure{border:1px solid #334155;border-radius:12px;padding:16px;min-width:0}
    .report-disclosure>summary{font-weight:600;font-size:.9rem;color:#e2e8f0;cursor:pointer}
    .report-disclosure[open]>summary{margin-bottom:18px}
    .report-disclosure>.sec-title{display:none}
    .finding-overview,.finding-overview thead,.finding-overview tbody{display:block;width:100%}
    .finding-overview tr{display:grid;grid-template-columns:minmax(0,1fr) 110px 150px 145px;align-items:start}
    .finding-overview th,.finding-overview td{min-width:0;overflow-wrap:anywhere;white-space:normal}
    .finding-overview th{text-align:left}
    .finding-overview td{border-bottom:0}
    .finding-overview tbody tr{border-bottom:1px solid #334155}
    .finding-overview tbody tr:hover{background:#1e293b}
    .finding-overview tbody tr:hover td{background:transparent}
    .finding-overview td:first-child>br{display:none}
    .finding-overview .match-tier,.finding-overview .workload-runtime-evidence{display:block;margin-top:4px}
    .finding-overview .vuln-id{font-size:.88rem;color:#bfdbfe;word-break:normal}
    .finding-package{margin-top:6px;color:#e2e8f0;font-size:.85rem;font-weight:600}
    .finding-package span{color:#94a3b8;font-weight:400}
    .finding-overview tr:has(.finding-evidence[open]) .finding-evidence-cell{grid-column:1/-1}
    .finding-evidence>summary{cursor:pointer;color:#6ee7b7;font-size:.8rem;white-space:nowrap}
    .finding-evidence[open]>summary{margin-bottom:16px}
    .finding-evidence-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,200px),1fr));gap:16px 24px;padding:18px;background:#0f172a;border:1px solid #334155;border-radius:8px}
    .finding-evidence-grid div{min-width:0}
    .finding-evidence-grid dt{font-size:.7rem;color:#94a3b8;margin-bottom:6px}
    .finding-evidence-grid dd{margin:0;font-size:.83rem;color:#e2e8f0;overflow-wrap:anywhere}
    .finding-description{font-size:.83rem;line-height:1.7;color:#cbd5e1;max-width:90ch;max-height:20rem;overflow:auto;margin-top:16px;white-space:pre-wrap}
    .evidence-unavailable{color:#94a3b8;font-size:.8rem}
    :focus-visible{outline:2px solid #38bdf8;outline-offset:3px}

    .graph-filter-bar{position:relative!important;top:auto!important;left:auto!important;flex-wrap:wrap;padding-right:50px!important}
    @media screen and (max-width:700px){
      .tab-bar{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));overflow:visible;gap:2px}
      .tab-btn{padding:9px 4px;font-size:.75rem;white-space:normal}
      .paginated,.paginated tbody,.paginated tr:not(.pg-hidden){display:block;width:100%}
      .paginated thead{display:none}
      .paginated tr:not(.pg-hidden){border:1px solid #334155;border-radius:10px;padding:10px;margin-bottom:12px}
      .paginated td{display:block;max-width:none!important;width:100%;padding:8px!important;overflow-wrap:anywhere;white-space:normal!important}
      .paginated td::before{content:attr(data-label);display:block;font-size:.65rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
      .paginated tr:not(.row-expanded) td:nth-child(n+4){display:none}
      .paginated.finding-overview tr:not(.row-expanded) td.finding-evidence-cell{display:block}
      .finding-overview .finding-evidence-cell::before{display:none}
      .row-detail-toggle{display:block;margin-top:8px;background:transparent;border:1px solid #475569;border-radius:6px;color:#a7f3d0;padding:5px 10px;font:inherit;font-size:.75rem;cursor:pointer}
      .graph-relationships li{grid-template-columns:minmax(0,1fr);gap:4px}
      .cy-minimap{display:none}
      .container{padding-left:16px;padding-right:16px}
      .panel{padding:16px}
      .report-disclosure{padding:12px}
      .agent-summary{flex-wrap:wrap;gap:8px;overflow-wrap:anywhere}
      #cy,#cyAttack{height:clamp(320px,65dvh,560px)}
      .legend{gap:10px;font-size:.72rem}
    }
"""


_REPORT_PRINT_CSS = """\
    @page{size:A4;margin:12mm}
    @media print{
      body{background:#fff;color:#1e293b;font-size:12px}
      .sidebar,.graph-controls,.graph-filter-bar,.vuln-filter-bar,.policy-filter-bar,.toggle-btn,.inv-search,.print-btn,.node-sidebar,.sidebar-toggle,.cy-minimap{display:none!important}
      .container{margin-left:0;max-width:100%;padding:10px}
      footer{margin-left:0}
      section{break-inside:auto;margin-bottom:20px}
      section[data-tab="graphs"],section#inventory,section#vulns,section#compliance,section#remediation{break-before:page}
      h3,.sec-title,summary{break-after:avoid}
      tr,.stat-card,.graph-container{break-inside:avoid}
      thead{display:table-header-group}
      .report-disclosure{border:0;padding:0}
      .graph-view-switch,.graph-relationships{display:none!important}
      .row-detail-toggle{display:none!important}
      .graph-container[hidden]{display:flex!important}
      .report-disclosure>summary,.agent-summary,.agent-name{color:#0f172a}
      .panel,.stat-card,.agent-card,.server-card,.chart-panel{background:#f8fafc;border:1px solid #e2e8f0;box-shadow:none}
      .headline-risk{background:#fff;border-color:#cbd5e1;break-inside:avoid}
      .headline-risk h3,.headline-risk summary,.headline-risk dd{color:#0f172a}
      .headline-risk dt,.headline-risk-note{color:#475569}
      .charts-row{grid-template-columns:1fr 1fr;gap:12px;break-inside:avoid}
      .chart-panel{padding:12px}
      .chart-wrap,.donut-wrap{height:200px}
      .charts-row canvas{max-height:200px}
      .stat-value,.sec-title{color:#0f172a}
      .data-table th{background:#f1f5f9;color:#334155;border-bottom:2px solid #cbd5e1}
      .data-table td{border-bottom:1px solid #e2e8f0}
      .data-table{table-layout:fixed;width:100%}
      .data-table th,.data-table td{white-space:normal!important;overflow-wrap:anywhere}
      .panel p,.panel div,.panel span,.panel a,.panel strong,.panel code,.panel td,.agent-detail,.agent-detail *{color:#1e293b!important}
      .table-wrap{overflow:visible}
      .paginated,.paginated tbody{display:block;width:100%}
      .paginated thead{display:none}
      .data-table.paginated tr,.data-table.paginated tr.pg-hidden{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;border:1px solid #cbd5e1;border-radius:8px;padding:10px;margin:0 0 14px;break-inside:avoid}
      .paginated td{display:block;min-width:0;max-width:none!important;width:auto;padding:4px;overflow-wrap:anywhere;white-space:normal!important;font-size:10px}
      .paginated td::before{content:attr(data-label);display:block;color:#475569;font-size:8px;font-weight:600;margin-bottom:3px}
      .finding-overview .finding-evidence-cell{grid-column:1/-1}
      .finding-evidence-grid{grid-template-columns:repeat(3,minmax(0,1fr));background:#fff;border-color:#cbd5e1;padding:10px;gap:10px}
      .finding-evidence-grid dt,.finding-evidence-grid dd,.finding-evidence>summary{color:#1e293b}
      .finding-description{max-height:none;overflow:visible;font-size:10px}
      .path-rank,.path-meta span{background:#f1f5f9;border-color:#e2e8f0}
      .path-title{color:#0f172a}
      .path-summary{color:#475569}
      .path-fix{color:#15803d}
      #cy,#cyAttack{height:360px;background:#0f172a;border:1px solid #e2e8f0;print-color-adjust:exact}
      .legend{color:#475569}
      a{color:#2563eb}
      footer{color:#94a3b8}
      .graph-container{border:1px solid #e2e8f0}
    }
"""


def render_styles(status_color: str) -> str:
    """Return the report's inline <style> block."""
    return f"""  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b1120;color:#cbd5e1;line-height:1.6;font-size:14px}}
    a{{color:#60a5fa;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    code{{font-family:"SF Mono","Cascadia Code",Consolas,monospace;font-size:.9em}}

    /* SIDEBAR NAV */
    .sidebar{{position:fixed;top:0;left:0;bottom:0;width:220px;background:#0a0f1a;border-right:1px solid #1e293b;z-index:100;display:flex;flex-direction:column;overflow-y:auto;transition:width .2s}}
    .sidebar-brand{{display:flex;align-items:center;gap:10px;padding:18px 18px 14px;border-bottom:1px solid #1e293b18}}
    .sidebar-brand .brand-icon{{width:32px;height:32px;border-radius:8px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2);display:flex;align-items:center;justify-content:center;font-size:1rem}}
    .sidebar-brand .brand-text{{font-weight:700;font-size:.88rem;color:#f1f5f9;letter-spacing:-.01em}}
    .sidebar-brand .brand-sub{{font-size:.6rem;color:#475569;font-family:monospace}}
    .sidebar-status{{padding:8px 18px 12px;display:flex;align-items:center;gap:8px}}
    .status-badge{{padding:3px 10px;border-radius:5px;font-size:.62rem;font-weight:700;letter-spacing:.05em;background:{status_color}12;color:{status_color};border:1px solid {status_color}25;white-space:nowrap}}
    .scan-time{{color:#475569;font-size:.62rem;white-space:nowrap}}
    .sidebar-group{{padding:4px 0}}
    .sidebar-group-label{{font-size:.58rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#3f4f65;padding:10px 18px 4px;user-select:none}}
    .sidebar-link{{display:flex;align-items:center;gap:8px;padding:7px 18px;font-size:.78rem;color:#64748b;text-decoration:none;border-left:2px solid transparent;transition:all .12s;cursor:pointer}}
    .sidebar-link:hover{{background:#111827;color:#e2e8f0;text-decoration:none;border-left-color:#334155}}
    .sidebar-link.active{{background:rgba(16,185,129,.08);color:#10b981;border-left-color:#10b981;font-weight:600}}
    .sidebar-link .link-icon{{font-size:.85rem;width:20px;text-align:center;flex-shrink:0}}
    .sidebar-link .link-badge{{margin-left:auto;font-size:.6rem;font-weight:700;padding:1px 6px;border-radius:10px;font-family:monospace}}
    .sidebar-spacer{{flex:1}}
    .sidebar-footer{{padding:14px 18px;border-top:1px solid #1e293b18;font-size:.65rem;color:#334155}}
    .sidebar-footer a{{color:#475569}}
    .print-btn{{background:transparent;border:1px solid #1e293b;color:#475569;font-size:.68rem;padding:5px 12px;border-radius:6px;cursor:pointer;transition:all .15s;width:100%;margin-top:8px;text-align:center}}
    .print-btn:hover{{background:#111827;color:#94a3b8}}

    /* MOBILE SIDEBAR TOGGLE */
    .sidebar-toggle{{display:none;position:fixed;top:12px;left:12px;z-index:200;width:36px;height:36px;border-radius:8px;background:rgba(10,15,26,.95);border:1px solid #1e293b;color:#94a3b8;font-size:18px;cursor:pointer;backdrop-filter:blur(8px)}}

    /* LAYOUT */
    .container{{max-width:1400px;margin:0 auto;padding:28px 32px 80px;margin-left:220px}}
    section{{margin-bottom:44px;scroll-margin-top:20px}}
    .sec-title{{font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid #1e293b}}
    .panel{{background:#1e293b;border-radius:12px;padding:24px;border:1px solid #ffffff08}}
    /* STAT CARDS */
    .stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px}}
    .stat-card{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:10px;padding:20px 22px;border-left:4px solid #334155;border:1px solid #ffffff06;transition:transform .15s,box-shadow .15s}}
    .stat-card:hover{{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}}
    .stat-icon{{font-size:1.4rem;margin-bottom:6px}}
    .stat-value{{font-size:2.2rem;font-weight:800;line-height:1;margin-bottom:6px}}
    .stat-label{{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em}}

    /* CHARTS ROW */
    .charts-row{{display:grid;grid-template-columns:320px 1fr;gap:16px}}
    .chart-panel{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:12px;padding:24px;border:1px solid #ffffff06}}
    .chart-title{{font-size:.73rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:16px}}
    .chart-wrap{{position:relative}}
    .donut-wrap{{max-width:260px;margin:0 auto}}

    /* GRAPH */
    .graph-container{{position:relative;border-radius:12px;overflow:hidden;border:1px solid #ffffff08}}
    .graph-container:fullscreen{{border-radius:0;background:#0f172a}}
    .graph-container:fullscreen .cy-graph{{height:100vh}}
    .cy-graph{{width:100%;height:600px;background:#0f172a}}
    #cy{{width:100%;height:clamp(320px,60dvh,560px)}}
    #cyAttack{{width:100%;height:clamp(320px,55dvh,520px)}}
    .graph-controls{{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:10}}
    .graph-btn{{width:36px;height:36px;border-radius:8px;border:1px solid #334155;background:rgba(15,23,42,.85);color:#94a3b8;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;backdrop-filter:blur(8px)}}
    .graph-btn:hover{{background:#1e293b;color:#e2e8f0;border-color:#475569}}
    .legend{{display:flex;gap:20px;flex-wrap:wrap;font-size:.76rem;color:#64748b;margin-top:12px;padding:0 4px}}
    .legend span{{display:flex;align-items:center;gap:6px}}
    .legend i{{display:inline-block;width:10px;height:10px;border-radius:3px}}
    .legend i.diamond{{transform:rotate(45deg);border-radius:1px}}

    /* MINIMAP */
    .cy-minimap{{position:absolute;bottom:12px;left:12px;width:180px;height:130px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;overflow:hidden;z-index:10;backdrop-filter:blur(8px)}}
    .cy-minimap canvas{{width:100%!important;height:100%!important}}

    /* CONTEXT MENU */
    .cy-ctx-menu{{position:fixed;background:rgba(15,23,42,.97);border:1px solid #334155;border-radius:10px;padding:6px 0;min-width:200px;z-index:300;backdrop-filter:blur(12px);box-shadow:0 8px 32px rgba(0,0,0,.5);display:none}}
    .cy-ctx-menu.show{{display:block}}
    .cy-ctx-item{{padding:8px 16px;font-size:.8rem;color:#cbd5e1;cursor:pointer;display:flex;align-items:center;gap:8px;transition:background .1s}}
    .cy-ctx-item:hover{{background:#1e293b;color:#f1f5f9}}
    .cy-ctx-sep{{height:1px;background:#1e293b;margin:4px 0}}

    /* RISK PULSE for critical nodes */
    @keyframes riskPulse{{0%{{box-shadow:0 0 0 0 rgba(220,38,38,.5)}}70%{{box-shadow:0 0 0 12px rgba(220,38,38,0)}}100%{{box-shadow:0 0 0 0 rgba(220,38,38,0)}}}}

    /* NODE DETAIL SIDEBAR */
    .node-sidebar{{position:fixed;top:0;right:0;bottom:0;width:340px;background:rgba(15,23,42,.97);border-left:1px solid #334155;backdrop-filter:blur(12px);z-index:200;overflow-y:auto;transform:translateX(100%);transition:transform .25s ease;padding:0}}
    .node-sidebar.open{{transform:translateX(0);display:block}}
    .sidebar-header{{display:flex;justify-content:space-between;align-items:center;padding:16px 20px 8px;border-bottom:1px solid #1e293b}}
    .sidebar-type{{font-size:.65rem;letter-spacing:.08em;text-transform:uppercase;color:#64748b;font-weight:700;padding:3px 8px;border-radius:4px;border:1px solid #334155}}
    .sidebar-close{{background:none;border:none;color:#64748b;font-size:1.4rem;cursor:pointer;padding:4px 8px;border-radius:4px;transition:all .15s}}
    .sidebar-close:hover{{color:#e2e8f0;background:#1e293b}}
    .sidebar-name{{font-size:1rem;font-weight:700;color:#f1f5f9;padding:12px 20px 4px;margin:0}}
    .sidebar-meta{{font-size:.78rem;color:#94a3b8;padding:0 20px 12px;font-family:monospace;white-space:pre-line}}
    .sidebar-section{{padding:0 20px 16px}}
    .sidebar-section:empty{{display:none}}
    .sidebar-label{{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:#64748b;font-weight:700;margin-bottom:8px}}
    .sidebar-list{{list-style:none;padding:0;margin:0}}
    .sidebar-list li{{font-size:.8rem;color:#cbd5e1;padding:5px 0;border-bottom:1px solid #0f172a}}
    .sidebar-list li:last-child{{border-bottom:none}}
    .sidebar-link{{color:#60a5fa;font-size:.78rem;text-decoration:none}}
    .sidebar-link:hover{{text-decoration:underline;color:#93c5fd}}
    .sidebar-cred{{color:#fbbf24;font-family:monospace;font-size:.78rem}}
    @media(max-width:900px){{.node-sidebar{{width:100%}}}}

    /* TOOLTIP */
    #tip{{position:fixed;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;font-size:.76rem;color:#e2e8f0;pointer-events:none;white-space:pre-line;max-width:280px;z-index:9999;display:none;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.4)}}

    /* TABS */
    .tab-bar{{display:flex;gap:2px;overflow-x:auto;max-width:100%;margin:0 0 24px;border-bottom:1px solid #334155;position:sticky;top:0;background:#0b1120;z-index:60;padding-top:6px;scrollbar-width:thin}}
    .tab-btn{{background:transparent;border:none;border-bottom:2px solid transparent;color:#94a3b8;font-size:.82rem;font-weight:600;padding:11px 14px;cursor:pointer;transition:color .15s,border-color .15s;letter-spacing:.01em;white-space:nowrap;flex-shrink:0}}
    .tab-btn:hover{{color:#e2e8f0}}
    .tab-btn.active{{color:#10b981;border-bottom-color:#10b981}}
    .tab-count{{font-size:.66rem;background:#1e293b;color:#94a3b8;border-radius:10px;padding:1px 7px;margin-left:7px;font-weight:700}}
    .tab-btn.active .tab-count{{background:rgba(16,185,129,.15);color:#6ee7b7}}
    body.js-tabs .container>section[data-tab]{{display:none}}
    body.js-tabs .container>section[data-tab].tab-active{{display:block}}

    /* PAGINATION */
    .pager{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:14px;padding:10px 14px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;font-size:.76rem;color:#94a3b8}}
    .pager-btn{{background:#1e293b;border:1px solid #334155;color:#cbd5e1;font-size:.74rem;font-weight:600;padding:5px 11px;border-radius:6px;cursor:pointer;transition:all .12s}}
    .pager-btn:hover:not(:disabled){{background:#334155;color:#f1f5f9}}
    .pager-btn:disabled{{opacity:.35;cursor:default}}
    .pager-info{{color:#cbd5e1;font-variant-numeric:tabular-nums;padding:0 4px}}
    .pager-sep{{flex:1}}
    .pager-size-label{{display:flex;align-items:center;gap:6px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;font-size:.68rem;font-weight:700}}
    .pager-size{{background:#1e293b;border:1px solid #334155;border-radius:6px;color:#e2e8f0;font-size:.74rem;padding:4px 6px;outline:none}}
    .pg-hidden{{display:none}}
    @media print{{
      .tab-bar,.pager{{display:none!important}}
      body.js-tabs .container>section[data-tab]{{display:block!important}}
      .pg-hidden{{display:table-row!important}}
    }}

    /* TABLES */
    .table-wrap{{overflow-x:auto;border-radius:8px}}
    .data-table{{width:100%;border-collapse:collapse;font-size:.83rem}}
    .data-table th{{padding:10px 14px;font-size:.68rem;letter-spacing:.06em;color:#64748b;font-weight:700;text-transform:uppercase;border-bottom:2px solid #334155;white-space:nowrap;background:#0f172a;position:sticky;top:0}}
    .data-table.sortable th{{cursor:pointer;user-select:none;transition:color .15s}}
    .data-table.sortable th:hover{{color:#e2e8f0}}
    .sort-arrow{{font-size:.6rem;margin-left:3px;opacity:.4}}
    .sort-arrow.asc::after{{content:"\\25B2"}}
    .sort-arrow.desc::after{{content:"\\25BC"}}
    .data-table td{{padding:10px 14px;border-bottom:1px solid #1e293b;vertical-align:middle}}
    .data-table tr{{transition:background .1s}}
    .data-table tr:hover td{{background:rgba(255,255,255,.03)}}

    /* BADGES */
    .badge-kev{{background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700}}
    .badge-exploit-likely{{background:#7c2d12;color:#fdba74;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700}}
    .badge-exploit-public{{background:#713f12;color:#fde047;padding:2px 8px;border-radius:4px;font-size:.66rem;font-weight:600}}
    .badge-ai{{background:#1d4ed8;color:#bfdbfe;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;margin-right:4px}}
    .badge-vuln{{background:#7f1d1d;color:#fca5a5;font-size:.65rem;padding:2px 6px;border-radius:4px;font-weight:700}}
    .badge-cred{{background:#78350f;color:#fde68a;font-size:.65rem;padding:2px 6px;border-radius:4px;font-weight:700}}
    .vuln-id{{color:#93c5fd;font-size:.78rem}}

    /* REMEDIATION */
    .exposure-paths{{display:grid;gap:12px}}
    .exposure-path-card{{display:flex;gap:14px;padding:14px 0;border-bottom:1px solid #1e293b}}
    .exposure-path-card:last-child{{border-bottom:none}}
    .path-rank{{width:42px;height:42px;border:2px solid #334155;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;flex-shrink:0;background:#0f172a}}
    .path-body{{min-width:0;flex:1}}
    .path-title{{color:#e2e8f0;font-weight:700;font-size:.92rem;margin-bottom:4px}}
    .path-summary{{color:#94a3b8;font-size:.82rem;line-height:1.45;margin-bottom:8px}}
    .path-meta{{display:flex;flex-wrap:wrap;gap:8px;color:#64748b;font-size:.74rem;margin-bottom:8px}}
    .path-meta span{{background:#0f172a;border:1px solid #1e293b;border-radius:999px;padding:3px 8px}}
    .path-fix{{color:#4ade80;font-size:.78rem;font-weight:600}}
    .remediation-item{{display:flex;align-items:flex-start;gap:14px;padding:16px 0;border-bottom:1px solid #1e293b;transition:background .1s}}
    .remediation-item:hover{{background:rgba(255,255,255,.02);margin:0 -12px;padding-left:12px;padding-right:12px;border-radius:8px}}
    .subsection-label{{font-size:.7rem;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:10px}}

    /* INVENTORY */
    .inv-search{{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:.85rem;margin-bottom:16px;outline:none;transition:border-color .15s}}
    .inv-search:focus{{border-color:#3b82f6}}
    .inv-search::placeholder{{color:#475569}}
    .agent-card{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:12px;margin-bottom:12px;overflow:hidden;border:1px solid #ffffff06;transition:box-shadow .15s}}
    .agent-card:hover{{box-shadow:0 4px 16px rgba(0,0,0,.2)}}
    .agent-summary{{list-style:none;display:flex;justify-content:space-between;align-items:center;padding:18px 22px;cursor:pointer;user-select:none;font-weight:700;font-size:.95rem;color:#f1f5f9}}
    .agent-summary::-webkit-details-marker{{display:none}}
    .agent-summary::before{{content:"\\25B6";margin-right:10px;font-size:.6rem;color:#475569;transition:transform .2s}}
    details[open] .agent-summary::before{{transform:rotate(90deg)}}
    .agent-detail{{padding:18px 22px;border-top:1px solid #0b112060}}
    .server-card{{background:#0b1120;border-radius:8px;padding:14px 16px;margin-bottom:10px;border-left:3px solid #334155;border:1px solid #ffffff04;border-left:3px solid #334155}}
    .pkg-row{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #0a162830;font-size:.78rem}}
    .pkg-row:last-child{{border-bottom:none}}
    .pkg-name{{color:#e2e8f0}}
    .pkg-ver{{color:#64748b;font-family:monospace;font-size:.73rem}}
    .toggle-btn{{background:transparent;border:1px solid #334155;color:#64748b;font-size:.72rem;padding:6px 12px;border-radius:6px;cursor:pointer;margin-top:10px;width:100%;transition:all .15s}}
    .toggle-btn:hover{{background:#1e293b;color:#94a3b8}}

    /* HINTS */
    .hint-box{{background:#1e3a5f40;border:1px solid #3b82f640;border-radius:8px;padding:14px 18px;margin-bottom:18px;font-size:.82rem;color:#93c5fd}}
    .empty-state{{background:#052e1615;border:1px solid #16a34a30;border-radius:10px;padding:24px;color:#4ade80;text-align:center;font-size:.9rem}}

    footer{{border-top:1px solid #1e293b;padding:24px 32px;text-align:center;font-size:.75rem;color:#334155;margin-left:220px}}
    .print-btn{{background:transparent;border:1px solid #334155;color:#64748b;font-size:.75rem;padding:4px 12px;border-radius:6px;cursor:pointer;margin-left:12px;transition:all .15s}}
    .print-btn:hover{{background:#1e293b;color:#94a3b8}}

    @media(max-width:900px){{
      .sidebar{{display:none}}
      .sidebar.mobile-open{{display:flex}}
      .sidebar-toggle{{display:flex;align-items:center;justify-content:center}}
      .container{{margin-left:0;padding:60px 16px 60px}}
      footer{{margin-left:0}}
      .charts-row{{grid-template-columns:1fr}}
      .stat-grid{{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}}
      .node-sidebar{{width:100%}}
    }}

    {_REPORT_LAYOUT_CSS}
    /* PRINT */
{_REPORT_PRINT_CSS}  </style>"""
