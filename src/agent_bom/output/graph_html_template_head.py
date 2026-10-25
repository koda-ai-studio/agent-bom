"""Markup and styles of the interactive standalone graph HTML export."""

_GRAPH_HTML_TEMPLATE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-bom Supply Chain Graph</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0f1419; color: #e7e9ea; }}
  #header {{ padding: 16px 24px; display: flex; align-items: flex-start; justify-content: space-between;
    border-bottom: 1px solid #2f3336; gap: 16px; }}
  #header h1 {{ font-size: 20px; font-weight: 700; }}
  #header p {{ font-size: 13px; color: #9ba1a6; margin-top: 6px; max-width: 780px; }}
  #stats {{ font-size: 13px; color: #71767b; white-space: nowrap; padding-top: 4px; }}
  #stats span {{ margin: 0 8px; }}
  #cy {{ width: 100%; height: calc(100vh - 176px); }}
  #toolbar {{ padding: 10px 24px; display: flex; align-items: center; justify-content: space-between;
    gap: 16px; border-bottom: 1px solid #2f3336; background: #10151b; }}
  #toolbar .left, #toolbar .right {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .chip {{ border: 1px solid #2f3336; background: #151b22; color: #e7e9ea; font-size: 12px; font-weight: 600;
    border-radius: 999px; padding: 7px 10px; cursor: pointer; }}
  .chip:hover {{ background: #1b2330; }}
  .chip.active {{ border-color: #4a9eff; background: #15202b; color: #d9ecff; }}
  .chip.count {{ cursor: default; }}
  .chip.critical {{ border-color: #b42318; color: #ffb4ae; }}
  .chip.high {{ border-color: #c56b1f; color: #ffd1a5; }}
  .chip.medium {{ border-color: #9d7d13; color: #ffe28a; }}
  .chip.low {{ border-color: #6e7681; color: #c6ccd3; }}
  #search {{
    width: 230px; max-width: 100%; border: 1px solid #2f3336; background: #0f1419; color: #e7e9ea;
    border-radius: 10px; padding: 8px 12px; font-size: 12px;
  }}
  .panel {{ position: fixed; z-index: 10; background: rgba(26, 31, 37, 0.96); border: 1px solid #2f3336;
    border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.28); backdrop-filter: blur(10px); }}
  #riskpanel {{ top: 138px; left: 16px; width: 360px; max-height: calc(100vh - 270px); overflow: auto; }}
  #riskpanel h2, #detail h2 {{ font-size: 14px; font-weight: 700; margin-bottom: 10px; }}
  #riskpanel .inner, #detail .inner {{ padding: 14px; }}
  #riskpanel .hint {{ font-size: 12px; color: #9ba1a6; line-height: 1.45; margin-bottom: 10px; }}
  .risk-item {{ width: 100%; display: block; text-align: left; border: 1px solid #2f3336; background: #11161c;
    color: #e7e9ea; border-radius: 10px; padding: 12px; margin-bottom: 10px; cursor: pointer; }}
  .risk-item:hover, .risk-item.active {{ border-color: #4a9eff; background: #15202b; }}
  .risk-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: baseline; margin-bottom: 6px; }}
  .risk-title {{ font-size: 12px; font-weight: 700; line-height: 1.35; }}
  .risk-score {{ font-size: 12px; font-weight: 700; color: #ffd33d; }}
  .risk-meta {{ font-size: 11px; color: #9ba1a6; line-height: 1.45; }}
  .risk-summary {{ font-size: 12px; line-height: 1.45; color: #c6ccd3; margin-top: 8px; }}
  .pill {{ display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 999px;
    background: #2f3336; color: #e7e9ea; margin-right: 6px; }}
  .pill.critical {{ background: #5b1f24; color: #ffb3b8; }}
  .pill.high {{ background: #5b341f; color: #ffd1a5; }}
  .pill.medium {{ background: #4b3d18; color: #ffe28a; }}
  .pill.low {{ background: #30363d; color: #e7e9ea; }}
  #legend {{ bottom: 16px; left: 16px; padding: 12px; font-size: 11px; width: 220px; }}
  #legend div {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; }}
  .dot {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
  #detail {{ top: 138px; right: 16px; width: 360px; max-height: calc(100vh - 270px); overflow: auto; display: none; }}
  #detail .subtle {{ color: #9ba1a6; font-size: 12px; line-height: 1.45; margin-bottom: 12px; }}
  #detail .section {{ margin-top: 12px; }}
  #detail .section h3 {{ font-size: 12px; font-weight: 700; margin-bottom: 8px; color: #d9ecff;
    text-transform: uppercase; letter-spacing: .04em; }}
  #detail ul {{ padding-left: 18px; color: #c6ccd3; font-size: 12px; line-height: 1.5; }}
  #detail code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #11161c; padding: 1px 4px; border-radius: 4px; }}
  #controls {{ position: fixed; bottom: 16px; right: 16px; z-index: 10; display: flex; gap: 8px; }}
  #controls button {{ padding: 8px 12px; border: 1px solid #2f3336; background: rgba(26, 31, 37, 0.96);
    color: #e7e9ea; border-radius: 8px; cursor: pointer; font-size: 12px; }}
  #controls button:hover {{ background: #2f3336; }}
</style>
</head>
<body>
<div id="header">
  <div>
    <h1>agent-bom Supply Chain Graph</h1>
    <p>Open on the highest-risk blast-radius path first, then inspect the full
    agent → server → package → vulnerability chain. Click a risk card or node to
    focus the relevant path.</p>
  </div>
  <div id="stats">
    <span>{total_agents} agents</span> | <span>{total_servers} servers</span> |
    <span>{total_pkgs} packages</span> | <span>{total_vulns} CVEs</span>
  </div>
</div>
<div id="toolbar">
  <div class="left">
    <button class="chip active" id="sev-all" onclick="setSeverityFilter('all')">All severities</button>
    <button class="chip critical" id="sev-critical" onclick="setSeverityFilter('critical')">Critical</button>
    <button class="chip high" id="sev-high" onclick="setSeverityFilter('high')">High</button>
    <button class="chip medium" id="sev-medium" onclick="setSeverityFilter('medium')">Medium</button>
    <button class="chip low" id="sev-low" onclick="setSeverityFilter('low')">Low</button>
    <button class="chip" id="chip-credentials" onclick="toggleCredentialFilter()">Credential exposure</button>
    <button class="chip" id="chip-focus" onclick="toggleFocusedOnly()">Focused path only</button>
  </div>
  <div class="right">
    <span class="chip count critical" id="count-critical"></span>
    <span class="chip count high" id="count-high"></span>
    <span class="chip count" id="count-credentials"></span>
    <span class="chip count" id="count-agents"></span>
    <input id="search" type="search" placeholder="Search CVE, package, server, agent" oninput="searchNodes(this.value)">
  </div>
</div>
<div id="cy"></div>
<div id="riskpanel" class="panel">
  <div class="inner">
    <h2>Top risky paths</h2>
    <div class="hint">Start here. These are the blast-radius paths with the highest risk score in this report.</div>
    <div id="riskList"></div>
    <h2 id="findingHead" style="margin-top:14px">Correlated findings</h2>
    <div class="hint" id="findingHint">Graph-derived findings (toxic combinations, prompt security, policy)
    from the same unified stream as the report.</div>
    <div id="findingList"></div>
  </div>
</div>
<div id="legend" class="panel">
  <div><span class="dot" style="background:#4a9eff"></span> Provider</div>
  <div><span class="dot" style="background:#2ea043"></span> Agent</div>
  <div><span class="dot" style="background:#818cf8"></span> Agent framework</div>
  <div><span class="dot" style="background:#6e7681"></span> Server (clean)</div>
  <div><span class="dot" style="background:#f85149"></span> Server (vulnerable)</div>
  <div><span class="dot" style="background:#d29922"></span> Server (credentials)</div>
  <div><span class="dot" style="background:#0d9488"></span> Directory</div>
  <div><span class="dot" style="background:#f97316"></span> Config file</div>
  <div><span class="dot" style="background:#22d3ee"></span> Source file</div>
  <div><span class="dot" style="background:#da3633"></span> CVE critical</div>
  <div><span class="dot" style="background:#db6d28"></span> CVE high</div>
  <div><span class="dot" style="background:#d29922"></span> CVE medium</div>
  <div><span class="dot" style="background:#a371f7"></span> Graph finding</div>
</div>
<div id="detail" class="panel">
  <div class="inner">
    <h2 id="dt"></h2>
    <div id="db"></div>
  </div>
</div>
<div id="controls">
  <button onclick="focusTopRisk()">Top risk</button>
  <button onclick="fitAll()">Fit all</button>
  <button onclick="cy.zoom(cy.zoom()*1.2);cy.center()">+</button>
  <button onclick="cy.zoom(cy.zoom()/1.2);cy.center()">-</button>
  <button onclick="dlPng()">PNG</button>
</div>
{vendor_scripts}
"""
