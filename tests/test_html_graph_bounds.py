"""Report graphs lay out a bounded, labelled subset after the page loads; the full data stays in the file."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from agent_bom.output.html import to_html
from agent_bom.output.html.graph_js_bounds import DRAW_LIMIT, GRAPH_BOUNDS_JS
from agent_bom.output.html.scripts import render_graph_script
from tests.html_report_scale_fixtures import scale_report


def _node(script: str) -> object:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the exported graph contract")
    result = subprocess.run([node, "-e", GRAPH_BOUNDS_JS + "\n" + script], capture_output=True, text=True, check=True, timeout=60)
    return json.loads(result.stdout)


_SEVERITIES = "['low', 'medium', 'high', 'critical']"


def test_small_graph_is_drawn_whole():
    out = _node(
        """
const els = [{data:{id:'a', type:'agent'}}, {data:{id:'cve:1', type:'cve', severity:'low'}}];
els.push({data:{source:'a', target:'cve:1', type:'affects'}});
const b = boundGraph(els, 10, 'in');
console.log(JSON.stringify({same: b.elements === els, bounded: b.bounded, nodes: b.totalNodes, findings: b.totalFindings}));
"""
    )
    assert out == {"same": True, "bounded": False, "nodes": 2, "findings": 1}


def test_attack_flow_at_50k_draws_the_most_severe_paths_within_the_limit():
    out = _node(
        f"""
const sev = {_SEVERITIES};
const els = [];
for (let p = 0; p < 3600; p++) els.push({{data:{{id:'pkg:' + p, type:'pkg_vuln'}}}});
for (let i = 0; i < 45000; i++) {{
  els.push({{data:{{id:'cve:' + i, type:'cve', severity: sev[i % 4]}}}});
  els.push({{data:{{source:'cve:' + i, target:'pkg:' + (i % 3600), type:'exploits'}}}});
}}
const started = Date.now();
const b = boundGraph(els, {DRAW_LIMIT}, 'out');
const ms = Date.now() - started;
const drawn = b.elements.filter(e => e.data.source === undefined);
const ids = new Set(drawn.map(e => e.data.id));
const edges = b.elements.filter(e => e.data.source !== undefined);
const cves = drawn.filter(e => e.data.type === 'cve');
console.log(JSON.stringify({{
  ms, bounded: b.bounded, drawnNodes: drawn.length, totalNodes: b.totalNodes,
  drawnFindings: b.drawnFindings, totalFindings: b.totalFindings, totalEdges: b.totalEdges,
  allCritical: cves.every(e => e.data.severity === 'critical'),
  edgesClosed: edges.every(e => ids.has(e.data.source) && ids.has(e.data.target)),
  everyCveHasItsPackage: cves.every(c => edges.some(e => e.data.source === c.data.id)),
}}));
"""
    )
    assert out["bounded"] is True
    assert out["drawnNodes"] <= DRAW_LIMIT
    assert out["totalNodes"] == 3600 + 45000
    assert out["totalFindings"] == 45000 and out["totalEdges"] == 45000
    assert out["drawnFindings"] > DRAW_LIMIT // 4
    assert out["allCritical"] and out["edgesClosed"] and out["everyCveHasItsPackage"]
    assert out["ms"] < 2000


def test_supply_chain_keeps_inventory_and_bounds_finding_leaves():
    out = _node(
        f"""
const sev = {_SEVERITIES};
const els = [{{data:{{id:'provider:local', type:'provider'}}}}];
for (let a = 0; a < 12; a++) {{
  els.push({{data:{{id:'agent:' + a, type:'agent'}}}});
  els.push({{data:{{source:'provider:local', target:'agent:' + a, type:'hosts'}}}});
}}
for (let i = 0; i < 5000; i++) {{
  els.push({{data:{{id:'finding:' + i, type:'finding', severity: sev[i % 4]}}}});
  els.push({{data:{{source:'agent:' + (i % 12), target:'finding:' + i, type:'has_finding'}}}});
}}
const b = boundGraph(els, {DRAW_LIMIT}, 'in', true);
const drawn = b.elements.filter(e => e.data.source === undefined);
const types = drawn.map(e => e.data.type);
console.log(JSON.stringify({{
  drawn: drawn.length, agents: types.filter(t => t === 'agent').length, provider: types.includes('provider'),
  findings: b.drawnFindings, total: b.totalFindings,
  order: drawn.filter(e => e.data.type === 'finding').every(e => e.data.severity === 'critical'),
}}));
"""
    )
    assert out["drawn"] <= DRAW_LIMIT
    assert out["agents"] == 12 and out["provider"] is True
    assert out["total"] == 5000 and 0 < out["findings"] < 5000 and out["order"] is True


def test_relationship_rows_cover_every_recorded_edge():
    out = _node(
        """
const els = [{data:{id:'a', label:'Agent A'}}, {data:{id:'b', label:'pkg\\n@1'}}];
for (let i = 0; i < 3; i++) els.push({data:{source:'a', target:'b', type:'depends_on'}});
els.push({data:{source:'a', target:'missing'}});
const rows = relationshipRows(els);
console.log(JSON.stringify({count: rows.length, first: rows[0], last: rows[3]}));
"""
    )
    assert out == {
        "count": 4,
        "first": {"source": "Agent A", "relation": "depends on", "target": "pkg @1"},
        "last": {"source": "Agent A", "relation": "related to", "target": "missing"},
    }


def test_after_load_waits_for_the_load_event():
    out = _node(
        """
const handlers = {}; const timers = [];
global.window = {addEventListener(name, cb) { handlers[name] = cb; }};
global.document = {readyState: 'loading'};
global.setTimeout = (cb) => timers.push(cb);
let ran = 0;
afterLoad(() => ran++);
const beforeLoad = ran;
handlers.load(); const atLoad = ran;
timers.splice(0).forEach(cb => cb());
document.readyState = 'complete'; afterLoad(() => ran++); timers.splice(0).forEach(cb => cb());
console.log(JSON.stringify({beforeLoad, atLoad, after: ran}));
"""
    )
    # Layout runs in its own task after ``load``, so the event never waits on it.
    assert out == {"beforeLoad": 0, "atLoad": 0, "after": 2}


def test_graph_data_is_inert_json_read_after_load():
    script = render_graph_script("{}", '[{"data":{"id":"x"}}]', "[]")
    assert '<script type="application/json" class="graph-data" id="agentBomGraphElements">[{"data":{"id":"x"}}]</script>' in script
    assert '<script type="application/json" class="graph-data" id="agentBomAttackFlow">[]</script>' in script
    assert "var GRAPH_ELEMENTS = [" not in script and "var ATTACK_FLOW = [" not in script
    assert "afterLoad(drawSupplyChainGraph)" in script and "afterLoad(drawAttackFlowGraph)" in script


def test_large_report_keeps_every_graph_record_in_the_file():
    report, radii = scale_report(600)
    document = to_html(report, radii)
    data = re.search(r'<script type="application/json" class="graph-data" id="agentBomAttackFlow">(.*?)</script>', document, re.DOTALL)
    assert data is not None
    elements = json.loads(data.group(1))
    cves = {e["data"]["id"] for e in elements if e["data"].get("type") == "cve"}
    assert len(cves) == len(radii)
    offline = to_html(report, radii, offline_assets=True)
    assert 'class="graph-data"' not in offline
