"""Report diagrams open readable, and their search and severity filters cover every record, not just drawn nodes.

The pure functions run in Node.js; Cytoscape is not needed for them.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from agent_bom.output.html import to_html
from agent_bom.output.html.graph_js_bounds import DRAW_LIMIT, FIRST_DRAW_LIMIT, GRAPH_BOUNDS_JS
from agent_bom.output.html.graph_js_view import GRAPH_VIEW_JS
from tests.html_report_scale_fixtures import scale_report


def _node(script: str) -> object:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the exported graph contract")
    source = GRAPH_BOUNDS_JS + "\n" + GRAPH_VIEW_JS + "\n" + script
    result = subprocess.run([node, "-e", source], capture_output=True, text=True, check=True, timeout=60)
    return json.loads(result.stdout)


_PAIRS = """
const sev = ['critical', 'high', 'medium', 'low'];
function pairs(n) {
  const els = [];
  for (let i = 0; i < n; i++) {
    els.push({data:{id:'cve:' + i, label:'CVE-2026-' + i, type:'cve', severity: sev[i % 4]}});
    els.push({data:{id:'pkg:' + i, label:'pkg-' + i + ' @1.0', type:'pkg_vuln'}});
    els.push({data:{source:'cve:' + i, target:'pkg:' + i, type:'exploits'}});
  }
  return els;
}
"""


def test_first_draw_is_smaller_than_the_layout_ceiling():
    assert 0 < FIRST_DRAW_LIMIT < DRAW_LIMIT


def test_findings_with_the_same_severity_and_path_are_drawn_as_one_group():
    out = _node(
        """
const els = [{data:{id:'pkg:a', type:'pkg_vuln', label:'a'}}, {data:{id:'pkg:b', type:'pkg_vuln', label:'b'}}];
for (let i = 0; i < 5; i++) {
  els.push({data:{id:'cve:' + i, label:'CVE-' + i, type:'cve', severity:'critical'}});
  els.push({data:{source:'cve:' + i, target:'pkg:a', type:'exploits'}});
}
els.push({data:{id:'cve:low', label:'CVE-low', type:'cve', severity:'low'}});
els.push({data:{source:'cve:low', target:'pkg:a', type:'exploits'}});
els.push({data:{id:'cve:other', label:'CVE-other', type:'cve', severity:'critical'}});
els.push({data:{source:'cve:other', target:'pkg:b', type:'exploits'}});
const before = JSON.stringify(els);
const kept = groupFindings(els, {'cve:4': true}).find(e => e.data.count > 1).data.members;
const grouped = groupFindings(els);
const nodes = grouped.filter(e => e.data.source === undefined);
const group = nodes.find(n => n.data.count > 1);
const edges = grouped.filter(e => e.data.source !== undefined);
console.log(JSON.stringify({
  unchanged: JSON.stringify(els) === before, kept,
  nodes: nodes.length, members: group.data.members, label: group.data.label, severity: group.data.severity,
  type: group.data.type, groupEdges: edges.filter(e => e.data.source === group.data.id).map(e => [e.data.target, e.data.type]),
  singles: nodes.filter(n => !n.data.count).map(n => n.data.id).sort(),
  edgesClosed: edges.every(e => nodes.some(n => n.data.id === e.data.source) && nodes.some(n => n.data.id === e.data.target)),
}));
"""
    )
    assert out["unchanged"] is True
    # A search match is drawn on its own so its name stays visible.
    assert out["kept"] == ["cve:0", "cve:1", "cve:2", "cve:3"]
    assert out["members"] == ["cve:0", "cve:1", "cve:2", "cve:3", "cve:4"]
    assert out["label"] == "5 critical CVEs" and out["severity"] == "critical" and out["type"] == "cve"
    assert out["groupEdges"] == [["pkg:a", "exploits"]]
    assert out["singles"] == ["cve:low", "cve:other", "pkg:a", "pkg:b"]
    assert out["nodes"] == 5 and out["edgesClosed"] is True


def test_bound_counts_every_member_of_a_drawn_group():
    out = _node(
        """
const els = [{data:{id:'agent:1', type:'agent'}}];
for (let i = 0; i < 40; i++) {
  els.push({data:{id:'finding:' + i, type:'finding', severity:'high'}});
  els.push({data:{source:'agent:1', target:'finding:' + i, type:'has_finding'}});
}
const b = boundGraph(groupFindings(els), 600, 'in', true);
console.log(JSON.stringify({drawnFindings: b.drawnFindings, totalFindings: b.totalFindings, drawnNodes: b.drawnNodes,
  drawnAssets: b.drawnAssets, totalAssets: b.totalAssets}));
"""
    )
    assert out == {"drawnFindings": 40, "totalFindings": 40, "drawnNodes": 2, "drawnAssets": 1, "totalAssets": 1}


def test_severity_filter_runs_over_every_record_and_drops_orphaned_assets():
    out = _node(
        _PAIRS
        + """
const els = pairs(2000);
els.push({data:{id:'agent:idle', type:'agent'}});
const kept = filterBySeverity(els, {critical: true});
const nodes = kept.filter(e => e.data.source === undefined);
console.log(JSON.stringify({
  cves: nodes.filter(n => n.data.type === 'cve').length,
  allCritical: nodes.filter(n => n.data.type === 'cve').every(n => n.data.severity === 'critical'),
  pkgs: nodes.filter(n => n.data.type === 'pkg_vuln').length,
  idleAgentKept: nodes.some(n => n.data.id === 'agent:idle'),
  everything: filterBySeverity(els, null) === els,
}));
"""
    )
    assert out == {"cves": 500, "allCritical": True, "pkgs": 500, "idleAgentKept": True, "everything": True}


def test_search_matches_records_the_diagram_does_not_draw_and_draws_them_first():
    out = _node(
        _PAIRS
        + f"""
const els = pairs(50000);
const view = graphView(els, {{limit: {FIRST_DRAW_LIMIT}, follow: 'out'}});
const target = 'CVE-2026-49999';  // a low finding, last in the records
const drawnBefore = view.elements.some(e => e.data.id === 'cve:49999');
const matches = searchRecords(els, target.toLowerCase());
const focused = graphView(els, {{limit: {FIRST_DRAW_LIMIT}, follow: 'out', matches}});
console.log(JSON.stringify({{
  drawnBefore, matches: Object.keys(matches),
  drawnAfter: focused.elements.some(e => e.data.id === 'cve:49999' || (e.data.members || []).includes('cve:49999')),
  pkgAfter: focused.elements.some(e => e.data.id === 'pkg:49999'),
  byPackage: Object.keys(searchRecords(els, 'pkg-49999 ')).length,
  none: Object.keys(searchRecords(els, 'no-such-record')).length,
}}));
"""
    )
    assert out["drawnBefore"] is False
    assert out["matches"] == ["cve:49999"]
    assert out["drawnAfter"] is True and out["pkgAfter"] is True
    assert out["byPackage"] == 1 and out["none"] == 0


def test_first_view_of_50k_findings_is_small_labelled_and_fast():
    out = _node(
        _PAIRS
        + f"""
const els = pairs(50000);
const started = Date.now();
const view = graphView(els, {{limit: {FIRST_DRAW_LIMIT}, follow: 'out'}});
const ms = Date.now() - started;
const nodes = view.elements.filter(e => e.data.source === undefined);
const critical = nodes.filter(n => n.data.type === 'cve').every(n => n.data.severity === 'critical');
console.log(JSON.stringify({{ms, nodes: nodes.length, bounded: view.bounded, totalFindings: view.totalFindings,
  totalAssets: view.totalAssets, totalEdges: view.totalEdges, critical}}));
"""
    )
    assert out["nodes"] <= FIRST_DRAW_LIMIT and out["bounded"] is True
    assert out["totalFindings"] == 50000 and out["totalAssets"] == 50000 and out["totalEdges"] == 50000
    assert out["critical"] is True
    assert out["ms"] < 3000


def test_disconnected_paths_are_packed_into_rows_not_one_column():
    out = _node(
        """
const boxes = [];
for (let i = 0; i < 30; i++) boxes.push({w: 380, h: 60});
const offsets = packBoxes(boxes, 1100 / 520, 40);
const rows = new Set(offsets.map(o => o.y)).size;
const width = Math.max(...offsets.map((o, i) => o.x + boxes[i].w));
const height = Math.max(...offsets.map((o, i) => o.y + boxes[i].h));
let overlap = false;
offsets.forEach((a, i) => offsets.forEach((b, j) => {
  if (i < j && a.x < b.x + boxes[j].w && b.x < a.x + boxes[i].w && a.y < b.y + boxes[j].h && b.y < a.y + boxes[i].h) overlap = true;
}));
const capped = packBoxes(boxes, 10, 40, 900);
const cappedRight = Math.max(...capped.map((o, i) => o.x + boxes[i].w));
console.log(JSON.stringify({rows, overlap, ratio: width / height, single: packBoxes([{w: 10, h: 5}], 2, 40), cappedRight}));
"""
    )
    assert out["overlap"] is False
    # Rows never run wider than the container at a readable zoom, so nothing is cut off on the right.
    assert out["cappedRight"] <= 900 + 40
    assert 1 < out["rows"] < 30
    assert 1.0 < out["ratio"] < 4.0
    assert out["single"] == [{"x": 0, "y": 0}]


def test_note_names_the_recorded_totals_and_the_active_filters():
    out = _node(
        """
const view = {bounded: true, drawnFindings: 30, totalFindings: 1800, drawnAssets: 30, totalAssets: 1800, totalEdges: 1800,
  grouped: true, hiddenBySeverity: 900, limit: 60};
console.log(JSON.stringify({text: graphNoteText(view), whole: graphNoteText({bounded: false, drawnFindings: 4, totalFindings: 4,
  drawnAssets: 2, totalAssets: 2, totalEdges: 4, grouped: false, hiddenBySeverity: 0})}));
"""
    )
    text = out["text"]
    assert "30 of 1,800 findings" in text and "30 of 1,800 assets" in text
    assert "all 1,800 recorded relationships" in text and "findings tables list every finding" in text
    assert "same severity and path" in text
    assert "severity filter hides 900" in text.lower()
    assert out["whole"] == ""


def test_both_diagrams_have_filters_and_a_draw_more_control():
    report, radii = scale_report(400)
    document = to_html(report, radii)
    attack = document[document.index('<section id="attackflow"') :]
    attack = attack[: attack.index("</section>")]
    for value in ("critical", "high", "medium", "low"):
        assert f'value="{value}"' in attack
    assert 'type="search"' in attack and 'aria-label="Search all recorded findings and assets"' in attack
    assert 'aria-label="Search all recorded findings and assets"' in document[document.index('<section id="riskmap"') :]
    assert "Draw more" in document
    # The supply-chain filter no longer hides drawn nodes in place.
    assert "n.style('display', 'none')" not in document
