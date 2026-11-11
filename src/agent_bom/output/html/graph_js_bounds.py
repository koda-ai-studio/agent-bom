"""Bound what the report graphs lay out, and run the layout after the page loads.

The hierarchical layout costs far more than linear time in the node count: at
10,000 findings it took about 40 s, and at 50,000 the page never finished
loading. The diagram therefore draws at most ``DRAW_LIMIT`` nodes: the
most severe findings first, each with the assets on its path, then the rest of
the inventory while room remains. It opens at ``FIRST_DRAW_LIMIT`` nodes, which
stays legible, and "Draw more" doubles that up to ``DRAW_LIMIT``. A note above
the diagram gives the drawn and recorded totals, and the Relationships view
pages through every recorded edge, so no record is left out of the report.
"""

from __future__ import annotations

DRAW_LIMIT = 600
FIRST_DRAW_LIMIT = 60

GRAPH_BOUNDS_JS = (
    r"""
  var GRAPH_DRAW_LIMIT = """
    + str(DRAW_LIMIT)
    + r""";
  var GRAPH_FIRST_DRAW = """
    + str(FIRST_DRAW_LIMIT)
    + r""";
  var GRAPH_SEVERITY_RANK = {critical: 4, high: 3, medium: 2, low: 1};
  function isFindingNode(data) {
    var t = data.type || '';
    return t === 'cve' || t.indexOf('cve_') === 0 || t === 'finding';
  }
  function findingRank(data) {
    var sev = data.severity || (data.type || '').replace('cve_', '');
    return GRAPH_SEVERITY_RANK[sev] || 0;
  }
  // A grouped node stands for every finding it holds.
  function findingWeight(data) { return data.count > 1 ? data.count : 1; }
  // follow: 'out' when edges run from a finding toward what it reaches, 'in' when they run toward the finding.
  // inventoryFirst: the inventory is the subject, so it takes up to half the room before findings.
  // priority: record ids drawn before anything else (search matches), or null.
  function boundGraph(elements, limit, follow, inventoryFirst, priority) {
    var nodes = [], edges = [];
    elements.forEach(function(e) { (e.data.source !== undefined ? edges : nodes).push(e); });
    var findings = nodes.filter(function(n) { return isFindingNode(n.data); });
    var weight = findings.reduce(function(sum, n) { return sum + findingWeight(n.data); }, 0);
    var assets = nodes.length - findings.length;
    var result = {elements: elements, bounded: false, totalNodes: nodes.length, totalFindings: weight,
      totalEdges: edges.length, drawnNodes: nodes.length, drawnFindings: weight, totalAssets: assets, drawnAssets: assets};
    if (nodes.length <= limit) return result;
    function wanted(data) {
      return !!priority && (priority[data.id] === true || (data.members || []).some(function(id) { return priority[id] === true; }));
    }
    var byId = {}, next = {};
    nodes.forEach(function(n) { byId[n.data.id] = n; });
    edges.forEach(function(e) {
      var from = follow === 'out' ? e.data.source : e.data.target;
      var to = follow === 'out' ? e.data.target : e.data.source;
      (next[from] = next[from] || []).push(to);
    });
    var kept = {}, count = 0, drawnFindings = 0, drawnAssets = 0;
    // The path from one finding, without other findings or nodes already drawn.
    function path(id) {
      var found = [id], seen = {}, stack = [id];
      seen[id] = true;
      while (stack.length) {
        (next[stack.pop()] || []).forEach(function(to) {
          if (seen[to] || kept[to] || !byId[to] || isFindingNode(byId[to].data)) return;
          seen[to] = true; found.push(to); stack.push(to);
        });
      }
      return found;
    }
    function keepAssets(room, test) {
      nodes.forEach(function(n) {
        if (count < room && !kept[n.data.id] && !isFindingNode(n.data) && test(n.data)) { kept[n.data.id] = true; count++; drawnAssets++; }
      });
    }
    if (priority) keepAssets(Math.floor(limit / 2), wanted);
    if (inventoryFirst) keepAssets(Math.floor(limit / 2), function() { return true; });
    var ranked = findings.map(function(n, i) { return {n: n, i: i, r: findingRank(n.data), p: wanted(n.data) ? 1 : 0}; });
    ranked.sort(function(a, b) { return b.p - a.p || b.r - a.r || a.i - b.i; });
    for (var k = 0; k < ranked.length; k++) {
      var ids = path(ranked[k].n.data.id);
      if (count + ids.length > limit) break;
      ids.forEach(function(id) { kept[id] = true; });
      count += ids.length; drawnAssets += ids.length - 1; drawnFindings += findingWeight(ranked[k].n.data);
    }
    keepAssets(limit, function() { return true; });
    result.elements = nodes.filter(function(n) { return kept[n.data.id]; }).concat(
      edges.filter(function(e) { return kept[e.data.source] && kept[e.data.target]; }));
    result.bounded = true; result.drawnNodes = count; result.drawnFindings = drawnFindings; result.drawnAssets = drawnAssets;
    return result;
  }
  function relationshipRows(elements) {
    var labels = {};
    elements.forEach(function(e) { if (e.data.source === undefined) labels[e.data.id] = e.data.label || e.data.id; });
    function name(id) { return String(labels[id] !== undefined ? labels[id] : id).replace(/\n/g, ' '); }
    return elements.filter(function(e) { return e.data.source !== undefined; }).map(function(e) {
      return {source: name(e.data.source), relation: (e.data.type || 'related to').split('_').join(' '), target: name(e.data.target)};
    });
  }
  function readGraphData(id) {
    var el = document.getElementById(id);
    if (!el) return [];
    try { return JSON.parse(el.textContent); } catch (e) { return []; }
  }
  // Layout runs in its own task after load, so a large graph never holds the page back.
  function afterLoad(draw) {
    if (document.readyState === 'complete') { setTimeout(draw, 0); return; }
    window.addEventListener('load', function() { setTimeout(draw, 0); });
  }
"""
)
