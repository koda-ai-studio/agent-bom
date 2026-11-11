"""Bound what the report graphs lay out, and run the layout after the page loads.

The hierarchical layout costs far more than linear time in the node count: at
10,000 findings it took about 40 s, and at 50,000 the page never finished
loading. The diagram therefore draws at most ``DRAW_LIMIT`` nodes: the
most severe findings first, each with the assets on its path, then the rest of
the inventory while room remains. A note above the diagram gives the drawn and
recorded totals, and the Relationships view pages through every recorded edge,
so no record is left out of the report.
"""

from __future__ import annotations

DRAW_LIMIT = 600

GRAPH_BOUNDS_JS = (
    r"""
  var GRAPH_DRAW_LIMIT = """
    + str(DRAW_LIMIT)
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
  // follow: 'out' when edges run from a finding toward what it reaches, 'in' when they run toward the finding.
  // inventoryFirst: the inventory is the subject, so it takes up to half the room before findings.
  function boundGraph(elements, limit, follow, inventoryFirst) {
    var nodes = [], edges = [];
    elements.forEach(function(e) { (e.data.source !== undefined ? edges : nodes).push(e); });
    var findings = nodes.filter(function(n) { return isFindingNode(n.data); });
    var result = {elements: elements, bounded: false, totalNodes: nodes.length, totalFindings: findings.length,
      totalEdges: edges.length, drawnNodes: nodes.length, drawnFindings: findings.length};
    if (nodes.length <= limit) return result;
    var byId = {}, next = {};
    nodes.forEach(function(n) { byId[n.data.id] = n; });
    edges.forEach(function(e) {
      var from = follow === 'out' ? e.data.source : e.data.target;
      var to = follow === 'out' ? e.data.target : e.data.source;
      (next[from] = next[from] || []).push(to);
    });
    var kept = {}, count = 0, drawnFindings = 0;
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
    if (inventoryFirst) {
      nodes.forEach(function(n) {
        if (count < Math.floor(limit / 2) && !isFindingNode(n.data)) { kept[n.data.id] = true; count++; }
      });
    }
    var ranked = findings.map(function(n, i) { return {n: n, i: i, r: findingRank(n.data)}; });
    ranked.sort(function(a, b) { return b.r - a.r || a.i - b.i; });
    for (var k = 0; k < ranked.length; k++) {
      var ids = path(ranked[k].n.data.id);
      if (count + ids.length > limit) break;
      ids.forEach(function(id) { kept[id] = true; });
      count += ids.length; drawnFindings++;
    }
    nodes.forEach(function(n) {
      if (count < limit && !kept[n.data.id] && !isFindingNode(n.data)) { kept[n.data.id] = true; count++; }
    });
    result.elements = nodes.filter(function(n) { return kept[n.data.id]; }).concat(
      edges.filter(function(e) { return kept[e.data.source] && kept[e.data.target]; }));
    result.bounded = true; result.drawnNodes = count; result.drawnFindings = drawnFindings;
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
  function noteGraphBound(container, bound) {
    if (!bound.bounded) return;
    var note = document.createElement('p');
    note.className = 'graph-bound-note';
    note.textContent = 'Diagram draws ' + bound.drawnFindings.toLocaleString() + ' of ' + bound.totalFindings.toLocaleString() +
      ' findings, most severe first, and ' + (bound.drawnNodes - bound.drawnFindings).toLocaleString() + ' of ' +
      (bound.totalNodes - bound.totalFindings).toLocaleString() + ' assets. Relationships lists all ' +
      bound.totalEdges.toLocaleString() + ' recorded relationships, and the findings tables list every finding.';
    container.parentNode.before(note);
  }
  // Layout runs in its own task after load, so a large graph never holds the page back.
  function afterLoad(draw) {
    if (document.readyState === 'complete') { setTimeout(draw, 0); return; }
    window.addEventListener('load', function() { setTimeout(draw, 0); });
  }
"""
)
