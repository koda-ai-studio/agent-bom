"""Keep report diagrams legible, and let their filters reach every record.

At a few hundred nodes the hierarchical layout stacks every path into the same
ranks, so the fitted diagram becomes one tall column of unreadable boxes. Four
things keep it readable without leaving any record out:

* findings with the same severity and the same path are drawn as one group
  node that names its members;
* disconnected paths are laid out separately and packed into rows;
* the first frame never zooms out past a readable size; it opens on the most
  severe paths, and the fit button still shows everything;
* the diagram opens at ``FIRST_DRAW_LIMIT`` nodes and "Draw more" adds more.

Severity filters and search run over every recorded node, not only the drawn
ones, and redraw the diagram so matches that were not drawn come first. The
note above the diagram and the search status give drawn and recorded totals.
"""

from __future__ import annotations

GRAPH_VIEW_JS = r"""
  var GRAPH_READABLE_ZOOM = 0.8;
  function splitGraph(elements) {
    var nodes = [], edges = [];
    elements.forEach(function(e) { (e.data.source !== undefined ? edges : nodes).push(e); });
    return {nodes: nodes, edges: edges};
  }
  function groupLabel(data, count) {
    var sev = data.severity || (data.type || '').replace('cve_', '');
    var noun = (data.type === 'cve' || (data.type || '').indexOf('cve_') === 0) ? 'CVEs' : 'findings';
    return count + ' ' + (sev && sev !== 'cve' ? sev + ' ' : '') + noun;
  }
  // Findings that share a severity and exactly the same neighbours become one node listing its members.
  // Ids in keep (search matches) are always drawn on their own.
  function groupFindings(elements, keep) {
    var parts = splitGraph(elements), finding = {}, links = {}, solo = {};
    parts.nodes.forEach(function(n) { if (isFindingNode(n.data)) finding[n.data.id] = true; });
    parts.edges.forEach(function(e) {
      var s = e.data.source, t = e.data.target, type = e.data.type || '';
      if (finding[s] && finding[t]) { solo[s] = solo[t] = true; return; }
      if (finding[s]) (links[s] = links[s] || []).push('>' + type + '>' + t);
      else if (finding[t]) (links[t] = links[t] || []).push('<' + type + '<' + s);
    });
    var buckets = {}, order = [];
    parts.nodes.forEach(function(n) {
      var id = n.data.id;
      if (!finding[id] || solo[id] || n.data.count || (keep && keep[id])) return;
      var key = (n.data.type || '') + '|' + (n.data.severity || '') + '|' + (links[id] || []).sort().join('\u0001');
      if (!buckets[key]) { buckets[key] = []; order.push(key); }
      buckets[key].push(n);
    });
    var groupOf = {}, groupNode = {}, made = false;
    order.forEach(function(key, index) {
      var members = buckets[key];
      if (members.length < 2) return;
      made = true;
      var first = members[0].data, ids = members.map(function(m) { return m.data.id; });
      var names = members.slice(0, 12).map(function(m) { return m.data.label || m.data.id; });
      var label = groupLabel(first, members.length);
      var id = 'group:' + index + ':' + first.id;
      groupNode[id] = {data: {id: id, type: first.type, severity: first.severity, severityClass: first.severityClass,
        count: members.length, members: ids, label: label,
        tip: label + ' on the same path: ' + names.join(', ') + (members.length > 12 ? ', and ' + (members.length - 12) + ' more' : '')}};
      ids.forEach(function(m) { groupOf[m] = id; });
    });
    if (!made) return elements;
    var out = [], placed = {}, seen = {}, edgeIndex = 0;
    parts.nodes.forEach(function(n) {
      var g = groupOf[n.data.id];
      if (!g) out.push(n);
      else if (!placed[g]) { placed[g] = true; out.push(groupNode[g]); }
    });
    parts.edges.forEach(function(e) {
      var s = groupOf[e.data.source] || e.data.source, t = groupOf[e.data.target] || e.data.target;
      if (s === e.data.source && t === e.data.target) { out.push(e); return; }
      var key = s + '\u0001' + t + '\u0001' + (e.data.type || '');
      if (seen[key]) return;
      seen[key] = true;
      var data = Object.assign({}, e.data, {id: 'group-edge:' + (edgeIndex++), source: s, target: t});
      out.push({data: data});
    });
    return out;
  }
  // severities: {critical: true, ...} for the checked boxes, or null for no filter.
  // Findings with an unranked severity stay, and so do assets that never had a relationship.
  function filterBySeverity(elements, severities) {
    if (!severities) return elements;
    var parts = splitGraph(elements), drop = {}, dropped = 0;
    parts.nodes.forEach(function(n) {
      var sev = n.data.severity || (n.data.type || '').replace('cve_', '');
      if (isFindingNode(n.data) && GRAPH_SEVERITY_RANK[sev] && !severities[sev]) { drop[n.data.id] = true; dropped++; }
    });
    if (!dropped) return elements;
    var linked = {}, hadEdge = {};
    var edges = parts.edges.filter(function(e) {
      hadEdge[e.data.source] = hadEdge[e.data.target] = true;
      if (drop[e.data.source] || drop[e.data.target]) return false;
      linked[e.data.source] = linked[e.data.target] = true;
      return true;
    });
    var nodes = parts.nodes.filter(function(n) {
      var id = n.data.id;
      return !drop[id] && (linked[id] || !hadEdge[id] || isFindingNode(n.data));
    });
    return nodes.concat(edges);
  }
  // Ids of every recorded node whose label contains the (lower-case) query, drawn or not.
  function searchRecords(elements, query) {
    var found = {};
    if (!query || !query.trim()) return found;
    elements.forEach(function(e) {
      if (e.data.source !== undefined) return;
      if (String(e.data.label || e.data.id).toLowerCase().indexOf(query) >= 0) found[e.data.id] = true;
    });
    return found;
  }
  function countRecords(elements) {
    var parts = splitGraph(elements), findings = 0;
    parts.nodes.forEach(function(n) { if (isFindingNode(n.data)) findings++; });
    return {findings: findings, assets: parts.nodes.length - findings, edges: parts.edges.length};
  }
  // state: {limit, follow, inventoryFirst, severities, matches}. Totals always describe the full record.
  function graphView(recorded, state) {
    var filtered = filterBySeverity(recorded, state.severities || null);
    var matches = state.matches && Object.keys(state.matches).length ? state.matches : null;
    var grouped = groupFindings(filtered, matches);
    var view = boundGraph(grouped, state.limit, state.follow, !!state.inventoryFirst, matches);
    var all = state.totals || countRecords(recorded);
    var shown = filtered === recorded ? all : countRecords(filtered);
    view.totalFindings = all.findings; view.totalAssets = all.assets; view.totalEdges = all.edges;
    view.hiddenBySeverity = all.findings - shown.findings;
    view.grouped = grouped !== filtered && view.elements.some(function(e) { return e.data.count > 1; });
    view.limit = state.limit;
    view.bounded = view.drawnFindings < view.totalFindings || view.drawnAssets < view.totalAssets;
    return view;
  }
  function graphNoteText(view) {
    if (!view.bounded && !view.grouped) return '';
    var n = function(value) { return value.toLocaleString('en-US'); };
    var text = 'Diagram draws ' + n(view.drawnFindings) + ' of ' + n(view.totalFindings) + ' findings, most severe first, and ' +
      n(view.drawnAssets) + ' of ' + n(view.totalAssets) + ' assets.';
    if (view.grouped) text += ' Findings with the same severity and path are drawn as one group; hover a group to see its members.';
    if (view.hiddenBySeverity) text += ' The severity filter hides ' + n(view.hiddenBySeverity) + ' findings.';
    return text + ' Relationships lists all ' + n(view.totalEdges) + ' recorded relationships, and the findings tables list every finding.';
  }
  // Top-left corners for boxes packed into rows whose width suits the given aspect ratio,
  // never wider than maxWidth (the container at a readable zoom) unless one box is wider.
  function packBoxes(boxes, aspect, gap, maxWidth) {
    var area = 0, widest = 0;
    boxes.forEach(function(b) { area += (b.w + gap) * (b.h + gap); widest = Math.max(widest, b.w); });
    var rowWidth = Math.max(widest, Math.min(Math.sqrt(area * (aspect > 0 ? aspect : 1.6)), maxWidth || Infinity));
    var x = 0, y = 0, rowHeight = 0;
    return boxes.map(function(b) {
      if (x > 0 && x + b.w > rowWidth) { x = 0; y += rowHeight + gap; rowHeight = 0; }
      var at = {x: x, y: y};
      x += b.w + gap; rowHeight = Math.max(rowHeight, b.h);
      return at;
    });
  }
  function componentRank(part) {
    var rank = 0;
    part.nodes().forEach(function(n) { if (isFindingNode(n.data())) rank = Math.max(rank, findingRank(n.data())); });
    return rank;
  }
  // Lay out each disconnected path on its own and pack them into rows, most severe first.
  function layoutGraph(graph, options) {
    var base = Object.assign({name: 'dagre', animate: false, fit: false}, options);
    var box = graph.container();
    // A diagram drawn on a hidden tab is packed again when it is first shown at its real width.
    graph.scratch('agentBomLayout', {options: options, width: box ? box.clientWidth : 0});
    var parts = graph.elements().components();
    if (parts.length < 2) { graph.layout(base).run(); return; }
    var ranked = parts.map(function(part, i) { return {part: part, i: i, r: componentRank(part)}; });
    ranked.sort(function(a, b) { return b.r - a.r || a.i - b.i; });
    ranked.forEach(function(item) { item.part.layout(base).run(); });
    var boxes = ranked.map(function(item) { return item.part.boundingBox(); });
    var width = box && box.clientWidth ? box.clientWidth : window.innerWidth;
    var aspect = box && box.clientHeight ? box.clientWidth / box.clientHeight : (window.innerWidth < 700 ? 0.75 : 2);
    // Leave room for the padding and the zoom buttons on the right.
    var offsets = packBoxes(boxes.map(function(b) { return {w: b.w, h: b.h}; }), aspect, 48, (width - 160) / GRAPH_READABLE_ZOOM);
    ranked.forEach(function(item, i) {
      var dx = offsets[i].x - boxes[i].x1, dy = offsets[i].y - boxes[i].y1;
      item.part.nodes().positions(function(node) { var p = node.position(); return {x: p.x + dx, y: p.y + dy}; });
    });
  }
  // Fit the whole diagram unless that makes labels unreadable; then open on the top-left, most severe corner.
  function fitReadable(graph, padding) {
    graph.fit(graph.elements(), padding);
    if (!graph.elements().length || graph.zoom() >= GRAPH_READABLE_ZOOM) return false;
    var box = graph.elements().boundingBox();
    graph.zoom(GRAPH_READABLE_ZOOM);
    graph.pan({x: padding - box.x1 * GRAPH_READABLE_ZOOM, y: padding - box.y1 * GRAPH_READABLE_ZOOM});
    return true;
  }
  // config: {graph, container, recorded, view, state, layout, bar, onRedraw}
  function mountGraphView(config) {
    var graph = config.graph, state = config.state, view = config.view;
    var note = document.createElement('div');
    note.className = 'graph-bound-note';
    var text = document.createElement('p');
    var more = document.createElement('button');
    more.type = 'button'; more.className = 'graph-draw-more'; more.textContent = 'Draw more';
    var hint = document.createElement('p');
    hint.className = 'graph-pan-hint';
    note.append(text, more, hint);
    config.container.parentNode.before(note);
    var bar = config.bar, search = bar ? bar.querySelector('input[type="search"]') : null;
    var status = bar ? bar.querySelector('.graph-search-status') : null;
    function drawnIds() {
      var ids = {};
      graph.nodes().forEach(function(node) {
        ids[node.id()] = node;
        (node.data('members') || []).forEach(function(id) { ids[id] = node; });
      });
      return ids;
    }
    function describe(zoomedIn) {
      text.textContent = graphNoteText(view);
      note.hidden = !text.textContent;
      more.hidden = !view.bounded || state.limit >= GRAPH_DRAW_LIMIT;
      more.textContent = 'Draw more (up to ' + Math.min(state.limit * 2, GRAPH_DRAW_LIMIT) + ' nodes)';
      hint.textContent = zoomedIn ? 'Shown at a readable size from the most severe paths: drag to pan, or use the fit button to see the whole diagram.' : '';
    }
    function highlight() {
      graph.elements().removeClass('faded highlighted');
      if (!state.matches) { if (status) status.textContent = ''; return; }
      var wanted = Object.keys(state.matches), drawn = drawnIds(), hits = graph.collection(), shown = 0;
      wanted.forEach(function(id) { if (drawn[id]) { shown++; hits = hits.union(drawn[id]); } });
      if (status) {
        status.textContent = !wanted.length ? 'No recorded node matches' :
          wanted.length.toLocaleString('en-US') + ' recorded match' + (wanted.length === 1 ? '' : 'es') + ', ' + shown.toLocaleString('en-US') + ' drawn';
      }
      if (!hits.length) { if (wanted.length === 0) graph.elements().addClass('faded'); return; }
      graph.elements().not(hits.closedNeighborhood()).addClass('faded');
      hits.addClass('highlighted');
      // Bring the matches into view at a readable size.
      graph.fit(hits.closedNeighborhood(), 80);
      if (graph.zoom() > 1.5 || graph.zoom() < GRAPH_READABLE_ZOOM) {
        graph.zoom(Math.min(1.5, Math.max(graph.zoom(), GRAPH_READABLE_ZOOM)));
        graph.center(hits);
      }
    }
    function redraw() {
      view = graphView(config.recorded, state);
      graph.batch(function() { graph.elements().remove(); graph.add(view.elements); });
      layoutGraph(graph, config.layout);
      var zoomedIn = fitReadable(graph, 40);
      highlight(); describe(zoomedIn);
      if (config.onRedraw) config.onRedraw(view);
    }
    more.addEventListener('click', function() { state.limit = Math.min(state.limit * 2, GRAPH_DRAW_LIMIT); redraw(); });
    if (bar) {
      var boxes = Array.from(bar.querySelectorAll('input[type="checkbox"][value]'));
      boxes.forEach(function(box) {
        box.addEventListener('change', function() {
          var on = {}, all = true;
          boxes.forEach(function(b) { if (b.checked) on[b.value] = true; else all = false; });
          state.severities = all ? null : on;
          redraw();
        });
      });
    }
    if (search) {
      var timer = null;
      search.addEventListener('input', function() {
        clearTimeout(timer);
        timer = setTimeout(function() {
          var query = search.value.toLowerCase();
          state.matches = query.trim() ? searchRecords(config.recorded, query) : null;
          var drawn = drawnIds();
          var missing = state.matches && Object.keys(state.matches).some(function(id) { return !drawn[id]; });
          if (missing) redraw(); else highlight();
        }, 250);
      });
    }
    graph.on('agent-bom:fitted', function(event, zoomedIn) { describe(zoomedIn); });
    describe(false);
    return {redraw: redraw, view: function() { return view; }};
  }
"""
