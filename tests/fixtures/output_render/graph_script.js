<script>
(function() {
  // Injected data
  var CHART_DATA = __CHART_DATA__;

  // Chart.js: Severity donut
  var sevCtx = document.getElementById('sevChart');
  if (sevCtx && CHART_DATA.sev.data.some(function(v){ return v > 0; })) {
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: CHART_DATA.sev.labels,
        datasets: [{
          data: CHART_DATA.sev.data,
          backgroundColor: CHART_DATA.sev.colors,
          borderColor: '#0b1120',
          borderWidth: 3,
          hoverOffset: 8,
        }],
      },
      options: {
        responsive: true,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { size: 11 },
              boxWidth: 12,
              padding: 14,
            },
          },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            padding: 10,
            callbacks: {
              label: function(ctx) {
                return ' ' + ctx.label + ': ' + ctx.parsed;
              },
            },
          },
        },
      },
    });
  } else if (sevCtx) {
    var p = document.createElement('p');
    p.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p.innerHTML = '&#x2705; No vulnerabilities';
    sevCtx.parentNode.replaceChild(p, sevCtx);
  }

  // Chart.js: Blast radius bar
  var blastCtx = document.getElementById('blastChart');
  if (blastCtx && CHART_DATA.blast.labels.length > 0) {
    new Chart(blastCtx, {
      type: 'bar',
      data: {
        labels: CHART_DATA.blast.labels,
        datasets: [{
          label: 'Blast Score',
          data: CHART_DATA.blast.scores,
          backgroundColor: CHART_DATA.blast.colors,
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        scales: {
          x: {
            min: 0, max: 10,
            grid: { color: '#1e293b' },
            ticks: { color: '#64748b', font: { size: 11 } },
          },
          y: {
            grid: { display: false },
            ticks: { color: '#94a3b8', font: { size: 11 } },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            callbacks: {
              label: function(ctx) {
                return ' Score: ' + ctx.parsed.x.toFixed(2);
              },
            },
          },
        },
      },
    });
  } else if (blastCtx) {
    var p2 = document.createElement('p');
    p2.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p2.innerHTML = '&#x2705; No blast radius data';
    blastCtx.parentNode.replaceChild(p2, blastCtx);
  }


  var GRAPH_DRAW_LIMIT = 600;
  var GRAPH_FIRST_DRAW = 60;
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
    // Packed paths are short, so a tighter rank gap lets more of them share a row.
    var packed = Object.assign({}, base, {rankSep: Math.min(base.rankSep || 60, 60)});
    ranked.forEach(function(item) { item.part.layout(packed).run(); });
    var boxes = ranked.map(function(item) { return item.part.boundingBox(); });
    var width = box && box.clientWidth ? box.clientWidth : window.innerWidth;
    var aspect = box && box.clientHeight ? box.clientWidth / box.clientHeight : (window.innerWidth < 700 ? 0.75 : 2);
    // Rows fill the container at a readable zoom, less the left padding and the zoom buttons on the right.
    var offsets = packBoxes(boxes.map(function(b) { return {w: b.w, h: b.h}; }), aspect, 32, (width - 120) / GRAPH_READABLE_ZOOM);
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
  function addGraphViews(graph, container, recorded) {
    var canvas = container.parentNode;
    canvas.classList.toggle('small-graph', graph.nodes().length <= 20);
    var toolbar = document.createElement('div');
    toolbar.className = 'graph-view-switch';
    var diagram = document.createElement('button'); diagram.textContent = 'Diagram';
    var relationships = document.createElement('button'); relationships.textContent = 'Relationships';
    toolbar.append(diagram, relationships);
    var panel = document.createElement('div'); panel.className = 'graph-relationships';
    var rows = document.createElement('ol');
    var pager = document.createElement('div'); pager.className = 'pager';
    var previous = document.createElement('button'); previous.textContent = 'Previous';
    var next = document.createElement('button'); next.textContent = 'Next';
    var count = document.createElement('span'); count.setAttribute('aria-live', 'polite');
    pager.append(previous, count, next); panel.append(rows, pager);
    canvas.before(toolbar); canvas.after(panel);
    // Every recorded relationship, including those the bounded diagram leaves out.
    var page = 0; var edges = relationshipRows(recorded); var size = window.innerWidth < 700 ? 5 : 15;
    function render() {
      rows.replaceChildren();
      edges.slice(page * size, (page + 1) * size).forEach(function(edge) {
        var item = document.createElement('li');
        var source = document.createElement('strong'); source.textContent = edge.source;
        var relation = document.createElement('span'); relation.textContent = edge.relation;
        var target = document.createElement('strong'); target.textContent = edge.target;
        item.append(source, relation, target); rows.append(item);
      });
      count.textContent = edges.length ? (page * size + 1) + '\u2013' + Math.min((page + 1) * size, edges.length) + ' of ' + edges.length + ' relationships' : 'No relationships recorded';
      previous.disabled = page === 0; next.disabled = (page + 1) * size >= edges.length;
    }
    previous.onclick = function() { page--; render(); };
    next.onclick = function() { page++; render(); };
    function select(showDiagram) {
      canvas.hidden = !showDiagram; panel.hidden = showDiagram;
      diagram.setAttribute('aria-pressed', String(showDiagram));
      relationships.setAttribute('aria-pressed', String(!showDiagram));
      document.dispatchEvent(new Event('agent-bom:report-tab'));
    }
    diagram.onclick = function() { select(true); };
    relationships.onclick = function() { select(false); };
    render(); select(window.innerWidth >= 700);
  }
  function fitGraphWhenVisible(graph, container) {
    var fitted = false;
    var printView = null;
    var userMoved = false, fitting = false, width = 0, height = 0;
    graph.on('pan zoom', function() { if (!fitting && !printView) userMoved = true; });
    function refresh() {
      if (!container.clientWidth || !container.clientHeight) return;
      var resized = width !== container.clientWidth || height !== container.clientHeight;
      width = container.clientWidth; height = container.clientHeight;
      fitting = true;
      graph.resize();
      var laidOut = graph.scratch('agentBomLayout');
      if (!fitted && laidOut && !laidOut.width) layoutGraph(graph, laidOut.options);
      if (!fitted || (resized && !userMoved)) {
        graph.emit('agent-bom:fitted', [fitReadable(graph, 40)]);
        fitted = true;
      }
      fitting = false;
    }
    if (typeof ResizeObserver !== 'undefined') new ResizeObserver(refresh).observe(container);
    window.addEventListener('resize', refresh);
    window.addEventListener('beforeprint', function() {
      printView = {zoom: graph.zoom(), pan: graph.pan()};
      graph.resize(); graph.fit(graph.elements(), 24);
    });
    window.addEventListener('afterprint', function() {
      if (!printView) return;
      graph.resize(); graph.viewport(printView); printView = null;
    });
    document.addEventListener('agent-bom:report-tab', refresh);
    refresh();
  }
  function drawSupplyChainGraph() {
  var GRAPH_RECORDED = readGraphData('agentBomGraphElements');
  var GRAPH_STATE = {limit: GRAPH_FIRST_DRAW, follow: 'in', inventoryFirst: true, severities: null, matches: null};
  var GRAPH_BOUND = graphView(GRAPH_RECORDED, GRAPH_STATE);
  var GRAPH_ELEMENTS = GRAPH_BOUND.elements;
  // Cytoscape: Supply chain graph with dagre hierarchical layout
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {
    var cy = cytoscape({
      container: cyContainer,
      elements: GRAPH_ELEMENTS,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)', 'font-size': 12, 'color': '#e2e8f0',
            'text-valign': 'center', 'text-halign': 'center',
            'text-wrap': 'wrap', 'text-max-width': 140,
            'width': 156, 'height': 60, 'shape': 'round-rectangle',
            'background-color': '#334155', 'border-color': '#94a3b8', 'border-width': 1.5,
          },
        },
        {
          selector: 'node[type="provider"]',
          style: {
            'background-color': '#1e1b4b',
            'border-color': '#818cf8',
            'border-width': 3,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '13px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 140,
            'height': 44,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '125px',
          },
        },
        {
          selector: 'node[type="agent"]',
          style: {
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '12px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 40,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="server_clean"]',
          style: {
            'background-color': '#052e16',
            'border-color': '#10b981',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#6ee7b7',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="server_cred"]',
          style: {
            'background-color': '#431407',
            'border-color': '#f59e0b',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="server_vuln"]',
          style: {
            'background-color': '#450a0a',
            'border-color': '#ef4444',
            'border-width': 2.5,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="pkg_vuln"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '11px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          },
        },
        {
          selector: 'node[type="cve"][severity="critical"], node[type^="cve_critical"]',
          style: {
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fecaca',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 110,
            'height': 30,
            'shape': 'round-rectangle',
            'underlay-color': '#ef4444',
            'underlay-padding': '6px',
            'underlay-opacity': 0.15,
            'underlay-shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type="cve"][severity="high"], node[type^="cve_high"]',
          style: {
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fed7aa',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 28,
            'shape': 'round-rectangle',
            'underlay-color': '#fb923c',
            'underlay-padding': '4px',
            'underlay-opacity': 0.1,
            'underlay-shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type^="cve_medium"], node[type^="cve_low"], node[type^="cve_none"]',
          style: {
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'label': 'data(label)',
            'color': '#fef08a',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 90,
            'height': 26,
            'shape': 'round-rectangle',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          },
        },
        {
          selector: 'edge[type="hosts"]',
          style: {
            'line-color': '#818cf8',
            'target-arrow-color': '#818cf8',
            'opacity': 0.5,
            'line-opacity': 0.63,
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
          },
        },
        {
          selector: 'edge[type="affects"]',
          style: {
            'line-color': '#dc2626',
            'target-arrow-color': '#dc2626',
            'opacity': 0.5,
            'line-opacity': 0.63,
          },
        },
        {
          selector: '.highlighted',
          style: {
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          },
        },
        {
          selector: '.faded',
          style: { 'opacity': 0.08 },
        },
        {
          selector: 'node[type="cve"], node[type^="cve_"]',
          style: {
            'label': function(node) { return (node.data('label') || '').split(' ')[0]; },
            'font-size': 11, 'width': 140, 'height': 42,
            'text-wrap': 'wrap', 'text-max-width': 128, 'text-overflow-wrap': 'anywhere',
          },
        },
        {
          selector: 'node[type="directory"], node[type="source_file"], node[type="config_file"]',
          style: {
            'label': function(node) { var label = node.data('label') || ''; return label === '.' ? 'Project root' : label.replace(/^project:/, ''); },
            'text-overflow-wrap': 'anywhere',
          },
        },
      ],
      layout: {name: 'null'},
      minZoom: 0.15,
      maxZoom: 4,
      autoungrabify: false,
    });
    var GRAPH_LAYOUT = {rankDir: window.innerWidth < 700 ? 'TB' : 'LR', nodeSep: 50, rankSep: 80, edgeSep: 15, padding: 30};
    layoutGraph(cy, GRAPH_LAYOUT);
    cy.ready(function() { fitGraphWhenVisible(cy, cyContainer); });
    addGraphViews(cy, cyContainer, GRAPH_RECORDED);
    mountGraphView({graph: cy, container: cyContainer, recorded: GRAPH_RECORDED, view: GRAPH_BOUND, state: GRAPH_STATE,
      layout: GRAPH_LAYOUT, bar: cyContainer.parentNode.querySelector('.graph-filter-bar'),
      onRedraw: function(view) { renderSupplyStats(view); }});

    // Tooltip
    var tip = document.getElementById('tip');
    cy.on('mouseover', 'node', function(e) {
      var t = e.target.data('tip');
      if (t) { tip.textContent = t; tip.style.display = 'block'; }
    });
    cy.on('mousemove', function(e) {
      if (tip.style.display === 'block') {
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }
    });
    cy.on('mouseout', 'node', function() { tip.style.display = 'none'; });

    // Click to highlight + sidebar
    var sidebar = document.getElementById('nodeDetailSidebar');
    var sidebarCloseBtn = document.getElementById('sidebarClose');

    function escHtml(value) {
      return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
      });
    }

    function urlPart(value) {
      return encodeURIComponent(String(value == null ? '' : value));
    }

    function showSidebar(node) {
      var d = node.data();
      var t = d.type || '';
      // A group node lists its members in its tip; it has no single advisory to link to.
      var isCveNode = (t === 'cve' || t.indexOf('cve_')===0) && !(d.count > 1);
      var typeLabels = {'provider':'Provider','agent':'Agent','server_clean':'MCP Server','server_cred':'MCP Server','server_vuln':'MCP Server','pkg_vuln':'Package','cve':'Vulnerability'};
      var typeLabel = typeLabels[t] || (isCveNode ? 'Vulnerability' : t);
      var typeColors = {'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'};
      var badgeColor = typeColors[t] || (isCveNode ? '#f87171' : '#64748b');

      document.getElementById('sidebarNodeType').textContent = typeLabel;
      document.getElementById('sidebarNodeType').style.borderColor = badgeColor;
      document.getElementById('sidebarNodeType').style.color = badgeColor;
      document.getElementById('sidebarNodeName').textContent = d.label || d.id;

      ['sidebarMeta','sidebarConnected','sidebarCredentials','sidebarCves','sidebarRemediation'].forEach(function(id) {
        document.getElementById(id).innerHTML = '';
      });

      // Connected nodes
      var neighbors = node.neighborhood('node');
      if (neighbors.length > 0) {
        var h = '<div class="sidebar-label">Connected (' + neighbors.length + ')</div><ul class="sidebar-list">';
        neighbors.forEach(function(n) {
          var nt = n.data('type') || '';
          var icon = nt === 'agent' ? '&#x1f916;' : nt.indexOf('server')===0 ? '&#x2699;' : nt === 'pkg_vuln' ? '&#x1f4e6;' : (nt === 'cve' || nt.indexOf('cve_')===0) ? '&#x1f41b;' : '&#x25cf;';
          h += '<li>' + icon + ' ' + escHtml((n.data('label') || n.data('id')).replace('\n',' ')) + '</li>';
        });
        h += '</ul>';
        document.getElementById('sidebarConnected').innerHTML = h;
      }

      // Agent
      if (t === 'agent') {
        var meta = '';
        if (d.agentType) meta += 'Type: ' + d.agentType + '\n';
        if (d.discovery_source) meta += 'Source: ' + d.discovery_source + '\n';
        if (d.configPath) meta += 'Config: ' + d.configPath;
        document.getElementById('sidebarMeta').textContent = meta;
        var s = '<div class="sidebar-label">Statistics</div><ul class="sidebar-list">';
        s += '<li>Servers: ' + (d.serverCount || 0) + '</li>';
        s += '<li>Packages: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) s += '<li style="color:#f87171">Vulnerabilities: ' + d.vulnCount + '</li>';
        s += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = s;
      }

      // Server
      if (t.indexOf('server_')===0) {
        if (d.command) document.getElementById('sidebarMeta').textContent = d.command;
        var creds = []; try { creds = JSON.parse(d.credentials || '[]'); } catch(e) {}
        if (creds.length > 0) {
          var ch = '<div class="sidebar-label">Credentials (' + creds.length + ')</div><ul class="sidebar-list">';
          creds.forEach(function(c) { ch += '<li>&#x1f511; <span class="sidebar-cred">' + escHtml(c) + '</span></li>'; });
          ch += '</ul>';
          document.getElementById('sidebarCredentials').innerHTML = ch;
        }
        var tools = []; try { tools = JSON.parse(d.toolNames || '[]'); } catch(e) {}
        if (tools.length > 0) {
          var th = '<div class="sidebar-label">MCP Tools (' + tools.length + ')</div><ul class="sidebar-list">';
          tools.forEach(function(tl) { th += '<li>&#x1f527; ' + escHtml(tl) + '</li>'; });
          th += '</ul>';
          document.getElementById('sidebarRemediation').innerHTML = th;
        }
        var ph = '<div class="sidebar-label">Packages</div><ul class="sidebar-list">';
        ph += '<li>Total: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) ph += '<li style="color:#f87171">Vulnerable: ' + d.vulnCount + '</li>';
        ph += '</ul>';
        document.getElementById('sidebarCves').innerHTML = ph;
      }

      // Package
      if (t === 'pkg_vuln') {
        document.getElementById('sidebarMeta').textContent = (d.ecosystem || '') + ' \u00b7 ' + (d.version || '');
        var vids = []; try { vids = JSON.parse(d.vulnIds || '[]'); } catch(e) {}
        if (vids.length > 0) {
          var vh = '<div class="sidebar-label">CVEs (' + vids.length + ')</div><ul class="sidebar-list">';
          vids.forEach(function(vid) {
            vh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(vid) + '" target="_blank" rel="noopener noreferrer">' + escHtml(vid) + ' &#x2197;</a></li>';
          });
          vh += '</ul>';
          document.getElementById('sidebarCves').innerHTML = vh;
        }
      }

      // CVE
      if (isCveNode) {
        var sev = d.severity || t.replace('cve_', '');
        var mp = [];
        if (sev) mp.push('Severity: ' + sev.toUpperCase());
        if (d.cvssScore) mp.push('CVSS: ' + d.cvssScore);
        document.getElementById('sidebarMeta').textContent = mp.join(' \u00b7 ');
        if (d.summary) {
          document.getElementById('sidebarCredentials').innerHTML = '<div class="sidebar-label">Summary</div><p style="font-size:.8rem;color:#cbd5e1;margin:0">' + escHtml(d.summary) + '</p>';
        }
        var rh = '<div class="sidebar-label">Remediation</div><ul class="sidebar-list">';
        if (d.fixVersion) {
          rh += '<li style="color:#4ade80">&#x2705; Fix: upgrade to <code>' + escHtml(d.fixVersion) + '</code></li>';
        } else {
          rh += '<li style="color:#f59e0b">&#x26a0; No fix available</li>';
        }
        var lbl = d.label || '';
        rh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on OSV &#x2197;</a></li>';
        rh += '<li><a class="sidebar-link" href="https://nvd.nist.gov/vuln/detail/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on NVD &#x2197;</a></li>';
        rh += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = rh;
      }

      sidebar.classList.add('open');
      sidebar.style.display = 'block';
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      setTimeout(function() { sidebar.style.display = 'none'; }, 250);
    }

    sidebarCloseBtn.addEventListener('click', closeSidebar);

    cy.on('tap', 'node', function(e) {
      cy.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cy.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
      showSidebar(e.target);
    });
    cy.on('tap', function(e) {
      if (e.target === cy) {
        cy.elements().removeClass('faded highlighted');
        closeSidebar();
      }
    });

    // Graph controls
    document.getElementById('zoomIn').addEventListener('click', function() {
      cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    });
    document.getElementById('zoomOut').addEventListener('click', function() {
      cy.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    });
    document.getElementById('fitBtn').addEventListener('click', function() {
      cy.fit(cy.elements(), 40);
    });
    document.getElementById('fullscreenBtn').addEventListener('click', function() {
      var gc = document.querySelector('.graph-container');
      if (!document.fullscreenElement) {
        gc.requestFullscreen().then(function() {
          setTimeout(function() { cy.resize(); cy.fit(cy.elements(), 50); }, 100);
        }).catch(function() {});
      } else {
        document.exitFullscreen();
      }
    });
    document.addEventListener('fullscreenchange', function() {
      if (!document.fullscreenElement) {
        setTimeout(function() { cy.resize(); cy.fit(cy.elements(), 40); }, 100);
      }
    });
    // Context menu (right-click on nodes)
    var ctxMenu = document.createElement('div');
    ctxMenu.className = 'cy-ctx-menu';
    document.body.appendChild(ctxMenu);

    function hideCtxMenu() { ctxMenu.classList.remove('show'); }
    document.addEventListener('click', hideCtxMenu);
    document.addEventListener('scroll', hideCtxMenu);

    cy.on('cxttap', 'node', function(e) {
      e.originalEvent.preventDefault();
      var node = e.target;
      var d = node.data();
      var t = d.type || '';
      var items = [];

      // Focus neighborhood
      items.push({icon:'&#x1f50d;',label:'Focus neighborhood',action:function(){
        cy.elements().removeClass('faded highlighted');
        var hood = node.closedNeighborhood();
        cy.elements().not(hood).addClass('faded');
        node.addClass('highlighted');
        showSidebar(node);
      }});
      // Fit to node
      items.push({icon:'&#x1f4cd;',label:'Zoom to node',action:function(){
        cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 }, duration: 400 });
      }});
      // Highlight path to root
      items.push({icon:'&#x2b06;',label:'Trace to root',action:function(){
        cy.elements().removeClass('faded highlighted');
        var path = node.predecessors().union(node);
        cy.elements().not(path).addClass('faded');
        path.nodes().addClass('highlighted');
      }});
      // Highlight downstream
      items.push({icon:'&#x2b07;',label:'Show downstream impact',action:function(){
        cy.elements().removeClass('faded highlighted');
        var downstream = node.successors().union(node);
        cy.elements().not(downstream).addClass('faded');
        downstream.nodes().addClass('highlighted');
      }});

      // Vulnerability node: open in OSV
      if ((t === 'cve' || t.indexOf('cve_')===0) && !(d.count > 1)) {
        var vid = d.label || '';
        items.push({sep:true});
        items.push({icon:'&#x1f517;',label:'Open in OSV',action:function(){
          window.open('https://osv.dev/vulnerability/'+vid, '_blank');
        }});
        items.push({icon:'&#x1f517;',label:'Open in NVD',action:function(){
          window.open('https://nvd.nist.gov/vuln/detail/'+vid, '_blank');
        }});
      }

      // Build menu HTML
      ctxMenu.innerHTML = '';
      items.forEach(function(item) {
        if (item.sep) {
          var sep = document.createElement('div');
          sep.className = 'cy-ctx-sep';
          ctxMenu.appendChild(sep);
        } else {
          var el = document.createElement('div');
          el.className = 'cy-ctx-item';
          el.innerHTML = '<span>'+item.icon+'</span> '+item.label;
          el.addEventListener('click', function(ev) {
            ev.stopPropagation();
            hideCtxMenu();
            item.action();
          });
          ctxMenu.appendChild(el);
        }
      });

      var cx = e.originalEvent.clientX, cy2 = e.originalEvent.clientY;
      ctxMenu.style.left = cx + 'px';
      ctxMenu.style.top = cy2 + 'px';
      ctxMenu.classList.add('show');
    });

    // Minimap: render a small overview of the full graph
    var minimapEl = document.createElement('div');
    minimapEl.className = 'cy-minimap';
    cyContainer.parentNode.appendChild(minimapEl);
    var mmCanvas = document.createElement('canvas');
    mmCanvas.width = 180; mmCanvas.height = 130;
    minimapEl.appendChild(mmCanvas);

    function drawMinimap() {
      var ctx2d = mmCanvas.getContext('2d');
      ctx2d.clearRect(0, 0, 180, 130);
      var bb = cy.elements().boundingBox();
      if (!bb || bb.w === 0) return;
      var scaleX = 170 / bb.w, scaleY = 120 / bb.h;
      var sc = Math.min(scaleX, scaleY);
      var offX = (180 - bb.w * sc) / 2 - bb.x1 * sc;
      var offY = (130 - bb.h * sc) / 2 - bb.y1 * sc;

      // Draw edges
      ctx2d.strokeStyle = '#334155'; ctx2d.lineWidth = 0.5;
      cy.edges().forEach(function(edge) {
        var sp = edge.sourceEndpoint(), tp = edge.targetEndpoint();
        ctx2d.beginPath();
        ctx2d.moveTo(sp.x * sc + offX, sp.y * sc + offY);
        ctx2d.lineTo(tp.x * sc + offX, tp.y * sc + offY);
        ctx2d.stroke();
      });

      // Draw nodes
      cy.nodes().forEach(function(n) {
        var pos = n.position(); var t = n.data('type') || '';
        var colors = {'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'};
        ctx2d.fillStyle = colors[t] || (t === 'cve' || t.indexOf('cve_')===0 ? '#f87171' : '#64748b');
        var nx = pos.x * sc + offX, ny = pos.y * sc + offY;
        ctx2d.beginPath();
        if (t === 'cve' || t.indexOf('cve_')===0) {
          // Diamond
          ctx2d.moveTo(nx, ny - 4); ctx2d.lineTo(nx + 5, ny); ctx2d.lineTo(nx, ny + 4); ctx2d.lineTo(nx - 5, ny);
        } else {
          ctx2d.arc(nx, ny, 3, 0, Math.PI * 2);
        }
        ctx2d.fill();
      });

      // Viewport rectangle
      var ext = cy.extent();
      ctx2d.strokeStyle = '#60a5fa'; ctx2d.lineWidth = 1.5;
      ctx2d.strokeRect(ext.x1 * sc + offX, ext.y1 * sc + offY, ext.w * sc, ext.h * sc);
    }

    cy.on('render viewport', drawMinimap);
    setTimeout(drawMinimap, 500);

    // Click minimap to pan
    mmCanvas.addEventListener('click', function(e) {
      var rect = mmCanvas.getBoundingClientRect();
      var mx = e.clientX - rect.left, my = e.clientY - rect.top;
      var bb = cy.elements().boundingBox();
      if (!bb || bb.w === 0) return;
      var scaleX = 170 / bb.w, scaleY = 120 / bb.h;
      var sc = Math.min(scaleX, scaleY);
      var offX = (180 - bb.w * sc) / 2 - bb.x1 * sc;
      var offY = (130 - bb.h * sc) / 2 - bb.y1 * sc;
      var targetX = (mx - offX) / sc, targetY = (my - offY) / sc;
      cy.animate({ center: { x: targetX, y: targetY }, duration: 300 });
    });

    // Node statistics overlay; a group counts every finding it holds.
    var nodeStats = document.createElement('div');
    nodeStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    cyContainer.parentNode.appendChild(nodeStats);
    function renderSupplyStats(view) {
    var nodeCounts = {};
    cy.nodes().forEach(function(n) {
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      else if (t.indexOf('server_')===0) t = 'server';
      nodeCounts[t] = (nodeCounts[t] || 0) + findingWeight(n.data());
    });
    var statsHTML = [];
    if (nodeCounts.agent) statsHTML.push('<span style="color:#3b82f6">' + nodeCounts.agent + ' agents</span>');
    if (nodeCounts.server) statsHTML.push('<span style="color:#10b981">' + nodeCounts.server + ' servers</span>');
    if (nodeCounts.pkg_vuln) statsHTML.push('<span style="color:#dc2626">' + nodeCounts.pkg_vuln + ' packages</span>');
    if (nodeCounts.cve) statsHTML.push('<span style="color:#f87171">' + nodeCounts.cve + ' CVEs</span>');
    if (nodeCounts.finding) statsHTML.push('<span style="color:#fca5a5">' + nodeCounts.finding + ' findings</span>');
    nodeStats.innerHTML = (view.bounded ? 'Drawn: ' : '') + statsHTML.join(' &middot; ');
    }
    renderSupplyStats(GRAPH_BOUND);

  } else if (cyContainer) {
    cyContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#4ade80;font-size:.9rem">&#x2705; No supply chain nodes to display</div>';
  }

  // Findings-table pagination, filtering, and tabs live in the standalone
  // scale-report script (below) so they keep working even if the CDN chart /
  // graph libraries fail to load, the common case for an offline or emailed
  // report. Nothing table/tab related runs here.

  }
  function drawAttackFlowGraph() {
  var ATTACK_FLOW_RECORDED = readGraphData('agentBomAttackFlow');
  var ATTACK_FLOW_STATE = {limit: GRAPH_FIRST_DRAW, follow: 'out', inventoryFirst: false, severities: null, matches: null};
  var ATTACK_FLOW_BOUND = graphView(ATTACK_FLOW_RECORDED, ATTACK_FLOW_STATE);
  var ATTACK_FLOW = ATTACK_FLOW_BOUND.elements;
  // Cytoscape: CVE Attack Flow graph
  var cyAtkContainer = document.getElementById('cyAttack');
  if (cyAtkContainer && ATTACK_FLOW.length > 0) {
    var cyAtk = cytoscape({
      container: cyAtkContainer,
      elements: ATTACK_FLOW,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)', 'font-size': 12, 'color': '#e2e8f0',
            'text-valign': 'center', 'text-halign': 'center',
            'text-wrap': 'wrap', 'text-max-width': 140,
            'width': 156, 'height': 60, 'shape': 'round-rectangle',
            'background-color': '#334155', 'border-color': '#94a3b8', 'border-width': 1.5,
          },
        },
        {
          selector: 'node[type="cve"], node[type^="cve_"]',
          style: {
            'shape': 'round-rectangle',
            'width': 120,
            'height': 34,
            'label': 'data(label)',
            'font-size': '11px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'color': '#fecaca',
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2.5,
          },
        },
        {
          selector: 'node[type="cve"][severity="critical"], node[type="cve_critical"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#ef4444',
            'border-width': 3,
            'width': 130,
            'height': 38,
            'underlay-color': '#ef4444',
            'underlay-padding': '6px',
            'underlay-opacity': 0.15,
            'underlay-shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type="cve"][severity="high"], node[type="cve_high"]',
          style: {
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'color': '#fed7aa',
            'underlay-color': '#fb923c',
            'underlay-padding': '4px',
            'underlay-opacity': 0.1,
            'underlay-shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type="cve_medium"], node[type="cve_low"], node[type="cve_none"]',
          style: {
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'color': '#fef08a',
            'width': 100,
            'height': 28,
          },
        },
        {
          selector: 'node[type="pkg_vuln"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '11px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          },
        },
        {
          selector: 'node[type="server"]',
          style: {
            'background-color': '#1e293b',
            'border-color': '#475569',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': '12px',
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="credential"]',
          style: {
            'background-color': '#78350f',
            'border-color': '#fbbf24',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '11px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 32,
            'shape': 'hexagon',
          },
        },
        {
          selector: 'node[type="tool"]',
          style: {
            'background-color': '#312e81',
            'border-color': '#818cf8',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '11px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 30,
            'shape': 'round-tag',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
          },
        },
        {
          selector: 'node[type="agent"]',
          style: {
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '11px',
            'font-weight': 700,
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          },
        },
        {
          selector: 'edge[type="exploits"]',
          style: {
            'line-color': '#dc2626',
            'target-arrow-color': '#ef4444',
            'width': 2.5,
          },
        },
        {
          selector: 'edge[type="runs_on"]',
          style: {
            'line-color': '#475569',
            'target-arrow-color': '#64748b',
          },
        },
        {
          selector: 'edge[type="exposes"]',
          style: {
            'line-color': '#f59e0b',
            'target-arrow-color': '#fbbf24',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
            'width': 2,
          },
        },
        {
          selector: 'edge[type="reaches"]',
          style: {
            'line-color': '#818cf8',
            'target-arrow-color': '#a5b4fc',
            'line-style': 'dashed',
            'line-dash-pattern': [4, 4],
          },
        },
        {
          selector: 'edge[type="compromises"]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#f87171',
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4],
            'width': 2.5,
          },
        },
        {
          selector: '.highlighted',
          style: {
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          },
        },
        {
          selector: '.faded',
          style: { 'opacity': 0.08 },
        },
        {
          selector: 'node[type="cve"], node[type^="cve_"]',
          style: {
            'label': function(node) { return (node.data('label') || '').split(' ')[0]; },
            'font-size': 11, 'width': 140, 'height': 42,
            'text-wrap': 'wrap', 'text-max-width': 128, 'text-overflow-wrap': 'anywhere',
          },
        },
        {
          selector: 'node[count > 1]',
          style: {'label': 'data(label)', 'width': 176, 'height': 44, 'text-max-width': 164, 'font-size': 12},
        },
        {
          selector: 'node[type="directory"], node[type="source_file"], node[type="config_file"]',
          style: {
            'label': function(node) { var label = node.data('label') || ''; return label === '.' ? 'Project root' : label.replace(/^project:/, ''); },
            'text-overflow-wrap': 'anywhere',
          },
        },
      ],
      layout: {name: 'null'},
      minZoom: 0.15,
      maxZoom: 4,
    });
    var ATTACK_FLOW_LAYOUT = {rankDir: window.innerWidth < 700 ? 'TB' : 'LR', nodeSep: 40, rankSep: 100, edgeSep: 12, padding: 30};
    layoutGraph(cyAtk, ATTACK_FLOW_LAYOUT);
    cyAtk.ready(function() { fitGraphWhenVisible(cyAtk, cyAtkContainer); });
    addGraphViews(cyAtk, cyAtkContainer, ATTACK_FLOW_RECORDED);
    mountGraphView({graph: cyAtk, container: cyAtkContainer, recorded: ATTACK_FLOW_RECORDED, view: ATTACK_FLOW_BOUND,
      state: ATTACK_FLOW_STATE, layout: ATTACK_FLOW_LAYOUT, bar: cyAtkContainer.parentNode.querySelector('.graph-filter-bar'),
      onRedraw: function(view) { renderAttackStats(view); }});

    // Attack flow tooltip
    cyAtk.on('mouseover', 'node', function(e) {
      var t = e.target.data('tip');
      if (t) { tip.textContent = t; tip.style.display = 'block'; }
    });
    cyAtk.on('mousemove', function(e) {
      if (tip.style.display === 'block') {
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }
    });
    cyAtk.on('mouseout', 'node', function() { tip.style.display = 'none'; });

    // Attack flow click to highlight
    cyAtk.on('tap', 'node', function(e) {
      cyAtk.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cyAtk.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
    });
    cyAtk.on('tap', function(e) {
      if (e.target === cyAtk) {
        cyAtk.elements().removeClass('faded highlighted');
      }
    });

    // Attack flow controls
    var afZoomIn = document.getElementById('afZoomIn');
    var afZoomOut = document.getElementById('afZoomOut');
    var afFitBtn = document.getElementById('afFitBtn');
    if (afZoomIn) afZoomIn.addEventListener('click', function() {
      cyAtk.zoom({ level: cyAtk.zoom() * 1.3, renderedPosition: { x: cyAtk.width() / 2, y: cyAtk.height() / 2 } });
    });
    if (afZoomOut) afZoomOut.addEventListener('click', function() {
      cyAtk.zoom({ level: cyAtk.zoom() / 1.3, renderedPosition: { x: cyAtk.width() / 2, y: cyAtk.height() / 2 } });
    });
    if (afFitBtn) afFitBtn.addEventListener('click', function() {
      cyAtk.fit(cyAtk.elements(), 40);
    });

    // Animated dash flow on exploit/compromises edges
    var dashOffset = 0;
    function animateAttackEdges() {
      dashOffset = (dashOffset + 0.5) % 24;
      cyAtk.edges('[type="exploits"],[type="compromises"]').forEach(function(edge) {
        edge.style('line-dash-offset', -dashOffset);
      });
      requestAnimationFrame(animateAttackEdges);
    }
    // Only animate if attack edges exist
    if (cyAtk.edges('[type="exploits"],[type="compromises"]').length > 0) {
      // Set dashed style for animation
      cyAtk.edges('[type="exploits"]').style({
        'line-style': 'dashed',
        'line-dash-pattern': [8, 4],
      });
      cyAtk.edges('[type="compromises"]').style({
        'line-style': 'dashed',
        'line-dash-pattern': [10, 5],
      });
      animateAttackEdges();
    }

    // Attack flow node count stats; a group counts every finding it holds.
    var afStats = document.createElement('div');
    afStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    cyAtkContainer.parentNode.appendChild(afStats);
    function renderAttackStats(view) {
    var afCounts = {};
    cyAtk.nodes().forEach(function(n) {
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      afCounts[t] = (afCounts[t] || 0) + findingWeight(n.data());
    });
    var afParts = [];
    if (afCounts.cve) afParts.push('<span style="color:#f87171">' + afCounts.cve + ' CVEs</span>');
    if (afCounts.pkg_vuln) afParts.push('<span style="color:#dc2626">' + afCounts.pkg_vuln + ' pkgs</span>');
    if (afCounts.directory || afCounts.source_file) afParts.push('<span style="color:#94a3b8">' + ((afCounts.directory || 0) + (afCounts.source_file || 0)) + ' inventory sources</span>');
    if (afCounts.server) afParts.push('<span style="color:#64748b">' + afCounts.server + ' servers</span>');
    if (afCounts.credential) afParts.push('<span style="color:#fbbf24">' + afCounts.credential + ' creds</span>');
    if (afCounts.tool) afParts.push('<span style="color:#818cf8">' + afCounts.tool + ' tools</span>');
    if (afCounts.agent) afParts.push('<span style="color:#3b82f6">' + afCounts.agent + ' agents</span>');
    afStats.innerHTML = (view.bounded ? 'Drawn: ' : '') + afParts.join(' &middot; ');
    }
    renderAttackStats(ATTACK_FLOW_BOUND);
  }

  }
  afterLoad(drawSupplyChainGraph);
  afterLoad(drawAttackFlowGraph);
  // Table sorting
  document.querySelectorAll('.data-table.sortable th').forEach(function(th) {
    th.addEventListener('click', function() {
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var col = parseInt(th.getAttribute('data-col'));
      var arrow = th.querySelector('.sort-arrow');
      var asc = !arrow.classList.contains('asc');

      table.querySelectorAll('.sort-arrow').forEach(function(a) { a.className = 'sort-arrow'; });
      arrow.className = 'sort-arrow ' + (asc ? 'asc' : 'desc');
      // A paginated list sorts every stored record, not only the mounted page.
      if (window.PAGINATORS && window.PAGINATORS[table.id] && window.PAGINATORS[table.id].sort) {
        window.PAGINATORS[table.id].sort(col, asc);
        return;
      }

      rows.sort(function(a, b) {
        var at = (a.children[col] || {}).textContent || '';
        var bt = (b.children[col] || {}).textContent || '';
        var an = parseFloat(at.replace(/[^\d.-]/g, ''));
        var bn = parseFloat(bt.replace(/[^\d.-]/g, ''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? at.localeCompare(bt) : bt.localeCompare(at);
      });
      rows.forEach(function(r) { tbody.appendChild(r); });
    });
  });

  // Inventory search
  var searchInput = document.getElementById('invSearch');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      var q = this.value.toLowerCase();
      document.querySelectorAll('.agent-card').forEach(function(card) {
        var text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
      });
    });
  }

  // Package list toggle
  window.togglePkgs = function(id, btn) {
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    btn.innerHTML = hidden
      ? 'Show fewer &#x25B2;'
      : btn.dataset.orig || btn.innerHTML;
    if (hidden && !btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
  };

  // Smooth scroll + close mobile sidebar. Tab reveal + robust anchor handling
  // live in the standalone scale-report script so they survive CDN/graph load
  // failures (offline / emailed reports).
  document.querySelectorAll('a[href^="#"]').forEach(function(a) {
    a.addEventListener('click', function() {
      var sb = document.getElementById('mainSidebar');
      if (sb) sb.classList.remove('mobile-open');
    });
  });

  // Sidebar active section tracking via IntersectionObserver
  var sidebarLinks = document.querySelectorAll('.sidebar-link');
  var sections = document.querySelectorAll('section[id]');
  if (sections.length > 0 && 'IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          sidebarLinks.forEach(function(link) {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + entry.target.id) {
              link.classList.add('active');
            }
          });
        }
      });
    }, { rootMargin: '-20% 0px -60% 0px', threshold: 0 });
    sections.forEach(function(sec) { observer.observe(sec); });
  }
})();
</script>
<script type="application/json" class="graph-data" id="agentBomGraphElements">__GRAPH_ELEMENTS__</script>
<script type="application/json" class="graph-data" id="agentBomAttackFlow">__ATTACK_FLOW__</script>
