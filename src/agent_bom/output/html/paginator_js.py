"""Client-side paginator for findings lists whose later records are stored as inert text.

Every record keeps its server-rendered markup. Only the visible page is parsed
into the document; filters, whole-list search and sorting read attributes and
text straight from the stored markup, so a 50,000-row list never becomes
50,000 live rows. Printing mounts every record, so a printed or PDF export
stays complete.
"""

PAGINATOR_JS = r"""
  var ENTITIES = {amp: '&', lt: '<', gt: '>', quot: '"', nbsp: ' ', mdash: '—', ndash: '–', middot: '·', hellip: '…', rsaquo: '›', lsaquo: '‹'};
  function decodeText(s) {
    return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, function(m, e) {
      if (e[0] === '#') { var c = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return isNaN(c) ? m : String.fromCodePoint(c); }
      return Object.prototype.hasOwnProperty.call(ENTITIES, e.toLowerCase()) ? ENTITIES[e.toLowerCase()] : m;
    });
  }
  function stripTags(s) { return decodeText(s.replace(/<[^>]*>/g, '')); }
  // One list record: its stored markup, plus the element only while it is mounted.
  function Row(html) { this.html = html; this.el = null; this.text = null; }
  Row.prototype.getAttribute = function(name) {
    var open = this.html.slice(0, this.html.indexOf('>'));
    var m = open.match(new RegExp('\\s' + name + '="([^"]*)"'));
    return m ? decodeText(m[1]) : null;
  };
  Object.defineProperty(Row.prototype, 'textContent', {get: function() {
    if (this.text === null) this.text = stripTags(this.html);
    return this.text;
  }});
  Row.prototype.cell = function(col) {
    var re = /<td\b[^>]*>/gi, m, i = -1, start = -1;
    while ((m = re.exec(this.html))) { i++; if (i === col) { start = re.lastIndex; break; } }
    if (start < 0) return '';
    var rest = this.html.slice(start), end = rest.search(/<td\b/i);
    return stripTags(end >= 0 ? rest.slice(0, end) : rest);
  };
  Row.prototype.mount = function() {
    if (!this.el) {
      var t = document.createElement('template');
      t.innerHTML = this.html;
      this.el = t.content.firstElementChild;
    }
    return this.el;
  };

  function makePaginator(tableId, filterFn) {
    var table = document.getElementById(tableId);
    if (!table) return null;
    var body = table.tBodies && table.tBodies[0] ? table.tBodies[0] : table;
    var bar = document.querySelector('.pager[data-pager="' + tableId + '"]');
    var rows = Array.prototype.map.call(body.children, function(el) { var r = new Row(el.outerHTML); r.el = el; return r; });
    var store = document.querySelector('script.deferred-rows[data-rows-for="' + tableId + '"]');
    if (store) store.textContent.split('\n').forEach(function(html) { if (html) rows.push(new Row(html)); });
    var pageSize = bar ? (parseInt(bar.getAttribute('data-page-size'), 10) || 50) : 50;
    var page = 1;
    var matched = rows;
    var shown = [];
    var infoEl = bar ? bar.querySelector('.pager-info') : null;
    var headings = Array.from(table.querySelectorAll('thead th')).map(function(th) { return th.textContent.trim(); });
    function prepareRow(row) {
      if (row.dataset.detailsReady) return;
      row.dataset.detailsReady = 'true';
      if (!table.tBodies) return;
      Array.from(row.cells).forEach(function(cell, index) { cell.setAttribute('data-label', headings[index] || 'Evidence'); });
      if (!table.classList.contains('paginated') || table.classList.contains('finding-overview')) return;
      var button = document.createElement('button');
      button.className = 'row-detail-toggle'; button.textContent = 'Show evidence';
      button.setAttribute('aria-expanded', 'false');
      button.onclick = function() {
        var expanded = row.classList.toggle('row-expanded');
        button.setAttribute('aria-expanded', String(expanded));
        button.textContent = expanded ? 'Hide evidence' : 'Show evidence';
      };
      if (row.cells[0]) row.cells[0].append(button);
    }
    function show(list) {
      // Rows leaving the page are released; their stored markup mounts them again.
      shown.forEach(function(r) { r.el = null; });
      var fragment = document.createDocumentFragment();
      list.forEach(function(r) { var el = r.mount(); el.classList.remove('pg-hidden'); prepareRow(el); fragment.appendChild(el); });
      body.textContent = '';
      body.appendChild(fragment);
      shown = list;
    }
    function render() {
      var total = matched.length;
      var pages = Math.max(1, Math.ceil(total / pageSize));
      if (page > pages) page = pages;
      if (page < 1) page = 1;
      var start = (page - 1) * pageSize;
      var end = start + pageSize;
      show(matched.slice(start, end));
      if (bar) {
        if (infoEl) infoEl.innerHTML = total ? (start + 1) + '&ndash;' + Math.min(end, total) + ' of ' + total : '0 of 0';
        var f = bar.querySelector('[data-act="first"]'), pv = bar.querySelector('[data-act="prev"]'),
            nx = bar.querySelector('[data-act="next"]'), ls = bar.querySelector('[data-act="last"]');
        if (f) f.disabled = page <= 1;
        if (pv) pv.disabled = page <= 1;
        if (nx) nx.disabled = page >= pages;
        if (ls) ls.disabled = page >= pages;
        bar.style.display = pages > 1 ? '' : 'none';
      }
    }
    function apply() { matched = filterFn ? rows.filter(filterFn) : rows; page = 1; render(); }
    function sort(col, asc) {
      var keyed = rows.map(function(r, i) {
        var text = r.cell(col), num = parseFloat(text.replace(/[^\d.-]/g, ''));
        return {r: r, text: text, num: num, i: i};
      });
      keyed.sort(function(a, b) {
        var d = !isNaN(a.num) && !isNaN(b.num) ? a.num - b.num : a.text.localeCompare(b.text);
        return (asc ? d : -d) || a.i - b.i;
      });
      rows = keyed.map(function(k) { return k.r; });
      apply();
    }
    if (bar) {
      bar.addEventListener('click', function(e) {
        var act = e.target.getAttribute && e.target.getAttribute('data-act');
        if (!act) return;
        var pages = Math.max(1, Math.ceil(matched.length / pageSize));
        if (act === 'first') page = 1;
        else if (act === 'prev') page = Math.max(1, page - 1);
        else if (act === 'next') page = Math.min(pages, page + 1);
        else if (act === 'last') page = pages;
        render();
      });
      var sizeSel = bar.querySelector('.pager-size');
      if (sizeSel) sizeSel.addEventListener('change', function() { pageSize = parseInt(this.value, 10) || 50; page = 1; render(); });
    }
    var api = {
      apply: apply, render: render, sort: sort,
      counts: function() { return {matched: matched.length, total: rows.length}; },
    };
    // A printed or PDF export lists every record with its evidence open.
    window.addEventListener('beforeprint', function() {
      show(rows);
      body.querySelectorAll('details').forEach(function(d) { d.open = true; });
    });
    window.addEventListener('afterprint', render);
    window.PAGINATORS[tableId] = api;
    apply();
    return api;
  }
"""
