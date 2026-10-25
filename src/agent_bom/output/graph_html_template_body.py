"""Script section of the interactive standalone graph HTML export."""

_GRAPH_HTML_TEMPLATE_BODY = """<script>
const els={elements_json};
const topRisks={top_risks_json};
const overview={overview_json};
const categoryFindings={category_findings_json};
let activeRiskNodeId=null;
let focusedPathOnly=false;
let credentialsOnly=false;
let activeSeverity='all';
const expandedPackages = new Map();
cytoscape.use(cytoscapeDagre);
const cy=cytoscape({{
  container:document.getElementById('cy'),elements:els,
  layout:{{name:'dagre',rankDir:'LR',align:'DL',nodeSep:90,edgeSep:20,rankSep:240,padding:56,ranker:'network-simplex',acyclicer:'greedy'}},
  style:[
    {{selector:'node',style:{{'label':'data(label)','text-wrap':'wrap','text-max-width':180,
      'font-size':14,'font-weight':700,'min-zoomed-font-size':6,'text-valign':'center','color':'#e7e9ea','width':160,'height':46,
      'shape':'roundrectangle','background-color':'#2f3336','border-width':1.2,'border-color':'#444',
      'text-outline-width':2,'text-outline-color':'#0f1419'}}}},
    {{selector:'node[type="provider"]',style:{{'background-color':'#1a3a5c','border-color':'#4a9eff','width':132,'height':38,'font-size':11}}}},
    {{selector:'node[type="agent"]',style:{{'background-color':'#1a3520','border-color':'#2ea043','shape':'barrel','width':200,'height':56}}}},
    {{selector:'node[type="server_clean"]',style:{{
      'background-color':'#21262d','border-color':'#6e7681','border-width':3,
      'width':'mapData(packageCount, 1, 12, 190, 250)','height':56,'opacity':0.78
    }}}},
    {{selector:'node[type="server_blocked"]',style:{{
      'background-color':'#4a0612','border-color':'#ff3b30','border-width':4,
      'width':'mapData(securityIntelligenceCount, 1, 10, 210, 300)','height':60
    }}}},
    {{selector:'node[type="server_intel"]',style:{{
      'background-color':'#3f2a0b','border-color':'#f59e0b','border-width':3,
      'width':'mapData(securityIntelligenceCount, 1, 10, 200, 280)','height':58
    }}}},
    {{selector:'node[type="server_vuln"]',style:{{
      'background-color':'#451f24','border-color':'#ff5d5d','border-width':3,
      'width':'mapData(vulnCount, 1, 40, 200, 300)','height':56
    }}}},
    {{selector:'node[type="server_cred"]',style:{{
      'background-color':'#4c3411','border-color':'#f2b84b','border-width':3,
      'width':'mapData(vulnCount, 0, 40, 200, 300)','height':56
    }}}},
    {{selector:'node[type="credential"]',style:{{
      'background-color':'#f2b84b','border-color':'#b45309','color':'#111827',
      'shape':'tag','width':150,'height':42,'font-size':12
    }}}},
    {{selector:'node[type="tool"]',style:{{
      'background-color':'#38bdf8','border-color':'#0369a1','color':'#082f49',
      'shape':'roundrectangle','width':160,'height':42,'font-size':12
    }}}},
    {{selector:'node[type="pkg_vuln"]',style:{{
      'background-color':'#3b1a1a','border-color':'#da3633',
      'width':'mapData(vulnCount, 1, 15, 180, 280)','height':58,'text-max-width':220
    }}}},
    {{selector:'node[type="directory"]',style:{{
      'background-color':'#0f2e2b','border-color':'#0d9488','border-width':2,
      'shape':'roundrectangle','width':150,'height':42,'font-size':12
    }}}},
    {{selector:'node[type="config_file"]',style:{{
      'background-color':'#3f2a0b','border-color':'#f97316','color':'#fed7aa',
      'shape':'cut-rectangle','width':150,'height':40,'font-size':12
    }}}},
    {{selector:'node[type="source_file"]',style:{{
      'background-color':'#0c2b33','border-color':'#22d3ee','color':'#a5f3fc',
      'shape':'cut-rectangle','width':150,'height':40,'font-size':12
    }}}},
    {{selector:'node[type="cve"][severity="critical"], node[type^="cve_critical"]',style:{{'background-color':'#ff3b30','color':'#fff',
      'shape':'diamond','width':160,'height':70}}}},
    {{selector:'node[type="cve"][severity="high"], node[type^="cve_high"]',style:{{'background-color':'#ff8a24','color':'#fff',
      'shape':'diamond','width':140,'height':60}}}},
    {{selector:'node[type="cve"][severity="medium"], node[type^="cve_medium"]',style:{{'background-color':'#ffd33d','color':'#000',
      'shape':'diamond','width':120,'height':52}}}},
    {{selector:'node[type="cve"][severity="low"], node[type^="cve_low"]',style:{{'background-color':'#6e7681','color':'#fff',
      'shape':'diamond','width':100,'height':44}}}},
    {{selector:'node[type="cve"][severity="unknown"], node[type^="cve_unknown"]',style:{{'background-color':'#4b5563','color':'#d1d5db',
      'shape':'roundrectangle','width':90,'height':40,'opacity':0.66}}}},
    {{selector:'node[type="framework"]',style:{{'background-color':'#1e1b4b','border-color':'#818cf8','border-width':2,
      'shape':'round-tag','width':150,'height':40,'font-size':12}}}},
    {{selector:'node[type="finding"]',style:{{'background-color':'#2d1f47','border-color':'#a371f7','border-width':2,
      'shape':'hexagon','width':180,'height':56,'font-size':11}}}},
    {{selector:'edge',style:{{'width':1.5,'line-color':'#444','target-arrow-color':'#444',
      'target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8,'opacity':0.7}}}},
    {{selector:'edge[type="hosts"]',style:{{'line-color':'#4a9eff','target-arrow-color':'#4a9eff','width':2}}}},
    {{selector:'edge[type="uses"]',style:{{'line-color':'#2ea043','target-arrow-color':'#2ea043','width':2}}}},
    {{selector:'edge[type="uses"][securityBlocked = 1]',style:{{'line-color':'#ff3b30','target-arrow-color':'#ff3b30','width':3.5}}}},
    {{selector:'edge[type="uses"][securityIntelligence = 1]',style:{{'line-color':'#f59e0b','target-arrow-color':'#f59e0b','width':3}}}},
    {{selector:'edge[type="uses"][credentialEdge = 1]',style:{{'line-color':'#f2b84b','target-arrow-color':'#f2b84b','width':3}}}},
    {{selector:'edge[type="exposes_cred"]',style:{{'line-color':'#f2b84b','target-arrow-color':'#f2b84b','width':2}}}},
    {{selector:'edge[type="provides_tool"]',style:{{'line-color':'#38bdf8','target-arrow-color':'#38bdf8','width':1.8}}}},
    {{selector:'edge[type="reaches_tool"]',style:{{'line-style':'dashed','line-color':'#f59e0b','target-arrow-color':'#f59e0b','width':2}}}},
    {{selector:'edge[type="depends_on"]',style:{{'line-color':'#8b949e','target-arrow-color':'#8b949e','width':1.5}}}},
    {{selector:'edge[type="depends_on"][maxSeverity = "critical"]',style:{{
      'line-color':'#ff5d5d','target-arrow-color':'#ff5d5d','width':2.5
    }}}},
    {{selector:'edge[type="depends_on"][maxSeverity = "high"]',style:{{'line-color':'#ff8a24','target-arrow-color':'#ff8a24','width':2}}}},
    {{selector:'edge[type="delegated_to"]',style:{{'line-color':'#2ea043','target-arrow-color':'#2ea043','width':2.4}}}},
    {{selector:'edge[type="uses_framework"]',style:{{'line-style':'dotted','line-color':'#818cf8','target-arrow-color':'#818cf8','width':1.4}}}},
    {{selector:'edge[type="contains"]',style:{{'line-color':'#0d9488','target-arrow-color':'#0d9488','width':1.6}}}},
    {{selector:'edge[type="has_finding"]',style:{{'line-style':'dashed','line-color':'#a371f7','target-arrow-color':'#a371f7','width':1.8}}}},
    {{selector:'edge[type="affects"]',style:{{'line-style':'dashed','line-color':'#ff5d5d','target-arrow-color':'#ff5d5d','width':1.8}}}},
    {{selector:'.faded',style:{{'opacity':0.08}}}},
    {{selector:'.focus',style:{{'opacity':1,'border-width':4,'border-color':'#58a6ff','z-index':9999}}}},
    {{selector:'edge.focus',style:{{'opacity':1,'line-color':'#58a6ff','target-arrow-color':'#58a6ff','width':2.4}}}},
    {{selector:'.filtered',style:{{'display':'none'}}}},
  ],wheelSensitivity:0.3
}});

const riskByNodeId = new Map(topRisks.map((risk)=>[risk.nodeId, risk]));

function runGraphLayout(){{
  cy.layout({{
    name:'dagre',
    rankDir:'LR',
    align:'DL',
    nodeSep:90,
    edgeSep:20,
    rankSep:240,
    padding:56,
    ranker:'network-simplex',
    acyclicer:'greedy',
    animate:false,
    fit:false,
  }}).run();
}}

function severityClass(sev){{
  if(sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low') return sev;
  return '';
}}

function escapeHtml(value){{
  return String(value ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}}

function listHtml(items){{
  if(!items || !items.length) return '<div class="subtle">None in this path.</div>';
  return `<ul>${{items.map((item)=>`<li><code>${{escapeHtml(item)}}</code></li>`).join('')}}</ul>`;
}}

function recommendationHtml(risk){{
  const steps = [];
  if(risk.fixVersion) {{
    steps.push(`Upgrade <code>${{escapeHtml(risk.packageName)}}</code> to <code>${{escapeHtml(risk.fixVersion)}}</code>.`);
  }} else {{
    steps.push('No fixed version is advertised yet; isolate or contain the affected server path first.');
  }}
  if(risk.credentialCount) {{
    steps.push('Rotate or scope down exposed credentials on affected servers before wider rollout.');
  }}
  if(risk.toolCount) {{
    steps.push('Review reachable MCP tools to reduce post-exploitation blast radius.');
  }}
  if(risk.reachability && risk.reachability !== 'unknown') {{
    steps.push(`Reachability is reported as <code>${{escapeHtml(risk.reachability)}}</code>; prioritize live paths first.`);
  }}
  return `<ul>${{steps.map((item)=>`<li>${{item}}</li>`).join('')}}</ul>`;
}}

function intelligenceDetail(d){{
  let titles=[];
  try{{ titles=JSON.parse(d.securityIntelligence||'[]'); }}catch(_e){{ titles=[]; }}
  if(!Array.isArray(titles) || !titles.length) return '';
  return `<div class="subtle">MCP intelligence: ${{titles.map(t=>escapeHtml(String(t))).join(', ')}}</div>`;
}}
function setDetail(title, bodyHtml){{
  document.getElementById('detail').style.display='block';
  document.getElementById('dt').textContent=title;
  document.getElementById('db').innerHTML=bodyHtml;
}}

function setRiskDetail(risk){{
  const tags = [
    ...(risk.owaspTags || []),
    ...(risk.atlasTags || []),
    ...(risk.owaspMcpTags || []),
    ...(risk.owaspAgenticTags || []),
  ].slice(0, 8);
  const tagHtml = tags.length
    ? `<div class="section"><h3>Mapped controls</h3><div>${{
        tags.map((tag)=>`<span class="pill">${{escapeHtml(tag)}}</span>`).join('')
      }}</div></div>`
    : '';
  setDetail(
    risk.vulnerabilityId,
    `
      <div class="subtle">${{escapeHtml(risk.summary || 'No summary was available for this vulnerability.')}}</div>
      <div><span class="pill ${{severityClass(risk.severity)}}">${{escapeHtml(risk.severity.toUpperCase())}}</span>
        <span class="pill">risk ${{escapeHtml(risk.riskScore)}}</span>
        <span class="pill">${{escapeHtml(risk.reachability)}}</span></div>
      <div class="section"><h3>Package</h3>
        <div><code>${{escapeHtml(risk.packageName)}}</code> @
          <code>${{escapeHtml(risk.packageVersion)}}</code>
          (${{escapeHtml(risk.packageEcosystem)}})</div>
        <div class="subtle">${{
          risk.fixVersion
            ? `Recommended fix: <code>${{escapeHtml(risk.fixVersion)}}</code>`
            : 'No fixed version reported yet.'
        }}</div>
      </div>
      <div class="section"><h3>Impact</h3>
        <ul>
          <li>${{escapeHtml(risk.agentCount)}} agent(s) affected</li>
          <li>${{escapeHtml(risk.serverCount)}} server(s) affected</li>
          <li>${{escapeHtml(risk.credentialCount)}} credential(s) exposed</li>
          <li>${{escapeHtml(risk.toolCount)}} tool(s) reachable</li>
        </ul>
      </div>
      <div class="section"><h3>Affected agents</h3>${{listHtml(risk.agents)}}</div>
      <div class="section"><h3>Affected servers</h3>${{listHtml(risk.servers)}}</div>
      <div class="section"><h3>Credentials</h3>${{listHtml(risk.credentials)}}</div>
      <div class="section"><h3>Reachable tools</h3>${{listHtml(risk.tools)}}</div>
      ${{tagHtml}}
      <div class="section"><h3>Operator actions</h3>${{recommendationHtml(risk)}}</div>
    `,
  );
}}

function clearFocus(){{
  cy.elements().removeClass('focus faded');
  document.querySelectorAll('.risk-item').forEach((el)=>el.classList.remove('active'));
  activeRiskNodeId=null;
}}

function updateOverview(){{
  document.getElementById('count-critical').textContent=`${{overview.critical}} critical`;
  document.getElementById('count-high').textContent=`${{overview.high}} high`;
  document.getElementById('count-credentials').textContent=`${{overview.credentialCount}} exposed creds`;
  document.getElementById('count-agents').textContent=`${{overview.affectedAgentCount}} impacted agents`;
}}

function setSeverityFilter(level){{
  activeSeverity=level;
  ['all','critical','high','medium','low'].forEach((item)=>{{
    const el=document.getElementById(`sev-${{item}}`);
    if(el) el.classList.toggle('active', item===level);
  }});
  applyFilters();
}}

function toggleCredentialFilter(){{
  credentialsOnly=!credentialsOnly;
  document.getElementById('chip-credentials').classList.toggle('active', credentialsOnly);
  applyFilters();
}}

function toggleFocusedOnly(){{
  focusedPathOnly=!focusedPathOnly;
  document.getElementById('chip-focus').classList.toggle('active', focusedPathOnly);
  applyFilters();
}}

function matchingSeverityNodes(){{
  return cy.nodes().filter((node)=>{{
    const severity = node.data('severity');
    if(!severity) return false;
    return activeSeverity === 'all' ? true : severity === activeSeverity;
  }});
}}

function nodesForCredentialExposure(){{
  const servers = cy.nodes().filter((node)=>Boolean(node.data('hasCredentials')));
  let result = cy.collection();
  servers.forEach((node)=>{{
    result = result.union(node).union(node.predecessors()).union(node.successors());
  }});
  return result;
}}

function nodesForSearch(query){{
  const trimmed = (query || '').trim().toLowerCase();
  if(!trimmed) return null;
  const matches = cy.nodes().filter((node)=>{{
    const searchText = String(node.data('searchText') || node.data('label') || '').toLowerCase();
    return searchText.includes(trimmed);
  }});
  if(matches.empty()) return cy.collection();
  let result = cy.collection();
  matches.forEach((node)=>{{
    result = result.union(node).union(node.predecessors()).union(node.successors());
  }});
  return result;
}}

function expandedCveNodeId(packageNodeId, vulnId){{
  return `${{packageNodeId}}::${{vulnId}}`;
}}

function packageExpansionElements(node){{
  const rawList = node.data('cveList');
  if(!rawList) return [];
  let cveList = [];
  try {{
    cveList = JSON.parse(rawList);
  }} catch (_error) {{
    return [];
  }}

  const created = [];
  cveList.forEach((vulnInfo)=>{{
    const vulnId = String(vulnInfo.id || '');
    if(!vulnId) return;
    const severity = String(vulnInfo.severity || 'unknown');
    const cveId = expandedCveNodeId(node.id(), vulnId);
    if(cy.getElementById(cveId).length) return;
    created.push(
      {{
        data: {{
          id: cveId,
          label: `${{vulnId}}\\n${{severity.toUpperCase()}}`,
          type: 'cve',
          kind: 'cve',
          severity,
          severityClass: `cve_${{severity}}`,
          severityWeight: 1,
          summary: vulnInfo.summary || '',
          fixVersion: vulnInfo.fix_version || '',
          tip: `${{vulnId}}\\nSeverity: ${{severity}}\\n${{vulnInfo.summary || ''}}`,
          searchText: `${{vulnId}} ${{severity}} ${{vulnInfo.summary || ''}}`.toLowerCase(),
        }},
      }},
      {{
        data: {{
          source: node.id(),
          target: cveId,
          type: 'affects',
        }},
      }},
    );
  }});
  return created;
}}

function togglePackageExpansion(node){{
  if(!node.data('collapsedCves')) return false;
  const expanded = Boolean(expandedPackages.get(node.id()));
  if(expanded) {{
    let related = cy.collection();
    cy.elements().forEach((ele)=>{{
      const id = String(ele.data('id') || '');
      const source = String(ele.data('source') || '');
      const target = String(ele.data('target') || '');
      if(
        id.startsWith(`${{node.id()}}::`) ||
        (source === node.id() && target.startsWith(`${{node.id()}}::`))
      ) {{
        related = related.union(ele);
      }}
    }});
    cy.remove(related);
    expandedPackages.delete(node.id());
  }} else {{
    const created = packageExpansionElements(node);
    if(created.length) {{
      cy.add(created);
      expandedPackages.set(node.id(), true);
    }}
  }}
  runGraphLayout();
  applyFilters();
  return true;
}}

function focusedSubgraph(){{
  if(!activeRiskNodeId) return null;
  const node = cy.getElementById(activeRiskNodeId);
  if(!node || node.empty()) return null;
  return node.union(node.predecessors()).union(node.successors());
}}

function applyFilters(){{
  cy.elements().removeClass('filtered');
  let visible = cy.elements();

  // "All severities" is no filter. Treating it as "nodes with a severity and
  // their predecessors" hid every unrelated node, so the first fit zoomed onto
  // a lone finding instead of the whole graph.
  const severityNodes = activeSeverity !== 'all' ? matchingSeverityNodes() : cy.collection();
  if(!severityNodes.empty()) {{
    let severityGraph = cy.collection();
    severityNodes.forEach((node)=>{{
      severityGraph = severityGraph.union(node).union(node.predecessors());
    }});
    visible = visible.intersection(severityGraph.union(severityGraph.connectedEdges()));
  }}

  if(credentialsOnly) {{
    const credGraph = nodesForCredentialExposure();
    visible = visible.intersection(credGraph.union(credGraph.connectedEdges()));
  }}

  const searchGraph = nodesForSearch(document.getElementById('search').value);
  if(searchGraph !== null) {{
    visible = visible.intersection(searchGraph.union(searchGraph.connectedEdges()));
  }}

  const focusedGraph = focusedSubgraph();
  if(focusedPathOnly && focusedGraph) {{
    visible = visible.intersection(focusedGraph.union(focusedGraph.connectedEdges()));
  }}

  cy.elements().difference(visible).addClass('filtered');
}}

function fitAll(){{
  clearFocus();
  document.getElementById('detail').style.display='none';
  focusedPathOnly=false;
  document.getElementById('chip-focus').classList.remove('active');
  applyFilters();
  cy.resize();
  cy.fit(cy.elements(':visible'), 60);
}}

function focusNode(nodeId, opts){{
  const node = cy.getElementById(nodeId);
  if(!node || node.empty()) return;
  const focus = node.union(node.predecessors()).union(node.successors());
  cy.elements().addClass('faded');
  focus.removeClass('faded');
  focus.addClass('focus');
  cy.animate({{ fit: {{ eles: focus, padding: 90 }}, duration: 350 }});
  activeRiskNodeId=nodeId;
  if(!(opts && opts.silent)){{
    const risk = riskByNodeId.get(nodeId);
    if(risk){{
      setRiskDetail(risk);
    }} else {{
      const d=node.data();
      setDetail(d.label||d.id, `<div class="subtle">${{escapeHtml(d.tip || '')}}</div>${{intelligenceDetail(d)}}`);
    }}
  }}
  applyFilters();
}}

function focusTopRisk(){{
  if(topRisks.length){{
    focusRisk(topRisks[0].nodeId);
  }} else {{
    fitAll();
  }}
}}

function focusRisk(nodeId){{
  clearFocus();
  focusNode(nodeId);
  const active=document.querySelector('[data-node-id=\"'+nodeId+'\"]');
  if(active) active.classList.add('active');
}}

function renderRiskList(){{
  const list=document.getElementById('riskList');
  if(!topRisks.length){{
    list.innerHTML='<div class=\"hint\">No vulnerable blast-radius paths were present in this report.</div>';
    return;
  }}
  list.innerHTML=topRisks.map((risk, index)=>`
    <button class="risk-item${{index===0 ? ' active' : ''}}"
      data-node-id="${{escapeHtml(risk.nodeId)}}" data-node-index="${{index}}"
      onclick="focusRiskByIndex(${{index}})">
      <div class="risk-head">
        <div class="risk-title">${{escapeHtml(risk.vulnerabilityId)}}${{risk.packageName ? ' in '+escapeHtml(risk.packageName) : ''}}</div>
        <div class="risk-score">risk ${{escapeHtml(risk.riskScore)}}</div>
      </div>
      <div class="risk-meta">
        <span class="pill ${{severityClass(risk.severity)}}">${{escapeHtml(String(risk.severity || '').toUpperCase())}}</span>
        <span class="pill">${{escapeHtml(risk.reachability)}}</span><br>
        ${{escapeHtml(risk.agentCount)}} agent(s) · ${{escapeHtml(risk.serverCount)}} server(s) ·
        ${{escapeHtml(risk.credentialCount)}} credential(s) · ${{escapeHtml(risk.toolCount)}} tool(s)
        ${{risk.fixVersion ? '<br>Fix: '+escapeHtml(risk.fixVersion) : ''}}
      </div>
      <div class="risk-summary">${{escapeHtml(risk.summary ? risk.summary.slice(0, 130) : 'No summary available.')}}</div>
    </button>
  `).join('');
}}

function focusRiskByIndex(index){{
  const risk = topRisks[index];
  if(risk) focusRisk(risk.nodeId);
}}

function renderFindingList(){{
  const list=document.getElementById('findingList');
  if(!categoryFindings.length){{
    document.getElementById('findingHead').style.display='none';
    document.getElementById('findingHint').style.display='none';
    list.innerHTML='';
    return;
  }}
  list.innerHTML=categoryFindings.map((finding)=>`
    <button class="risk-item" data-node-id="${{escapeHtml(finding.nodeId)}}"
      data-node-index="${{categoryFindings.indexOf(finding)}}"
      onclick="focusRiskByFindingIndex(${{categoryFindings.indexOf(finding)}})">
      <div class="risk-head">
        <div class="risk-title">${{escapeHtml(finding.title)}}</div>
      </div>
      <div class="risk-meta">
        <span class="pill ${{severityClass(finding.severity)}}">${{escapeHtml(finding.severity.toUpperCase())}}</span>
        <span class="pill">${{escapeHtml(finding.category)}}</span>
      </div>
      <div class="risk-summary">${{escapeHtml(finding.summary ? finding.summary.slice(0, 130) : '')}}</div>
    </button>
  `).join('');
}}

function focusRiskByFindingIndex(index){{
  const finding = categoryFindings[index];
  if(finding) focusRisk(finding.nodeId);
}}

cy.on('tap','node',function(e){{
  const node = e.target;
  if(togglePackageExpansion(node)){{
    clearFocus();
    focusNode(node.id(), {{ silent: false }});
    return;
  }}
  clearFocus();
  focusNode(node.id(), {{ silent: false }});
}});
cy.on('tap',function(e){{ if(e.target===cy) fitAll(); }});

function searchNodes(query){{
  const trimmed = (query || '').trim();
  applyFilters();
  if(!trimmed) return;
  const match = cy
    .nodes(':visible')
    .filter((node)=>String(node.data('label') || '').toLowerCase().includes(trimmed.toLowerCase()))
    .first();
  if(match && !match.empty()){{
    cy.animate({{ fit: {{ eles: match.closedNeighborhood(), padding: 120 }}, duration: 250 }});
  }}
}}

function togglePanel(id){{
  ['riskpanel','legend'].forEach((other)=>{{
    const el=document.getElementById(other);
    if(el) el.classList.toggle('open', other===id ? !el.classList.contains('open') : false);
  }});
}}

function dlPng(){{
  const a=document.createElement('a');
  a.href=cy.png({{scale:2,bg:'#0f1419'}});
  a.download='agent-bom-graph.png';
  a.click();
}}

renderRiskList();
renderFindingList();
updateOverview();
cy.ready(function(){{
  setTimeout(function(){{ fitAll(); }}, 120);
}});
</script>
</body>
</html>"""
