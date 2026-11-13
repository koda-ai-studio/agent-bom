import { expect, test } from "@playwright/test";

for (const recorded of [true,false]) test(`credential context only joins recorded hops: ${recorded}`, async ({ page },info) => {
  await page.setViewportSize({width:1440,height:1000});
  const stamp="2026-11-01T00:00:00Z";
  const node=(id:string,entity_type:string) => ({id,label:id,entity_type,severity:"high",status:"active",risk_score:0,attributes:{},dimensions:{},data_sources:["synthetic-fixture"],compliance_tags:[]});
  const nodes=recorded ? [node("client","agent"),node("warehouse-mcp","server"),node("WAREHOUSE_TOKEN_REFERENCE","credential"),node("Customer records","data_store")]
    : [node("client","agent"),node("warehouse-mcp","server"),node("CVE-2026-1000","vulnerability")];
  const hops=nodes.map(n=>n.id),relationships=recorded ? ["uses","exposes_cred","can_access"] : ["uses","vulnerable_to"];
  const edges=relationships.map((relationship,i)=>({id:`e${i}`,source:hops[i],target:hops[i+1],relationship,direction:"directed",traversable:true,weight:1,evidence:{tier:"static_scan",source:"synthetic-fixture"},first_seen:stamp,last_seen:stamp}));
  const path={source:hops[0],target:hops.at(-1),hops,edges:relationships,composite_risk:75,summary:"",credential_exposure:["WAREHOUSE_TOKEN_REFERENCE"],tool_exposure:[],vuln_ids:recorded ? [] : ["CVE-2026-1000"],finding_ids:[]};
  const graph={scan_id:"snapshot",tenant_id:"fixture",created_at:stamp,nodes,edges,attack_paths:[path],interaction_risks:[],stats:{total_nodes:nodes.length,total_edges:edges.length,severity_counts:{}},pagination:{total:1,offset:0,limit:100,returned:1,has_more:false}};
  await page.route("**/health",r=>r.fulfill({json:{status:"ok"}}));
  await page.route("**/v1/**",r=>{
    const u=new URL(r.request().url());
    if(u.pathname==="/v1/auth/me") return r.fulfill({json:{authenticated:true,auth_required:false,tenant_id:"fixture",role:"admin",auth_method:"anonymous",memberships:[],configured_modes:[],recommended_ui_mode:"no_auth"}});
    if(u.pathname==="/v1/graph/snapshots") return r.fulfill({json:[{scan_id:"snapshot",created_at:stamp,snapshot_kind:"scan",node_count:nodes.length,edge_count:edges.length}]});
    if(u.pathname==="/v1/graph/attack-paths") return r.fulfill({json:graph});
    if(u.pathname==="/v1/graph/views/fix-first") return r.fulfill({json:{scan_id:"snapshot",tenant_id:"fixture",created_at:stamp,cards:[],attack_campaigns:[],summary:{total_paths:1,matched_paths:1,returned_paths:0,highest_risk:75,covered_findings:0,node_count:nodes.length,edge_count:edges.length},focus:{cve:"",package:"",agent:""}}});
    return r.fulfill({status:404,json:{detail:"Outside fixture"}});
  });
  await page.goto("/security-graph?lens=attack-path&scan=snapshot");
  const canvas=page.locator('.react-flow');
  // A finding is a badge on the asset it affects, never a hop of its own.
  const drawn=recorded ? nodes : nodes.filter(n=>n.entity_type!=="vulnerability");
  await expect(canvas.locator('.react-flow__node')).toHaveCount(drawn.length);
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(drawn.length-1);
  if(recorded) {
    await expect(canvas.locator('.react-flow__node[data-id="WAREHOUSE_TOKEN_REFERENCE"]')).toBeVisible();
    await expect(canvas.locator('.react-flow__node[data-id="Customer records"]')).toBeVisible();
  } else {
    await expect(canvas.getByText("WAREHOUSE_TOKEN_REFERENCE")).toHaveCount(0);
    await expect(canvas.getByRole("button",{name:"1 finding on warehouse-mcp, worst high (1 high). Open findings"})).toBeVisible();
    await page.getByText("Evidence & relationships",{exact:true}).click();
    await expect(page.getByRole("region",{name:"Reported exposure context"})).toContainText("WAREHOUSE_TOKEN_REFERENCE");
    await expect(page.getByRole("region",{name:"Reported exposure context"})).toContainText("do not add path hops or establish access");
  }
  await expect(page.getByRole("region",{name:"Reported path exposure"})).toContainText("References only");
  await expect(page.getByText("Reached from this path",{exact:true})).toHaveCount(0);
  // Relationship names sit off the lines until a line is hovered or focused.
  await expect(canvas.getByRole("tooltip")).toHaveCount(0);
  const line=canvas.locator(`.react-flow__edge[data-id="${recorded ? "e1" : "e0"}"]`);
  await line.focus();
  await expect(canvas.getByRole("tooltip")).toHaveText(recorded ? /Exposes Credential/ : /Uses/);
  await expect.poll(() => canvas.evaluate(root => {
    const tip=root.querySelector('[role="tooltip"]')!.getBoundingClientRect();
    return [...root.querySelectorAll('[data-node-glyph]')].some(glyph=>{
      const n=glyph.getBoundingClientRect();
      return tip.left<n.right && tip.right>n.left && tip.top<n.bottom && tip.bottom>n.top;
    });
  })).toBe(false);
  await line.blur();
  await expect(canvas.getByRole("tooltip")).toHaveCount(0);
  await page.screenshot({path:info.outputPath(`credential-context-${recorded}.png`),fullPage:true});
});
