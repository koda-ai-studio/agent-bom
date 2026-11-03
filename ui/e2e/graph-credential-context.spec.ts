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
  await expect(canvas.locator('.react-flow__node')).toHaveCount(nodes.length);
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(edges.length);
  if(recorded) {
    await expect(canvas.locator('.react-flow__node[data-id="WAREHOUSE_TOKEN_REFERENCE"]')).toBeVisible();
    await expect(canvas.locator('.react-flow__node[data-id="Customer records"]')).toBeVisible();
  } else {
    await expect(canvas.getByText("WAREHOUSE_TOKEN_REFERENCE")).toHaveCount(0);
    await page.getByText("Evidence & relationships",{exact:true}).click();
    await expect(page.getByRole("region",{name:"Reported exposure context"})).toContainText("WAREHOUSE_TOKEN_REFERENCE");
    await expect(page.getByRole("region",{name:"Reported exposure context"})).toContainText("do not add path hops or establish access");
  }
  await expect(page.getByRole("region",{name:"Reported path exposure"})).toContainText("References only");
  await expect(page.getByText("Reached from this path",{exact:true})).toHaveCount(0);
  await page.getByLabel("Relationship labels",{exact:true}).selectOption("show");
  await expect.poll(() => canvas.evaluate(root => {
    const boxes=[...root.querySelectorAll(".graph-entity-glyph")].map(n=>n.getBoundingClientRect());
    return [...root.querySelectorAll(".graph-relationship-label")].filter(label=>{
      const b=label.getBoundingClientRect();
      return b.width>0 && b.height>0 && boxes.some(n=> b.left<n.right && b.right>n.left && b.top<n.bottom && b.bottom>n.top);
    }).length;
  })).toBe(0).catch(async error => {
    await info.attach("label-geometry", { contentType:"application/json",body:JSON.stringify(await canvas.evaluate(root => ({
      glyphs:[...root.querySelectorAll(".graph-entity-glyph")].map(n=>({box:n.getBoundingClientRect().toJSON(),html:n.outerHTML.slice(0,220)})),
      labels:[...root.querySelectorAll<HTMLElement>(".graph-relationship-label")].map(n=>({box:n.getBoundingClientRect().toJSON(),text:n.textContent,style:n.style.cssText}))
    }))) });
    throw error;
  });
  if (recorded) await expect.poll(() => canvas.evaluate(root => {
    const label = [...root.querySelectorAll(".graph-relationship-label")].find(n => n.textContent?.includes("Exposes Credential"))!;
    const glyph = root.querySelector('.react-flow__node[data-id="warehouse-mcp"] .graph-entity-glyph')!.getBoundingClientRect();
    const box = label.getBoundingClientRect();
    return Math.abs((box.top + box.bottom - glyph.top - glyph.bottom) / 2);
  })).toBeLessThan(20);
  await page.screenshot({path:info.outputPath(`credential-labels-shown-${recorded}.png`),fullPage:true});
  await page.getByLabel("Relationship labels",{exact:true}).selectOption("auto");
  if(recorded) await expect(canvas.locator('.graph-relationship-label').filter({hasText:"Exposes Credential"})).toBeHidden();
  await page.screenshot({path:info.outputPath(`credential-context-${recorded}.png`),fullPage:true});
});
