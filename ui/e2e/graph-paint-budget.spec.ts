import { expect, test, type Page } from "@playwright/test";
import os from "node:os";
import { installGraphPaintMeasurement } from "./helpers/graph-paint-measurement";
import { readFileSync, writeFileSync } from "node:fs";

const stamp = "2026-10-15T00:00:00Z";
const node = (id:string, entity_type:string) => ({id,label:id,entity_type,severity:"none",status:"active",risk_score:0,
  attributes:{},dimensions:{},data_sources:["synthetic-paint-budget"],compliance_tags:[]});

async function fixture(page:Page, agents:number) {
  const all = [node("Workspace", "agent"), ...Array.from({length:agents},(_,i)=>node(`mcp-${i}`,"server"))];
  const nodes = all.slice(0,100);
  const edges = nodes.slice(1).map(n=>({id:`use-${n.id}`,source:"Workspace",target:n.id,relationship:"uses",direction:"directed",
    weight:1,traversable:false,evidence:{source:"synthetic-paint-budget",tier:"static_scan"},first_seen:stamp,last_seen:stamp}));
  const graph = {scan_id:"paint",tenant_id:"fixture",created_at:stamp,nodes,edges,attack_paths:[],interaction_risks:[],
    stats:{total_nodes:all.length,total_edges:all.length-1,node_counts:{},edge_counts:{},severity_counts:{},risk_score:0},
    pagination:{total:all.length,offset:0,limit:100,returned:nodes.length,has_more:all.length>100},
    completeness:{complete:all.length<=100,truncated:all.length>100,returned:nodes.length,total:all.length}};
  const payload = JSON.stringify(graph);
  await page.route("**/health",r=>r.fulfill({json:{status:"ok"}}));
  await page.route("**/v1/**",r=>{
    const url=new URL(r.request().url());
    if(url.pathname==="/v1/auth/me") return r.fulfill({json:{authenticated:true,auth_required:false,tenant_id:"fixture",role:"admin",auth_method:"anonymous",memberships:[],configured_modes:[],recommended_ui_mode:"no_auth"}});
    if(url.pathname==="/v1/graph/snapshots") return r.fulfill({json:[{scan_id:"paint",created_at:stamp,node_count:all.length,edge_count:all.length-1}]});
    if(url.pathname==="/v1/graph") return r.fulfill({contentType:"application/json",body:payload});
    return r.fulfill({status:404,json:{detail:"Outside paint fixture"}});
  });
  return {source_nodes:all.length,returned_nodes:nodes.length,payload_bytes:Buffer.byteLength(payload)};
}

function percentile(values:number[], p:number) {
  const sorted=[...values].sort((a,b)=>a-b);
  return sorted[Math.min(sorted.length-1, Math.ceil(sorted.length*p)-1)]!;
}

for(const agents of [12,120]) test(`first useful graph paint below two seconds at ${agents} servers`,async({browser},info)=>{
  test.setTimeout(90_000);
  const records:Array<{condition:string;ms:number;resources:unknown}> = [];
  let basis:Awaited<ReturnType<typeof fixture>>|undefined;
  for(const condition of ["fresh_context","reused_context"]){
    let context=await browser.newContext({viewport:{width:1440,height:1000}});
    for(let sample=0;sample<10;sample++){
      if(condition==="fresh_context" && sample>0){await context.close();context=await browser.newContext({viewport:{width:1440,height:1000}});}
      const page=await context.newPage();
      basis=await fixture(page,agents);
      await page.addInitScript(installGraphPaintMeasurement);
      await page.goto("/graph?scan=paint&rollup=0&layers=agent,server",{waitUntil:"domcontentloaded"});
      await expect(page.locator(".react-flow__node .graph-entity-glyph").first()).toBeVisible();
      await expect(page.locator(".react-flow__edge").first()).toBeVisible();
      await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled","true");
      // Names and recorded branches must be visible before expanding the rest.
      await expect(page.locator(".react-flow__node")).toHaveCount(5);
      await expect(page.locator(".react-flow__node-serverNode")).toHaveCount(3);
      await expect(page.locator(".react-flow__edge")).toHaveCount(4);
      await expect(page.locator(".graph-relationship-label")).toHaveCount(0);
      expect(await page.locator(".react-flow__node").evaluateAll(nodes => nodes.every(node => {
        const box = node.getBoundingClientRect();
        const frame = node.closest(".react-flow")!.getBoundingClientRect();
        return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
      }))).toBe(true);
      expect(await page.locator(".react-flow__node").evaluateAll(nodes => {
        const boxes = nodes.map(node => node.getBoundingClientRect());
        const frame = nodes[0]!.closest(".react-flow")!.getBoundingClientRect();
        const center = (Math.min(...boxes.map(b => b.top)) + Math.max(...boxes.map(b => b.bottom))) / 2;
        return Math.abs(center - (frame.top + frame.height / 2)) / frame.height;
      })).toBeLessThan(0.1);
      const result=await page.evaluate(async()=>{
        await new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve())));
        const resources=performance.getEntriesByType("resource").filter(r=>r.name.includes("/v1/graph?")).map(r=>({ms:r.duration}));
        const scripts = performance.getEntriesByType("resource").filter((entry): entry is PerformanceResourceTiming =>
          entry instanceof PerformanceResourceTiming && entry.initiatorType === "script");
        const readyAt = (window as Window & { graphPaintReadyAt?: number }).graphPaintReadyAt;
        if (readyAt === undefined) throw new Error("Browser did not record a fully visible, settled graph");
        return {ms:readyAt,assertionsCompletedMs:performance.now(),resources,scriptCount:scripts.length,
          scriptBytes:scripts.reduce((total,entry)=>total+entry.decodedBodySize,0)};
      });
      records.push({condition,...result});
      if(sample===0) await page.screenshot({path:info.outputPath(`paint-${agents}-${condition}.png`),animations:"disabled"});
      await page.close();
    }
    await context.close();
  }
  const summary=Object.fromEntries(["fresh_context","reused_context"].map(condition=>{
    const times=records.filter(r=>r.condition===condition).map(r=>r.ms);
    return [condition,{p50:percentile(times,.5),p95:percentile(times,.95),p99:percentile(times,.99),max:Math.max(...times)}];
  }));
  const receipt=info.outputPath("paint-budget.json");
  writeFileSync(receipt,JSON.stringify({basis,records,summary,platform:os.platform(),arch:os.arch(),cpus:os.cpus()[0]?.model,memory:os.totalmem(),
    conditions:"Production JavaScript; deterministic intercepted API page. Fresh/reused browser contexts; Playwright routing disables HTTP cache. Browser readiness requires the same node/edge counts, visible contained nodes, centered framing, settled camera and two further animation frames. Driver assertion completion is recorded separately. No backend build or external network latency is included."},null,2));
  await info.attach("paint-budget.json",{path:receipt,contentType:"application/json"});
  expect(Math.max(...records.map(r=>r.ms)),JSON.stringify(summary)).toBeLessThan(2000);
});

// This suite runs against the production build, as enforced by test:e2e.
// Verify actual chunk requests as well as timing: inspectors must remain usable.
test("loads node evidence code only when the inspector is opened", async ({ page }) => {
  const manifest = JSON.parse(readFileSync(".next/react-loadable-manifest.json", "utf8"));
  const entry = manifest["components/graph-page-view.tsx -> @/components/graph-entity-drawer"];
  expect(entry, "Node evidence must have an on-demand production chunk").toBeDefined();
  const chunk = entry.files.at(-1) as string;
  expect(chunk).toMatch(/\.js$/);
  const requested: string[] = [];
  page.on("request", request => requested.push(new URL(request.url()).pathname));
  await fixture(page, 120);
  await page.goto("/graph?scan=paint&rollup=0&layers=agent,server");
  await expect(page.locator("[data-graph-adaptive-frame]")).toHaveAttribute("data-graph-camera-settled", "true");
  expect(requested.some(path => path.endsWith(chunk))).toBe(false);
  await page.locator(".react-flow__node-agentNode").click();
  await expect(page.getByRole("tablist", { name: "Node detail sections" })).toBeVisible();
  expect(requested.some(path => path.endsWith(chunk))).toBe(true);
});
