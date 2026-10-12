import assert from "node:assert/strict";
import test from "node:test";
import { AgentBomClient } from "../dist/index.js";

test("consequences reuse authenticated transport and preserve the server revision and gaps", async () => {
  const request = {scan_id: "scan-1", snapshot_generation: "revision-1", root_node_id: "principal:one", mode: "assumed_compromise", assume_control: true};
  const receipt = {snapshot_generation: "revision-1", consequences: [], frontier: [{reason_codes: ["session_binding_missing"]}], coverage: "partial"};
  const client = new AgentBomClient({baseUrl: "https://example.test", apiKey: "fixture", tenantId: "tenant-a", fetch: async (url, init) => {
    assert.equal(url, "https://example.test/v1/graph/consequences");
    assert.equal(init.method, "POST");
    assert.equal(init.headers["x-api-key"], "fixture");
    assert.equal(init.headers["x-agent-bom-tenant-id"], "tenant-a");
    assert.deepEqual(JSON.parse(init.body), request);
    return new Response(JSON.stringify(receipt), {status: 200, headers: {"content-type": "application/json"}});
  }});
  assert.deepEqual(await client.consequenceAssessment(request), receipt);
});
