import { describe, expect, it } from "vitest";

import { decodeNodeIdPart, nodeIdTail, readableNodeId } from "@/lib/node-id-tail";
import { reachabilitySourceLabel } from "@/lib/reachability-source";
import { reachingEntity } from "@/lib/finding-holder";

describe("nodeIdTail", () => {
  it("decodes a percent-encoded last segment", () => {
    expect(nodeIdTail("agent:Cursor%20First-Run%20Workspace")).toBe("Cursor First-Run Workspace");
  });

  it("keeps an encoded separator inside the name instead of splitting on it", () => {
    expect(nodeIdTail("server:team%2Fapi%3Agateway")).toBe("team/api:gateway");
  });

  it("falls back to the raw segment when it is not valid percent-encoding", () => {
    expect(nodeIdTail("agent:100%-coverage")).toBe("100%-coverage");
    expect(decodeNodeIdPart("%E0%A4%A")).toBe("%E0%A4%A");
  });

  it("returns the input when there is no segment", () => {
    expect(nodeIdTail("::")).toBe("::");
  });
});

describe("node-id tails shown to people", () => {
  it("reach column label shows the decoded agent name", () => {
    expect(reachabilitySourceLabel("agent:Cursor%20First-Run%20Workspace")).toBe("Cursor First-Run Workspace");
  });

  it("reaching entity names decode for agents, servers and workloads but keep the raw id", () => {
    expect(reachingEntity("agent:Cursor%20First-Run%20Workspace").name).toBe("Cursor First-Run Workspace");
    expect(reachingEntity("server:My%20Server").name).toBe("My Server");
    expect(reachingEntity("kubernetes:workload:prod/claims%20engine").name).toBe("claims engine");
    expect(reachingEntity("agent:Cursor%20First-Run%20Workspace").id).toBe("agent:Cursor%20First-Run%20Workspace");
  });
});

describe("readableNodeId", () => {
  it("decodes every segment and keeps the separators", () => {
    expect(readableNodeId("agent:Team%205%20Agent%2032")).toBe("agent:Team 5 Agent 32");
    expect(readableNodeId("kubernetes:workload:prod/claims%20engine")).toBe("kubernetes:workload:prod/claims engine");
  });

  it("keeps an encoded separator readable and malformed segments as recorded", () => {
    expect(readableNodeId("server:team%2Fapi")).toBe("server:team/api");
    expect(readableNodeId("agent:100%-coverage")).toBe("agent:100%-coverage");
  });
});
