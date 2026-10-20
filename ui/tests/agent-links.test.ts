import { describe, expect, it } from "vitest";

import { agentBlastPathHref, agentLineageHref, lifecycleAgentLabel } from "@/lib/agent-links";

const graph = {
  nodes: [
    { id: "agent:cfg-a598:langchain-service", entity_type: "agent", label: "langchain-service" },
    { id: "server:orch", entity_type: "server", label: "orch" },
  ],
};

describe("agent links", () => {
  it("opens a blast-radius CVE on this agent's own path", () => {
    const href = agentBlastPathHref("langchain-service", { vulnerability_id: "CVE-2023-36258", canonical_id: "8d96119f", package: "langchain@0.0.150" });
    const params = new URL(href, "http://x").searchParams;
    expect(params.get("lens")).toBe("attack-path");
    expect(params.get("node")).toBe("agent:langchain-service");
    expect(params.get("cve")).toBe("CVE-2023-36258");
    expect(params.get("finding")).toBe("8d96119f");
    expect(params.get("agent")).toBe("langchain-service");
  });

  it("names the agent from its graph node, never a raw id", () => {
    expect(lifecycleAgentLabel(graph, "b2a5a525-66c7-5571-9090-e6aa3ca86bb0")).toBe("langchain-service");
    expect(lifecycleAgentLabel({ nodes: [] }, "cursor")).toBe("cursor");
  });

  it("keeps the agent scope when opening lineage", () => {
    const params = new URL(agentLineageHref(graph, "b2a5a525"), "http://x").searchParams;
    expect(params.get("lens")).toBe("lineage");
    expect(params.get("root")).toBe("agent:langchain-service");
    expect(params.get("agent")).toBe("langchain-service");
  });
});
