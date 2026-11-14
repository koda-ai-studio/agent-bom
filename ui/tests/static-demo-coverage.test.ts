import { describe, expect, it } from "vitest";

import { createStaticDemoCoverage } from "../scripts/static-demo-coverage.mjs";
import { agentsPage } from "../scripts/capture-product-proof.mjs";

describe("static demo coverage", () => {
  it("marks every page that needs an unanswered path, not only the first", () => {
    const coverage = createStaticDemoCoverage();
    coverage.noAnswer("v1_agents", { exactQuery: false, apiPath: "/v1/agents?limit=50", route: "/agents" });
    expect(coverage.alreadyUnanswered("v1_agents", { exactQuery: false, apiPath: "/v1/agents", route: "/agents/topology" })).toBe(true);
    expect([...coverage.incomplete].sort()).toEqual(["/agents", "/agents/topology"]);
    expect([...coverage.missing]).toEqual(["/v1/agents"]);
  });

  it("does not fail a page over an optional exact-query file", () => {
    const coverage = createStaticDemoCoverage();
    coverage.noAnswer("v1_agents__q1", { exactQuery: true, apiPath: "/v1/agents?limit=50", route: "/agents" });
    expect(coverage.alreadyUnanswered("v1_agents__q1", { exactQuery: true, apiPath: "/v1/agents?limit=50", route: "/agents/topology" })).toBe(true);
    expect(coverage.incomplete.size).toBe(0);
    expect(coverage.alreadyUnanswered("v1_agents", { exactQuery: false, apiPath: "/v1/agents", route: "/x" })).toBe(false);
  });
});

describe("fixture /v1/agents pages", () => {
  const agents = [{ name: "a" }, { name: "b" }, { name: "c" }];

  it("answers a bounded page with the full population counted", () => {
    const page = agentsPage(new URLSearchParams("limit=2&offset=0"), agents);
    expect(page.agents.map((agent: { name: string }) => agent.name)).toEqual(["a", "b"]);
    expect(page).toMatchObject({ count: 3, total: 3, limit: 2, offset: 0, has_more: true });
    expect(agentsPage(new URLSearchParams("limit=2&offset=2"), agents)).toMatchObject({ has_more: false, agents: [{ name: "c" }] });
  });

  it("returns every agent when no limit is sent", () => {
    expect(agentsPage(new URLSearchParams(), agents)).toMatchObject({ limit: null, has_more: false, total: 3 });
  });
});
