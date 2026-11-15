import { describe, expect, it } from "vitest";

import { agentsInventoryMismatch, agentsPage, inventoryHeadlineFrom } from "../scripts/capture-product-proof.mjs";

const inventoryCards = [
  "Unique packages: 4 unique packages, in snapshot",
  "MCP servers: 4 MCP servers, plus 4 tools, in snapshot",
  "AI agents: 3 AI agents, plus 1 dataset and 1 model, in snapshot",
  "Identities: 2 identities, plus 3 credentials, 1 policy, and 1 role, in snapshot",
];

describe("Agents page and Inventory headline counts", () => {
  it("reads Inventory's AI-agent and MCP-server card counts", () => {
    expect(inventoryHeadlineFrom(inventoryCards)).toEqual({ agents: 3, mcpServers: 4 });
    expect(inventoryHeadlineFrom(["AI agents: 1,204 AI agents, in snapshot", "MCP servers: 1 MCP server, in snapshot"])).toEqual({ agents: 1204, mcpServers: 1 });
  });

  it("accepts equal headlines", () => {
    expect(agentsInventoryMismatch({ agents: 3, mcpServers: 4, serversLabel: "Unique MCP servers" }, { agents: 3, mcpServers: 4 })).toBeNull();
  });

  it("names each count that disagrees", () => {
    expect(agentsInventoryMismatch({ agents: 18, mcpServers: 7, serversLabel: "Unique MCP servers" }, { agents: 3, mcpServers: 4 }))
      .toBe("18 agents vs 3 AI agents; 7 vs 4 MCP servers");
  });

  it("rejects a configured-entry server total in place of the unique count", () => {
    expect(agentsInventoryMismatch({ agents: 3, mcpServers: 4, serversLabel: "MCP servers" }, { agents: 3, mcpServers: 4 }))
      .toMatch(/not the unique MCP-server count/);
  });

  it("fails when Inventory's headline could not be read", () => {
    expect(agentsInventoryMismatch({ agents: 3, mcpServers: 4, serversLabel: "Unique MCP servers" }, { agents: null, mcpServers: 4 }))
      .toMatch(/unreadable/);
  });

  it("serves the API population summary with every agents page", () => {
    const summary = { agents: 2, mcp_servers: 1, mcp_server_configurations: 2 };
    expect(agentsPage(new URLSearchParams("limit=1"), [{ name: "a" }, { name: "b" }], summary)).toMatchObject({ summary, total: 2 });
    expect(agentsPage(new URLSearchParams(), [{ name: "a" }])).not.toHaveProperty("summary");
  });
});
