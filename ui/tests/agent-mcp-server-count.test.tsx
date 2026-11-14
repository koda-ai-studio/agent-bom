import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/app/agents/agent-blast-summary", () => ({ AgentBlastSummary: () => null }));

import { AgentDetailDrawer } from "@/app/agents/agent-detail-drawer";
import type { Agent } from "@/lib/api";

const server = (name: string, surface: string) => ({ name, surface, command: "npx", args: [], env: {}, packages: [], tools: [] });

const agent = {
  name: "project:mixed",
  canonical_id: "agent-mixed",
  agent_type: "custom",
  source: "project",
  mcp_servers: [server("fs", "mcp-server"), server("gh", "mcp-server"), server("ai-inventory", "ai-inventory"), server("mixed", "other")],
} as unknown as Agent;

describe("agent drawer counts MCP servers by the shared rule", () => {
  it("does not count a manifest or SDK inventory record as an MCP server", () => {
    render(<AgentDetailDrawer agent={agent} open onClose={() => {}} />);
    const dialog = screen.getByRole("dialog");
    const stat = within(dialog).getByText("MCP servers").parentElement?.parentElement as HTMLElement;
    expect(stat).toHaveTextContent(/^MCP servers2$/);
    expect(dialog).toHaveTextContent("Servers and manifests(4)");
  });
});
