import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/app/agents/agent-blast-summary", () => ({ AgentBlastSummary: () => null }));

import { AgentDetailDrawer } from "@/app/agents/agent-detail-drawer";
import type { Agent } from "@/lib/api";

const agent = {
  name: "laptop-7f3a",
  display_name: "Finance laptops",
  canonical_id: "agent-b",
  agent_type: "custom",
  source: "fleet",
  mcp_servers: [],
} as unknown as Agent;

describe("agent drawer names the agent the way the list does", () => {
  it("titles the drawer with the API display name and keeps the raw id as a hint", () => {
    render(<AgentDetailDrawer agent={agent} open onClose={() => {}} />);
    const dialog = screen.getByRole("dialog", { name: "Agent Finance laptops" });
    expect(dialog).toHaveTextContent("Finance laptops");
    expect(dialog).toHaveTextContent("laptop-7f3a · fleet");
    expect(dialog).not.toHaveTextContent("Laptop 7f3a");
  });
});
