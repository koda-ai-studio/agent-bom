import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AgentTopologyPage from "@/app/agents/topology/page";
import { TOPOLOGY_AGENT_LIMIT } from "@/app/agents/agents-list-state";

const { apiMock } = vi.hoisted(() => ({ apiMock: { listAgents: vi.fn() } }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: null }) }));
vi.mock("@/components/agent-topology", () => ({
  AgentTopology: ({ agents }: { agents: { name: string }[] }) => <div data-testid="topology">{agents.map((a) => a.name).join(",")}</div>,
}));

const agent = (name: string) => ({ name, agent_type: "ide", source: "config", status: "configured", mcp_servers: [] });

describe("agent topology page", () => {
  beforeEach(() => apiMock.listAgents.mockReset());

  it("reads one bounded page instead of the unpaged list", async () => {
    apiMock.listAgents.mockResolvedValue({ agents: [agent("a")], count: 1, total: 1, scope: "scanned_estate" });
    render(<AgentTopologyPage />);
    await screen.findByTestId("topology");
    expect(apiMock.listAgents).toHaveBeenCalledWith({ limit: TOPOLOGY_AGENT_LIMIT }, expect.anything());
    expect(TOPOLOGY_AGENT_LIMIT).toBeLessThanOrEqual(500);
    expect(screen.queryByTestId("topology-truncated")).toBeNull();
  });

  it("says how many agents the map leaves out when the estate is larger than the page", async () => {
    apiMock.listAgents.mockResolvedValue({ agents: [agent("a"), agent("b")], count: 1200, total: 1200, scope: "scanned_estate" });
    render(<AgentTopologyPage />);
    await waitFor(() => expect(screen.getByTestId("topology-truncated")).toHaveTextContent("Showing 2 of 1,200 agents"));
    expect(screen.getByRole("link", { name: /Agents list/ })).toHaveAttribute("href", "/agents");
  });
});
