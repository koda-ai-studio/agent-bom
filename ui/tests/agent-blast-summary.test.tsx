import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getAgentDetail } = vi.hoisted(() => ({ getAgentDetail: vi.fn() }));
vi.mock("@/lib/api", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/api")>()), api: { getAgentDetail } }));

import { AgentBlastSummary } from "@/app/agents/agent-blast-summary";

const blast = (vulnerability_id: string, severity: string, exposed_credentials: string[], extra: Record<string, unknown> = {}) => ({
  vulnerability_id, severity, package: "langchain@0.0.150", exposed_credentials, reachable_tools: [], affected_servers: ["llm-orchestrator-server"], ...extra,
});

describe("agent drawer blast radius", () => {
  beforeEach(() => getAgentDetail.mockReset());

  it("summarizes the blast radius worst first with each finding's exposed credentials", async () => {
    getAgentDetail.mockResolvedValue({
      blast_radius: [
        blast("CVE-2023-32681", "medium", ["DATABASE_URL", "PINECONE_API_KEY"], { package: "requests@2.28.0" }),
        blast("CVE-2023-36258", "critical", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]),
        blast("CVE-2023-50782", "high", []),
      ],
    });
    render(<AgentBlastSummary agentName="langchain-service" />);
    await waitFor(() => expect(screen.getByText("3 findings · 4 unique credentials exposed")).toBeVisible());
    const rows = screen.getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("CVE-2023-36258");
    expect(rows[0]).toHaveTextContent("2 credentials exposed");
    expect(rows[1]).toHaveTextContent("No credentials exposed");
    expect(rows[2]).toHaveTextContent("CVE-2023-32681");
    expect(screen.getByRole("link", { name: "CVE-2023-36258" })).toHaveAttribute("href", expect.stringContaining("node=agent%3Alangchain-service"));
  });

  it("says when there is no blast radius instead of showing zeroes", async () => {
    getAgentDetail.mockResolvedValue({ blast_radius: [] });
    render(<AgentBlastSummary agentName="cursor" />);
    await waitFor(() => expect(screen.getByText("No vulnerable package reaches this agent's servers.")).toBeVisible());
  });

  it("reports an unavailable blast radius", async () => {
    getAgentDetail.mockRejectedValueOnce(new Error("offline"));
    render(<AgentBlastSummary agentName="cursor" />);
    await waitFor(() => expect(screen.getByText("Blast radius unavailable.")).toBeVisible());
  });
});
