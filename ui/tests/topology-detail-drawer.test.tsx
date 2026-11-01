import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TopologyDetailDrawer } from "@/components/topology-detail-drawer";
import type { Agent } from "@/lib/api";

const agents = [
  {
    name: "claude-desktop",
    agent_type: "claude",
    mcp_servers: [
      {
        name: "github",
        packages: [{ name: "octokit", version: "4.0.0", vulnerabilities: [] }],
        tools: [{ name: "create_issue" }],
        env: { GITHUB_TOKEN: "***" },
      },
    ],
  },
] as unknown as Agent[];

describe("TopologyDetailDrawer", () => {
  it("does not open an arbitrary record when a legacy name is ambiguous", () => {
    render(<TopologyDetailDrawer agents={[
      { ...agents[0]!, canonical_id: "agent:device-a" },
      { ...agents[0]!, canonical_id: "agent:device-b" },
    ]} selection={{ kind: "agent", name: "claude-desktop" }} onClose={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("could not be uniquely identified");
    expect(screen.queryByRole("link", { name: /Open agent record/ })).not.toBeInTheDocument();
  });

  it("selects the recorded identity instead of the first matching display name", () => {
    const scoped: Agent[] = [
      { name: "cursor", canonical_id: "agent:device-a", agent_type: "ide", mcp_servers: [{ name: "dev-only", packages: [] }] },
      { name: "cursor", canonical_id: "agent:device-b", agent_type: "ide", mcp_servers: [{ name: "prod-only", packages: [] }] },
    ];
    render(<TopologyDetailDrawer agents={scoped} selection={{ kind: "agent", name: "cursor", agentKey: "agent:device-b" }} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: /Services/ }));
    expect(screen.getByText("prod-only")).toBeInTheDocument();
    expect(screen.queryByText("dev-only")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Actions" }));
    expect(screen.getByRole("link", { name: /Open agent record/ })).toHaveAttribute("href", "/agents?name=agent%3Adevice-b");
  });

  it("traps modal focus, closes on Escape, and restores the trigger", async () => {
    const onClose = vi.fn();
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();

    const { unmount } = render(
      <TopologyDetailDrawer
        agents={agents}
        selection={{ kind: "agent", name: "claude-desktop" }}
        onClose={onClose}
      />,
    );

    const panel = screen.getByRole("dialog").querySelector("aside");
    expect(panel).not.toBeNull();
    await waitFor(() => expect(panel).toHaveFocus());
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);

    unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });

  it("uses bounded tabs instead of one long detail column", () => {
    render(
      <TopologyDetailDrawer
        agents={agents}
        selection={{ kind: "agent", name: "claude-desktop" }}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("github")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Services/ }));
    expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Services1");
    expect(screen.getByText("github")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Actions" }));
    expect(screen.getByRole("link", { name: /Open security graph/ })).toBeInTheDocument();
  });
});
