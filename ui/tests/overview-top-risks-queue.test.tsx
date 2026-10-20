import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { TopRisksPanel } from "@/components/overview/risks";
import type { ExposurePathView } from "@/components/overview/shared";

const risk = (cve: string, agent: string, riskScore: number, href: string): ExposurePathView => ({
  key: cve, riskScore, href, affectedWorkloads: [agent], nodes: [{ type: "cve", label: cve, severity: "high" }, { type: "agent", label: agent }],
});

const queue = [
  risk("CVE-2023-4863", "Data Pipeline", 9.06, "/security-graph?lens=attack-path&node=agent%3Adata-pipeline&cve=CVE-2023-4863"),
  risk("CVE-2023-36258", "LangChain Service", 9.9, "/security-graph?lens=attack-path&node=agent%3Alangchain-service&cve=CVE-2023-36258"),
];

describe("top risks ranked by the investigation queue", () => {
  it("keeps the queue order and says it is the Investigation order", () => {
    render(<TopRisksPanel loading={false} unavailable={false} scans={1} topPath={null} exposurePaths={queue} ranking={{ source: "queue", total: 3417 }} />);
    const rows = screen.getAllByRole("button").filter((button) => /CVE-/.test(button.textContent ?? ""));
    expect(rows[0]).toHaveTextContent("Data Pipeline");
    expect(rows[1]).toHaveTextContent("LangChain Service");
    expect(screen.getByText(/Same order as Investigation/)).toBeVisible();
    expect(screen.getByText(/3,417 ranked paths/)).toBeVisible();
  });

  it("opens Investigation on the selected risk's own path", async () => {
    render(<TopRisksPanel loading={false} unavailable={false} scans={1} topPath={null} exposurePaths={queue} ranking={{ source: "queue", total: 2 }} />);
    expect(screen.getByRole("link", { name: /Open investigation/ })).toHaveAttribute("href", queue[0]!.href);
    await userEvent.click(screen.getByRole("button", { name: /LangChain Service/ }));
    expect(screen.getByRole("link", { name: /Open investigation/ })).toHaveAttribute("href", queue[1]!.href);
  });

  it("labels a finding-score ranking as different from Investigation", () => {
    render(<TopRisksPanel loading={false} unavailable={false} scans={1} topPath={null} exposurePaths={queue} />);
    expect(screen.getByText(/Ranked by finding risk score/)).toBeVisible();
    expect(screen.getAllByRole("button").find((button) => /CVE-/.test(button.textContent ?? ""))).toHaveTextContent("LangChain Service");
  });
});
