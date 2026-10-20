import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PathReachSummary } from "@/components/path-reach-summary";
import type { AttackPath } from "@/lib/graph-schema";

const path = {
  source: "agent:langchain-service", target: "vuln:CVE-2023-36258",
  hops: ["agent:langchain-service", "server:llm-orchestrator-server", "pkg:pypi:langchain@0.0.150", "vuln:CVE-2023-36258"],
  edges: [], composite_risk: 80, summary: "", vuln_ids: ["CVE-2023-36258"],
  credential_exposure: ["OPENAI_API_KEY"], tool_exposure: ["eval_expression", "http_get"],
} as unknown as AttackPath;

describe("path reach summary", () => {
  it("draws the credentials and tools the path's server exposes, with a route to them", () => {
    render(<PathReachSummary path={path} scanId="scan-1" />);
    expect(screen.getByText("OPENAI_API_KEY")).toBeVisible();
    expect(screen.getByText("eval_expression")).toBeVisible();
    expect(screen.getByText(/1 credential · 2 tools/)).toBeVisible();
    const link = screen.getByRole("link", { name: /Show what the server reaches/ });
    const params = new URL(link.getAttribute("href")!, "http://x").searchParams;
    expect(params.get("root")).toBe("server:llm-orchestrator-server");
    expect(params.get("direction")).toBe("forward");
  });

  it("renders nothing when the path reaches no credential or tool", () => {
    const { container } = render(<PathReachSummary path={{ ...path, credential_exposure: [], tool_exposure: [] }} scanId="scan-1" />);
    expect(container).toBeEmptyDOMElement();
  });
});
