import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LakeImportWorkflow } from "@/components/connections/lake-import";

describe("Lake import activation", () => {
  it("separates private preview from authenticated push and labels the sample", () => {
    render(<LakeImportWorkflow />);
    expect(screen.getByText(/Synthetic sample for an isolated pilot/)).toBeInTheDocument();
    expect(screen.getByText("agent-bom ingest lake-sample --directory lake-pilot")).toBeInTheDocument();
    expect(screen.getByText(/-o lake-pilot\/preview-report.json$/)).toBeInTheDocument();
    expect(screen.getByText(/pushed-report.json --push "\$AGENT_BOM_CONTROL_PLANE_URL"/)).toBeInTheDocument();
    expect(screen.getByText(/AGENT_BOM_PUSH_API_KEY through your secret manager/)).toBeInTheDocument();
    expect(screen.getByText(/A missing graph receipt stays unconfirmed/)).toBeInTheDocument();
  });

  it("switches to customer-selected exports without claiming a native warehouse connection", () => {
    render(<LakeImportWorkflow />);
    fireEvent.click(screen.getByRole("button", { name: "Use your export" }));
    expect(screen.queryByText(/Synthetic sample for an isolated pilot/)).not.toBeInTheDocument();
    expect(screen.queryByText(/lake-sample --directory/)).not.toBeInTheDocument();
    expect(screen.getByText(/Provider labels record provenance; they do not run warehouse queries/)).toBeInTheDocument();
    expect(screen.getByText("agent-bom ingest lake findings.json --mapping mapping.json -o preview-report.json")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Set up a self-hosted control plane" })).toHaveAttribute("href", "https://koda-ai-studio.github.io/agent-bom/deployment/docker/");
  });
});
