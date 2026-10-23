import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphChangeAttribution, changeSourceHeading } from "@/components/graph-change-attribution";

describe("GraphChangeAttribution", () => {
  it("attributes changed nodes to each collected vendor and account, with units", () => {
    render(<GraphChangeAttribution attribution={{
      unit: "nodes",
      sources: [
        { vendor: "aws", account: "100000000002", added: 246, removed: 3, changed: 1 },
        { vendor: "snowflake", account: "NORTHSTAR_02", added: 128, removed: 0, changed: 0 },
      ],
      omitted_sources: 4,
      unattributed: { added: 12, removed: 0, changed: 0 },
    }} />);
    const list = screen.getByRole("list", { name: "Changed nodes by collected source" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("AWS · 100000000002");
    expect(rows[0]).toHaveTextContent("+246 −3 · 1 changed nodes");
    expect(rows[1]).toHaveTextContent("Snowflake · NORTHSTAR_02");
    expect(rows[1]).toHaveTextContent("+128 nodes");
    expect(rows[1]).not.toHaveTextContent("−0");
    expect(screen.getByText(/4 more sources/)).toBeInTheDocument();
    expect(screen.getByText(/12 nodes without a recorded vendor/)).toBeInTheDocument();
  });

  it("renders nothing for older servers", () => {
    const { container } = render(<GraphChangeAttribution attribution={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("changeSourceHeading", () => {
  const attribution = {
    unit: "nodes" as const,
    sources: [
      { vendor: "gcp", account: "", added: 260, removed: 0, changed: 0 },
      { vendor: "aws", account: "", added: 245, removed: 0, changed: 0 },
      { vendor: "snowflake", account: "", added: 222, removed: 0, changed: 0 },
      { vendor: "aws", account: "210987654321", added: 13, removed: 12, changed: 0 },
      { vendor: "azure", account: "", added: 171, removed: 0, changed: 0 },
    ],
    omitted_sources: 0,
    unattributed: { added: 0, removed: 0, changed: 0 },
  };

  it("titles an unnamed scan request by the vendors its changes were collected from", () => {
    expect(changeSourceHeading({ label: "local-agents", label_basis: "default_scan_request", changes_by_source: attribution })).toBe("Google Cloud, AWS, Snowflake +1 more");
  });

  it("keeps a named scan target, and the default label when no vendor was recorded", () => {
    expect(changeSourceHeading({ label: "repo-a", label_basis: "scan_target", changes_by_source: attribution })).toBe("repo-a");
    expect(changeSourceHeading({ label: "local-agents", label_basis: "default_scan_request", changes_by_source: { ...attribution, sources: [] } })).toBe("local-agents");
  });
});
