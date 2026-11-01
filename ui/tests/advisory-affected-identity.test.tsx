import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AffectedAssetIdentity, affectedAssetLabel } from "@/components/advisories/affected-asset-identity";
import { AffectedSummaryTiles } from "@/components/advisories/affected-summary";
import type { AdvisoryAffectedResponse, AdvisoryAffectedRow } from "@/lib/advisory-affected";

const imageRow = (overrides: Partial<AdvisoryAffectedRow> = {}): AdvisoryAffectedRow => ({
  asset: { agent: "", server: "", asset_type: "package", node_id: "pkg:pypi:pyyaml@5.3:image:bda9" },
  asset_label: "pyyaml@5.3", asset_type: "package", asset_node_id: "pkg:pypi:pyyaml@5.3:image:bda9",
  package: { name: "pyyaml", version: "5.3", ecosystem: "pypi" }, installed_version: "5.3", fixed_version: "5.4",
  verdict: "affected", verdict_reason: null, verdict_detail: null, provenance: "feed", scan_id: "showcase", last_observed_at: null,
  graph: { package_node_id: "pkg:pypi:pyyaml@5.3:image:bda9", server_node_id: null, agent_node_id: null },
  asset_display: { name: "claims-engine-00:2026.08.28", kind: "container_image", agent: "", host: "claims-engine-00" },
  ...overrides,
});

describe("affected asset identity", () => {
  it("names an image occurrence by its image and shows where it runs", () => {
    render(<AffectedAssetIdentity row={imageRow()} />);
    expect(screen.getByText("claims-engine-00:2026.08.28")).toBeInTheDocument();
    expect(screen.getByText(/Container image · runs on claims-engine-00 · pyyaml@5.3/)).toBeInTheDocument();
    expect(affectedAssetLabel(imageRow())).toBe("claims-engine-00:2026.08.28");
  });
  it("names a server occurrence with its agent and host", () => {
    const row = imageRow({
      asset: { agent: "cursor", server: "shell-runner-server" }, asset_label: "shell-runner-server", asset_type: "mcp_server",
      asset_display: { name: "shell-runner-server", kind: "mcp_server", agent: "Cursor", host: "shell-runner-0" },
    });
    render(<AffectedAssetIdentity row={row} />);
    expect(screen.getByText(/MCP server · agent Cursor · runs on shell-runner-0/)).toBeInTheDocument();
  });
  it("falls back to the recorded label when the API carries no display name", () => {
    const row = imageRow({ asset_display: undefined });
    render(<AffectedAssetIdentity row={row} />);
    expect(screen.getByText("pyyaml@5.3")).toBeInTheDocument();
    expect(screen.getByText("package")).toBeInTheDocument();
  });
  it("captions the tiles with the counting basis the API states", () => {
    const answer = {
      summary: { affected: 52, possibly_affected: 0, not_affected: 0, clean_scanned: 726, assets_examined: 778, reports_examined: 1, count_basis: "package_occurrence_per_holding_asset", count_basis_note: "One row per package occurrence on each holding asset." },
    } as unknown as AdvisoryAffectedResponse;
    render(<AffectedSummaryTiles answer={answer} />);
    expect(screen.getByText(/One row per package occurrence on each holding asset\./)).toBeInTheDocument();
  });
});
