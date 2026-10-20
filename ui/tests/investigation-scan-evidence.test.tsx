import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { InvestigationScanEvidence } from "@/components/investigation-scan-evidence";
import type { GraphSnapshot } from "@/lib/api-types";
import { investigationEstateMode } from "@/lib/investigation-estate-mode";

vi.mock("next/link", () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

function snapshot(scan_id: string): GraphSnapshot {
  return { scan_id, created_at: "2026-10-19T00:00:00+00:00", node_count: 12, edge_count: 30, risk_summary: {} };
}

const LONG_A = "current-estate:b420bb7c8d4fc9ac35d37a4af81e8501";
const LONG_B = "current-estate:b420bb7c8d4fc9ac35d37a4af81e9999";

describe("InvestigationScanEvidence snapshot chips", () => {
  it("names snapshots like the graph page: short names whole, long ids by their tail, full id as tooltip", () => {
    const snapshots = [snapshot("showcase"), snapshot("showcase-baseline"), snapshot(LONG_A), snapshot(LONG_B)];
    render(
      <InvestigationScanEvidence selectedScanId="showcase" selectedSnapshot={snapshots[0]!} posture={null} fixFirstView={null}
        loadingSnapshots={false} snapshots={snapshots} currentEstateId="" displayedSnapshots={snapshots} onSelect={() => {}}
        hiddenSnapshotCount={0} showAll={false} onToggleShowAll={() => {}} estateMode={investigationEstateMode(12, "showcase")} />,
    );
    const chips = screen.getAllByRole("button").filter(button => button.textContent?.includes("12 nodes"));
    const names = chips.map(chip => chip.querySelector("span")?.textContent);
    expect(names).toEqual(["showcase", "showcase-baseline", "current-estate:b42…af81e8501", "current-estate:b42…af81e9999"]);
    expect(chips.map(chip => chip.getAttribute("title"))).toEqual(["showcase", "showcase-baseline", LONG_A, LONG_B]);
  });
});
