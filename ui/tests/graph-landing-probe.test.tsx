import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { getGraphClusterMap, getGraphRollup } = vi.hoisted(() => ({ getGraphClusterMap: vi.fn(), getGraphRollup: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getGraphClusterMap, getGraphRollup } }));

import { useGroupedLandingProbe } from "@/hooks/use-grouped-landing-probe";
import { clusterMapHasScopeGroups, type ClusterMapResponse } from "@/lib/graph-cluster-map";
import { graphRollupCanvasMode, graphRollupEligible } from "@/lib/graph-rollup-default";

afterEach(() => vi.clearAllMocks());

const listing = (key: string, tier: number, count = 3) => ({
  id: `@group:${key}`, cluster_key: key, label: key, tier, tier_label: "", member_count: count, worst_severity: "none",
  severity_counts: {}, on_attack_path_count: 0, risky: false, entity_types: {}, folded: false,
});
const frame = (clusters: ReturnType<typeof listing>[]) => ({ mode: "cluster_map", nodes: [], edges: [], clusters }) as unknown as ClusterMapResponse;

describe("clusterMapHasScopeGroups", () => {
  it("finds organization, account, environment and fleet groups in the scope tier", () => {
    for (const key of ["type:org", "type:account", "type:environment", "type:fleet"]) {
      expect(clusterMapHasScopeGroups(frame([listing("type:agent", 1), listing(key, 0)]))).toBe(true);
    }
  });

  it("reads a flat estate, and a lone provider, as having no scope to rank", () => {
    expect(clusterMapHasScopeGroups(frame([listing("type:agent", 1), listing("package:pypi", 3)]))).toBe(false);
    expect(clusterMapHasScopeGroups(frame([listing("type:provider", 0)]))).toBe(false);
    expect(clusterMapHasScopeGroups(frame([listing("type:account", 0, 0)]))).toBe(false);
  });
});

describe("useGroupedLandingProbe", () => {
  const base = {
    hasSelectedScan: true, rollupPreference: "default" as const, rollupDismissed: false, estateNodeCount: 5_000,
    investigationMode: false, selectedAttackPath: false, reachabilityActive: false, blastRadiusActive: false,
  };

  it("lands a flat estate on the grouped map without waiting on the roll-up read", async () => {
    getGraphRollup.mockReturnValue(new Promise(() => {}));
    getGraphClusterMap.mockResolvedValue(frame([listing("type:agent", 1, 41), listing("package:pypi", 3, 1200)]));
    const { result } = renderHook(() => useGroupedLandingProbe("scan-1", true));
    expect(result.current).toBe("pending");
    await waitFor(() => expect(result.current).toBe("flat"));
    expect(getGraphRollup).not.toHaveBeenCalled();
    const eligible = graphRollupEligible({ ...base, landingProbe: result.current });
    expect(eligible).toBe(false);
    // The roll-up is still unanswered, yet nothing holds the canvas for it.
    expect(graphRollupCanvasMode({ eligible, dismissed: false, hasView: false, unavailable: false, failed: false })).toBe("raw");
  });

  it("leaves a scoped estate, or a failed probe, to the roll-up", async () => {
    getGraphClusterMap.mockResolvedValueOnce(frame([listing("type:account", 0, 30)]));
    const scoped = renderHook(() => useGroupedLandingProbe("scan-1", true));
    await waitFor(() => expect(scoped.result.current).toBe("scoped"));
    expect(graphRollupEligible({ ...base, landingProbe: "scoped" })).toBe(true);

    getGraphClusterMap.mockRejectedValueOnce(new Error("503"));
    const failed = renderHook(() => useGroupedLandingProbe("scan-2", true));
    await waitFor(() => expect(failed.result.current).toBe("failed"));
    expect(graphRollupEligible({ ...base, landingProbe: "failed" })).toBe(true);
    expect(graphRollupEligible({ ...base, landingProbe: "pending" })).toBe(true);
  });

  it("does not probe when disabled, and an explicit roll-up ignores a flat probe", () => {
    const { result } = renderHook(() => useGroupedLandingProbe("scan-1", false));
    expect(result.current).toBe("idle");
    expect(getGraphClusterMap).not.toHaveBeenCalled();
    expect(graphRollupEligible({ ...base, rollupPreference: "force", landingProbe: "flat" })).toBe(true);
  });

  it("re-probes when the snapshot changes", async () => {
    getGraphClusterMap.mockResolvedValueOnce(frame([listing("type:agent", 1)])).mockResolvedValueOnce(frame([listing("type:org", 0)]));
    const { result, rerender } = renderHook(({ scan }) => useGroupedLandingProbe(scan, true), { initialProps: { scan: "a" } });
    await waitFor(() => expect(result.current).toBe("flat"));
    rerender({ scan: "b" });
    await waitFor(() => expect(result.current).toBe("scoped"));
  });
});
