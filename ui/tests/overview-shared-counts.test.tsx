import { render, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { OverviewDashboard } from "@/components/overview-dashboard";
import { ShellDeploymentProvider } from "@/components/shell-deployment-context";

const getCounts = vi.hoisted(() => vi.fn().mockResolvedValue({ scan_count: 0, scan_sources: [], services: {} }));
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, getPostureCounts: getCounts } };
});

it("reuses the shell counts when previewing a local report", async () => {
  render(<ShellDeploymentProvider><OverviewDashboard initialReport={{ agents: [], blast_radius: [] }} /></ShellDeploymentProvider>);
  await waitFor(() => expect(getCounts).toHaveBeenCalled());
  expect(getCounts).toHaveBeenCalledTimes(1);
});
