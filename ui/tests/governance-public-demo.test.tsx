import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import GovernancePage from "@/app/governance/page";
import { ApiError } from "@/lib/api-errors";

const { apiMock, demoMode } = vi.hoisted(() => ({
  apiMock: { getGovernance: vi.fn() },
  demoMode: { isDemoMode: true, loading: false },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

vi.mock("@/hooks/use-demo-mode", () => ({
  useDemoMode: () => demoMode,
}));

vi.mock("@/lib/theme-colors", () => ({
  useChartTheme: () => ({}),
}));

describe("GovernancePage public demo", () => {
  beforeEach(() => {
    apiMock.getGovernance.mockReset();
    demoMode.isDemoMode = true;
    demoMode.loading = false;
  });

  it("does not request or expose backend setup diagnostics", () => {
    render(<GovernancePage />);

    expect(screen.getByRole("heading", { level: 1, name: /Cloud governance telemetry is not shown/i })).toBeInTheDocument();
    // A local `serve --demo-estate` install is anonymous read-only too: never call it "public".
    expect(screen.getByTestId("governance-public-demo")).not.toHaveTextContent(/public demo/i);
    expect(screen.queryByText(/pip install/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SNOWFLAKE_ACCOUNT/i)).not.toBeInTheDocument();
    expect(apiMock.getGovernance).not.toHaveBeenCalled();
  });
});

it("does not misdiagnose an unavailable service as a missing integration or display raw errors", async () => {
  demoMode.isDemoMode = false;
  apiMock.getGovernance.mockRejectedValue(new Error("private-connection-details"));
  render(<GovernancePage />);
  await screen.findByText("Governance evidence unavailable");
  expect(screen.queryByText("Governance integration is not configured")).not.toBeInTheDocument();
  expect(screen.queryByText("private-connection-details")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
});

function apiError(status: number): ApiError {
  return new ApiError("operator-account-detail", { status, statusText: "", url: "/v1/governance", method: "GET" });
}

it("shows an honest not-enabled state when the operator has not opted in", async () => {
  demoMode.isDemoMode = false;
  apiMock.getGovernance.mockRejectedValue(apiError(404));
  render(<GovernancePage />);
  const state = await screen.findByTestId("governance-not-enabled");
  expect(state).toHaveTextContent("AGENT_BOM_SNOWFLAKE_GOVERNANCE");
  expect(screen.queryByText("Governance evidence unavailable")).not.toBeInTheDocument();
  expect(screen.queryByText("operator-account-detail")).not.toBeInTheDocument();
});

it("tells non-admins the read is admin-only instead of reporting an outage", async () => {
  demoMode.isDemoMode = false;
  apiMock.getGovernance.mockRejectedValue(apiError(403));
  render(<GovernancePage />);
  const state = await screen.findByTestId("governance-admin-only");
  expect(state).toHaveTextContent(/admin/i);
  expect(screen.queryByText("Governance evidence unavailable")).not.toBeInTheDocument();
});
