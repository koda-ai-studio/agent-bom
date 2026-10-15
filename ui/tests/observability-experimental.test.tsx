import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ObservabilityConnections } from "@/components/connections/observability";

const traces = { id: "traces", title: "Trace pull", surfaces: ["api", "mcp", "ui"], enabled_by: "AGENT_BOM_EXPERIMENTAL=traces", doc: "docs/TRACE_CONNECTIONS.md", flag_gated: true };
const mocks = vi.hoisted(() => ({ health: vi.fn(), list: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { systemHealth: mocks.health, listTraceConnectors: mocks.list, traceCollectionStatus: vi.fn().mockResolvedValue({ status: "not_started", persisted: 0 }), collectTracePage: vi.fn(), pullTraceConnector: vi.fn() } }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => true }) }));
afterEach(() => { vi.clearAllMocks(); });

it("labels platform traces experimental and shows the enable hint instead of the pull form when disabled", async () => {
  mocks.health.mockResolvedValue({ status: "ok", version: "x", experimental_features: [{ ...traces, enabled: false }] });
  render(<ObservabilityConnections />);
  expect(screen.getByText("Experimental")).toBeInTheDocument();
  expect(await screen.findByText(/experimental and disabled on this server/)).toBeInTheDocument();
  expect(screen.getByText("AGENT_BOM_EXPERIMENTAL=traces")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Pull and correlate" })).not.toBeInTheDocument();
  expect(mocks.list).not.toHaveBeenCalled();
});

it("renders the pull workflow when the server reports traces enabled", async () => {
  mocks.health.mockResolvedValue({ status: "ok", version: "x", experimental_features: [{ ...traces, enabled: true }] });
  mocks.list.mockResolvedValue({ connections: [] });
  render(<ObservabilityConnections />);
  expect(await screen.findByRole("button", { name: "Pull and correlate" })).toBeInTheDocument();
  expect(screen.queryByText(/experimental and disabled/)).not.toBeInTheDocument();
});
