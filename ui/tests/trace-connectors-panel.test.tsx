import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { TraceConnectorsPanel } from "@/components/trace-connectors-panel";
const mocks = vi.hoisted(() => ({ pull: vi.fn(), list: vi.fn().mockResolvedValue({ connections: [{id: "production", provider: "langfuse", display_name: "Production traces"}] }), allowed: true }));
vi.mock("@/lib/api", () => ({ api: { traceCollectionStatus: vi.fn().mockResolvedValue({status: "not_started", persisted: 0}), collectTracePage: vi.fn(), pullTraceConnector: mocks.pull, listTraceConnectors: mocks.list } }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => mocks.allowed }) }));
afterEach(() => { vi.clearAllMocks(); mocks.allowed = true; });
it("pulls metadata without content and labels ephemeral results honestly", async () => {
  mocks.pull.mockResolvedValue({ pulled_spans: 2, attack_paths: [], content_findings: [], content_screened: false });
  render(<TraceConnectorsPanel />);
  fireEvent.click(screen.getByText("Advanced: use temporary credentials"));
  fireEvent.change(await screen.findByLabelText("Public key"), { target: { value: "public-test" } });
  fireEvent.change(await screen.findByLabelText("Secret key"), { target: { value: "secret-test" } });
  fireEvent.click(screen.getByRole("button", { name: "Pull and correlate" }));
  await waitFor(() => expect(mocks.pull).toHaveBeenCalled());
  expect(mocks.pull.mock.calls[0]?.[1]).toMatchObject({ screen_content: false, limit: 50 });
  expect(await screen.findByText(/2 tool calls reviewed/)).toBeInTheDocument();
  expect(screen.getByText(/not saved to the trace explorer/)).toBeInTheDocument();
  expect(screen.getByLabelText("Secret key")).toHaveValue("");
  expect(screen.getByText(/No matches.*does not establish/)).toBeInTheDocument();
});
it("clears provider secrets and rejects viewing credentials without ingest capability", async () => {
  const view = render(<TraceConnectorsPanel />);
  fireEvent.click(screen.getByText("Advanced: use temporary credentials"));
  fireEvent.change(await screen.findByLabelText("Secret key"), { target: { value: "secret-test" } });
  fireEvent.change(screen.getByLabelText("Platform"), { target: { value: "langsmith" } });
  fireEvent.change(screen.getByLabelText("Platform"), { target: { value: "langfuse" } });
  expect(screen.getByLabelText("Secret key")).toHaveValue("");
  view.unmount(); mocks.allowed = false; render(<TraceConnectorsPanel />);
  expect(screen.queryByRole("button", { name: "Pull and correlate" })).not.toBeInTheDocument();
  expect(mocks.pull).not.toHaveBeenCalled();
});

it("uses a managed connection without requesting or transmitting credentials", async () => {
  mocks.pull.mockResolvedValue({ pulled_spans: 2, attack_paths: [], content_findings: [], content_screened: false });
  render(<TraceConnectorsPanel />);
  expect(screen.queryByLabelText("Secret key")).not.toBeInTheDocument();
  await screen.findByRole("option", { name: "Production traces" });
  fireEvent.change(screen.getByLabelText("Managed connection"), { target: {value: "production"} });
  fireEvent.click(screen.getByRole("button", { name: "Pull and correlate" }));
  await waitFor(() => expect(mocks.pull).toHaveBeenCalled());
  expect(mocks.pull.mock.calls[0]?.[1]).toEqual({ connection_id: "production", screen_content: false, limit: 50 });
});
