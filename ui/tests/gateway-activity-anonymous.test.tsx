import { act, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GatewayFeedPanel } from "@/app/gateway/GatewayFeedPanel";
import { ActivityStreamError } from "@/lib/gateway-activity";
import { activity } from "./fixtures/gateway-activity";

const mocks = vi.hoisted(() => ({ stream: vi.fn(), snapshot: vi.fn(), session: { tenant_id: "default", subject: "anonymous", auth_required: false, auth_method: "anonymous" } as Record<string, unknown> }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: mocks.session }) }));
vi.mock("@/lib/gateway-activity", async () => ({ ...await vi.importActual("@/lib/gateway-activity"), streamGatewayActivity: mocks.stream, gatewayFeedSnapshot: mocks.snapshot }));
const page = (count: number) => ({ schema_version: "gateway.activity.stream.v1", tenant_id: "default", events: Array.from({ length: count }, (_, i) => ({ ...activity(i + 1), tenant_id: "default" })), next_cursor: "", has_more: false, latest_ordinal: count, retention_floor_ordinal: 1 });
afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); mocks.session.auth_required = false; });

it("serves the REST feed snapshot when the ledger stream refuses an anonymous no-auth session", async () => {
  vi.useFakeTimers();
  mocks.stream.mockImplementation(async function* () { throw new ActivityStreamError("auth"); });
  mocks.snapshot.mockResolvedValue(page(3));
  render(<GatewayFeedPanel />);
  await act(() => vi.advanceTimersByTimeAsync(0));
  await act(async () => {});
  expect(screen.getByRole("status")).toHaveTextContent(/Retained feed snapshot/);
  expect(screen.queryByText(/Sign in with permission/)).toBeNull();
  expect(screen.getByText("Newest 3 events in this view", { exact: false })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Browse retained history" })).toBeNull();
  // The snapshot refreshes on a timer instead of a long-lived stream.
  await act(() => vi.advanceTimersByTimeAsync(15_000));
  expect(mocks.snapshot).toHaveBeenCalledTimes(2);
});

it("shows the honest empty state when the anonymous feed snapshot is empty", async () => {
  vi.useFakeTimers();
  mocks.stream.mockImplementation(async function* () { throw new ActivityStreamError("auth"); });
  mocks.snapshot.mockResolvedValue(page(0));
  render(<GatewayFeedPanel />);
  await act(() => vi.advanceTimersByTimeAsync(0));
  await act(async () => {});
  expect(screen.getByText("No retained gateway activity yet.")).toBeInTheDocument();
  expect(screen.queryByText(/Sign in with permission/)).toBeNull();
});

it("still asks for sign-in when the deployment requires authentication", async () => {
  vi.useFakeTimers();
  mocks.session.auth_required = true;
  mocks.stream.mockImplementation(async function* () { throw new ActivityStreamError("auth"); });
  render(<GatewayFeedPanel />);
  await act(() => vi.advanceTimersByTimeAsync(0));
  expect(screen.getByText(/Sign in with permission/)).toBeInTheDocument();
  expect(mocks.snapshot).not.toHaveBeenCalled();
});
