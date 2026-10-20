import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "@/components/auth-gate";
import { AuthProvider, STARTING_MAX_WAIT_MS } from "@/components/auth-provider";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/agents",
  useSearchParams: () => new URLSearchParams(),
}));

const originalFetch = global.fetch;
afterEach(() => { global.fetch = originalFetch; vi.useRealTimers(); vi.restoreAllMocks(); });

const starting = () => ({
  ok: false, status: 503, statusText: "Service Unavailable", headers: new Headers({ "retry-after": "2" }),
  json: () => Promise.resolve({ error: { code: "API_STARTING", message: "The control plane API is starting." }, retry_after_seconds: 0.05 }),
});
const ready = () => ({
  ok: true, status: 200, statusText: "OK",
  json: () => Promise.resolve({
    authenticated: false, auth_required: false, configured_modes: [], recommended_ui_mode: "no_auth", auth_method: null,
    subject: null, role: null, tenant_id: "default", role_summary: null, memberships: [], request_id: null, trace_id: null, span_id: null,
  }),
});

function mount() {
  render(<AuthProvider><AuthGate><div>protected surface</div></AuthGate></AuthProvider>);
}

describe("control plane starting", () => {
  it("waits calmly while the API boots, one request per poll, then continues", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(starting()).mockResolvedValueOnce(starting()).mockResolvedValue(ready());
    global.fetch = fetchMock as unknown as typeof fetch;
    mount();
    expect(await screen.findByText("Starting the control plane…")).toBeInTheDocument();
    expect(screen.queryByText("Control plane unreachable")).toBeNull();
    await waitFor(() => expect(screen.getByText("protected surface")).toBeInTheDocument(), { timeout: 3000 });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("stops polling after a bounded wait and says so", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(starting()));
    global.fetch = fetchMock as unknown as typeof fetch;
    mount();
    await screen.findByText("Starting the control plane…");
    await vi.advanceTimersByTimeAsync(STARTING_MAX_WAIT_MS + 5_000);
    expect(await screen.findByText("Control plane unreachable")).toBeInTheDocument();
    const calls = fetchMock.mock.calls.length;
    expect(calls).toBeLessThanOrEqual(Math.ceil(STARTING_MAX_WAIT_MS / 1000) + 4);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchMock.mock.calls.length).toBe(calls);
  });
});
