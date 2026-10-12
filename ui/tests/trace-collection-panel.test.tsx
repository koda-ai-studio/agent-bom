import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { TraceCollectionPanel } from "@/components/trace-collection-panel";
const mocks = vi.hoisted(() => ({ status: vi.fn(), collect: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { traceCollectionStatus: mocks.status, collectTracePage: mocks.collect } }));
it("loads saved progress and resumes one bounded page", async () => {
  mocks.status.mockResolvedValue({status: "partial", persisted: 100, pages: 1, retry_after_seconds: 0});
  mocks.collect.mockResolvedValue({status: "caught_up", persisted: 130, pages: 2, retry_after_seconds: 0});
  render(<TraceCollectionPanel connectionId="production" />);
  expect(await screen.findByText(/100 observations saved/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", {name: "Collect next page"}));
  await waitFor(() => expect(mocks.collect).toHaveBeenCalledWith("production", expect.any(AbortSignal)));
  expect(await screen.findByText(/130 observations saved/)).toBeInTheDocument();
  expect(screen.getByText(/does not establish workload identity/)).toBeInTheDocument();
});
it("disables collection while provider backoff is active", async () => {
  mocks.status.mockResolvedValue({status: "failed", persisted: 100, pages: 1, last_error: "rate_limited", retry_after_seconds: 900});
  render(<TraceCollectionPanel connectionId="production" />);
  expect(await screen.findByText(/Provider rate limit/)).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Collect next page"})).toBeDisabled();
});
