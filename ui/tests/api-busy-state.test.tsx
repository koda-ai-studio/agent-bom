import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiOfflineState } from "@/components/api-offline-state";
import { InvestigationLoadError } from "@/components/investigation-load-error";
import { ApiAuthError, ApiForbiddenError, ApiNetworkError, ApiRateLimitError, ApiServerError } from "@/lib/api-errors";
import { classifyApiOfflineKind } from "@/lib/api-offline-kind";
import { attackPathLoadErrorCopy } from "@/lib/investigation-queue-copy";

const ctx = { status: 429, statusText: "", url: "/v1/graph/attack-paths", method: "GET" };

afterEach(() => vi.useRealTimers());

describe("busy API state", () => {
  it("classifies backpressure as busy and keeps every other kind", () => {
    expect(classifyApiOfflineKind(new ApiRateLimitError("shed", ctx, 1))).toBe("busy");
    expect(classifyApiOfflineKind(new ApiServerError("retry", { ...ctx, status: 503 }, 2))).toBe("busy");
    expect(classifyApiOfflineKind(new ApiServerError("starting", { ...ctx, status: 503, body: { error: { code: "API_STARTING" } } }, 1))).toBe("network");
    expect(classifyApiOfflineKind(new ApiAuthError("no", { ...ctx, status: 401 }))).toBe("auth");
    expect(classifyApiOfflineKind(new ApiForbiddenError("no", { ...ctx, status: 403 }))).toBe("forbidden");
    expect(classifyApiOfflineKind(new ApiNetworkError("down", { url: "/v1/x", method: "GET" }))).toBe("network");
  });

  it("says the running API is busy, never suggests starting a server, and retries on its own", () => {
    vi.useFakeTimers();
    const onRetry = vi.fn();
    render(<ApiOfflineState kind="busy" detail="Backpressure active for runtime path" onRetry={onRetry} />);
    expect(screen.getByRole("heading", { name: /busy/i })).toBeInTheDocument();
    expect(screen.queryByText(/Cannot connect/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/agent-bom serve/)).not.toBeInTheDocument();
    expect(screen.queryByText("Local setup instructions")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/Retrying in \d+s/);
    act(() => { vi.advanceTimersByTime(20_000); });
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("renders the attack-path busy state as non-fatal, without the serve command", () => {
    vi.useFakeTimers();
    const onRetry = vi.fn();
    render(<InvestigationLoadError copy={attackPathLoadErrorCopy("shed")} retryHref="/graph" resetFocusHref={null} busy onRetry={onRetry} />);
    expect(screen.getByText(/API is busy/i)).toBeInTheDocument();
    expect(screen.queryByText(/agent-bom serve/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Cannot load attack paths/)).not.toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(20_000); });
    expect(onRetry).toHaveBeenCalled();
  });

  it("reports a failed attack-path read without telling the user to start the running server", () => {
    render(<InvestigationLoadError copy={attackPathLoadErrorCopy("500 Internal Server Error")} retryHref="/graph" resetFocusHref={null} />);
    expect(screen.getByText(/Cannot load attack paths/)).toBeInTheDocument();
    expect(screen.queryByText(/agent-bom serve/)).not.toBeInTheDocument();
  });
});
