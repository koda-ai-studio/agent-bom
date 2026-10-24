import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const health = vi.fn();
let pathname = "/findings";
vi.mock("next/navigation", () => ({ usePathname: () => pathname }));
vi.mock("@/lib/api", () => ({ api: { health: () => health() } }));

import { DEMO_SEED_POLL_MS, DemoSeedNotice } from "@/components/demo-seed-notice";

const base = { status: "ok", version: "0.0.0" };

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe("DemoSeedNotice", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    health.mockReset();
    pathname = "/findings";
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("says the demo is still seeding and reloads once the seed lands", async () => {
    health.mockResolvedValueOnce({ ...base, demo_seed: "pending" }).mockResolvedValueOnce({ ...base, demo_seed: "complete" });
    const reload = vi.fn();
    render(<DemoSeedNotice reload={reload} />);
    await flush();

    expect(screen.getByRole("status", { name: "Demo estate seeding" })).toHaveTextContent(/counts are partial/i);
    expect(reload).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(DEMO_SEED_POLL_MS);
    });
    await flush();

    expect(health).toHaveBeenCalledTimes(2);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("status", { name: "Demo estate seeding" })).toBeNull();
  });

  it("renders nothing and never reloads when the seed already finished", async () => {
    health.mockResolvedValue({ ...base, demo_seed: "complete" });
    const reload = vi.fn();
    const { container } = render(<DemoSeedNotice reload={reload} />);
    await flush();
    await act(async () => {
      vi.advanceTimersByTime(DEMO_SEED_POLL_MS * 3);
    });

    expect(container).toBeEmptyDOMElement();
    expect(health).toHaveBeenCalledTimes(1);
    expect(reload).not.toHaveBeenCalled();
  });

  it("stays silent outside demo mode", async () => {
    health.mockResolvedValue({ ...base, demo_seed: null });
    const reload = vi.fn();
    const { container } = render(<DemoSeedNotice reload={reload} />);
    await flush();

    expect(container).toBeEmptyDOMElement();
    expect(reload).not.toHaveBeenCalled();
  });

  it("keeps polling through a dropped health read while seeding", async () => {
    health
      .mockResolvedValueOnce({ ...base, demo_seed: "pending" })
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce({ ...base, demo_seed: "complete" });
    const reload = vi.fn();
    render(<DemoSeedNotice reload={reload} />);
    await flush();
    for (let i = 0; i < 2; i += 1) {
      await act(async () => {
        vi.advanceTimersByTime(DEMO_SEED_POLL_MS);
      });
      await flush();
    }

    expect(health).toHaveBeenCalledTimes(3);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("leaves the overview's own seeding notice alone but still reloads it", async () => {
    pathname = "/";
    health.mockResolvedValueOnce({ ...base, demo_seed: "pending" }).mockResolvedValueOnce({ ...base, demo_seed: "complete" });
    const reload = vi.fn();
    const { container } = render(<DemoSeedNotice reload={reload} />);
    await flush();
    expect(container).toBeEmptyDOMElement();
    await act(async () => {
      vi.advanceTimersByTime(DEMO_SEED_POLL_MS);
    });
    await flush();
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
