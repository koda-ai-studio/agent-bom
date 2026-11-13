import { describe, expect, it, vi } from "vitest";

import { ApiConflictError, ApiServerError, ApiValidationError } from "@/lib/api-errors";
import { loadArchitecturePage, type ArchitecturePagesState } from "@/lib/agent-architecture-pages";
import { architecturePages } from "./fixtures/agent-architecture-fixture";

const ctx = (status: number) => ({ status, statusText: "", url: "/v1/graph/agent-architecture", method: "GET" });

describe("agent architecture paging", () => {
  it("loads the first page without a cursor", async () => {
    const { first_page } = architecturePages();
    const fetchPage = vi.fn().mockResolvedValue(first_page);
    const state = await loadArchitecturePage(fetchPage, null);
    expect(fetchPage).toHaveBeenCalledWith(undefined, { fresh: false });
    expect(state).toMatchObject({ status: "ready", notice: null });
    expect(state.harnesses).toHaveLength(2);
    expect(state.hasMore).toBe(true);
  });

  it("appends the next page with the API cursor", async () => {
    const { first_page, second_page } = architecturePages();
    const first = await loadArchitecturePage(vi.fn().mockResolvedValue(first_page), null);
    const fetchPage = vi.fn().mockResolvedValue(second_page);
    const next = await loadArchitecturePage(fetchPage, first);
    expect(fetchPage).toHaveBeenCalledWith(first_page.pagination.next_cursor, { fresh: false });
    expect(next.harnesses.map(harness => harness.harness_id)).toEqual([...first_page.harnesses, ...second_page.harnesses].map(harness => harness.harness_id));
    expect(next.hasMore).toBe(false);
    expect(next.total).toBe(3);
  });

  it("restarts from the first page when the snapshot changed (409)", async () => {
    const { first_page } = architecturePages();
    const first = await loadArchitecturePage(vi.fn().mockResolvedValue(first_page), null);
    const fetchPage = vi.fn()
      .mockRejectedValueOnce(new ApiConflictError("Graph snapshot changed; restart the query from its first page.", ctx(409)))
      .mockResolvedValueOnce(first_page);
    const state = await loadArchitecturePage(fetchPage, first);
    // The restart bypasses the client GET cache: a cached first page would be the old snapshot.
    expect(fetchPage.mock.calls).toEqual([[first_page.pagination.next_cursor, { fresh: false }], [undefined, { fresh: true }]]);
    expect(state.status).toBe("ready");
    expect(state.harnesses).toHaveLength(2);
    expect(state.notice).toMatch(/snapshot changed/i);
  });

  it("shows an error for a rejected cursor (422) and keeps what was loaded", async () => {
    const { first_page } = architecturePages();
    const first = await loadArchitecturePage(vi.fn().mockResolvedValue(first_page), null);
    const state = await loadArchitecturePage(vi.fn().mockRejectedValue(new ApiValidationError("Invalid cursor for this query; restart from the first page.", ctx(422))), first);
    expect(state).toMatchObject({ status: "error", errorKind: "cursor" });
    expect(state.error).toMatch(/Invalid cursor/);
    expect(state.harnesses).toHaveLength(2);
  });

  it("starts over without the client cache when asked", async () => {
    const fetchPage = vi.fn().mockResolvedValue(architecturePages().first_page);
    await loadArchitecturePage(fetchPage, null, { fresh: true });
    expect(fetchPage).toHaveBeenCalledWith(undefined, { fresh: true });
  });

  it("reports other failures without inventing data", async () => {
    const state: ArchitecturePagesState = await loadArchitecturePage(vi.fn().mockRejectedValue(new ApiServerError("Graph store unavailable", ctx(503))), null);
    expect(state).toMatchObject({ status: "error", errorKind: "request", harnesses: [] });
  });
});
