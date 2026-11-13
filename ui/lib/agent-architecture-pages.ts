import { ApiConflictError, ApiValidationError } from "@/lib/api-errors";
import type { AgentArchitectureResponse, AgentHarness } from "@/lib/agent-architecture-types";

export type ArchitecturePagesState = {
  status: "ready" | "error";
  harnesses: AgentHarness[];
  /** The latest page: summary, coverage and the cursor to continue from. */
  page: AgentArchitectureResponse | null;
  total: number;
  hasMore: boolean;
  /** Shown once after the view restarted because the snapshot changed between pages. */
  notice: string | null;
  error: string | null;
  /** `cursor`: the API rejected the continuation (422); `request`: anything else. */
  errorKind: "cursor" | "request" | null;
};

/** `fresh` bypasses the client GET cache: a restart must read the server's current snapshot. */
export type FetchArchitecturePage = (cursor: string | undefined, options: { fresh: boolean }) => Promise<AgentArchitectureResponse>;

const SNAPSHOT_CHANGED = "The snapshot changed while paging, so harnesses were reloaded from the first page.";

function ready(page: AgentArchitectureResponse, previous: AgentHarness[], notice: string | null): ArchitecturePagesState {
  const seen = new Set(previous.map(harness => harness.harness_id));
  return {
    status: "ready",
    harnesses: [...previous, ...page.harnesses.filter(harness => !seen.has(harness.harness_id))],
    page, total: page.pagination.total, hasMore: page.pagination.has_more && Boolean(page.pagination.next_cursor),
    notice, error: null, errorKind: null,
  };
}

function failed(error: unknown, current: ArchitecturePagesState | null): ArchitecturePagesState {
  const message = error instanceof Error ? error.message : "The architecture could not be loaded.";
  return {
    status: "error",
    harnesses: current?.harnesses ?? [], page: current?.page ?? null, total: current?.total ?? 0, hasMore: current?.hasMore ?? false,
    notice: null, error: message, errorKind: error instanceof ApiValidationError ? "cursor" : "request",
  };
}

/**
 * The first page (no `current`) or the next one from the API cursor. A 409
 * means the snapshot moved under the cursor: restart from the first page
 * rather than mix two snapshots. A 422 is reported, keeping what was shown.
 */
export async function loadArchitecturePage(
  fetchPage: FetchArchitecturePage, current: ArchitecturePagesState | null, options: { fresh?: boolean } = {},
): Promise<ArchitecturePagesState> {
  const cursor = current?.page?.pagination.next_cursor || undefined;
  try {
    return ready(await fetchPage(cursor, { fresh: options.fresh ?? false }), cursor ? current!.harnesses : [], null);
  } catch (error) {
    if (!(error instanceof ApiConflictError) || !cursor) return failed(error, current);
    try {
      return ready(await fetchPage(undefined, { fresh: true }), [], SNAPSHOT_CHANGED);
    } catch (retry) {
      return failed(retry, null);
    }
  }
}
