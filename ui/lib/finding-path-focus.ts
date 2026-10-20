import type { AttackPathFocus } from "@/lib/attack-paths";
import type { GraphAnalysisStatus } from "@/lib/graph-schema";
import type { GraphPathFocus } from "@/lib/graph-path-focus";

/**
 * The exact occurrence a finding link carries; the server matches it across the whole queue.
 * Paths record advisories rather than finding-store occurrence ids, so the advisory travels
 * with the occurrence's own node and resolves only there.
 */
export function serverPathFocus(focus: { nodeId?: string; findingId?: string; cve?: string; framework?: string; control?: string }): {
  nodeId?: string; findingId?: string; advisoryId?: string; framework?: string; control?: string;
} {
  const nodeId = focus.nodeId?.trim();
  const findingId = focus.findingId?.trim();
  const advisoryId = nodeId && findingId ? focus.cve?.trim() : "";
  const framework = focus.framework?.trim();
  const control = focus.control?.trim();
  return {
    ...(nodeId ? { nodeId } : {}),
    ...(findingId ? { findingId } : {}),
    ...(advisoryId ? { advisoryId } : {}),
    ...(framework && control ? { framework, control } : {}),
  };
}

/**
 * A finding raised in a historical snapshot may have no path in the current estate.
 * When the current estate's complete focused search misses, retry the finding's own snapshot.
 */
export function sourceSnapshotFallback(input: {
  selectedScanId: string;
  findingScanId: string;
  focus: Pick<GraphPathFocus, "covers_all_matches"> | null;
  matches: number;
}): string | null {
  const source = input.findingScanId.trim();
  if (!source || !input.focus || !input.focus.covers_all_matches || input.matches > 0) return null;
  if (source === input.selectedScanId || source.startsWith("current-estate:")) return null;
  return input.selectedScanId.startsWith("current-estate:") ? source : null;
}

/**
 * A server-focused page already holds only matching paths, keyed by the
 * canonical node. Re-filtering it with the link's (possibly replaced) node id
 * or advisory labels would drop the very path the server found.
 */
export function clientQueueFocus<T extends AttackPathFocus>(focus: T, serverFocused: boolean): Partial<T> {
  return serverFocused ? {} : focus;
}

/** A green "complete" receipt beside an empty result reads as "nothing to see"; only limits explain an empty queue. */
export function showAnalysisBannerForEmptyQueue(status: Pick<GraphAnalysisStatus, "status"> | undefined): boolean {
  return Boolean(status && status.status !== "complete");
}

export function focusedPathEmptyState(input: {
  serverFocused: boolean;
  coversAllMatches: boolean;
  cve: string;
  currentEstate: boolean;
}): { title: string; detail: string } | null {
  if (!input.serverFocused) return null;
  if (!input.coversAllMatches) {
    return {
      title: "No matching path in the searched part of the queue",
      detail: "The focused search stopped at a recorded bound, so this is not proof that no path reaches the finding. Open the package neighbourhood to inspect its connections.",
    };
  }
  const scope = input.currentEstate ? "the current estate" : "this snapshot";
  const advisory = input.cve ? ` Paths for ${input.cve} on other assets are available as related context.` : "";
  return {
    title: `No attack path reaches this finding in ${input.currentEstate ? "the current estate" : "this snapshot"}`,
    detail: `Every ranked path in ${scope} was checked. Open the package neighbourhood to see what this asset connects to.${advisory} An absent path does not establish that the vulnerability is unexploitable.`,
  };
}

/** Title and detail for an empty investigation queue, most specific explanation first. */
export function emptyQueueCopy(input: {
  focused: { title: string; detail: string } | null;
  morePagesUnloaded: boolean;
  relatedHref: string | null;
  fallback: { title: string; detail: string };
}): { title: string; detail: string } {
  if (input.focused) return input.focused;
  if (input.morePagesUnloaded) {
    return { title: "No matching paths in loaded pages", detail: "Continue through the queue to check later pages against this focus. Unloaded paths remain unknown." };
  }
  if (input.relatedHref) {
    return {
      title: "No path is linked to this finding record",
      detail: "Paths match this package and advisory in the selected snapshot, but their evidence does not link the selected finding record. Open that broader context explicitly.",
    };
  }
  return input.fallback;
}
