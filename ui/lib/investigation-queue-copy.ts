import { graphAnalysisStatusCopy } from "@/components/graph-analysis-status";
import type { GraphAnalysisStatus } from "@/lib/graph-schema";

export interface QueueStateCopy {
  title: string;
  detail: string;
  suggestions: string[];
}

/** Why the attack-path queue is empty, most specific recorded reason first. */
export function emptyAttackPathQueueCopy(
  analysis: GraphAnalysisStatus | undefined,
  hasFocusContext: boolean,
  focusLabel: string | null,
): QueueStateCopy {
        const executionCopy = graphAnalysisStatusCopy(analysis);
    if (analysis?.status === "skipped" || analysis?.status === "failed") {
      return {
        title: executionCopy.label,
        detail: executionCopy.detail,
        suggestions: [
          "Run a fresh scan after reviewing the recorded analysis limit or failure.",
          "Open the full graph to inspect the inventory and findings that did persist.",
          "Do not treat this snapshot as proof that no attack paths exist.",
        ],
      };
    }
    if (analysis?.status === "limited") {
      return {
        title: "No paths in the retained partial result",
        detail: executionCopy.detail,
        suggestions: [
          "Review the recorded execution limits before relying on this result.",
          "Open the full graph to inspect topology outside the retained path set.",
          "Run a narrower or higher-capacity scan for complete path coverage.",
        ],
      };
    }
    if (hasFocusContext) {
      return {
        title: "No attack paths matched the current focus",
        detail: `No recorded path matched ${focusLabel ?? "the current filters"} in this snapshot. This does not establish whether the vulnerability is exploitable or whether another path exists.`,
        suggestions: [
          "Clear focus to review every persisted path in this snapshot.",
          "Open the full graph to inspect broader topology.",
          "Review the finding and its missing evidence before choosing a remediation.",
        ],
      };
    }

    return {
      title: "No precomputed attack paths are available for this snapshot",
      detail:
        "This snapshot has no recorded attack paths. Vulnerability presence, structural reachability, and exploitation are separate assessments.",
      suggestions: [
        "Run a fresh scan to refresh the persisted graph snapshot.",
        "Open the full graph to inspect inventory and findings that did persist.",
        "Check the vulnerabilities page if you need fix context before the next scan completes.",
      ],
    };
}

/** The attack-path queue failed to load for this snapshot. */
export function attackPathLoadErrorCopy(graphLoadError: string | null): QueueStateCopy {
    const detail = graphLoadError ?? "The graph API did not return attack-path data for this snapshot.";
    return {
      title: "Cannot load attack paths for this snapshot",
      detail,
      suggestions: [
        "Retry the graph load after confirming the API is reachable.",
        "Open the full graph only after this error clears.",
        "Check API logs for the rejected or failed attack-path request.",
      ],
    };
}
