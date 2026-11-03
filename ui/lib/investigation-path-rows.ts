import type { RankedPathRow } from "@/components/ranked-path-list";
import type { FixFirstPathCard } from "./api-types";
import type { AttackPath, UnifiedNode } from "./graph-schema";
import { attackPathKey, attackPathRoleChain, descriptiveAttackPathTitle, labelsForAttackPathType, rankedAttackPathRows, toAttackCardNodes } from "./attack-paths";

/** Preview positions retain their rank in the loaded authoritative queue. */
export function investigationPathRows(paths: AttackPath[], cards: FixFirstPathCard[], nodes: Map<string, UnifiedNode>, queue: AttackPath[]): RankedPathRow[] {
  const ranks = new Map<string, number>();
  queue.forEach((path, index) => { if (!ranks.has(attackPathKey(path))) ranks.set(attackPathKey(path), index + 1); });
  return rankedAttackPathRows(paths, cards).flatMap(({ path, card, rank, key }) => {
    const pathNodes = toAttackCardNodes(path, nodes);
    if (pathNodes.length === 0) return [];
    const row: RankedPathRow = {
      key, selectionKey: attackPathKey(path), rank: ranks.get(attackPathKey(path)) ?? rank,
      title: descriptiveAttackPathTitle(pathNodes), cve: path.vuln_ids[0] ?? null,
      riskScore: path.composite_risk, nodeCount: path.hops.length,
      agents: labelsForAttackPathType(path, nodes, "agent").length,
      roleChain: attackPathRoleChain(path, nodes),
    };
    if (card?.rank_meta?.tool_capabilities?.length) row.capabilityTags = card.rank_meta.tool_capabilities;
    if (card?.rank_meta?.environments?.length) row.environmentTags = card.rank_meta.environments;
    return [row];
  });
}
