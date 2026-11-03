import type { AttackPath, UnifiedNode } from "./graph-schema";
import { matchesAttackPathFocus, type AttackPathFocus } from "./attack-paths";

/** The server orders the occurrence queue by evidence, then risk. Enrichment
 * cards must not reorder it or introduce occurrences outside the current page. */
export function selectAttackPathQueue(
  page: AttackPath[] | undefined,
  fallback: AttackPath[],
  nodes: Map<string, UnifiedNode>,
  focus: AttackPathFocus,
  campaignMembers?: string[],
): AttackPath[] {
  const members = campaignMembers?.length ? new Set(campaignMembers) : null;
  const hasFocus = [focus.cve, focus.packageName, focus.agentName, focus.nodeId, focus.findingId].some(value => value?.trim());
  return (page ?? fallback).filter((path) =>
    (!hasFocus || matchesAttackPathFocus(path, nodes, focus))
    && (!members || members.has(`${path.source}->${path.target}`)),
  );
}

/** Bounded presentation only; canonical queue and cursor order stay unchanged. */
export function representativeAttackPaths(paths: AttackPath[], nodes: Map<string, UnifiedNode>, limit = 10): AttackPath[] {
  const count = Math.max(0, Math.min(10, Math.floor(limit)));
  const candidates = paths.map((path, index) => {
    const hops = path.hops.flatMap(id => nodes.get(id) ? [nodes.get(id)!] : []);
    const families = path.vuln_ids.map(id => `advisory:${id.trim().toLowerCase()}`);
    for (const node of hops) {
      if (node.entity_type === "misconfiguration") families.push(`finding:${node.attributes.rule_id ?? node.attributes.finding_kind ?? node.label}`);
    }
    if (path.credential_exposure.length) families.push("credential exposure");
    if (path.tool_exposure.length) families.push("tool exposure");
    if (!families.length) families.push(`topology:${hops.map(node => node.entity_type).join(">")}`);
    const assets = hops.filter(node => ["server", "container", "cloud_resource", "application", "resource"].includes(node.entity_type)).map(node => node.id);
    return { path, index, families, assets: assets.length ? assets : [path.source] };
  });
  const selected = new Set<number>(), families = new Set<string>(), assets = new Set<string>();
  const result: AttackPath[] = [];
  const pick = (candidate: typeof candidates[number]) => {
    if (selected.has(candidate.index) || result.length >= count) return;
    selected.add(candidate.index);
    candidate.families.forEach(key => families.add(key));
    candidate.assets.forEach(key => assets.add(key));
    result.push(candidate.path);
  };
  // Within each pass the recorded evidence/risk order remains the tie-breaker.
  for (const candidate of candidates) if (candidate.families.some(key => !families.has(key))) pick(candidate);
  for (const candidate of candidates) if (candidate.assets.some(key => !assets.has(key))) pick(candidate);
  for (const candidate of candidates) pick(candidate);
  return result;
}
