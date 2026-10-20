import type { ExposurePathView } from "@/components/overview/shared";
import type { OverviewTopRisk, UnifiedGraphResponse } from "@/lib/api-types";
import { buildSecurityGraphHref } from "@/lib/attack-paths";
import { agentDisplayName } from "@/lib/display-name";

const basePackage = (id: string) => id.split(":image:")[0] ?? id;

/**
 * The overview's top risks in the Investigation queue's own order. The server
 * ranks paths (KEV, evidence tier, severity, composite risk…); re-sorting here
 * would make the overview and Investigation disagree on what is #1. One row
 * per advisory on a package version: its highest-ranked path.
 */
export function queueTopRisks(graph: UnifiedGraphResponse, topRisks: OverviewTopRisk[] | null | undefined, limit = 5): ExposurePathView[] {
  const labels = new Map(graph.nodes.map((node) => [node.id, node.label]));
  const seen = new Set<string>();
  const rows: ExposurePathView[] = [];
  for (const path of graph.attack_paths ?? []) {
    if (path.suppressed) continue;
    const cve = path.vuln_ids[0];
    if (!cve) continue;
    const packageId = path.hops.find((hop) => hop.startsWith("pkg:"));
    const packageLabel = packageId ? labels.get(packageId) ?? basePackage(packageId).replace(/^pkg:[^:]+:/, "") : undefined;
    const key = `${cve}::${packageId ? basePackage(packageId) : path.target}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const agentId = path.source.startsWith("agent:") ? path.source : undefined;
    const agent = agentId ? agentDisplayName(agentId.slice(6), labels.get(agentId)) : undefined;
    const serverId = path.hops.find((hop) => hop.startsWith("server:"));
    const server = serverId ? labels.get(serverId) ?? serverId.slice(7) : undefined;
    const nodes: ExposurePathView["nodes"] = [
      path.severity ? { type: "cve", label: cve, severity: path.severity.toLowerCase() } : { type: "cve", label: cve },
    ];
    if (packageLabel) nodes.push({ type: "package", label: packageLabel });
    if (server) nodes.push({ type: "server", label: server });
    if (agent) nodes.push({ type: "agent", label: agent });

    const overview = (topRisks ?? []).find((risk) => risk.vulnerability_id === cve && (!packageLabel || risk.package === packageLabel));
    rows.push({
      key: `queue::${key}`,
      nodes,
      riskScore: path.composite_risk / 10,
      affectedWorkloads: agent ? [agent] : [],
      affectedServices: server ? [server] : [],
      ...(overview?.impact_category ? { impactCategory: overview.impact_category } : {}),
      ...(overview?.fixed_version ? { fixedVersion: overview.fixed_version } : {}),
      ...(overview ? { ownership: { owner: overview.owner ?? null, sla_due_at: overview.sla_due_at ?? null, sla_due_at_source: overview.sla_due_at_source ?? null } } : {}),
      href: buildSecurityGraphHref({ nodeId: path.source, cve, findingId: path.finding_ids?.[0], ...(agentId ? { agentName: agentId.slice(6) } : {}) }),
    });
    if (rows.length >= limit) break;
  }
  return rows;
}
