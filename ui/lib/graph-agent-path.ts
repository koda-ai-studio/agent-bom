import { MarkerType, type Edge, type Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import type { AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { layoutAttackPathGraph } from "@/lib/attack-path-graph-layout";
import { graphEdgeEvidence } from "@/lib/graph-edge-evidence";
import { internetExposure, INTERNET_ANCHOR_ID, withInternetAnchor } from "@/lib/graph-internet-context";

type Flow = { nodes: Node<LineageNodeData>[]; edges: Edge[] };
const SERVER = new Set(["server", "mcp_server"]);

/** A reading projection of recorded connections. Inverse hosting retains its original receipt;
 * Internet and finding groups are display context and never enter the persisted graph. */
export function agentPathGraph(graph: UnifiedGraphData, flow: Flow, root: string, inspect: (id: string, label: string) => void, entry: "exposure" | "identity" = "exposure", selectIdentity?: () => void): Flow {
  const records = new Map(graph.nodes.map(node => [node.id, node]));
  const servers = new Set(graph.edges.filter(edge => edge.source === root && edge.relationship === "uses" && SERVER.has(records.get(edge.target)?.entity_type ?? "")).map(edge => edge.target));
  const peers = new Map<string, string[]>();
  for (const node of graph.nodes) {
    if (node.id === root || node.entity_type !== "agent") continue;
    const incident = graph.edges.filter(edge => edge.source === node.id || edge.target === node.id);
    if (incident.length && incident.every(edge => edge.source === node.id && edge.relationship === "uses" && servers.has(edge.target))) {
      peers.set(node.id, incident.map(edge => edge.target));
    }
  }
  const access = graph.edges.find(edge => edge.target === root && edge.relationship === "can_access" && records.get(edge.source)?.entity_type === "role");
  const assumption = graph.edges.find(edge => edge.target === access?.source && edge.relationship === "assumes");
  const identity = new Set([access?.source, assumption?.source].filter((id): id is string => !!id));
  const hosted = new Set(graph.edges.filter(edge => edge.source === root && edge.relationship === "hosted_on").map(edge => edge.target));
  let nodes: Node<LineageNodeData>[] = flow.nodes.filter(node => !peers.has(node.id) && !node.data.displayOnly && !(entry === "exposure" ? identity.has(node.id) : hosted.has(node.id))).map(node => ({ ...node,
    data: { ...node.data, captionAbove: false, scopePeers: [...peers].filter(([, targets]) => targets.includes(node.id)).map(([id]) => ({ id, label: records.get(id)!.label, inspect: () => inspect(id, records.get(id)!.label) })) },
  }));
  const ids = new Set(nodes.map(node => node.id));
  let edges: Edge[] = flow.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target) && !edge.data?.displayOnly).map(edge => {
    const record = graph.edges.find(record => record.id === edge.id)!;
    const evidence = graphEdgeEvidence(record.evidence ?? {});
    // Same compute-container host step as graph.attack_path_fusion.traversal_steps.
    // This inverse caption describes hosting, never a new permission grant.
    const inverse = record.relationship === "hosted_on" && records.get(record.target)?.entity_type === "container";
    return { ...edge, source: inverse ? record.target : record.source, target: inverse ? record.source : record.target,
      sourceHandle: null, targetHandle: null, ...(inverse ? { label: "Hosts", ariaLabel: `${records.get(record.target)?.label} hosts ${records.get(record.source)?.label}; inverse of recorded hosted_on relationship` } : {}),
      style: { ...edge.style, strokeDasharray: evidence.mode === "inferred" ? "6 3" : evidence.mode === "unknown" ? "1.5 5" : undefined },
      data: { ...edge.data, originalSource: record.source, originalTarget: record.target,
        ...(inverse ? { relationshipLabel: "Hosts", inverseRecordedRelationship: true,
          hoverDescription: `Hosts · ${evidence.label}. Reading the recorded hosted_on relationship in reverse; original endpoints are retained in relationship evidence.` } : {}),
        evidenceMode: evidence.mode, directOverview: true, quietLabel: record.relationship !== "can_access", labelVisibility: record.relationship === "can_access" ? "show" : "auto", directionEmphasis: true },
    };
  });
  const contextual = entry === "exposure" ? withInternetAnchor(nodes, edges) : { nodes, edges };
  nodes = contextual.nodes; edges = contextual.edges.map(edge => edge.data?.displayOnly ? {
    ...edge, style: { ...edge.style, strokeDasharray: undefined },
    // The line discloses an explicit true node attribute, not an inferred permission or runtime receipt.
    data: { ...edge.data, relationshipLabel: "Recorded internet exposure", evidenceMode: "static", traversable: false },
  } : edge);
  const byId = new Map(nodes.map(node => [node.id, node]));
  const exposedHost = edges.find(edge => edge.target === root && edge.data?.inverseRecordedRelationship && internetExposure(byId.get(edge.source)?.data.attributes) === true)?.source;
  const hasImpact = (id: string) => graph.edges.some(edge => edge.source === id && ["provides_tool", "exposes_cred"].includes(edge.relationship));
  const rankedServers = [...servers].sort((a, b) => Number(hasImpact(b)) - Number(hasImpact(a)) || (byId.get(b)?.data.findingAggregate?.issue_count ?? 0) - (byId.get(a)?.data.findingAggregate?.issue_count ?? 0) || a.localeCompare(b));
  const impact = edges.filter(edge => edge.source === rankedServers[0] && ["provides_tool", "exposes_cred"].includes(String(edge.data?.relationship)));
  const tool = impact.find(edge => records.get(edge.target)?.attributes.tool_class === "shell")?.target ?? impact[0]?.target;
  const entryIds = entry === "identity" ? [...(assumption ? [assumption.source] : []), ...(access ? [access.source] : [])] : exposedHost ? [INTERNET_ANCHOR_ID, exposedHost] : internetExposure(byId.get(root)?.data.attributes) === true ? [INTERNET_ANCHOR_ID] : [];
  const primary = [...entryIds, root, ...rankedServers.slice(0, 1), ...(tool ? [tool] : [])];
  const branchLanes = new Map<string, number>();
  for (const edge of impact) if (edge.target !== tool) branchLanes.set(edge.target, 1);
  for (const server of rankedServers.slice(1)) branchLanes.set(server, 1);

  for (const owner of [root, ...rankedServers]) {
    const asset = byId.get(owner)!, aggregate = asset.data.findingAggregate;
    if (!aggregate?.issue_count || !asset.data.onExploreFindings) continue;
    const id = `display:scope-findings:${owner}`;
    const group: Node<LineageNodeData> = { id, type: "findingGroupNode", position: { x: 0, y: 0 }, data: {
      label: `Findings (${aggregate.issue_count})`, nodeType: "misconfiguration", displayOnly: true, displayTargetId: owner,
      description: asset.data.label, findingAggregate: aggregate, readingFindings: { count: aggregate.issue_count, expanded: false, severity: aggregate.worst_severity, toggle: asset.data.onExploreFindings },
    } };
    nodes.push(group);
    edges.push({ id: `${id}:disclosure`, source: owner, target: id, type: "smoothstep",
      data: { displayOnly: true, traversable: false, relationship: "finding_group", relationshipLabel: "Open scope findings", directOverview: true, quietLabel: true, directionEmphasis: false },
    });
    branchLanes.set(id, -1);
  }
  const columns = new Map(primary.map((id, index) => [id, index]));
  for (let pass = 0; pass < nodes.length; pass++) for (const edge of edges) {
    if (columns.has(edge.source) && !columns.has(edge.target)) columns.set(edge.target, columns.get(edge.source)! + 1);
    if (columns.has(edge.target) && !columns.has(edge.source)) columns.set(edge.source, columns.get(edge.target)! - 1);
  }
  for (const node of nodes) if (!columns.has(node.id)) columns.set(node.id, 0);
  const model: AttackPathGraphModel = {
    nodes: nodes.map(node => ({ id: node.id, kind: "entity", role: primary.includes(node.id) ? "path" : "branch", label: node.data.label, typeLabel: "", entityType: node.data.entityType ?? node.data.nodeType, findings: [], markers: [] })),
    edges: edges.map(edge => ({ id: edge.id, source: edge.source, target: edge.target, relationship: String(edge.data?.relationship), relationshipLabel: "", evidence: "inferred", onPath: false, bidirectional: false })),
    pathNodeIds: primary, connectedPathCount: 0, omittedConnectedPaths: 0,
  };
  const layout = layoutAttackPathGraph(model, "LR", columns, { lanes: branchLanes, rankGap: 96 });
  const pathPairs = new Set(primary.slice(1).map((id, index) => `${primary[index]}\0${id}`));
  for (const edge of impact) pathPairs.add(`${edge.source}\0${edge.target}`);
  const exposure = primary[0] === INTERNET_ANCHOR_ID;
  return {
    nodes: nodes.map(node => ({ ...node, position: layout.positions.get(node.id)!, style: { ...node.style, width: 152, "--graph-node-card-width": "152px" },
      data: { ...node.data, scopePorts: true, scopeFindingLabel: false, pathPresentation: true,
        ...(node.id === root && entry === "exposure" && access ? { scopeAdmin: { label: records.get(access.source)!.label, inspect: selectIdentity ?? (() => inspect(access.source, records.get(access.source)!.label)) } } : {}),
        readingFindingsGroup: nodes.some(group => group.type === "findingGroupNode" && group.data.displayTargetId === node.id),
        semanticLayout: true, roomyName: node.id === INTERNET_ANCHOR_ID, internetAnchored: exposure, readingFocus: node.id === root } })),
    edges: edges.map(edge => {
      const privilege = edge.data?.relationship === "can_access";
      const onPath = exposure && pathPairs.has(`${edge.source}\0${edge.target}`);
      const color = privilege ? "var(--graph-edge-risk)" : onPath ? "var(--graph-edge-exposure)" : "var(--graph-edge-structure)";
      const from = layout.positions.get(edge.source)!, to = layout.positions.get(edge.target)!;
      return { ...edge, type: "smoothstep", sourceHandle: to.y < from.y ? "scope-out-0" : to.x < from.x ? "context" : to.y > from.y ? "scope-out-2" : "scope-out-1", targetHandle: to.x < from.x ? "context" : edge.data?.relationship === "finding_group" ? null : privilege ? "scope-in-lower-left" : from.y > to.y ? "scope-in-2" : "scope-in-1",
        ...(edge.data?.relationship === "finding_group" ? {} : { markerEnd: { type: MarkerType.ArrowClosed, color, width: 20, height: 16 } }),
        style: { ...edge.style, opacity: 1, stroke: color, strokeWidth: onPath ? 2.4 : 2 },
        data: { ...edge.data, exposurePath: onPath, directOverview: true, earlyRise: privilege && from.y > to.y, directionEmphasis: edge.data?.relationship !== "finding_group", quietLabel: !privilege, labelVisibility: privilege ? "show" : "auto" },
      };
    }),
  };
}
