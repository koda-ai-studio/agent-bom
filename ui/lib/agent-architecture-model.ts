import type { AgentHarness, HarnessAgent, HarnessFlowEdge, HarnessFlowKind, HarnessRole, HarnessUnresolvedRoute } from "@/lib/agent-architecture-types";

/** Sibling groups larger than this collapse; the agents with findings stay visible. */
export const COLLAPSE_AFTER = 6;
const KEEP_VISIBLE = 4;
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export type ArchitectureMode = "layered" | "flow";
export type ArchitectureNodeKind = "agent" | "group" | "stub" | "terminal";
export type ArchitectureEdgeKind = Exclude<HarnessFlowKind, "peer"> | "contains" | "unresolved";
/** A declared relationship shown on a node instead of as a line. */
export type ArchitectureMarker = { id: string; label: string; kind: HarnessFlowKind };

export type ArchitectureNode = {
  id: string;
  kind: ArchitectureNodeKind;
  label: string;
  subtitle: string;
  layer: number;
  /** Parent in the declared hierarchy ("" for the harness root). */
  parentId: string;
  role: HarnessRole | null;
  entry: boolean;
  agent: HarnessAgent | null;
  /** Findings the agent (or every agent in a group) is `vulnerable_to`, as the API counted them. */
  findings: number;
  findingSeverity: string;
  /** API order, the tie-break for placement. */
  order: number;
  memberIds?: string[];
  unresolved?: HarnessUnresolvedRoute[];
  /** Flow edges back to an earlier step: kept as a marker, never drawn against the reading direction. */
  returnsTo: ArchitectureMarker[];
  /** `shares_server` peers. */
  peers: ArchitectureMarker[];
  /** Declared edges between agents folded into the same group. */
  internal: number;
};

export type ArchitectureEdge = {
  id: string;
  source: string;
  target: string;
  kind: ArchitectureEdgeKind;
  provenance: "declared";
  /** The API's flow edges this line stands for (empty for containment and stubs). */
  declared: HarnessFlowEdge[];
  description: string;
};

export type ArchitectureModel = {
  mode: ArchitectureMode;
  nodes: ArchitectureNode[];
  edges: ArchitectureEdge[];
  rootId: string;
  /** Unresolved routes the API counted but did not list (it lists up to its cap). */
  unlistedUnresolved: number;
};

export const FLOW_KIND_LABEL: Record<ArchitectureEdgeKind | "peer", string> = {
  entry: "Entry",
  sequential: "Sequential step",
  conditional: "Conditional route",
  handoff: "Handoff",
  fan_out: "Fan-out",
  subgraph: "Runs subgraph",
  finish: "Finish",
  member: "Crew or group member",
  peer: "Shares a server",
  contains: "Declared inside",
  unresolved: "Unresolved route",
};

const FRAMEWORK_LABEL: Record<string, string> = { langgraph: "LangGraph", crewai: "CrewAI", autogen: "AutoGen" };
const ROLE_LABEL: Record<HarnessRole, string> = { harness: "Harness", orchestrator: "Orchestrator", subgraph: "Subgraph", sub_agent: "Agent" };

export function frameworkLabel(framework: string): string {
  return FRAMEWORK_LABEL[framework] ?? (framework || "Unknown framework");
}

export function severityRank(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  return index < 0 ? SEVERITY_ORDER.length : index;
}

export function worstSeverity(values: string[]): string {
  return values.filter(value => severityRank(value) < SEVERITY_ORDER.length).sort((a, b) => severityRank(a) - severityRank(b))[0] ?? "";
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

function agentNode(agent: HarnessAgent, harness: AgentHarness, order: number): ArchitectureNode {
  const subtitle = agent.role === "harness" ? `${harness.harness_kind} · ${frameworkLabel(agent.framework || harness.framework)}` : ROLE_LABEL[agent.role];
  return {
    id: agent.id, kind: "agent", label: agent.label, subtitle, layer: agent.layer, parentId: agent.parent_id, role: agent.role,
    entry: agent.entry, agent, findings: agent.security.findings, findingSeverity: agent.security.max_finding_severity,
    order, returnsTo: [], peers: [], internal: 0,
  };
}

/** Large sibling groups keep the riskiest few visible and fold the rest into one expandable node. */
function collapse(agents: HarnessAgent[], expanded: ReadonlySet<string>): { visible: Set<string>; groups: Map<string, HarnessAgent[]> } {
  const siblings = new Map<string, HarnessAgent[]>();
  for (const agent of agents) {
    if (agent.layer === 0) continue;
    const key = `group:${agent.parent_id}:${agent.layer}`;
    siblings.set(key, [...(siblings.get(key) ?? []), agent]);
  }
  const visible = new Set(agents.map(agent => agent.id));
  const groups = new Map<string, HarnessAgent[]>();
  for (const [key, members] of siblings) {
    if (members.length <= COLLAPSE_AFTER || expanded.has(key)) continue;
    const ranked = members.map((agent, index) => ({ agent, index })).sort((a, b) =>
      b.agent.security.findings - a.agent.security.findings
      || Number(b.agent.entry) - Number(a.agent.entry)
      || Number(b.agent.role === "orchestrator") - Number(a.agent.role === "orchestrator")
      || a.index - b.index);
    const folded = ranked.slice(KEEP_VISIBLE).map(item => item.agent);
    for (const agent of folded) visible.delete(agent.id);
    groups.set(key, folded);
  }
  return { visible, groups };
}

function groupNode(id: string, members: HarnessAgent[], order: number): ArchitectureNode {
  const first = members[0]!;
  return {
    id, kind: "group", label: `${members.length} more agents`, subtitle: `Layer ${first.layer} · collapsed`, layer: first.layer,
    parentId: first.parent_id, role: null, entry: false, agent: null, order,
    findings: members.reduce((sum, agent) => sum + agent.security.findings, 0),
    findingSeverity: worstSeverity(members.map(agent => agent.security.max_finding_severity)),
    memberIds: members.map(agent => agent.id), returnsTo: [], peers: [], internal: 0,
  };
}

function describe(edges: HarnessFlowEdge[], kind: ArchitectureEdgeKind): string {
  if (edges.length === 0) return `${FLOW_KIND_LABEL[kind]} · declared`;
  const kinds = [...new Set(edges.map(edge => FLOW_KIND_LABEL[edge.kind]))].join(", ");
  const branches = [...new Set(edges.flatMap(edge => edge.branches))].filter(branch => branch && !branch.startsWith("__"));
  const count = edges.length > 1 ? ` · ${edges.length} declared edges` : " · declared";
  return `${kinds}${branches.length ? ` · branch ${branches.join(", ")}` : ""}${count}`;
}

type Build = { nodes: Map<string, ArchitectureNode>; rep: (id: string) => string | undefined; label: (id: string) => string };

function baseNodes(harness: AgentHarness, expanded: ReadonlySet<string>): Build {
  const agents = harness.layers.flatMap(layer => layer.agents);
  const { visible, groups } = collapse(agents, expanded);
  const nodes = new Map<string, ArchitectureNode>();
  const owner = new Map<string, string>();
  agents.forEach((agent, index) => {
    if (visible.has(agent.id)) { nodes.set(agent.id, agentNode(agent, harness, index)); owner.set(agent.id, agent.id); }
  });
  for (const [id, members] of groups) {
    nodes.set(id, groupNode(id, members, Math.max(...members.map(agent => agents.indexOf(agent)))));
    for (const agent of members) owner.set(agent.id, id);
  }
  const labels = new Map(agents.map(agent => [agent.id, agent.label]));
  return { nodes, rep: id => owner.get(id), label: id => labels.get(id) ?? id };
}

function addStubs(harness: AgentHarness, build: Build, edges: ArchitectureEdge[]): void {
  const byAgent = new Map<string, HarnessUnresolvedRoute[]>();
  for (const route of harness.unresolved_routes) {
    const rep = build.rep(route.agent_id);
    if (rep) byAgent.set(rep, [...(byAgent.get(rep) ?? []), route]);
  }
  for (const [rep, routes] of byAgent) {
    const parent = build.nodes.get(rep)!;
    const id = `unresolved:${rep}`;
    build.nodes.set(id, {
      id, kind: "stub", label: plural(routes.length, "unresolved route"), subtitle: "Targets decided at runtime",
      layer: parent.layer + 1, parentId: rep, role: null, entry: false, agent: null, findings: 0, findingSeverity: "",
      order: parent.order + 0.5, unresolved: routes, returnsTo: [], peers: [], internal: 0,
    });
    edges.push({ id: `${rep}->${id}`, source: rep, target: id, kind: "unresolved", provenance: "declared", declared: [], description: `${plural(routes.length, "route")} the scan could not resolve statically` });
  }
}

function addPeers(harness: AgentHarness, build: Build): HarnessFlowEdge[] {
  const rest: HarnessFlowEdge[] = [];
  for (const edge of harness.flow_edges) {
    const source = build.rep(edge.source), target = build.rep(edge.target);
    if (!source || !target) continue;
    if (source === target) { build.nodes.get(source)!.internal += 1; continue; }
    if (edge.kind !== "peer") { rest.push(edge); continue; }
    build.nodes.get(source)!.peers.push({ id: target, label: build.nodes.get(target)!.label, kind: "peer" });
    build.nodes.get(target)!.peers.push({ id: source, label: build.nodes.get(source)!.label, kind: "peer" });
  }
  return rest;
}

function layeredEdges(harness: AgentHarness, build: Build, edges: ArchitectureEdge[]): void {
  const declaredBetween = (parent: string, child: string) =>
    harness.flow_edges.filter(edge => edge.source === parent && edge.target === child && edge.kind !== "finish" && edge.kind !== "peer");
  for (const node of [...build.nodes.values()]) {
    if (node.kind === "stub" || !node.parentId) continue;
    const parent = build.rep(node.parentId);
    if (!parent || parent === node.id) continue;
    const children = node.memberIds ?? [node.id];
    const declared = children.flatMap(child => declaredBetween(node.parentId, child));
    const kinds = new Set(declared.map(edge => edge.kind));
    const covered = new Set(declared.map(edge => edge.target));
    const kind: ArchitectureEdgeKind = kinds.size === 1 && covered.size === children.length ? [...kinds][0] as ArchitectureEdgeKind : "contains";
    edges.push({ id: `${parent}->${node.id}`, source: parent, target: node.id, kind, provenance: "declared", declared, description: describe(declared, kind) });
  }
}

/** Depth-first from the harness root: an edge into a node still on the stack runs against the flow. */
function backEdges(nodes: string[], edges: { source: string; target: string }[], rootId: string): Set<number> {
  const out = new Map<string, number[]>();
  edges.forEach((edge, index) => out.set(edge.source, [...(out.get(edge.source) ?? []), index]));
  const state = new Map<string, "open" | "done">();
  const back = new Set<number>();
  const visit = (start: string) => {
    const stack: { id: string; next: number }[] = [{ id: start, next: 0 }];
    state.set(start, "open");
    while (stack.length) {
      const top = stack[stack.length - 1]!;
      const outgoing = out.get(top.id) ?? [];
      if (top.next >= outgoing.length) { state.set(top.id, "done"); stack.pop(); continue; }
      const index = outgoing[top.next++]!;
      const target = edges[index]!.target;
      if (state.get(target) === "open") back.add(index);
      else if (!state.has(target)) { state.set(target, "open"); stack.push({ id: target, next: 0 }); }
    }
  };
  for (const id of [rootId, ...nodes]) if (!state.has(id)) visit(id);
  return back;
}

function flowEdges(harness: AgentHarness, build: Build, flow: HarnessFlowEdge[], edges: ArchitectureEdge[]): void {
  const mapped = flow.map(edge => {
    const source = build.rep(edge.source)!;
    let target = build.rep(edge.target)!;
    if (edge.kind === "finish") {
      target = `finish:${target}`;
      if (!build.nodes.has(target)) {
        const owner = build.nodes.get(build.rep(edge.target)!)!;
        build.nodes.set(target, {
          id: target, kind: "terminal", label: owner.id === harness.harness_id ? "End" : `End of ${owner.label}`, subtitle: "Finish",
          layer: owner.layer, parentId: owner.id, role: null, entry: false, agent: null, findings: 0, findingSeverity: "",
          order: owner.order, returnsTo: [], peers: [], internal: 0,
        });
      }
    }
    return { edge, source, target };
  });
  const back = backEdges([...build.nodes.keys()], mapped, harness.harness_id);
  const merged = new Map<string, ArchitectureEdge>();
  mapped.forEach(({ edge, source, target }, index) => {
    if (back.has(index)) {
      const node = build.nodes.get(source)!;
      if (!node.returnsTo.some(item => item.id === target && item.kind === edge.kind)) node.returnsTo.push({ id: target, label: build.nodes.get(target)!.label, kind: edge.kind });
      return;
    }
    const id = `${source}->${target}`;
    const existing = merged.get(id);
    if (existing) existing.declared.push(edge);
    else merged.set(id, { id, source, target, kind: edge.kind as ArchitectureEdgeKind, provenance: "declared", declared: [edge], description: "" });
  });
  for (const edge of merged.values()) edges.push({ ...edge, description: describe(edge.declared, edge.kind) });
}

/**
 * One harness as a drawable model. Layered: the declared hierarchy, one line
 * per parent. Flow: the declared pipeline from the harness to its finish
 * points. Both keep unresolved routes as stubs and collapse large sibling
 * groups. Nothing is drawn that the API did not record.
 */
export function buildArchitectureModel(harness: AgentHarness, options: { mode: ArchitectureMode; expanded: ReadonlySet<string> }): ArchitectureModel {
  const build = baseNodes(harness, options.expanded);
  const edges: ArchitectureEdge[] = [];
  const flow = addPeers(harness, build);
  if (options.mode === "layered") layeredEdges(harness, build, edges);
  else flowEdges(harness, build, flow, edges);
  addStubs(harness, build, edges);
  return {
    mode: options.mode,
    nodes: [...build.nodes.values()],
    edges,
    rootId: harness.harness_id,
    unlistedUnresolved: Math.max(0, harness.unresolved_route_count - harness.unresolved_routes.length),
  };
}
