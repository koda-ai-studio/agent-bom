import { describe, expect, it } from "vitest";

import { buildArchitectureModel, COLLAPSE_AFTER } from "@/lib/agent-architecture-model";
import { agentByLabel, crewHarness, supervisorHarness, toolTeamHarness, wideCrew } from "./fixtures/agent-architecture-fixture";

const none = new Set<string>();

describe("agent architecture model: layered", () => {
  it("draws every agent once with its layer and a parent edge per declared parent", () => {
    const harness = supervisorHarness();
    const model = buildArchitectureModel(harness, { mode: "layered", expanded: none });
    const agents = model.nodes.filter(node => node.kind === "agent");
    expect(agents).toHaveLength(harness.agent_count);
    const builder = agentByLabel(harness, "builder");
    const search = agentByLabel(harness, "search");
    expect(model.nodes.find(node => node.id === builder.id)!.layer).toBe(0);
    expect(model.nodes.find(node => node.id === search.id)!.layer).toBe(3);
    for (const agent of agents.filter(node => node.parentId)) {
      expect(model.edges.some(edge => edge.source === agent.parentId && edge.target === agent.id)).toBe(true);
    }
  });

  it("styles a parent edge with the declared flow kind and falls back to declared containment", () => {
    const harness = supervisorHarness();
    const model = buildArchitectureModel(harness, { mode: "layered", expanded: none });
    const kind = (source: string, target: string) => model.edges.find(edge => edge.source === agentByLabel(harness, source).id && edge.target === agentByLabel(harness, target).id)?.kind;
    expect(kind("builder", "supervisor")).toBe("entry");
    expect(kind("research", "research_builder")).toBe("subgraph");
    expect(kind("research_builder", "search")).toBe("entry");
    expect(kind("builder", "writer")).toBe("contains");
    expect(model.edges.every(edge => edge.provenance === "declared")).toBe(true);
  });

  it("keeps each unresolved route as a labelled stub on the agent that declared it", () => {
    const harness = supervisorHarness();
    const review = agentByLabel(harness, "review");
    for (const mode of ["layered", "flow"] as const) {
      const model = buildArchitectureModel(harness, { mode, expanded: none });
      const stubs = model.nodes.filter(node => node.kind === "stub");
      expect(stubs).toHaveLength(1);
      expect(stubs[0]!.label).toBe("1 unresolved route");
      expect(stubs[0]!.unresolved).toEqual(harness.unresolved_routes);
      expect(model.edges.find(edge => edge.target === stubs[0]!.id)).toMatchObject({ source: review.id, kind: "unresolved" });
    }
  });

  it("puts finding badges on the affected agent with the count the API recorded", () => {
    const harness = toolTeamHarness();
    const model = buildArchitectureModel(harness, { mode: "layered", expanded: none });
    const triage = agentByLabel(harness, "triage_agent", "subgraph");
    const node = model.nodes.find(item => item.id === triage.id)!;
    expect(node.findings).toBe(2);
    expect(node.findingSeverity).toBe("high");
    expect(model.nodes.reduce((sum, item) => sum + (item.kind === "agent" ? item.findings : 0), 0)).toBe(harness.security.findings);
  });

  it("collapses a large sibling group into one expandable node that keeps the findings", () => {
    const harness = wideCrew(COLLAPSE_AFTER + 4);
    const collapsed = buildArchitectureModel(harness, { mode: "layered", expanded: none });
    const group = collapsed.nodes.find(node => node.kind === "group")!;
    const visible = collapsed.nodes.filter(node => node.kind === "agent" && node.layer === 1);
    expect(visible.length + group.memberIds!.length).toBe(COLLAPSE_AFTER + 4);
    expect(group.label).toBe(`${group.memberIds!.length} more agents`);
    // The agent with findings stays visible; collapsing never hides risk.
    expect(visible.some(node => node.findings === 3)).toBe(true);
    const expanded = buildArchitectureModel(harness, { mode: "layered", expanded: new Set([group.id]) });
    expect(expanded.nodes.some(node => node.kind === "group")).toBe(false);
    expect(expanded.nodes.filter(node => node.kind === "agent")).toHaveLength(COLLAPSE_AFTER + 5);
  });

  it("does not collapse a group at the threshold", () => {
    const model = buildArchitectureModel(wideCrew(COLLAPSE_AFTER), { mode: "layered", expanded: none });
    expect(model.nodes.some(node => node.kind === "group")).toBe(false);
  });
});

describe("agent architecture model: flow", () => {
  it("starts at the harness, ends at finish terminals and never draws a backward edge", () => {
    const harness = supervisorHarness();
    const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
    const builder = agentByLabel(harness, "builder");
    const research = agentByLabel(harness, "research");
    const supervisor = agentByLabel(harness, "supervisor");
    const terminals = model.nodes.filter(node => node.kind === "terminal");
    expect(terminals.map(node => node.label).sort()).toEqual(["End", "End of research_builder"]);
    expect(model.edges.filter(edge => edge.kind === "finish").every(edge => terminals.some(node => node.id === edge.target))).toBe(true);
    expect(model.edges.some(edge => edge.target === builder.id)).toBe(false);
    // research hands back to supervisor: a return marker on research, not a line back.
    expect(model.edges.some(edge => edge.source === research.id && edge.target === supervisor.id)).toBe(false);
    expect(model.nodes.find(node => node.id === research.id)!.returnsTo).toEqual([{ id: supervisor.id, label: "supervisor", kind: "sequential" }]);
  });

  it("keeps every declared edge: drawn, a return marker or a peer marker", () => {
    for (const harness of [supervisorHarness(), toolTeamHarness(), crewHarness()]) {
      const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
      const drawn = model.edges.flatMap(edge => edge.declared).length;
      const returns = model.nodes.reduce((sum, node) => sum + node.returnsTo.length, 0);
      const peers = model.nodes.reduce((sum, node) => sum + node.peers.length, 0) / 2;
      expect(drawn + returns + peers).toBe(harness.flow_edges.length);
    }
  });

  it("shows a shared server as a peer marker on both members, not a line", () => {
    const harness = crewHarness();
    const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
    expect(model.edges.some(edge => edge.declared.some(declared => declared.kind === "peer"))).toBe(false);
    const reader = model.nodes.find(node => node.label === "Evidence Reader")!;
    const writer = model.nodes.find(node => node.label === "Report Writer")!;
    expect(reader.peers.map(peer => peer.label)).toEqual(["Report Writer"]);
    expect(writer.peers.map(peer => peer.label)).toEqual(["Evidence Reader"]);
  });

  it("redirects edges of collapsed agents to their group without duplicates", () => {
    const harness = wideCrew(COLLAPSE_AFTER + 3);
    const model = buildArchitectureModel(harness, { mode: "flow", expanded: none });
    const group = model.nodes.find(node => node.kind === "group")!;
    const intoGroup = model.edges.filter(edge => edge.target === group.id);
    expect(intoGroup).toHaveLength(1);
    expect(intoGroup[0]!.declared).toHaveLength(group.memberIds!.length);
  });
});
