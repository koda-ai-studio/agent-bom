/**
 * `GET /v1/graph/agent-architecture` answers produced by the backend read path
 * (`read_agent_architecture` over a SQLite graph store) for the repository's
 * `langgraph_supervisor`, `langgraph_tool_team` and `crewai_hierarchical`
 * framework fixtures, paged two harnesses at a time. Three findings were
 * attached with `vulnerable_to` edges, as the API tests do, so the overlay
 * has something to show. Nothing below is hand-written.
 */
import raw from "./agent-architecture.json";

import type { AgentArchitectureResponse, AgentHarness, HarnessAgent } from "@/lib/agent-architecture-types";

type Pages = { first_page: AgentArchitectureResponse; second_page: AgentArchitectureResponse };

export function architecturePages(): Pages {
  return structuredClone(raw) as unknown as Pages;
}

export function supervisorHarness(): AgentHarness {
  return architecturePages().first_page.harnesses.find(harness => harness.layers.flatMap(layer => layer.agents).some(agent => agent.label === "research_builder"))!;
}

export function toolTeamHarness(): AgentHarness {
  return architecturePages().first_page.harnesses.find(harness => harness.layers.flatMap(layer => layer.agents).some(agent => agent.label === "triage_agent"))!;
}

export function crewHarness(): AgentHarness {
  return architecturePages().second_page.harnesses[0]!;
}

export function agentByLabel(harness: AgentHarness, label: string, role?: string): HarnessAgent {
  return harness.layers.flatMap(layer => layer.agents).find(agent => agent.label === label && (!role || agent.role === role))!;
}

/** A crew whose single layer holds `count` members, for collapse tests. */
export function wideCrew(count: number): AgentHarness {
  const crew = crewHarness();
  const template = crew.layers[1]!.agents[0]!;
  const agents = Array.from({ length: count }, (_, index) => ({
    ...structuredClone(template),
    id: `member-${String(index).padStart(2, "0")}`,
    label: `Member ${String(index).padStart(2, "0")}`,
    security: { ...template.security, findings: index === count - 1 ? 3 : 0, max_finding_severity: index === count - 1 ? "critical" : "" },
  }));
  return {
    ...crew,
    agent_count: count + 1,
    layers: [crew.layers[0]!, { layer: 1, agents }],
    flow_edges: agents.map(agent => ({ ...crew.flow_edges.find(edge => edge.kind === "member")!, target: agent.id })),
    security: { ...crew.security, agents_with_findings: 1, findings: 3, max_severity: "critical" },
  };
}
