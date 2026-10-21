import { describe, expect, it } from "vitest";

import type { UnifiedGraphResponse } from "@/lib/api-types";
import { queueTopRisks } from "@/lib/overview-queue-risks";

const node = (id: string, label: string, severity = "") => ({ id, label, entity_type: id.split(":")[0], severity, attributes: {} });
const path = (source: string, server: string, pkg: string, cve: string, composite_risk: number, severity: string) => ({
  source, target: `vuln:${cve}`, hops: [source, server, pkg, `vuln:${cve}`], edges: [], composite_risk, severity, summary: "",
  credential_exposure: [], tool_exposure: [], vuln_ids: [cve], finding_ids: [`f-${cve}`],
});

const graph = {
  nodes: [
    node("agent:data-pipeline", "Data Pipeline"), node("agent:care-gap-outreach-09", "care-gap-outreach-09"), node("agent:langchain-service", "LangChain Service"),
    node("server:etl-server", "etl-server"), node("server:llm", "llm-orchestrator-server"), node("server:img", "img"),
    node("pkg:pypi:pillow@9.0.0", "pillow@9.0.0"), node("pkg:pypi:pillow@9.0.0:image:e802", "pillow@9.0.0"), node("pkg:pypi:langchain@0.0.150", "langchain@0.0.150"),
  ],
  edges: [],
  attack_paths: [
    path("agent:data-pipeline", "server:etl-server", "pkg:pypi:pillow@9.0.0", "CVE-2023-4863", 90.6, "high"),
    path("agent:care-gap-outreach-09", "server:img", "pkg:pypi:pillow@9.0.0:image:e802", "CVE-2023-4863", 86.6, "high"),
    path("agent:langchain-service", "server:llm", "pkg:pypi:langchain@0.0.150", "CVE-2023-36258", 99, "critical"),
  ],
  pagination: { total: 3417, offset: 0, limit: 50, has_more: true },
} as unknown as UnifiedGraphResponse;

describe("overview top risks from the investigation queue", () => {
  it("keeps the server's queue order instead of re-sorting by score", () => {
    const risks = queueTopRisks(graph, []);
    expect(risks.map((risk) => risk.nodes[0]!.label)).toEqual(["CVE-2023-4863", "CVE-2023-36258"]);
  });

  it("collapses the same advisory on the same package version to its top-ranked path", () => {
    const [first] = queueTopRisks(graph, []);
    expect(first!.affectedWorkloads).toEqual(["Data Pipeline"]);
    expect(first!.nodes).toContainEqual({ type: "server", label: "etl-server" });
  });

  it("deep-links each risk to its own path in Investigation", () => {
    const [first, second] = queueTopRisks(graph, []);
    const href = new URL(first!.href, "http://x");
    expect(href.pathname).toBe("/security-graph");
    expect(href.searchParams.get("lens")).toBe("attack-path");
    expect(href.searchParams.get("node")).toBe("agent:data-pipeline");
    expect(href.searchParams.get("cve")).toBe("CVE-2023-4863");
    expect(href.searchParams.get("finding")).toBe("f-CVE-2023-4863");
    expect(new URL(second!.href, "http://x").searchParams.get("node")).toBe("agent:langchain-service");
  });

  it("carries owner and SLA from the matching overview risk", () => {
    const [first] = queueTopRisks(graph, [{ vulnerability_id: "CVE-2023-4863", package: "pillow@9.0.0", severity: "high", risk_score: 9.5, is_kev: true, cvss_score: null, epss_score: null, affected_agents: [], owner: "Platform Data", sla_due_at: "2026-10-27T00:00:00Z" }]);
    expect(first!.ownership).toMatchObject({ owner: "Platform Data", sla_due_at: "2026-10-27T00:00:00Z" });
  });

  it("returns nothing for an empty queue so the caller can fall back", () => {
    expect(queueTopRisks({ ...graph, attack_paths: [] }, [])).toEqual([]);
  });
});
