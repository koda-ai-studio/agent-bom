import { COMPACT_NODE_WIDTH } from "@/lib/graph-compact-layout";
import { describe, expect, it } from "vitest";
import { FLOW_READABLE_NODE_LIMIT, flowAvailability, flowPinnedIds, investigationFlow, type InvestigationFlow } from "@/lib/graph-investigation-flow";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";
import { byLabel, k8sFlowGraph, type K8sScenario } from "./k8s-projection-fixture";

const run = (scenario: K8sScenario, flow: InvestigationFlow, narrow = false) => {
  const { nodes, edges } = k8sFlowGraph(scenario);
  return investigationFlow(nodes, edges, flow, narrow);
};
const at = (result: ReturnType<typeof run>, label: string) => byLabel(result.nodes, label).position;

describe("exposure on real Kubernetes projection output", () => {
  it("uses backend semantic columns without inventing a Kubernetes attack path", () => {
    const result = run("tokenMounted", "exposure");
    expect(result.applied).toBe(true);
    expect(result.primaryPath).toEqual([]);
    expect(result.nodes.every(node => typeof node.data.semanticLayer === "string")).toBe(true);
    expect(at(result, "Role: web-sa-reader").x).toBeGreaterThan(at(result, "pod: prod/web-7c9f-1").x);
    // A controller and the pod it owns share a backend layer; the pod takes the next rank.
    expect(at(result, "replicaset: prod/web-7c9f").x).toBeLessThan(at(result, "pod: prod/web-7c9f-1").x);
  });

  it("never invents or reverses an edge to do so", () => {
    const { edges } = k8sFlowGraph("tokenMounted");
    const result = run("tokenMounted", "exposure");
    expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(edges.map(e => [e.id, e.source, e.target]));
  });

  it("does not read an unmounted token as a flow step, but keeps the identity in context with the reason", () => {
    const result = run("snapshot", "exposure");
    const account = byLabel(result.nodes, "service account: prod/web-sa");
    expect(result.primaryPath).toEqual([]);
    expect(result.nodes.some(node => node.data.label === "secret: prod/db-pass")).toBe(true);
    expect(result.primaryPath).not.toContain(account.id);
    const hop = result.edges.find(e => e.target === account.id && e.data?.relationship === "assumes")!;
    expect(hop.data?.flowStep).toBe(false);
    expect(hop.label).toBe("Token not mounted");
    expect(hop.data?.quietLabel).toBe(false);
    expect(account.data.flowNote).toBe("token not mounted");
    expect(byLabel(run("tokenMounted", "exposure").nodes, "service account: prod/web-sa").data.flowNote).toBeUndefined();
  });

  it("keeps a mounted token relationship without promoting it to an assessed path", () => {
    const result = run("tokenMounted", "exposure");
    const hop = result.edges.find(e => e.data?.relationship === "assumes")!;
    expect(hop.data?.flowStep).toBe(false);
    expect(result.primaryPath).toEqual([]);
    expect(hop.label).toBeUndefined();
  });

  it("keeps same-layer Service nodes distinct without assigning topology-derived columns", () => {
    const result = run("twoServices", "exposure");
    const one = byLabel(result.nodes, "service: prod/web"), two = byLabel(result.nodes, "service: prod/web-public");
    expect(one.data.semanticLayer).toBeDefined();
    expect(two.data.semanticLayer).toBe(one.data.semanticLayer);
    expect(one.position.x).toBe(two.position.x);
    expect(one.position.y).not.toBe(two.position.y);
    expect(result.edges.some(edge => edge.source === one.id)).toBe(true);
    expect(result.edges.some(edge => edge.source === two.id)).toBe(true);
  });
});

describe("internal Services", () => {
  it("does not offer exposure when only ClusterIP Services exist, and automatic says what it chose", () => {
    const { nodes, edges } = k8sFlowGraph("internalOnly");
    expect(flowAvailability(nodes, edges).exposure.available).toBe(false);
    expect(flowAvailability(nodes, edges).exposure.reason).toMatch(/no ingress/i);
    expect(run("internalOnly", "auto").scenario).toBe("identity");
  });

  it("never starts exposure at a ClusterIP Service but keeps it on the map and calls it internal", () => {
    const result = run("snapshot", "exposure");
    const internal = byLabel(result.nodes, "service: prod/internal-only");
    expect(result.nodes.some(node => node.id === internal.id)).toBe(true);
    expect(result.primaryPath).not.toContain(internal.id);
    expect(result.primaryPath).toEqual([]);
    const route = result.edges.find(e => e.source === internal.id)!;
    expect(route.label).toBe("Routes in cluster to");
    expect(route.data?.relationship).toBe("exposed_to");
  });

  it("preserves a recorded Ingress to ClusterIP link without inferring a ranked path", () => {
    const result = run("snapshot", "exposure");
    const ingress = byLabel(result.nodes, "ingress: prod/web"), service = byLabel(result.nodes, "service: prod/web");
    expect(result.edges.find(edge => edge.source === ingress.id && edge.target === service.id)?.data?.relationship).toBe("exposed_to");
    expect(result.primaryPath).toEqual([]);
  });

  it("treats a LoadBalancer as an entry", () => {
    const { nodes, edges } = k8sFlowGraph("twoServices");
    expect(flowAvailability(nodes, edges).exposure.available).toBe(true);
    const lb = byLabel(run("twoServices", "exposure").nodes, "service: prod/web-public");
    expect(lb.data.semanticLayer).toBeDefined();
    expect(run("twoServices", "exposure").primaryPath).toEqual([]);
  });
});

describe("whether a flow applies", () => {
  it("bounds a large Kubernetes estate to a readable preview while retaining every loaded node", () => {
    const { nodes, edges } = k8sFlowGraph("clusterEstate");
    expect(nodes.length).toBeGreaterThan(FLOW_READABLE_NODE_LIMIT);
    expect(flowPinnedIds(nodes, edges, "exposure")).toEqual([]);
    const preview = graphConnectionPreview(nodes, edges)!;
    expect(preview.nodes.length).toBeGreaterThanOrEqual(6);
    expect(preview.nodes.length).toBeLessThanOrEqual(12);
    expect(preview.allNodes).toHaveLength(nodes.length);
    const result = investigationFlow(preview.nodes, preview.edges, "auto");
    expect(result.applied).toBe(true);
    expect(result.primaryPath).toEqual([]);
    expect(new Set(result.nodes.map(node => `${node.position.x}:${node.position.y}`)).size).toBe(result.nodes.length);
  });

  it("declines beyond the readable limit, says so, and adds no display objects", () => {
    const { nodes, edges } = k8sFlowGraph("clusterEstate");
    const assessed = nodes.map(n => n.data.attributes?.kubernetes_kind === "Ingress" ? { ...n, data: { ...n.data, attributes: { ...n.data.attributes, resource_id: n.id,
      network_reachability_assessment: { complete: true, decision: "allow", source_scope: "internet", target_id: n.id, evidence_refs: ["receipt"] } } } } : n);
    const many = assessed;
    expect(many.length).toBeGreaterThan(FLOW_READABLE_NODE_LIMIT);
    const result = investigationFlow(many, edges, "exposure");
    expect(result.applied).toBe(false);
    expect(result.reason).toMatch(/up to \d+ nodes/);
    expect(result.nodes).toBe(many);
    expect(result.nodes.some(n => n.data.displayOnly)).toBe(false);
  });

  it("reports nothing to show for a flow whose subject is absent", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const availability = flowAvailability(nodes, edges);
    expect(availability.vulnerability).toMatchObject({ available: false, reason: expect.stringMatching(/no findings/i) });
    const result = investigationFlow(nodes, edges, "vulnerability");
    expect(result.applied).toBe(false);
    expect(result.nodes).toBe(nodes);
    expect(result.reason).toMatch(/no findings/i);
  });

  it("applies semantic layout consistently to an image-only automatic view", () => {
    const pkg = k8sFlowGraph("snapshot").nodes.filter(n => n.data.label.startsWith("image:"));
    const result = investigationFlow(pkg, [], "auto");
    expect(result.applied).toBe(true);
    expect(result.nodes.map(node => node.id)).toEqual(pkg.map(node => node.id));
    expect(result.nodes.every(node => node.data.semanticLayout)).toBe(true);
  });

  it("leaves a view Automatic will not rearrange on its existing canvas page", () => {
    const pkg = k8sFlowGraph("snapshot").nodes.filter(n => n.data.label.startsWith("image:"));
    expect(flowPinnedIds(pkg, [], "auto")).toEqual([]);
  });

  it("marks applied nodes as full cards so the zoom band cannot turn them into pills", () => {
    const result = run("snapshot", "exposure");
    expect(result.nodes.every(n => n.data.renderBand === "detail" && n.data.evidenceFlow)).toBe(true);
  });
});

describe("the reading of each flow", () => {
  it("preserves the same semantic geometry for each investigation subject without node overlaps", () => {
    const results = (["exposure", "identity", "inventory", "vulnerability"] as const).map(flow => run("withFindings", flow));
    for (const result of results) {
      expect(result.applied).toBe(true);
      expect(new Set(result.nodes.map(node => `${node.position.x}:${node.position.y}`)).size).toBe(result.nodes.length);
      expect(result.nodes.map(node => node.position)).toEqual(results[0]!.nodes.map(node => node.position));
    }
  });

  it("branches package and finding context right of their recorded owners", () => {
    const result = run("withFindings", "vulnerability");
    const image = byLabel(result.nodes, "image: nginx:1.19.0"), pkg = byLabel(result.nodes, "openssl@1.1.1k"), finding = byLabel(result.nodes, "CVE-2021-3711");
    expect(pkg.data.semanticOwner).toBe(image.id);
    expect(finding.data.semanticOwner).toBe(pkg.id);
    expect(pkg.position.x).toBeGreaterThan(image.position.x);
    expect(finding.position.x).toBeGreaterThan(pkg.position.x);
  });

  it("does not manufacture a primary path when the snapshot has none", () => {
    for (const flow of ["exposure", "identity", "inventory"] as const) {
      const result = run("snapshot", flow);
      expect(result.primaryPath).toEqual([]);
      expect(result.edges.every(edge => !edge.data?.pathEmphasis)).toBe(true);
    }
  });

  it("opens a bounded connected window over the twenty-node map", () => {
    const result = run("snapshot", "exposure");
    const preview = graphConnectionPreview(result.nodes, result.edges)!;
    expect(preview.nodes.length).toBeGreaterThanOrEqual(6);
    expect(preview.nodes.length).toBeLessThanOrEqual(12);
    expect(preview.allNodes).toHaveLength(result.nodes.length);
    const ids = new Set(preview.nodes.map(node => node.id));
    expect(preview.edges.every(edge => ids.has(edge.source) && ids.has(edge.target))).toBe(true);
  });

  it("does not let one long label change the spacing of the whole map", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const long = nodes.map(n => n.data.label === "pod: prod/web-7c9f-1" ? { ...n, data: { ...n.data, label: "pod: production-payments/web-frontend-7c9f4d-x2k9p" } } : n);
    const positions = (input: typeof nodes) => new Map(investigationFlow(input, edges, "exposure").nodes.map(n => [n.id, n.position]));
    expect(positions(long)).toEqual(positions(nodes));
  });

  it("retains the controller-to-pod direction within their shared backend layer", () => {
    const result = run("tokenMounted", "exposure");
    const controller = byLabel(result.nodes, "replicaset: prod/web-7c9f"), pod = byLabel(result.nodes, "pod: prod/web-7c9f-1");
    expect(controller.data.semanticLayer).toBeDefined();
    expect(controller.position.x).toBeLessThan(pod.position.x);
    const owner = result.edges.find(edge => edge.source === controller.id && edge.target === pod.id)!;
    expect(owner).toBeDefined();
    expect(owner.sourceHandle).toBeNull();
    expect(owner.targetHandle).toBeNull();
  });

  it("treats drift incidents like other findings when one asset owns them", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const incident = { ...nodes[0]!, id: "drift-1", data: { label: "drift", nodeType: "driftIncident" as const, semanticLayer: "finding" } };
    const link = { id: "d", source: nodes[0]!.id, target: "drift-1", data: { relationship: "exhibits_drift" } };
    const result = investigationFlow([...nodes, incident], [...edges, link], "exposure");
    expect(result.nodes.find(n => n.id === "drift-1")?.data.readingOwner).toBe(nodes[0]!.id);
  });
});

describe("Internet boundary display context", () => {
  const assessed = () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const ingress = byLabel(nodes, "ingress: prod/web");
    return { edges, ingress, nodes: nodes.map(n => n.id === ingress.id ? { ...n, data: { ...n.data, attributes: { ...n.data.attributes, resource_id: "ing-1", risk_context: { internet_exposed: true },
      network_reachability_assessment: { complete: true, decision: "allow", source_scope: "internet", target_id: "ing-1", evidence_refs: ["receipt-1"] } } } } : n) };
  };

  it("draws the unproven link no stronger than a recorded non-traversable one", () => {
    const { nodes, edges, ingress } = assessed();
    const result = investigationFlow(nodes, edges, "exposure");
    const link = result.edges.find(e => e.data?.displayOnly)!;
    expect(link.target).toBe(ingress.id);
    expect(link.style?.strokeDasharray).toBeTruthy();
    expect(Number(link.style?.strokeWidth)).toBeLessThanOrEqual(1.2);
  });

  it("names display objects for assistive technology by their target, never by display id", () => {
    const { nodes, edges } = assessed();
    const result = investigationFlow(nodes, edges, "exposure");
    const boundary = result.nodes.find(n => n.data.displayOnly)!;
    const link = result.edges.find(e => e.data?.displayOnly)!;
    expect(boundary.ariaLabel).toBe("Internet, recorded exposure context");
    expect(link.ariaLabel).toBe("Recorded internet exposure for ingress: prod/web; display context, not a traversable relationship");
  });
});

describe("a large map with no specific flow", () => {
  it("keeps a large map connected without inferring an attack path from severity", () => {
    const { nodes, edges } = k8sFlowGraph("demoInventory");
    const result = investigationFlow(nodes, edges, "auto");
    expect(nodes.length).toBeGreaterThan(24);
    expect(result.applied).toBe(true);
    expect(result.primaryPath).toEqual([]);
    expect(new Set(result.nodes.map(node => `${node.position.x}:${node.position.y}`)).size).toBe(result.nodes.length);
    expect(result.edges.map(edge => [edge.source, edge.target])).toEqual(edges.map(edge => [edge.source, edge.target]));
  });

  it("keeps an operator's zoom band on a map past one readable page", () => {
    const { nodes, edges } = k8sFlowGraph("projectScan");
    const banded = nodes.map(n => ({ ...n, data: { ...n.data, renderBand: "summary" as const } }));
    const result = investigationFlow(banded, edges, "auto");
    expect(result.applied).toBe(true);
    expect(banded.length).toBeGreaterThan(24);
    expect(result.nodes.every(n => n.data.renderBand === "summary" && n.style?.width === COMPACT_NODE_WIDTH)).toBe(true);
  });

  it("uses the same semantic layout for small maps", () => {
    const { nodes, edges } = k8sFlowGraph("projectScan");
    const few = nodes.slice(0, 20);
    const result = investigationFlow(few, edges, "auto");
    expect(result.applied).toBe(true);
    expect(result.nodes.map(node => node.id)).toEqual(few.map(node => node.id));
    expect(result.nodes.every(node => node.data.semanticLayout)).toBe(true);
  });
});
