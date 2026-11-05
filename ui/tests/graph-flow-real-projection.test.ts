import { describe, expect, it } from "vitest";
import { FLOW_READABLE_NODE_LIMIT, flowAvailability, flowPinnedIds, investigationFlow, type InvestigationFlow } from "@/lib/graph-investigation-flow";
import { boundedGraphElements } from "@/lib/graph-neighbor-expansion";
import { byLabel, k8sFlowGraph, type K8sScenario } from "./k8s-projection-fixture";

const run = (scenario: K8sScenario, flow: InvestigationFlow, narrow = false) => {
  const { nodes, edges } = k8sFlowGraph(scenario);
  return investigationFlow(nodes, edges, flow, narrow);
};
const at = (result: ReturnType<typeof run>, label: string) => byLabel(result.nodes, label).position;
const CHAIN = ["ingress: prod/web", "service: prod/web", "pod: prod/web-7c9f-1", "replicaset: prod/web-7c9f", "deployment: prod/web", "service account: prod/web-sa", "Role: web-sa-reader"];

describe("exposure on real Kubernetes projection output", () => {
  it("runs endpoint, workload, owning controllers, identity and role in reading order on one row", () => {
    const result = run("tokenMounted", "exposure");
    expect(result.applied).toBe(true);
    const xs = CHAIN.map(label => at(result, label).x);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
    expect(new Set(xs).size).toBe(CHAIN.length);
    expect(CHAIN.map(label => at(result, label).y)).toEqual(CHAIN.map(() => 0));
    expect(CHAIN.map(label => byLabel(result.nodes, label).id).every(id => result.primaryPath.includes(id))).toBe(true);
  });

  it("never invents or reverses an edge to do so", () => {
    const { edges } = k8sFlowGraph("tokenMounted");
    const result = run("tokenMounted", "exposure");
    expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(edges.map(e => [e.id, e.source, e.target]));
  });

  it("does not read an unmounted token as a flow step, but keeps the identity in context with the reason", () => {
    const result = run("snapshot", "exposure");
    const account = byLabel(result.nodes, "service account: prod/web-sa");
    expect(at(result, "secret: prod/db-pass").y).toBe(0);
    expect(account.position.y).not.toBe(0);
    expect(result.primaryPath).not.toContain(account.id);
    const hop = result.edges.find(e => e.target === account.id && e.data?.relationship === "assumes")!;
    expect(hop.data?.flowStep).toBe(false);
    expect(hop.label).toBe("Token not mounted");
    expect(hop.data?.quietLabel).toBe(false);
    expect(account.data.flowNote).toBe("token not mounted");
    expect(byLabel(run("tokenMounted", "exposure").nodes, "service account: prod/web-sa").data.flowNote).toBeUndefined();
  });

  it("keeps a mounted token's hop as a flow step without a caveat", () => {
    const result = run("tokenMounted", "exposure");
    const hop = result.edges.find(e => e.data?.relationship === "assumes")!;
    expect(hop.data?.flowStep).toBe(true);
    expect(hop.label).toBeUndefined();
  });

  it("gives a second route's Service its own column before the pod", () => {
    const result = run("twoServices", "exposure");
    const pod = at(result, "pod: prod/web-7c9f-1").x;
    expect(at(result, "ingress: prod/web").x).toBeLessThan(at(result, "service: prod/web").x);
    expect(at(result, "service: prod/web").x).toBeLessThan(pod);
    expect(at(result, "service: prod/web-public").x).toBeLessThan(pod);
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
    expect(internal.position.y).not.toBe(0);
    expect(result.primaryPath).not.toContain(internal.id);
    expect(result.nodes.filter(n => n.position.x === 0 && n.position.y === 0).map(n => n.data.label)).toEqual(["ingress: prod/web"]);
    const route = result.edges.find(e => e.source === internal.id)!;
    expect(route.label).toBe("Routes in cluster to");
    expect(route.data?.relationship).toBe("exposed_to");
  });

  it("keeps a ClusterIP Service in sequence when a recorded Ingress routes to it", () => {
    const result = run("snapshot", "exposure");
    expect(result.primaryPath).toContain(byLabel(result.nodes, "service: prod/web").id);
  });

  it("treats a LoadBalancer as an entry", () => {
    const { nodes, edges } = k8sFlowGraph("twoServices");
    expect(flowAvailability(nodes, edges).exposure.available).toBe(true);
    const lb = byLabel(run("twoServices", "exposure").nodes, "service: prod/web-public");
    expect(lb.position.x).toBe(0);
  });
});

describe("whether a flow applies", () => {
  it("applies above the former 80-node limit at typical cluster size, with its entry on the canvas page", () => {
    const { nodes, edges } = k8sFlowGraph("clusterEstate");
    expect(nodes.length).toBeGreaterThan(FLOW_READABLE_NODE_LIMIT);
    const unpinned = boundedGraphElements(nodes, edges, [], 0);
    expect(unpinned.nodes.some(n => n.data.attributes?.kubernetes_kind === "Ingress")).toBe(false);
    const page = boundedGraphElements(nodes, edges, flowPinnedIds(nodes, edges, "exposure"), 0);
    expect(page.nodes.length).toBeGreaterThan(80);
    expect(page.nodes.filter(n => n.data.attributes?.kubernetes_kind === "Ingress")).toHaveLength(3);
    const result = investigationFlow(page.nodes, page.edges, "exposure");
    expect(result.applied).toBe(true);
    expect(byLabel(result.nodes, "ingress: prod/app-00").position).toEqual({ x: 0, y: 0 });
    expect(new Set(result.nodes.map(n => `${n.position.x}:${n.position.y}`)).size).toBe(result.nodes.length);
    expect(result.primaryPath.length).toBeGreaterThan(4);
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

  it("reports an untouched layout truthfully under automatic", () => {
    const pkg = k8sFlowGraph("snapshot").nodes.filter(n => n.data.label.startsWith("image:"));
    const result = investigationFlow(pkg, [], "auto");
    expect(result.applied).toBe(false);
    expect(result.nodes).toBe(pkg);
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
  it("starts each flow at its own subject and places nothing on top of anything else", () => {
    const origin = (flow: InvestigationFlow, scenario: K8sScenario) => {
      const result = run(scenario, flow);
      expect(new Set(result.nodes.map(n => `${n.position.x}:${n.position.y}`)).size).toBe(result.nodes.length);
      return result.nodes.find(n => n.position.x === 0 && n.position.y === 0)?.data.label;
    };
    expect(origin("exposure", "withFindings")).toBe("ingress: prod/web");
    expect(origin("identity", "withFindings")).toBe("service account: prod/web-sa");
    expect(origin("inventory", "withFindings")).toBe("cluster: prod-eks");
    expect(origin("vulnerability", "withFindings")).toBe("app");
  });

  it("leads the vulnerability flow through the image and package to the finding", () => {
    const result = run("withFindings", "vulnerability");
    const xs = ["app", "image: nginx:1.19.0", "openssl@1.1.1k", "CVE-2021-3711"].map(label => at(result, label));
    expect(xs.map(p => p.y)).toEqual([0, 0, 0, 0]);
    expect(xs.map(p => p.x)).toEqual([...xs.map(p => p.x)].sort((a, b) => a - b));
    expect(new Set(xs.map(p => p.x)).size).toBe(4);
  });

  it("frames a primary path that starts at the origin and only moves forward", () => {
    for (const flow of ["exposure", "identity", "inventory"] as const) {
      const result = run("snapshot", flow);
      const positions = result.primaryPath.map(id => result.nodes.find(n => n.id === id)!.position);
      expect(positions[0]).toEqual({ x: 0, y: 0 });
      expect(positions.every(p => p.y === 0)).toBe(true);
    }
  });

  it("keeps the real twenty-node map compact enough to frame legibly at 1440", () => {
    const result = run("snapshot", "exposure");
    const xs = result.nodes.map(n => n.position.x), ys = result.nodes.map(n => n.position.y);
    // A 1134px canvas at the 0.4 legibility floor shows about 2600 by 1250 world units.
    expect(Math.max(...xs) - Math.min(...xs) + 300).toBeLessThanOrEqual(2600);
    expect(Math.max(...ys) - Math.min(...ys) + 300).toBeLessThanOrEqual(1400);
  });

  it("does not let one long label change the spacing of the whole map", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const long = nodes.map(n => n.data.label === "pod: prod/web-7c9f-1" ? { ...n, data: { ...n.data, label: "pod: production-payments/web-frontend-7c9f4d-x2k9p" } } : n);
    const positions = (input: typeof nodes) => new Map(investigationFlow(input, edges, "exposure").nodes.map(n => [n.id, n.position]));
    expect(positions(long)).toEqual(positions(nodes));
  });

  it("connects a context edge to the side it faces", () => {
    const result = run("tokenMounted", "exposure");
    const owner = result.edges.find(e => e.source === byLabel(result.nodes, "replicaset: prod/web-7c9f").id && e.target === byLabel(result.nodes, "pod: prod/web-7c9f-1").id)!;
    expect(owner.sourceHandle).toBe("context");
    expect(owner.targetHandle).toBe("context");
  });

  it("treats drift incidents like other findings when one asset owns them", () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const incident = { ...nodes[0]!, id: "drift-1", data: { label: "drift", nodeType: "driftIncident" as const } };
    const link = { id: "d", source: nodes[0]!.id, target: "drift-1", data: { relationship: "exhibits_drift" } };
    const result = investigationFlow([...nodes, incident], [...edges, link], "exposure");
    expect(result.nodes.find(n => n.id === "drift-1")?.data.readingOwner).toBe(nodes[0]!.id);
  });
});

describe("Internet boundary display context", () => {
  const assessed = () => {
    const { nodes, edges } = k8sFlowGraph("snapshot");
    const ingress = byLabel(nodes, "ingress: prod/web");
    return { edges, ingress, nodes: nodes.map(n => n.id === ingress.id ? { ...n, data: { ...n.data, attributes: { ...n.data.attributes, resource_id: "ing-1",
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
    expect(boundary.ariaLabel).toBe("Internet, assessed ingress to ingress: prod/web");
    expect(link.ariaLabel).toBe("Assessed ingress from Internet to ingress: prod/web");
  });
});
