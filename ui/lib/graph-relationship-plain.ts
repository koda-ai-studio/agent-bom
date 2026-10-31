import { graphEdgeEvidence, graphEdgeEvidenceLabel } from "@/lib/graph-edge-evidence";
import type { UnifiedEdge } from "@/lib/graph-schema";

type PlainEdge = Pick<UnifiedEdge, "relationship" | "evidence" | "last_seen" | "source_scan_id">;

export interface PlainRelationshipSummary {
  why: string;
  source: string;
  kind: string;
  freshness: string;
  unknown: string;
}

// Collector ids as recorded by the producers, in the words a reviewer uses.
const SOURCE_NAMES: Record<string, string> = {
  bundled_advisory_scanner: "Bundled advisory database",
  repository_parser: "Repository manifest parser",
  cyclonedx_sbom: "CycloneDX SBOM",
  spdx_sbom: "SPDX SBOM",
  kubernetes_iac: "Kubernetes manifests",
  kubernetes_iac_sbom_projection: "Kubernetes manifests matched to the image SBOM",
  identity_model: "Identity model",
  gateway_runtime: "Runtime gateway",
  "source-ast": "Source code analysis",
  "cloud-inventory": "Cloud inventory",
  "cloud-audit-trail": "Cloud audit trail",
  agent_discovery: "Agent configuration discovery",
  "repo-structure-overlay": "Repository structure",
  "runtime-proxy": "Runtime proxy",
  "runtime-identity": "Runtime identity events",
  "runtime-feedback": "Runtime feedback",
};

const WHY: Record<string, (source: string, target: string) => string> = {
  vulnerable_to: (s, t) => `${s} is recorded as affected by ${t}.`,
  exploitable_via: (s, t) => `${s} is recorded as exploitable through ${t}.`,
  affects: (s, t) => `${s} identifies ${t} as affected.`,
  depends_on: (s, t) => `${s} declares ${t} as a dependency.`,
  imports: (s, t) => `${s} imports ${t}.`,
  platform_for: (s, t) => `${s} is the recorded platform associated with ${t}; this does not establish where it runs or which model it calls.`,
  contains: (s, t) => `${s} contains ${t} in the collected inventory.`,
  uses: (s, t) => `${s} is configured to use ${t}.`,
  provides_tool: (s, t) => `${s} lists ${t} as an available tool.`,
  exposes_cred: (s, t) => `${s} references the credential ${t}.`,
  shares_cred: (s, t) => `${s} and ${t} reference the same credential.`,
  configures: (s, t) => `${s} configures ${t}.`,
  correlates_with: (s, t) => `${s} and ${t} match on recorded identity fields.`,
  possibly_correlates_with: (s, t) => `${s} and ${t} may be the same asset; the match is not confirmed.`,
};

const ACCESS = new Set(["can_access", "has_permission", "assumes", "authenticates_as", "exposed_to", "accessed"]);
const CODE = new Set(["depends_on", "contains", "imports", "hosts"]);
const TOOL = new Set(["uses", "provides_tool", "uses_framework"]);
const CRED = new Set(["exposes_cred", "shares_cred"]);
const FINDING = new Set(["vulnerable_to", "exploitable_via", "affects"]);

const EVIDENCE_ACTIONS: Record<string, string> = {
  can_access: "access", has_permission: "hold a permission on", assumes: "assume",
  authenticates_as: "authenticate as", exposed_to: "be exposed to", accessed: "access",
  hosted_on: "run on", hosts: "host", invoked: "invoke", called: "call",
  delegated_to: "delegate work to",
};

function qualifiedRelationship(edge: PlainEdge, source: string, target: string): string | null {
  if (edge.evidence?.identity_scope_status === "conflict") {
    return `The snapshot links ${source} to ${target}, but owner scope conflicts; the relationship remains unresolved.`;
  }
  if (edge.evidence?.network_reachability === "unknown") {
    return `Collected configuration links ${source} to ${target}; effective network reachability is unknown.`;
  }
  if (!Object.hasOwn(EVIDENCE_ACTIONS, edge.relationship)) return null;
  const action = EVIDENCE_ACTIONS[edge.relationship]!;
  const { mode, blocked } = graphEdgeEvidence(edge.evidence ?? {});
  if (blocked) return `${source} had an attempt to ${action} ${target} blocked; completion is not established.`;
  if (mode === "inferred") {
    return edge.relationship === "can_access"
      ? `${source} is modeled as able to access ${target}.`
      : `${source} is modeled to ${action} ${target}.`;
  }
  if (mode === "static") {
    return edge.relationship === "can_access"
      ? `${source} is configured with access to ${target}.`
      : `${source} is configured to ${action} ${target}.`;
  }
  const relation = edge.relationship.replaceAll("_", " ");
  if (mode === "unknown") return `The snapshot links ${source} to ${target} as ${relation}; the evidence basis is not recorded.`;
  // A receipt establishes the recorded activity, not successful execution or
  // continuing effective authority. Denials and attempts are valid observations.
  return `A recorded ${relation} observation links ${source} to ${target}; its outcome is limited to the receipt.`;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function humanSource(raw: string): string {
  if (Object.hasOwn(SOURCE_NAMES, raw)) return SOURCE_NAMES[raw]!;
  const words = raw.replace(/:/g, ": ").replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** Why the link exists, who recorded it, how, when, and what it does not prove. */
export function plainRelationshipSummary(edge: PlainEdge, sourceLabel: string, targetLabel: string): PlainRelationshipSummary {
  const evidence = edge.evidence ?? {};
  const { mode, blocked } = graphEdgeEvidence(evidence);
  const rawSource = text(evidence.source) ?? text(evidence.data_source) ?? text(evidence.source_kind);
  const packageName = text(evidence.package);
  const why = edge.relationship === "vulnerable_to" && evidence.derived_via === "package" && packageName
    ? `${sourceLabel} contains ${packageName}, which is recorded as affected by ${targetLabel}.`
    : qualifiedRelationship(edge, sourceLabel, targetLabel)
      ?? (Object.hasOwn(WHY, edge.relationship) ? WHY[edge.relationship]!(sourceLabel, targetLabel) : `The snapshot records a link from ${sourceLabel} to ${targetLabel}.`);
  const kind = evidence.identity_scope_status === "conflict" ? "Unresolved identity scope"
    : evidence.tier === "recorded" && !blocked ? "Recorded observation"
    : mode === "runtime" ? (blocked ? "Observed at runtime — blocked" : "Observed at runtime")
    : mode === "static" ? "Static — read from files, manifests or configuration"
    : mode === "inferred" ? "Modeled — derived from collected configuration, not observed"
    : graphEdgeEvidenceLabel(edge);
  const observedAt = text(evidence.observed_at), receiptAt = text(evidence.timestamp), lastSeen = text(edge.last_seen);
  const freshness = observedAt ? `Observed ${formatTime(observedAt)}`
    : receiptAt ? `Receipt ${formatTime(receiptAt)}`
    : lastSeen ? `Recorded ${formatTime(lastSeen)} (link record time, not source activity)` : "Not recorded";
  const unknown = evidence.identity_scope_status === "conflict"
    ? "Which account, subscription or project owns this asset; traversal is disabled until the scope conflict is resolved."
    : evidence.network_reachability === "unknown"
    ? "Whether routes, firewall rules and listeners permit end-to-end access; no observed traffic is established by this configuration."
    : FINDING.has(edge.relationship) ? "Whether the vulnerable code is loaded or reachable at runtime."
    : ACCESS.has(edge.relationship) ? (blocked ? "Whether a later attempt succeeded; this attempt was blocked."
      : mode === "runtime" ? "Whether access succeeded unless the receipt records that outcome, and what occurred beyond it." : "Whether this access was ever exercised.")
    : CRED.has(edge.relationship) ? "Whether the secret value was read or used."
    : TOOL.has(edge.relationship) ? "Whether a tool was actually called."
    : CODE.has(edge.relationship) ? "Whether this component's code actually runs."
    : "Whether this relationship was exercised at runtime.";
  return { why, source: rawSource ? humanSource(rawSource) : text(edge.source_scan_id) ? "Scan inventory" : "Not recorded", kind, freshness, unknown };
}
