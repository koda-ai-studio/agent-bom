import type { UnifiedEdge } from "@/lib/graph-schema";

type RecordedLink = Pick<UnifiedEdge, "relationship" | "evidence">;

// Describe the recorded verb, not a stronger execution or access claim. The
// source receipt below remains separate from this explanation of the taxonomy.
const explanations: Record<string, string> = {
  uses: "A recorded use relationship. It does not establish that a tool was called.",
  provides_tool: "The source lists the target as an available tool. Availability does not prove invocation.",
  depends_on: "The source is linked to a dependency in the collected inventory. This does not establish that vulnerable code runs.",
  vulnerable_to: "The source is linked to a security finding. Review its affected asset, evidence, and remediation before choosing a fix.",
  affects: "The finding identifies the target as affected in this snapshot. Review the finding and its source evidence for the detection reason.",
  contains: "The source contains the target in the collected inventory. Containment alone does not establish execution or access.",
  exposes_cred: "The graph links the source to credential material or a secret reference. This alone does not establish that a secret value was read.",
  correlates_with: "The graph records an identity match across sources. Review the matching fields and scope before treating the records as the same asset.",
  possibly_correlates_with: "This is a possible identity match. The records are not confirmed to represent the same asset.",
  delegated_to: "The graph records delegation between these endpoints. The relationship name alone does not establish runtime execution.",
  invoked: "The graph records an invocation relationship. Review the receipt to distinguish attempted, blocked, failed and completed activity.",
  called: "The graph records a call relationship. Review the receipt to distinguish attempted, blocked, failed and completed activity.",
  trace_step: "One correlated trace touched these assets in sequence. The step comes from recorded audit evidence, not from a confirmed access path.",
};

const fields = [
  ["evidence_tier", "Recorded evidence tier"], ["evidence_basis", "Recorded evidence basis"],
  ["source", "Source"], ["data_source", "Data source"], ["basis", "Recorded basis"],
  ["mapping_method", "Mapping method"], ["package", "Package"], ["version", "Version"],
  ["ecosystem", "Ecosystem"], ["purl", "Package URL"],
] as const;

export function GraphRelationshipExplanation({ edge }: { edge: RecordedLink }) {
  const evidence = edge.evidence ?? {};
  const conservativeImpact = edge.relationship === "exploitable_via" && evidence.mapping_method === "server_scope_conservative";
  const explanation = conservativeImpact
    ? "This tool shares a server with the affected package. The mapping is conservative: an exact package-to-tool call path is not established."
    : (Object.hasOwn(explanations, edge.relationship) ? explanations[edge.relationship] : undefined) ?? "This link records a relationship between the two endpoints. Review its source evidence before drawing a security conclusion.";
  const rows = fields.flatMap(([key, label]) => {
    const value = evidence[key];
    return typeof value === "string" && value.trim() ? [{ key, label, value: value.trim() }] : [];
  });
  return <div className="space-y-2 text-xs text-ink-secondary [overflow-wrap:anywhere]">
    <p>{explanation}</p>
    {!Object.keys(evidence).length && <p>Source evidence not recorded for this link.</p>}
    {rows.length > 0 && <dl aria-label="Recorded link evidence" className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1">
      {rows.map(row => <div key={row.key} className="contents"><dt>{row.label}</dt><dd>{row.value}</dd></div>)}
    </dl>}
    {Object.keys(evidence).length > 0 && rows.length === 0 && <p>See the recorded evidence for this link’s source details.</p>}
  </div>;
}
