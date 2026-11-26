import type { LineageNodeData } from "../lineage-nodes";
import { Loader2, Radar } from "lucide-react";
import { nodeRiskLabel } from "@/lib/node-risk-assessment";
import type { LineageDetailProps } from "./types";
import { CodeBlock, Label, Row, shortDate } from "./fields";
import { EvidenceTierBadge, RuntimeEvidenceBadge } from "./evidence";
import { PrimaryNodeDetails } from "./node-details";

function LifecycleDetails({ data }: { data: LineageNodeData }) {
  return (<>
{(data.status ||
  data.riskAssessment != null ||
  data.riskScore != null ||
  data.firstSeen ||
  data.lastSeen) && (
  <div className="space-y-2">
    <Label>Lifecycle</Label>
    {data.status && <Row label="Status" value={data.status} />}
    {(data.riskScore != null || data.riskAssessment != null) && (
      <Row label="Node risk score" value={nodeRiskLabel(data.riskScore, data.riskAssessment)} />
    )}
    {data.firstSeen && (
      <Row label="First seen" value={shortDate(data.firstSeen)} />
    )}
    {data.lastSeen && (
      <Row label="Last seen" value={shortDate(data.lastSeen)} />
    )}
  </div>
)}
  </>);
}

function NodeIdentifier({ data }: { data: LineageNodeData }) {
  return (<>
{typeof data.attributes?.node_id === "string" &&
  data.attributes.node_id && (
    <div className="space-y-2">
      <Label>Identifier</Label>
      <CodeBlock
        label="Node ID"
        value={String(data.attributes.node_id)}
      />
    </div>
  )}
  </>);
}

export function OverviewDetails({ data, onShowBlastRadius, blastRadiusActive = false, blastRadiusLoading = false }: LineageDetailProps) {
  const aggregate = data.findingAggregate;
  const capability = data.attributes?.capability_risk as {score?: number; level?: string; justification?: string; basis?: string} | undefined;
  return (<>
    <PrimaryNodeDetails data={data} />
    {capability && Number.isFinite(capability.score) && <section aria-label="Capability risk assessment" className="space-y-2">
      <Label>Capability risk assessment</Label>
      <Row label="Capability risk" value={`${capability.score}/10 · ${capability.level}`} />
      <p className="text-xs text-ink-secondary">{capability.justification}</p>
      <p className="text-xs text-ink-secondary">Based on loaded tools and credential references.</p>
    </section>}
    {data.nodeType === "tool" && typeof data.attributes?.tool_class === "string" && <section aria-label="Recorded tool capability" className="space-y-2">
      <Label>Recorded tool capability</Label>
      <Row label="Capability" value={data.attributes.tool_class === "shell" ? "Shell command execution" : data.attributes.tool_class.replaceAll("_", " ")} />
      {Array.isArray(data.attributes.capabilities) && <Row label="Operations" value={data.attributes.capabilities.filter((value): value is string => typeof value === "string").join(", ")} />}
    </section>}
    {aggregate && <section aria-label="Finding count scope" className="space-y-2 rounded-lg border border-outline p-3 text-xs">
      <Label>Finding count scope</Label>
      <p className="text-ink-secondary">This asset and its containment scope in the selected snapshot. Counts can overlap between assets and are not estate totals.</p>
      <Row label="Distinct open findings" value={aggregate.issue_count ?? "Not available"} />
      <Row label="Finding occurrences" value={aggregate.finding_occurrence_count ?? "Not available"} />
      <Row label="Descendant entities" value={aggregate.descendant_count ?? "Not available"} />
      <p className="text-ink-secondary">{["critical", "high", "medium", "low", "none", "unknown"].filter(level => (aggregate.severity_counts?.[level] ?? 0) > 0).map(level => `${level}: ${aggregate.severity_counts[level]}`).join(" · ")}</p>
      <p className="text-ink-secondary">Inspect recorded relationships or explore this scope to follow the underlying assets and findings.</p>
    </section>}
    <EvidenceTierBadge tier={data.evidenceTier} captureReplay={data.evidenceCaptureReplay} notAfter={data.evidenceNotAfter} />
    <RuntimeEvidenceBadge tier={data.runtimeEvidenceTier} />
    <LifecycleDetails data={data} />
    <NodeIdentifier data={data} />
{onShowBlastRadius && <BlastRadiusButton onClick={onShowBlastRadius} active={blastRadiusActive} loading={blastRadiusLoading} />}
  </>);
}

export function BlastRadiusButton({ onClick, active, loading }: { onClick: () => void; active: boolean; loading: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      aria-pressed={active}
      className={`flex w-full items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-60 ${
        active
          ? "border-violet-400/50 bg-violet-500/20 text-violet-800 dark:text-violet-100"
          : "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-200 hover:border-violet-400/60 hover:bg-violet-500/20"
      }`}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Radar className="h-3.5 w-3.5" />}
      {active ? "Blast radius shown" : "Show blast radius"}
    </button>
  );
}
