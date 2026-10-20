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
  return (<>
    <PrimaryNodeDetails data={data} />
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
