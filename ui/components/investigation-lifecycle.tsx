"use client";

import { GraphPathImpact } from "@/components/graph-path-impact";
import { InvestigationStepStrip, type InvestigationStep } from "@/components/investigation-step-strip";
import { PathFixPanel } from "@/components/path-fix-panel";
import { PathOwnerPanel } from "@/components/path-owner-panel";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

function pathNodes(path: AttackPath | null, nodeById: Map<string, UnifiedNode>) {
  return path ? path.hops.map((id) => nodeById.get(id)).filter((node): node is UnifiedNode => Boolean(node)) : [];
}

/**
 * Path → Impact → Owner → Fix → Verify. Impact, Owner and Fix answer in place
 * (Fix links out to the package's remediation queue); Verify continues there.
 */
export function InvestigationLifecycleStrip({ step, onStepChange, completed, scanId }: {
  step: InvestigationStep;
  onStepChange: (next: InvestigationStep) => void;
  completed: Partial<Record<InvestigationStep, boolean>>;
  scanId: string;
}) {
  const historical = scanId && !scanId.startsWith("current-estate:") ? `?scan=${encodeURIComponent(scanId)}` : "";
  return (
    <InvestigationStepStrip
      step={step}
      onStepChange={onStepChange}
      completed={completed}
      stepHrefs={{ verify: `/remediation${historical}#verification` }}
    />
  );
}

/** The in-page answer for the active step (Impact or Owner). */
export function InvestigationLifecyclePanel({ step, path, nodeById, scanId, tenantId, snapshotGeneration }: {
  step: InvestigationStep;
  path: AttackPath | null;
  nodeById: Map<string, UnifiedNode>;
  scanId: string;
  tenantId: string | undefined;
  snapshotGeneration: string | null | undefined;
}) {
  const nodes = pathNodes(path, nodeById);
  const packageNode = nodes.find((node) => node.entity_type === "package");
  const impactRoot = nodes.find((node) => node.entity_type === "vulnerability" || node.entity_type === "misconfiguration")
    ?? (path ? nodeById.get(path.target) : undefined);
  const cve = path?.vuln_ids[0];
  if (step === "impact" && impactRoot && scanId && tenantId) {
    return (
      <GraphPathImpact
        key={JSON.stringify([scanId, impactRoot.id, snapshotGeneration])}
        nodeId={impactRoot.id} label={impactRoot.label} scanId={scanId}
        tenantId={tenantId} snapshotGeneration={snapshotGeneration}
        findingRoot={impactRoot.entity_type === "vulnerability" || impactRoot.entity_type === "misconfiguration"}
      />
    );
  }
  if (step === "owner" && path && cve) {
    return <PathOwnerPanel cve={cve} hops={path.hops} packageLabel={packageNode?.label} scanId={scanId} />;
  }
  if (step === "fix" && path) {
    return <PathFixPanel path={path} nodes={nodes} scanId={scanId} />;
  }
  if (step === "owner" && path) {
    return <p role="status" className="rounded-xl border border-outline bg-surface p-4 text-sm text-ink-secondary">This path carries no advisory, so no finding owner or SLA applies.</p>;
  }
  return null;
}
