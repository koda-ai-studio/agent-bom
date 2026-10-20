"use client";

import { useEffect, useRef, type ReactNode } from "react";

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

/** Sticky app header height plus breathing room; matches the wrapper's scroll margin. */
const HEADER_CLEARANCE_PX = 80;

/**
 * Keep a step's answer on screen. The answer renders under the page header,
 * so a step chosen after scrolling would otherwise answer out of view.
 * A step that arrives with the URL renders at the top and never moves the page.
 */
function StepAnswer({ step, reveal, children }: { step: InvestigationStep; reveal: boolean; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!reveal) return;
    const el = ref.current;
    if (!el) return;
    const { top, bottom } = el.getBoundingClientRect();
    const view = window.innerHeight;
    const hidden = top < HEADER_CLEARANCE_PX || top > view - HEADER_CLEARANCE_PX;
    const mostlyBelow = top > view / 2 && bottom > view;
    if (!hidden && !mostlyBelow) return;
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ block: "start", behavior: reduced ? "auto" : "smooth" });
  }, [step, reveal]);
  return <div ref={ref} className="scroll-mt-20" data-testid="investigation-step-answer">{children}</div>;
}

/** The in-page answer for the active step (Impact, Owner or Fix). */
export function InvestigationLifecyclePanel(props: {
  step: InvestigationStep;
  path: AttackPath | null;
  nodeById: Map<string, UnifiedNode>;
  scanId: string;
  tenantId: string | undefined;
  snapshotGeneration: string | null | undefined;
}) {
  const previous = useRef(props.step);
  const reveal = previous.current !== props.step;
  useEffect(() => {
    previous.current = props.step;
  }, [props.step]);
  const answer = stepAnswer(props);
  return answer ? <StepAnswer step={props.step} reveal={reveal}>{answer}</StepAnswer> : null;
}

function stepAnswer({ step, path, nodeById, scanId, tenantId, snapshotGeneration }: {
  step: InvestigationStep;
  path: AttackPath | null;
  nodeById: Map<string, UnifiedNode>;
  scanId: string;
  tenantId: string | undefined;
  snapshotGeneration: string | null | undefined;
}): ReactNode {
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
