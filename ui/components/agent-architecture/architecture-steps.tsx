"use client";

import { Bug } from "lucide-react";

import { RouteLine } from "@/components/agent-architecture/route-line";
import { useMemo } from "react";

import { architectureIcon, findingsLabel } from "@/components/agent-architecture/architecture-node";
import { severityStyle } from "@/components/attack-path-graph-node";
import { layoutArchitecture } from "@/lib/agent-architecture-layout";
import { FLOW_KIND_LABEL, type ArchitectureModel, type ArchitectureNode } from "@/lib/agent-architecture-model";

type Props = { model: ArchitectureModel; onOpen: (nodeId: string) => void; onExpand: (groupId: string) => void };

function Row({ node, model, onOpen, onExpand }: Props & { node: ArchitectureNode }) {
  const Icon = architectureIcon(node);
  const labels = new Map(model.nodes.map(item => [item.id, item.label]));
  const next = model.mode === "flow" ? model.edges.filter(edge => edge.source === node.id) : [];
  const group = node.kind === "group";
  return (
    <li className="rounded-xl border border-outline bg-surface">
      <button type="button" onClick={() => (group ? onExpand(node.id) : onOpen(node.id))}
        aria-label={group ? `Expand ${node.label}` : `${node.label}, ${node.subtitle}${node.entry ? ", entry" : ""}${node.findings ? `, ${findingsLabel(node)}` : ""}`}
        className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left hover:bg-surface-muted focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)]">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-surface-elevated text-foreground ${group || node.kind === "stub" ? "border border-dashed border-outline-strong" : "border border-outline-strong"}`}>
          <Icon className="h-5 w-5" aria-hidden="true" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[15px] font-semibold text-foreground">{node.label}</span>
          <span className="block truncate text-[13px] text-ink-secondary">{group ? "Tap to expand" : node.subtitle}{node.entry ? " · Entry" : ""}</span>
        </span>
        {node.findings > 0 && (
          <span data-severity={node.findingSeverity || "unrated"} className="inline-flex h-7 min-w-7 items-center gap-0.5 rounded-full border px-1.5 text-[13px] font-bold tabular-nums" style={severityStyle(node.findingSeverity)}>
            <Bug className="h-3.5 w-3.5" aria-hidden="true" />{node.findings}
          </span>
        )}
      </button>
      {(next.length > 0 || node.returnsTo.length > 0 || node.peers.length > 0) && (
        <ul className="space-y-0.5 border-t border-outline px-3 py-2 text-[13px] text-ink-secondary">
          {next.map(edge => <RouteLine key={edge.id} kind="next" text={edge.kind === "unresolved" ? labels.get(edge.target)! : `${labels.get(edge.target)} · ${FLOW_KIND_LABEL[edge.kind]}`} />)}
          {node.returnsTo.map(item => <RouteLine key={`r-${item.id}-${item.kind}`} kind="returns" text={`Returns to ${item.label} · ${FLOW_KIND_LABEL[item.kind]}`} />)}
          {node.peers.map(item => <RouteLine key={`p-${item.id}`} kind="peer" text={`Shares a server with ${item.label}`} />)}
        </ul>
      )}
    </li>
  );
}

/**
 * Phones read the harness as one column: layers top to bottom, or flow steps
 * in order, each agent a full-width row that opens its details.
 */
export function ArchitectureSteps(props: Props) {
  const { model } = props;
  const groups = useMemo(() => {
    const keyOf = model.mode === "flow" ? layoutArchitecture(model).columns : new Map(model.nodes.map(node => [node.id, node.layer]));
    const byKey = new Map<number, ArchitectureNode[]>();
    for (const node of model.nodes) byKey.set(keyOf.get(node.id)!, [...(byKey.get(keyOf.get(node.id)!) ?? []), node]);
    return [...byKey].sort(([a], [b]) => a - b).map(([key, nodes]) => ({ key, nodes: nodes.sort((a, b) => Number(a.kind !== "agent") - Number(b.kind !== "agent") || a.order - b.order) }));
  }, [model]);
  const flow = model.mode === "flow";
  return (
    <section aria-label={flow ? "Harness flow steps" : "Harness layers"} className="space-y-4 bg-surface px-3 py-3">
      {groups.map(({ key, nodes }, index) => (
        <div key={key}>
          <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-tertiary">{flow ? `Step ${index + 1}` : `Layer ${key}`}</h3>
          <ol className="space-y-2">{nodes.map(node => <Row key={node.id} {...props} node={node} />)}</ol>
        </div>
      ))}
    </section>
  );
}
