"use client";

import { useEffect, useRef } from "react";
import { Handle, Position, useNodeId, useUpdateNodeInternals } from "@xyflow/react";
import { FolderGit2 } from "lucide-react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { GraphPackageGlyph } from "@/components/graph-package-glyph";
import { GraphProviderMark } from "@/components/graph-provider-mark";
import { GraphCountHint } from "@/components/graph-count-hint";
import { topologyAgentTypeLabel } from "@/lib/agent-topology-graph";
import { entitySource } from "@/lib/agent-source";
import { assetKindLabel } from "@/lib/asset-icon-registry";
import { nodeGlyph } from "@/lib/graph-container-kind";
import { internetExposure } from "@/lib/graph-internet-context";
import { mcpNodeCaption } from "@/lib/graph-mcp-caption";
import { nodeBadges } from "@/lib/graph-node-badges";
import { findingSeverity, graphNodeTooltip } from "@/lib/graph-node-tooltip";
import { graphRepositoryContext } from "@/lib/graph-repository-context";
import { showsProviderMark } from "@/lib/graph-scope-context";

export type CompactNodeTone = { data: LineageNodeData; borderClass: string; bgClass: string; ringClass: string; iconClass: string; source?: boolean; target?: boolean };

const HANDLE = "!h-1 !w-1 !border-0 !bg-transparent";
const GLYPH = "calc(var(--graph-node-glyph-size, 56px) * 0.7)";
const ICON = "calc(var(--graph-node-icon-size, 28px) * 0.7)";
const META = { fontSize: "var(--graph-node-meta-size, 12px)" };

/** Long identifiers keep their distinguishing tail; CSS elides the middle only when it does not fit. */
export function nameParts(name: string): [string, string] {
  if (name.length <= 16) return [name, ""];
  const tail = Math.min(8, Math.floor(name.length / 3));
  return [name.slice(0, -tail), name.slice(-tail)];
}

function typeLine(data: LineageNodeData, title: string): string {
  const repository = graphRepositoryContext(data);
  const caption = data.evidenceFlow ? mcpNodeCaption(data, title) : null;
  if (data.nodeType === "misconfiguration" && data.attributes?.finding_kind === "iac") return "IaC finding";
  return caption?.meta ?? data.readingLabel ?? (repository ? "Repository" : data.nodeType === "agent"
    ? (data.agentType ? topologyAgentTypeLabel(data.agentType) : "Agent")
    : assetKindLabel({ entityType: data.entityType, nodeType: data.nodeType, attributes: data.attributes, provider: data.dimensions?.cloud_provider }));
}

function Handles({ data, source, target }: { data: LineageNodeData; source: boolean; target: boolean }) {
  const phone = data.phoneLayout;
  return <>
    <Handle type="target" position={phone ? Position.Top : Position.Left} className={`${HANDLE} ${target ? "" : "!opacity-0"}`} />
    <Handle type="source" position={phone ? Position.Bottom : Position.Right} className={`${HANDLE} ${source ? "" : "!opacity-0"}`} />
    <Handle type="source" id="context-up" position={Position.Top} className={HANDLE} />
    <Handle type="source" id="context" position={Position.Left} className={HANDLE} />
    <Handle type="target" id="context" position={Position.Right} className={HANDLE} />
    {phone && <>
      <Handle type="source" id="phone-up" position={Position.Top} className={HANDLE} />
      <Handle type="target" id="phone-down" position={Position.Bottom} className={HANDLE} />
      {[Position.Left, Position.Right].map(position => <span key={position}>
        <Handle type="source" id={`phone-${position}`} position={position} className={HANDLE} />
        <Handle type="target" id={`phone-${position}`} position={position} className={HANDLE} />
      </span>)}
    </>}
  </>;
}

function Markers({ data }: { data: LineageNodeData }) {
  const exposed = !data.displayOnly && internetExposure(data.attributes) === true;
  return <>
    {data.isKev && <span data-compact-marker="kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog"
      className="absolute -right-0.5 -top-0.5 h-[28%] w-[28%] rounded-full border-2 border-[var(--graph-canvas)] bg-[var(--severity-ring-critical)]"><span className="sr-only">KEV-listed</span></span>}
    {exposed && <span data-compact-marker="internet" title="Recorded internet exposure"
      className="absolute -left-0.5 -top-0.5 h-[28%] w-[28%] rounded-full border-2 border-[var(--graph-canvas)] bg-[var(--graph-edge-exposure)]"><span className="sr-only">Internet-exposed</span></span>}
  </>;
}

function FindingDisclosure({ data }: { data: LineageNodeData }) {
  const findings = data.readingFindings;
  if (!findings || data.readingFindingsGroup || findings.expanded) return null;
  const plural = findings.count === 1 ? "" : "s";
  return <span className="absolute -bottom-1 -right-3">
    <GraphCountHint text={`${data.label}: ${findings.count} linked finding${plural}${findings.severity ? ` · highest severity: ${findings.severity}` : " · severity not rated"}. Click to expand.`}>
      <button type="button" data-finding-disclosure aria-expanded={false} title="" aria-label={`Expand ${findings.count} finding${plural} for ${data.label}`}
        onClick={event => { event.stopPropagation(); findings.toggle(); }}
        className="nodrag nopan rounded-full border border-outline-strong bg-surface-elevated px-1.5 font-semibold leading-snug text-foreground" style={META}>
        {findings.count}<span className="sr-only"> findings</span>
      </button>
    </GraphCountHint>
  </span>;
}

/** A small circle, one name line and one type line; detail lives in the drawer. */
export function CompactGraphNode({ data, borderClass, bgClass, ringClass, iconClass, source = true, target = true }: CompactNodeTone) {
  const nodeId = useNodeId();
  const updateNodeInternals = useUpdateNodeInternals();
  const glyphRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!nodeId || !glyphRef.current || typeof ResizeObserver === "undefined") return;
    // The glyph resizes with zoom; handles must be remeasured to stay on its centre.
    let frame = 0;
    const observer = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => updateNodeInternals(nodeId)); });
    observer.observe(glyphRef.current);
    return () => { observer.disconnect(); cancelAnimationFrame(frame); };
  }, [nodeId, updateNodeInternals]);
  const repository = graphRepositoryContext(data);
  const Icon = repository ? FolderGit2 : nodeGlyph(data.nodeType, data.attributes, data.entityType, data.dimensions?.cloud_provider);
  const provider = repository?.source ?? (showsProviderMark(data) ? entitySource(data) : null);
  const severity = findingSeverity(data);
  const { badges, ring } = nodeBadges(data);
  const title = typeof data.attributes?.display_title === "string" && data.attributes.display_title.trim() ? data.attributes.display_title : data.label;
  const [head, tail] = nameParts(title);
  const held = data.heldConnections ? `${data.heldConnections} more ${data.heldConnections === 1 ? "connection" : "connections"} not drawn` : undefined;
  const tooltip = [graphNodeTooltip(data), data.evidenceFlowContext, ring?.description, held,
    ...(data.readingConnections ?? []).map(summary => `${summary.relationship === "hosts" ? "Hosts" : "Contains"} ${summary.label} in this view`)].filter(Boolean).join(" · ");
  return <div title={tooltip} data-graph-entity="true" data-compact-node data-evidence-flow={data.evidenceFlow || undefined} data-finding-owner={data.readingOwner}
    data-rollup-container={data.attributes?.rollup_is_container === true ? "true" : undefined}
    style={{ maxWidth: "var(--graph-node-card-width, 200px)" }} className={`relative mx-auto flex w-fit flex-col items-center text-center transition-opacity ${data.dimmed ? "opacity-25" : ""}`}>
    <div ref={glyphRef} data-severity-ring={severity} style={{ width: GLYPH, height: GLYPH }}
      className={`graph-entity-glyph relative flex items-center justify-center rounded-full border-2 ${borderClass} ${bgClass} ${data.highlighted ? `ring-2 ring-offset-2 ring-offset-[var(--graph-canvas)] ${ringClass}` : ""}`}>
      {severity && <span className="sr-only" data-finding-severity={severity}>{`${severity} severity`}</span>}
      <Handles data={data} source={source} target={target} />
      <GraphPackageGlyph ecosystem={data.nodeType === "package" ? badges.find(badge => badge.kind === "ecosystem")?.value : undefined}
        fallback={<Icon aria-hidden="true" style={{ width: ICON, height: ICON }} className={iconClass} />} />
      {provider && <GraphProviderMark source={provider} attributes={repository ? undefined : data.attributes} className="graph-provider-mark-node graph-provider-mark-compact absolute" />}
      <Markers data={data} />
      <FindingDisclosure data={data} />
      {held && <span data-testid="graph-held-connections" className="sr-only">{held}</span>}
    </div>
    <p data-semantic-name title={title} className="mt-[0.3em] flex min-w-0 max-w-full whitespace-nowrap font-semibold leading-[1.15] text-foreground" style={{ fontSize: "var(--graph-node-label-size, 14px)" }}>
      <span className="min-w-0 truncate whitespace-pre">{head}</span>{tail && <span className="shrink-0 whitespace-pre">{tail}</span>}
    </p>
    <span data-graph-caption data-entity-role className="block max-w-full truncate leading-[1.15] text-ink-secondary" style={META}>
      {typeLine(data, title)}
    </span>
  </div>;
}
