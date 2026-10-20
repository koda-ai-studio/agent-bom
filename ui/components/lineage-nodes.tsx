"use client";

import { useEffect, useRef, type ComponentType, type ReactNode } from "react";
import { Handle, Position, useNodeId, useUpdateNodeInternals } from "@xyflow/react";
import { Bug, FolderGit2, KeyRound, Package, Wrench } from "lucide-react";
import { graphRepositoryContext } from "@/lib/graph-repository-context";

import { GraphProviderMark } from "@/components/graph-provider-mark";
import { SegmentedLabel } from "@/components/graph-segmented-label";
import { entitySource } from "@/lib/agent-source";
import { FindingSignalDot, NodeBadgeRow } from "@/components/graph-node-badges";
import { assetKindLabel } from "@/lib/asset-icon-registry";
import { findingSeverity, graphNodeTooltip } from "@/lib/graph-node-tooltip";
import { showsEnvironmentChip, showsProviderMark, type ScopeContext } from "@/lib/graph-scope-context";
import { GraphScopeNode } from "@/components/graph-scope-node";
import type { GraphRollupContainer, GraphCompleteness } from "@/lib/api-types";
import type { ReachBreakdown } from "@/lib/effective-reach";
import { NODE_COLOR_MAP } from "@/lib/graph-utils";
import { SEVERITY_RING_CLASSES, findingRingSeverity, nodeBadges } from "@/lib/graph-node-badges";
import { nodeGlyph } from "@/lib/graph-container-kind";
import {
  ENTITY_ICONS,
  entityIcon,
  type EntityIcon,
  type LineageNodeType,
} from "@/lib/entity-icons";

// ENTITY_ICONS / entityIcon / LineageNodeType / EntityIcon now live in
// `@/lib/entity-icons` (the shared source of truth). Re-exported here so the
// many existing `@/components/lineage-nodes` importers keep working unchanged.
export { ENTITY_ICONS, entityIcon };
export type { EntityIcon, LineageNodeType };

export type RuntimeEvidenceTier = "static_scan" | "runtime_observed" | "runtime_blocked";

export type LineageNodeData = {
  label: string;
  rollup?: GraphRollupContainer | undefined;
  rollupCompact?: boolean | undefined;
  reverseFlow?: boolean;
  nodeType: LineageNodeType;
  entityType?: string | undefined;
  status?: string | undefined;
  riskScore?: number | undefined;
  riskAssessment?: import("@/lib/node-risk-assessment").NodeRiskAssessment | undefined;
  firstSeen?: string | undefined;
  lastSeen?: string | undefined;
  dataSources?: string[] | undefined;
  /** Distinguishes same-image container occurrences (inventory vs deployment). */
  occurrenceRole?: string | undefined;
  /** Visible distinction for same-name nodes; never substitutes for their IDs. */
  identityContext?: string | undefined;
  dimensions?: import("@/lib/graph-schema").NodeDimensions | undefined;
  complianceTags?: string[] | undefined;
  attributes?: Record<string, unknown> | undefined;
  neighborCount?: number | undefined;
  relationshipCountsPartial?: boolean | undefined;
  sourceCount?: number | undefined;
  incomingEdgeCount?: number | undefined;
  outgoingEdgeCount?: number | undefined;
  impactCount?: number | undefined;
  maxImpactDepth?: number | undefined;
  impactByType?: Record<string, number> | undefined;
  impactCompleteness?: GraphCompleteness | undefined;
  // Agent / provider
  agentType?: string | undefined;
  agentStatus?: string | undefined;
  agentCount?: number | undefined;
  serverCount?: number | undefined;
  packageCount?: number | undefined;
  vulnCount?: number | undefined;
  vulnCountPartial?: boolean | undefined;
  countScope?: "loaded_graph" | undefined;
  countHopLimits?: Partial<Record<"agentCount" | "serverCount" | "packageCount" | "vulnCount" | "toolCount" | "credentialCount", number>> | undefined;
  // Server / Shared Server
  toolCount?: number | undefined;
  credentialCount?: number | undefined;
  command?: string | undefined;
  sharedBy?: number | undefined;
  sharedAgents?: string[] | undefined;
  // Package / model / dataset
  ecosystem?: string | undefined;
  version?: string | undefined;
  versionSource?: string | undefined;
  versionConfidence?: string | undefined;
  registryVersion?: string | undefined;
  // Vulnerability / misconfiguration
  severity?: string | undefined;
  cvssScore?: number | undefined;
  epssScore?: number | undefined;
  isKev?: boolean | undefined;
  effectiveReach?: ReachBreakdown | undefined;
  fixedVersion?: string | undefined;
  owaspTags?: string[] | undefined;
  atlasTags?: string[] | undefined;
  // Credential
  serverName?: string | undefined;
  // Tool / generic assets
  description?: string | undefined;
  // Highlighting
  dimmed?: boolean | undefined;
  highlighted?: boolean | undefined;
  isCritical?: boolean | undefined;
  // Evidence redaction tier (#2261) — per-row badge in lineage detail panel.
  evidenceTier?: "safe_to_store" | "replay_only" | undefined;
  /** Runtime evidence overlay (#3610) — static vs observed vs blocked graph paths. */
  runtimeEvidenceTier?: RuntimeEvidenceTier | undefined;
  evidenceCaptureReplay?: boolean | undefined;
  evidenceNotAfter?: string | undefined;
  renderBand?: "detail" | "summary" | "cluster" | undefined;
  /** What the node's parent scope already shows; set by the flow builder. */
  scopeContext?: ScopeContext | undefined;
};

type CardProps = {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  iconClass: string;
  source?: boolean;
  target?: boolean;
  footer?: ReactNode;
  subtitle?: ReactNode;
};

const RUNTIME_EVIDENCE_CHIP: Record<
  RuntimeEvidenceTier,
  { label: string; className: string }
> = {
  static_scan: {
    label: "Static",
    className:
      "border-outline-strong bg-surface-muted text-ink-secondary",
  },
  runtime_observed: {
    label: "Observed",
    className:
      "border-sky-500/30 dark:border-sky-800/70 bg-sky-500/10 dark:bg-sky-950/50 text-sky-700 dark:text-sky-300",
  },
  runtime_blocked: {
    label: "Blocked",
    className:
      "border-rose-500/30 dark:border-rose-800/70 bg-rose-500/10 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300",
  },
};

function RuntimeEvidenceChip({ tier }: { tier: RuntimeEvidenceTier }) {
  const chip = RUNTIME_EVIDENCE_CHIP[tier];
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${chip.className}`}
    >
      {chip.label}
    </span>
  );
}

function ContextHandles() {
  return <>
    <Handle type="source" id="context-up" position={Position.Top} className="!h-1 !w-1 !border-0 !bg-transparent" />
    <Handle type="source" id="context" position={Position.Left} className="!h-1 !w-1 !border-0 !bg-transparent" />
    <Handle type="target" id="context" position={Position.Right} className="!h-1 !w-1 !border-0 !bg-transparent" />
  </>;
}

function NodeCard({
  data,
  borderClass,
  bgClass,
  ringClass,
  iconClass,
  source = true,
  target = true,
  subtitle,
  footer,
}: CardProps) {
  const nodeId = useNodeId();
  const updateNodeInternals = useUpdateNodeInternals();
  const glyphRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!nodeId || !glyphRef.current || typeof ResizeObserver === "undefined") return;
    // Readable glyphs resize with zoom. React Flow must remeasure their handles
    // or arrows land above the visible circle's centre after fitting the view.
    let frame = 0;
    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => updateNodeInternals(nodeId));
    });
    observer.observe(glyphRef.current);
    return () => { observer.disconnect(); cancelAnimationFrame(frame); };
  }, [nodeId, updateNodeInternals]);
  const repository = graphRepositoryContext(data);
  const Icon = repository ? FolderGit2 : nodeGlyph(data.nodeType, data.attributes, data.entityType, data.dimensions?.cloud_provider);
  const provider = repository?.source ?? (showsProviderMark(data) ? entitySource(data) : null);
  const severity = findingSeverity(data);
  const displayTitle = typeof data.attributes?.display_title === "string" && data.attributes.display_title.trim() ? data.attributes.display_title : data.label;
  const isRollupContainer = data.attributes?.rollup_is_container === true;
  const { badges: allBadges, ring } = nodeBadges(data);
  const badges = allBadges.filter((badge) => badge.kind !== "provider" && (badge.kind !== "environment" || showsEnvironmentChip(data)));
  const environmentRaw = allBadges.find((badge) => badge.kind === "environment")?.raw;
  // The environment chip and the vendor mark already name these; a caption repeating them is noise.
  const named = [environmentRaw, provider ? data.dimensions?.cloud_provider ?? data.attributes?.cloud_provider : undefined, provider?.label];
  const shownSubtitle = typeof subtitle === "string" && named.some(value => typeof value === "string" && value && subtitle.trim().toLowerCase() === value.toLowerCase())
    ? undefined : subtitle;
  return (
    <div title={graphNodeTooltip(data)} data-graph-entity="true" data-rollup-container={isRollupContainer ? "true" : undefined}
      style={{ width: "var(--graph-node-card-width, 220px)" }}
      className={`flex w-[220px] flex-col items-center text-center transition-opacity ${data.dimmed ? "opacity-25" : ""}`}>
      <div ref={glyphRef} data-severity-ring={severity} style={{ width: "var(--graph-node-glyph-size, 72px)", height: "var(--graph-node-glyph-size, 72px)" }} className={`graph-entity-glyph relative mb-3 flex h-[72px] w-[72px] items-center justify-center rounded-full border-2 shadow-sm ${
        isRollupContainer ? "border-outline-strong bg-surface-elevated" : `${borderClass} ${bgClass}`
      } ${data.highlighted ? `ring-2 ${ring ? "ring-offset-[10px]" : "ring-offset-4"} ring-offset-[var(--surface)] ${ringClass}` : ""}`}>
        {ring && !isRollupContainer && <FindingSignalDot ring={ring} />}
        {severity && <span className="sr-only" data-finding-severity={severity}>{`${severity} severity`}</span>}
        <Handle type="target" position={data.reverseFlow ? Position.Right : Position.Left}
          className={`!h-1 !w-1 !border-0 !bg-transparent ${target ? "" : "!opacity-0"}`} />
        <Handle type="source" position={data.reverseFlow ? Position.Left : Position.Right}
          className={`!h-1 !w-1 !border-0 !bg-transparent ${source ? "" : "!opacity-0"}`} />
        <ContextHandles />
        <Icon aria-hidden="true" style={{ width: "var(--graph-node-icon-size, 32px)", height: "var(--graph-node-icon-size, 32px)" }} className={`h-8 w-8 ${iconClass}`} />
        {/* A small vendor mark centred on the ring at 4:30, like a status badge; shown once per scope. */}
        {provider && <GraphProviderMark source={provider} attributes={repository ? undefined : data.attributes} className="graph-provider-mark-node absolute" />}
      </div>
      <SegmentedLabel text={repository?.slug || displayTitle} className="mb-1 w-full min-w-0 line-clamp-3 text-lg font-semibold leading-[1.2] text-foreground" style={{ fontSize: "var(--graph-node-label-size, 18px)" }} />
      {/* The vendor mark names the provider; a second text chip would repeat it. */}
      <NodeBadgeRow badges={badges}>
        <span style={{ fontSize: "var(--graph-node-meta-size, 12px)" }} className="text-xs text-ink-secondary">
          {repository ? "Repository" : assetKindLabel({ entityType: data.entityType, nodeType: data.nodeType, attributes: data.attributes, provider: data.dimensions?.cloud_provider })}
        </span>
        {data.occurrenceRole && <span style={{ fontSize: "var(--graph-node-meta-size, 12px)" }} data-testid="graph-occurrence-role" className="rounded border border-outline-strong px-1 text-xs font-medium uppercase tracking-wide text-ink-secondary">{data.occurrenceRole}</span>}
      </NodeBadgeRow>
      {repository && !repository.source && <span className="text-xs text-ink-secondary" style={{ fontSize: "var(--graph-node-meta-size, 12px)" }}>{repository.host}</span>}
      {data.identityContext && <p data-testid="graph-identity-context" className="mt-1 max-w-full break-words text-xs text-ink-secondary" style={{ fontSize: "var(--graph-node-meta-size, 12px)" }}>{data.identityContext}</p>}
      {data.runtimeEvidenceTier && data.runtimeEvidenceTier !== "static_scan" && <div className="mt-1">
        <RuntimeEvidenceChip tier={data.runtimeEvidenceTier} />
      </div>}
      {shownSubtitle && <div className="graph-node-context mt-1 max-w-full truncate text-xs leading-4 text-ink-secondary">{shownSubtitle}</div>}
      {footer && <div className={`${data.nodeType === "vulnerability" || data.nodeType === "misconfiguration" ? "" : "graph-node-context "}mt-1 flex max-w-full flex-wrap items-baseline justify-center gap-x-2`} title={data.countScope === "loaded_graph" ? graphCountDescription(data) : undefined}>
        {footer}
      </div>}
    </div>
  );
}

function linkedCount(count: number, singular: string): string {
  return `${count} linked ${singular}${count === 1 ? "" : "s"}`;
}

function graphCountDescription(data: LineageNodeData): string {
  const labels = { agentCount: "agents", serverCount: "servers", packageCount: "packages", vulnCount: "findings", toolCount: "tools", credentialCount: "credentials" };
  const limits = Object.entries(data.countHopLimits ?? {}).map(([key, depth]) => `${labels[key as keyof typeof labels]}: ${depth} hop${depth === 1 ? "" : "s"}`).join("; ");
  return `${limits.charAt(0).toUpperCase()}${limits.slice(1)}. Distinct entities linked in the loaded graph; these bounded counts are not inventory totals or proof of access.`;
}

function AgentNode({ data }: { data: LineageNodeData }) {
  const notConfigured = data.agentStatus === "installed-not-configured";
  return (
    <NodeCard
      data={data}
      borderClass={
        notConfigured
          ? "border-yellow-500 border-dashed"
          : "border-emerald-500 dark:border-emerald-600"
      }
      bgClass={
        notConfigured
          ? "bg-yellow-50 dark:bg-yellow-950/80"
          : "bg-emerald-50 dark:bg-emerald-950/80"
      }
      ringClass="ring-emerald-400"
      iconClass="text-emerald-600 dark:text-emerald-400"
      target={false}
      subtitle={entitySource(data)?.label ?? data.agentType}
      footer={
        <div className="mt-1 flex flex-wrap justify-center gap-x-2 gap-y-1 text-xs text-ink-secondary">
          {data.serverCount !== undefined && (
            <span>{linkedCount(data.serverCount, "server")}</span>
          )}
          {data.packageCount !== undefined && (
            <span>{linkedCount(data.packageCount, "package")}</span>
          )}
          {(data.vulnCount ?? 0) > 0 && (
            <span className="text-red-700 dark:text-red-300">{linkedCount(data.vulnCount ?? 0, "finding")}</span>
          )}
        </div>
      }
    />
  );
}

function ProviderNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-outline"
      bgClass="bg-surface"
      ringClass="ring-[var(--border-strong)]"
      iconClass="text-ink-tertiary"
      target={false}
      footer={
        data.agentCount !== undefined ? (
          <div className="mt-1 text-xs text-ink-tertiary">
            {linkedCount(data.agentCount, "agent")}
          </div>
        ) : undefined
      }
    />
  );
}

function IdentityNode({
  data,
  borderClass,
  bgClass,
  ringClass,
  iconClass,
  subtitle,
}: {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  iconClass: string;
  subtitle?: ReactNode;
}) {
  return (
    <NodeCard
      data={data}
      borderClass={borderClass}
      bgClass={bgClass}
      ringClass={ringClass}
      iconClass={iconClass}
      subtitle={subtitle}
    />
  );
}

function UserNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-emerald-400 dark:border-emerald-700"
      bgClass="bg-emerald-50 dark:bg-emerald-950/60"
      ringClass="ring-emerald-400"
      iconClass="text-emerald-600 dark:text-emerald-300"
      subtitle={data.description}
    />
  );
}

function GroupNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-fuchsia-400 dark:border-fuchsia-700"
      bgClass="bg-fuchsia-50 dark:bg-fuchsia-950/55"
      ringClass="ring-fuchsia-400"
      iconClass="text-fuchsia-600 dark:text-fuchsia-300"
      subtitle={data.description}
    />
  );
}

function ServiceAccountNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-amber-400 dark:border-amber-700"
      bgClass="bg-amber-50 dark:bg-amber-950/55"
      ringClass="ring-amber-400"
      iconClass="text-amber-600 dark:text-amber-300"
      subtitle={data.description}
    />
  );
}

function StructureNode({
  data,
  borderClass,
  bgClass,
  ringClass,
  iconClass,
}: {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  iconClass: string;
}) {
  return (
    <NodeCard
      data={data}
      borderClass={borderClass}
      bgClass={bgClass}
      ringClass={ringClass}
      iconClass={iconClass}
      subtitle={data.description}
      footer={
        <div className="mt-1 flex flex-wrap justify-center gap-x-2 gap-y-1 text-xs text-ink-secondary">
          {data.agentCount !== undefined && (
            <span>{linkedCount(data.agentCount, "agent")}</span>
          )}
          {data.serverCount !== undefined && (
            <span>{linkedCount(data.serverCount, "server")}</span>
          )}
        </div>
      }
    />
  );
}

function EnvironmentNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-teal-400 dark:border-teal-700"
      bgClass="bg-teal-50 dark:bg-teal-950/55"
      ringClass="ring-teal-400"
      iconClass="text-teal-600 dark:text-teal-300"
    />
  );
}

function FleetNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-cyan-400 dark:border-cyan-700"
      bgClass="bg-cyan-50 dark:bg-cyan-950/55"
      ringClass="ring-cyan-400"
      iconClass="text-cyan-600 dark:text-cyan-300"
    />
  );
}

function ClusterNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-sky-400 dark:border-sky-700"
      bgClass="bg-sky-50 dark:bg-sky-950/55"
      ringClass="ring-sky-400"
      iconClass="text-sky-600 dark:text-sky-300"
    />
  );
}

function ServerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-blue-500 dark:border-blue-600"
      bgClass="bg-blue-50 dark:bg-blue-950/80"
      ringClass="ring-blue-400"
      iconClass="text-blue-600 dark:text-blue-400"
      subtitle={data.command}
      footer={(data.toolCount ?? 0) + (data.credentialCount ?? 0) + (data.packageCount ?? 0) > 0 ? (
        <div className="mt-1 flex flex-wrap justify-center gap-2">
          {data.toolCount !== undefined && data.toolCount > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-purple-700 dark:text-purple-300">
              <Wrench className="w-2.5 h-2.5" /> {data.toolCount}
            </span>
          )}
          {data.credentialCount !== undefined && data.credentialCount > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-amber-800 dark:text-amber-300">
              <KeyRound className="w-2.5 h-2.5" /> {data.credentialCount}
            </span>
          )}
          {data.packageCount !== undefined && data.packageCount > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-ink-secondary">
              <Package className="w-2.5 h-2.5" /> {data.packageCount}
            </span>
          )}
        </div>
      ) : undefined}
    />
  );
}

function PackageNode({ data }: { data: LineageNodeData }) {
  const hasVulns = (data.vulnCount ?? 0) > 0;
  const provenance = data.versionSource
    ? `${data.versionSource}${data.versionConfidence ? ` · ${data.versionConfidence}` : ""}`
    : "";
  const ecosystem = nodeBadges(data).badges.some((badge) => badge.kind === "ecosystem") ? "" : data.ecosystem;
  return (
    <NodeCard
      data={data}
      // The full ring belongs to findings; linked vulnerabilities show as the dot and the count below.
      borderClass="border-outline"
      bgClass="bg-surface"
      ringClass="ring-[var(--border-strong)]"
      iconClass="text-ink-tertiary"
      subtitle={
        data.version
          ? `${data.version}${ecosystem ? ` · ${ecosystem}` : ""}${provenance ? ` · ${provenance}` : ""}`
          : ecosystem
      }
      footer={
        hasVulns ? (
          <div className="mt-1 text-xs text-red-700 dark:text-red-300">
            <Bug className="w-2.5 h-2.5 inline mr-0.5" />
            {data.vulnCount}
          </div>
        ) : undefined
      }
    />
  );
}

/** A finding's ring is its one severity indicator (shared ring tokens); KEV is a separate fact. */
const UNRATED_RING = "border-outline-strong border-dashed";

function FindingNode({ data, accentClass }: { data: LineageNodeData; accentClass: string }) {
  const severity = findingRingSeverity(data);
  return (
    <NodeCard
      data={data}
      borderClass={severity ? SEVERITY_RING_CLASSES[severity] : UNRATED_RING}
      bgClass="bg-surface"
      ringClass="ring-white/50"
      iconClass={accentClass}
      source={false}
      footer={data.isKev ? (
        <div className="graph-finding-metadata mt-1 flex justify-center">
          <span title="Listed in the CISA Known Exploited Vulnerabilities catalog" style={{ fontSize: "var(--graph-node-meta-size, 12px)" }} className="rounded border border-red-700 bg-red-900 px-1.5 py-0.5 font-mono text-xs text-red-300">KEV</span>
        </div>
      ) : undefined}
    />
  );
}

function VulnNode({ data }: { data: LineageNodeData }) {
  return <FindingNode data={data} accentClass="text-red-700 dark:text-red-300" />;
}

function MisconfigNode({ data }: { data: LineageNodeData }) {
  return <FindingNode data={data} accentClass="text-orange-600 dark:text-orange-300" />;
}

function CredentialNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-amber-500 border-dashed"
      bgClass="bg-amber-50 dark:bg-amber-950/60"
      ringClass="ring-amber-400"
      iconClass="text-amber-600 dark:text-amber-400"
      source={false}
      subtitle={data.serverName}
    />
  );
}

function ToolNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-purple-500 dark:border-purple-600"
      bgClass="bg-purple-50 dark:bg-purple-950/60"
      ringClass="ring-purple-400"
      iconClass="text-purple-600 dark:text-purple-400"
      source={false}
      subtitle={data.description}
    />
  );
}

function ModelNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-violet-500 dark:border-violet-600"
      bgClass="bg-violet-50 dark:bg-violet-950/70"
      ringClass="ring-violet-400"
      iconClass="text-violet-600 dark:text-violet-300"
      subtitle={data.description}
    />
  );
}

function DatasetNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-cyan-500 dark:border-cyan-600"
      bgClass="bg-cyan-50 dark:bg-cyan-950/70"
      ringClass="ring-cyan-400"
      iconClass="text-cyan-600 dark:text-cyan-300"
      subtitle={data.description}
    />
  );
}

function ContainerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-indigo-500 dark:border-indigo-600"
      bgClass="bg-indigo-50 dark:bg-indigo-950/70"
      ringClass="ring-indigo-400"
      iconClass="text-indigo-600 dark:text-indigo-300"
      subtitle={data.description}
    />
  );
}

function CloudResourceNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-sky-500 dark:border-sky-600"
      bgClass="bg-sky-50 dark:bg-sky-950/70"
      ringClass="ring-sky-400"
      iconClass="text-sky-600 dark:text-sky-300"
      subtitle={data.description}
    />
  );
}

/**
 * Cluster pill (#2257 — sibling aggregation).
 *
 * Visually distinct rounded pill that absorbs N siblings of the same type
 * and edge kind. Subtle pulse signals "click me to expand". The data shape
 * is the union of `LineageNodeData` + extra cluster fields injected by
 * `aggregateSiblings` — we read the cluster fields off `data` defensively
 * because the renderer is registered globally and any node could in theory
 * land here under that key.
 */
function ClusterPillNode({ data }: { data: LineageNodeData }) {
  const cluster = data as LineageNodeData & {
    count?: number;
    childType?: LineageNodeType;
  };
  const count = cluster.count ?? 0;
  const childType = (cluster.childType ?? cluster.nodeType) as LineageNodeType;
  const Icon = entityIcon(childType);
  return (
    <div
      data-testid="cluster-pill"
      data-cluster-count={count}
      className="relative rounded-full border border-sky-400/60 bg-sky-500/10 px-3 py-1.5 shadow-lg backdrop-blur hover:border-sky-300 hover:bg-sky-500/15 cluster-pill-pulse cursor-pointer"
      title="Click to expand"
    >
      <Handle
        type="target"
        position={data.reverseFlow ? Position.Right : Position.Left}
        className="!w-2 !h-2 !bg-sky-300"
      />
      <Handle
        type="source"
        position={data.reverseFlow ? Position.Left : Position.Right}
        className="!w-2 !h-2 !bg-sky-300"
      />
      <button type="button" aria-label={`Expand ${count} ${childType === "vulnerability" ? "findings" : "members"}`} className="nodrag nopan flex items-center gap-1.5 rounded-full focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-sky-500">
        <Icon className="w-3.5 h-3.5 text-sky-700 dark:text-sky-200" />
        <span className="text-lg font-semibold text-sky-900 dark:text-sky-100 whitespace-nowrap">
          {data.label}
        </span>
        <span className="text-lg text-sky-800 dark:text-sky-300/80">
          expand
        </span>
      </button>
    </div>
  );
}

function SharedServerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-cyan-400"
      bgClass="bg-cyan-50 dark:bg-cyan-950/80"
      ringClass="ring-cyan-300"
      iconClass="text-cyan-600 dark:text-cyan-300"
      subtitle={data.command}
      footer={
        <div className="flex gap-2 mt-1">
          {data.sharedBy && (
            <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-100 text-cyan-700 border border-cyan-300 font-mono dark:bg-cyan-900/60 dark:text-cyan-300 dark:border-cyan-700">
              Shared by {data.sharedBy}
            </span>
          )}
          {data.packageCount !== undefined && data.packageCount > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-ink-secondary">
              <Package className="w-2.5 h-2.5" /> {data.packageCount}
            </span>
          )}
        </div>
      }
    />
  );
}

/**
 * Summary-band renderer (#2257 LOD): compact dot with severity badge + label.
 *
 * Used when 0.4 <= zoom < 1.0 — the operator can still parse a label and a
 * one-glance severity/CVE-count chip but the canvas isn't drowning in chips
 * and footers. The same data shape as `LineageNodeData` so swap-in is free.
 */
function SummaryNode({ data }: { data: LineageNodeData }) {
  const sev = (data.severity ?? "").toLowerCase();
  const accent =
    sev === "critical"
      ? "border-red-500 bg-red-100 text-red-950 dark:bg-red-950/70 dark:text-red-200"
      : sev === "high"
        ? "border-orange-500 bg-orange-100 text-orange-950 dark:bg-orange-950/60 dark:text-orange-200"
        : sev === "medium"
          ? "border-yellow-500 bg-yellow-100 text-yellow-950 dark:bg-yellow-950/55 dark:text-yellow-200"
          : "border-outline bg-surface text-foreground";
  const vulnCount = data.vulnCount ?? 0;
  return (
    <div
      data-testid="summary-node"
      className={`min-w-[112px] max-w-[180px] rounded-lg border px-2.5 py-1.5 shadow transition-opacity ${accent} ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-sky-400" : ""}`}
    >
      <Handle
        type="target"
        position={data.reverseFlow ? Position.Right : Position.Left}
        className="!w-1.5 !h-1.5"
      />
      <Handle
        type="source"
        position={data.reverseFlow ? Position.Left : Position.Right}
        className="!w-1.5 !h-1.5"
      />
      <ContextHandles />
      <div className="flex items-center gap-1">
        <span className="min-w-0 flex-1 break-words line-clamp-2 text-xs font-semibold leading-tight">
          {data.label}
        </span>
        {vulnCount > 0 && (
          <span className="ml-auto rounded bg-white/70 px-1 text-xs font-mono dark:bg-black/40">
            {vulnCount}
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * Cluster-band renderer (#2257 LOD): one bubble per node — the operator
 * is zoomed too far out for labels to be readable anyway, so we render a
 * coloured circle keyed by entity type. The entity colour comes from the
 * standard ENTITY_COLOR_MAP via the parent's `nodeType`.
 */
function ClusterBubbleNode({ data }: { data: LineageNodeData }) {
  const color = CLUSTER_BUBBLE_COLORS[data.nodeType] ?? "#52525b";
  return (
    <div
      data-testid="cluster-bubble"
      className={`rounded-full border-2 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-sky-400" : ""}`}
      style={{
        width: 18,
        height: 18,
        backgroundColor: `${color}cc`,
        borderColor: color,
      }}
    >
      <Handle
        type="target"
        position={data.reverseFlow ? Position.Right : Position.Left}
        className="!w-1 !h-1 !bg-transparent !border-0"
      />
      <Handle
        type="source"
        position={data.reverseFlow ? Position.Left : Position.Right}
        className="!w-1 !h-1 !bg-transparent !border-0"
      />
      <ContextHandles />
    </div>
  );
}

const CLUSTER_BUBBLE_COLORS: Record<LineageNodeType, string> = NODE_COLOR_MAP;

const DETAIL_RENDERERS: Record<
  LineageNodeType,
  ComponentType<{ data: LineageNodeData }>
> = {
  provider: ProviderNode,
  agent: AgentNode,
  user: UserNode,
  group: GroupNode,
  serviceAccount: ServiceAccountNode,
  environment: EnvironmentNode,
  fleet: FleetNode,
  cluster: ClusterNode,
  server: ServerNode,
  sharedServer: SharedServerNode,
  package: PackageNode,
  vulnerability: VulnNode,
  misconfiguration: MisconfigNode,
  credential: CredentialNode,
  tool: ToolNode,
  model: ModelNode,
  framework: ModelNode,
  dataset: DatasetNode,
  container: ContainerNode,
  cloudResource: CloudResourceNode,
  org: ProviderNode,
  account: ProviderNode,
  role: CredentialNode,
  policy: CredentialNode,
  servicePrincipal: ServiceAccountNode,
  federatedIdentity: ServiceAccountNode,
  managedIdentity: ServiceAccountNode,
  accessGrant: CredentialNode,
  accessPolicy: CredentialNode,
  driftIncident: MisconfigNode,
  dataStore: CloudResourceNode,
  directory: ContainerNode,
  sourceFile: PackageNode,
  configFile: PackageNode,
  codeModule: PackageNode,
  ciJob: ToolNode,
  apiGateway: CloudResourceNode,
  toolCall: ToolNode,
  blueprint: CredentialNode,
};

function AdaptiveLineageNode({ data }: { data: LineageNodeData }) {
  if (data.rollup) return <GraphScopeNode item={data.rollup} identityContext={data.identityContext} compact={data.rollupCompact} dimmed={data.dimmed} highlighted={data.highlighted} />;
  if (data.renderBand === "cluster") return <ClusterBubbleNode data={data} />;
  if (data.renderBand === "summary") return <SummaryNode data={data} />;
  const Renderer = DETAIL_RENDERERS[data.nodeType] ?? SummaryNode;
  return <Renderer data={data} />;
}

export const lineageNodeTypesAdaptive = {
  providerNode: AdaptiveLineageNode,
  agentNode: AdaptiveLineageNode,
  userNode: AdaptiveLineageNode,
  groupNode: AdaptiveLineageNode,
  serviceAccountNode: AdaptiveLineageNode,
  environmentNode: AdaptiveLineageNode,
  fleetNode: AdaptiveLineageNode,
  clusterNode: AdaptiveLineageNode,
  serverNode: AdaptiveLineageNode,
  packageNode: AdaptiveLineageNode,
  vulnNode: AdaptiveLineageNode,
  misconfigNode: AdaptiveLineageNode,
  credentialNode: AdaptiveLineageNode,
  toolNode: AdaptiveLineageNode,
  modelNode: AdaptiveLineageNode,
  frameworkNode: AdaptiveLineageNode,
  datasetNode: AdaptiveLineageNode,
  containerNode: AdaptiveLineageNode,
  cloudResourceNode: AdaptiveLineageNode,
  sharedServerNode: AdaptiveLineageNode,
  managedIdentityNode: AdaptiveLineageNode,
  accessGrantNode: AdaptiveLineageNode,
  accessPolicyNode: AdaptiveLineageNode,
  driftIncidentNode: AdaptiveLineageNode,
  dataStoreNode: AdaptiveLineageNode,
  clusterPillNode: ClusterPillNode,
};

/** Detail renderers used by bounded investigations, with evidence metadata. */
export const lineageNodeTypes = {
  providerNode: ProviderNode,
  agentNode: AgentNode,
  userNode: UserNode,
  groupNode: GroupNode,
  serviceAccountNode: ServiceAccountNode,
  environmentNode: EnvironmentNode,
  fleetNode: FleetNode,
  clusterNode: ClusterNode,
  serverNode: ServerNode,
  packageNode: PackageNode,
  vulnNode: VulnNode,
  misconfigNode: MisconfigNode,
  credentialNode: CredentialNode,
  toolNode: ToolNode,
  modelNode: ModelNode,
  frameworkNode: ModelNode,
  datasetNode: DatasetNode,
  containerNode: ContainerNode,
  cloudResourceNode: CloudResourceNode,
  sharedServerNode: SharedServerNode,
  managedIdentityNode: ServiceAccountNode,
  accessGrantNode: CredentialNode,
  accessPolicyNode: CredentialNode,
  driftIncidentNode: MisconfigNode,
  dataStoreNode: CloudResourceNode,
  clusterPillNode: ClusterPillNode,
};
