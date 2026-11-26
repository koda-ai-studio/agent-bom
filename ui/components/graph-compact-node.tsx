"use client";

import { seenInSummary } from "@/lib/graph-evidence-fold";
import { nameBreaks } from "@/lib/graph-name-breaks";
import { NAME_LINES, PHONE_NAME_LINES } from "@/lib/graph-caption-geometry";
import { stacksOnPhone } from "@/lib/graph-portrait-layout";
import { Fragment, useEffect, useRef, type ReactNode } from "react";
import { Handle, Position, useNodeId, useUpdateNodeInternals } from "@xyflow/react";
import { Crown, Diamond, FolderGit2 } from "lucide-react";
import { GraphInternetGlobe } from "@/components/graph-internet-globe";
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
import { compactScopeCaption } from "@/lib/graph-compact-scope";
import { ANCHOR_GLYPH_SCALE, COMPACT_GLYPH_SCALE, PHONE_GLYPH_SCALE } from "@/lib/graph-compact-glyph";

/** Presentation flags shared with the bounded story layout. */
export type CompactNodePresentation = { scopeFindingLabel?: boolean | undefined; scopePeers?: { id: string; label: string; inspect: () => void }[] | undefined; scopePorts?: boolean | undefined; captionAbove?: boolean | undefined; phoneLinear?: boolean | undefined; roomyName?: boolean | undefined; connectedScope?: boolean | undefined; readingFocus?: boolean | undefined };

export type CompactNodeTone = { data: LineageNodeData; borderClass: string; bgClass: string; ringClass: string; iconClass: string; source?: boolean; target?: boolean };

const HANDLE = "!h-1 !w-1 !border-0 !bg-transparent";
const glyphSize = (scale: number) => `calc(var(--graph-node-glyph-size, 56px) * ${scale})`;
const iconSize = (scale: number) => `calc(var(--graph-node-icon-size, 28px) * ${scale})`;
const GLYPH = glyphSize(COMPACT_GLYPH_SCALE), ICON = iconSize(COMPACT_GLYPH_SCALE);
const PHONE_GLYPH = glyphSize(PHONE_GLYPH_SCALE), PHONE_ICON = iconSize(PHONE_GLYPH_SCALE);
const ANCHOR_GLYPH = glyphSize(ANCHOR_GLYPH_SCALE);
const isInternetAnchor = (data: LineageNodeData) => data.attributes?.resource_type === "internet_boundary";
const META = { fontSize: "var(--graph-node-meta-size, 12px)" };

const PROSE_LIMIT = 36;
/** Spelled out so Tailwind emits them; tests hold them to NAME_LINES and PHONE_NAME_LINES. */
export const NAME_CLAMP = { desktop: "line-clamp-4", phone: "line-clamp-3", lines: { desktop: NAME_LINES, phone: PHONE_NAME_LINES } } as const;

/** Canvas name: an image digest reads as its short tail; everything else is kept whole
 * and wraps. The full name stays in the title and drawer. */
export function canvasName(name: string): string {
  const digest = name.match(/^(.*)@sha256:([0-9a-f]{8,})$/i);
  const base = digest ? digest[1]! : name, suffix = digest ? ` @ ${digest[2]!.slice(-8)}` : "";
  return base + suffix;
}

/** On a phone the caption is one column beside the glyph; on a desktop its lines sit directly under it. */
function CaptionBox({ phone, above, wide, children }: { phone: boolean; above?: boolean | undefined; wide?: boolean | undefined; children: ReactNode }) {
  if (above) return <div className="mb-2">{children}</div>;
  if (wide) return <div className="w-[220px] max-w-none">{children}</div>;
  return phone ? <div className="min-w-0 flex-1">{children}</div> : <>{children}</>;
}

/** Desktop: glyph above a centred caption. Phone: the caption beside the glyph, facing away from the centre line. */
function phoneLayoutClass(data: LineageNodeData): string {
  if (data.captionAbove) return "mx-auto w-fit flex-col-reverse items-center text-center";
  // A finding id never truncates: on a phone it reads under its glyph, across the card's full width.
  if (!data.phoneLayout || stackedOnPhone(data)) return "mx-auto w-fit flex-col items-center text-center";
  return data.phoneSide === "left" ? "w-full flex-row-reverse items-center gap-1.5 text-right" : "w-full flex-row items-center gap-1.5 text-left";
}

function stackedOnPhone(data: LineageNodeData): boolean {
  return Boolean(data.phoneLayout) && !data.phoneLinear && stacksOnPhone(data.label);
}

export { nameBreaks, type NamePiece } from "@/lib/graph-name-breaks";

/** Names wrap between words, and inside an ordinary word only after a hyphen or underscore, to at most two lines
 * (the paragraph clamps the rest). Finding ids, digests and versions never split; a finding id never truncates. */
function NameWords({ text, hidden }: { text: string; hidden: boolean }) {
  return <span aria-hidden={hidden || undefined} className="[overflow-wrap:normal] [word-break:normal]">{text.split(" ").map((word, index) => <Fragment key={index}>{index ? " " : ""}
    <span className="inline">{nameBreaks(word).map((piece, at) => <Fragment key={at}>
      {piece.protect && /^(CVE|GHSA)-/i.test(piece.text)
        ? <span className="whitespace-nowrap">{piece.text}</span>
        : <span className="inline-block max-w-full truncate whitespace-nowrap align-top">{piece.text}</span>}
      {piece.breakAfter && <wbr />}</Fragment>)}</span></Fragment>)}</span>;
}

/** A prose finding title (a sentence, not an identifier) previews in about two lines, cut at a word. */
export function prosePreview(title: string, roomy = false): string {
  const limit = roomy ? 72 : PROSE_LIMIT;
  if (title.length <= limit || !title.includes(" ")) return title;
  return `${title.slice(0, limit - 2).replace(/\s+\S*$/, "")}…`;
}

function typeLine(data: LineageNodeData, title: string): string {
  const repository = graphRepositoryContext(data);
  const caption = data.evidenceFlow ? mcpNodeCaption(data, title) : null;
  if (data.nodeType === "misconfiguration" && data.attributes?.finding_kind === "iac") return "IaC finding";
  // A recorded agent type (workflow, assistant, ...) says more than the generic client role.
  if (data.nodeType === "agent" && data.agentType) return topologyAgentTypeLabel(data.agentType);
  // Two visible containers with one name: the recorded role (image inventory or deployment) tells them apart.
  if (data.occurrenceRole) return data.occurrenceRole;
  if (data.seenIn?.length) return `${data.readingLabel ?? "Package"} · seen in ${data.seenIn.length} source${data.seenIn.length === 1 ? "" : "s"}`;
  return caption?.meta ?? data.readingLabel ?? (repository ? "Repository" : data.nodeType === "agent"
    ? (data.agentType ? topologyAgentTypeLabel(data.agentType) : "Agent")
    : assetKindLabel({ entityType: data.entityType, nodeType: data.nodeType, attributes: data.attributes, provider: data.dimensions?.cloud_provider }));
}

export function CompactHandles({ data, source, target }: { data: LineageNodeData; source: boolean; target: boolean }) {
  const phone = data.phoneLayout;
  return <>
    <Handle type="target" position={phone ? Position.Top : Position.Left} className={`${HANDLE} ${target ? "" : "!opacity-0"}`} />
    <Handle type="source" position={phone ? Position.Bottom : Position.Right} className={`${HANDLE} ${source ? "" : "!opacity-0"}`} />
    <Handle type="source" id="context-up" position={Position.Top} className={HANDLE} />
    <Handle type="source" id="context" position={Position.Left} className={HANDLE} />
    <Handle type="target" id="context" position={Position.Right} className={HANDLE} />
    {/* The Internet arrow's own entry on the upper left, when another link also enters this node. */}
    <Handle type="target" id="above" position={Position.Left} style={{ top: "18%" }} className={HANDLE} />
    {data.scopePorts && [25, 50, 75].map((top, index) => <Handle key={top} type="source" id={`scope-out-${index}`} position={Position.Right} style={{ top: `${top}%` }} className={HANDLE} />)}
    {data.scopePorts && [25, 50, 75].map((top, index) => <Handle key={top} type="target" id={`scope-in-${index}`} position={Position.Left} style={{ top: `${top}%` }} className={HANDLE} />)}
    {data.scopePorts && <Handle type="target" id="scope-in-lower-left" position={Position.Left} style={{ top: "90%" }} className={HANDLE} />}
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

const SENSITIVE_CLASSES = new Set(["pii", "phi", "pci", "restricted", "confidential", "sensitive", "secret"]);

function Markers({ data }: { data: LineageNodeData }) {
  const rawContext = data.attributes?.risk_context;
  const context = rawContext && typeof rawContext === "object" && !Array.isArray(rawContext) ? rawContext as Record<string, unknown> : {};
  const admin = "is_admin" in context ? context.is_admin === true : data.attributes?.is_admin === true;
  const critical = context.crown_jewel === true;
  const classification = [context.data_sensitivity ?? data.attributes?.data_sensitivity, data.attributes?.data_classification]
    .filter((value): value is string => typeof value === "string" && (SENSITIVE_CLASSES.has(value.trim().toLowerCase()) || value === "regulated"))
    .map(value => value.trim()).join(", ");
  const sensitiveTitle = critical ? `Recorded critical asset${classification ? ` · data classification: ${classification}` : ""}` : `Recorded data classification: ${classification}`;
  // A drawn Internet anchor already says this; the dot stays for views without the anchor.
  const exposed = !data.displayOnly && !data.internetAnchored && internetExposure(data.attributes) === true;
  return <>
    {(admin || classification || critical) && <span data-asset-markers className="absolute top-0 left-1/2 flex -translate-x-1/2 -translate-y-1/2 gap-1 rounded bg-[var(--graph-canvas)] px-0.5">
      {admin && <GraphCountHint text="Recorded administrator privileges"><span tabIndex={0} role="img" data-compact-marker="privilege" aria-label="Recorded administrator privileges" className="rounded-sm bg-[var(--graph-canvas)] text-violet-600 dark:text-violet-300">
        <Crown aria-hidden="true" style={{ width: "var(--graph-node-meta-size, 14px)", height: "var(--graph-node-meta-size, 14px)" }} />
      </span></GraphCountHint>}
      {(classification || critical) && <GraphCountHint text={sensitiveTitle}><span tabIndex={0} role="img" data-compact-marker="sensitive" aria-label={sensitiveTitle} className="rounded-sm bg-[var(--graph-canvas)] text-emerald-700 dark:text-emerald-300">
        <Diamond aria-hidden="true" style={{ width: "var(--graph-node-meta-size, 14px)", height: "var(--graph-node-meta-size, 14px)" }} />
      </span></GraphCountHint>}
    </span>}
    {data.isKev && <span data-compact-marker="kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog"
      className="absolute -right-0.5 -top-0.5 h-[28%] w-[28%] rounded-full border-2 border-[var(--graph-canvas)] bg-[var(--severity-ring-critical)]"><span className="sr-only">KEV-listed</span></span>}
    {exposed && <span data-compact-marker="internet" title="Recorded internet exposure"
      className="absolute -left-0.5 -top-0.5 h-[28%] w-[28%] rounded-full border-2 border-[var(--graph-canvas)] bg-[var(--graph-edge-exposure)]"><span className="sr-only">Internet-exposed</span></span>}
  </>;
}

function FindingDisclosure({ data }: { data: LineageNodeData }) {
  const findings = data.readingFindings;
  const aggregate = data.findingAggregate ?? data.rollup?.aggregate;
  const count = findings?.count ?? aggregate?.issue_count;
  const toggle = findings?.toggle ?? data.onExploreFindings;
  if (data.displayOnly || data.readingFindingsGroup || !toggle || !Number.isSafeInteger(count) || !count || count < 0
    || ["vulnerability", "misconfiguration"].includes(data.nodeType)) return null;
  const plural = count === 1 ? "" : "s";
  const rating = findings?.severity ?? aggregate?.worst_severity;
  const severity = ["critical", "high", "medium", "low"].includes(rating ?? "") ? rating : undefined;
  const action = findings ? findings.expanded ? "Collapse" : "Expand" : "Inspect";
  const label = findings ? `${action} ${count} finding${plural} for ${data.label}` : `Inspect ${count} finding${plural} in the scope of ${data.label}`;
  return <span className={data.scopePorts ? "absolute -top-3 -right-4" : data.phoneLayout ? "absolute -bottom-2 left-1/2 -translate-x-1/2" : "absolute -bottom-1 -right-3"}>
    <GraphCountHint text={`${data.label}: ${count} distinct open finding${plural} in this asset's containment scope${severity ? ` · highest severity: ${severity}` : " · severity not rated"}. ${findings ? "Expand or collapse the loaded findings; selected attack paths retain their steps." : "Inspect the asset for scope and relationship details."}`}>
      <button type="button" data-finding-disclosure data-finding-count-source="rollup" data-finding-count-severity={severity} aria-expanded={findings?.expanded} title="" aria-label={label}
        onClick={event => { event.stopPropagation(); toggle(); }}
        className="nodrag nopan rounded-full border border-outline-strong bg-surface-elevated px-1.5 font-semibold leading-snug text-foreground" style={META}>
        {count}{data.scopeFindingLabel ? <span className="ml-1 whitespace-nowrap">in scope</span> : <span className="sr-only"> findings</span>}
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
    // Zoom resizes the glyph; a portrait side change moves it without resizing.
    // Re-observe either change so edges land on the newly rendered handles.
    let frame = 0;
    const observer = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => updateNodeInternals(nodeId)); });
    observer.observe(glyphRef.current);
    return () => { observer.disconnect(); cancelAnimationFrame(frame); };
  }, [nodeId, updateNodeInternals, data.phoneLayout, data.phoneSide, data.phoneLinear, data.label]);
  const repository = graphRepositoryContext(data);
  const Icon = repository ? FolderGit2 : nodeGlyph(data.nodeType, data.attributes, data.entityType, data.dimensions?.cloud_provider);
  const provider = repository?.source ?? (showsProviderMark(data) ? entitySource(data) : null);
  const severity = findingSeverity(data);
  const { badges, ring } = nodeBadges(data);
  const anchor = isInternetAnchor(data);
  const outline = ["role", "credential", "policy", "accessPolicy"].includes(data.nodeType) ? borderClass.replace(/\bborder-dashed\b/g, "") : borderClass;
  const glyph = anchor ? ANCHOR_GLYPH : data.phoneLayout ? PHONE_GLYPH : data.readingFocus ? glyphSize(1) : GLYPH, icon = data.phoneLayout ? PHONE_ICON : ICON;
  const fullTitle = typeof data.attributes?.display_title === "string" && data.attributes.display_title.trim() ? data.attributes.display_title : data.label;
  // A prose finding draws its short preview; the full title stays in the tooltip, drawer and assistive text.
  const preview = ["misconfiguration", "vulnerability"].includes(data.nodeType) ? prosePreview(fullTitle, data.roomyName && (!data.phoneLayout || data.phoneLinear)) : fullTitle;
  const scope = data.rollup ? compactScopeCaption(data.rollup) : null;
  const held = data.heldConnections ? `${data.heldConnections} more ${data.heldConnections === 1 ? "connection" : "connections"} not drawn` : undefined;
  const tooltip = [graphNodeTooltip(data), data.evidenceFlowContext, ring?.description, held, data.seenIn?.length ? seenInSummary(data.seenIn) : undefined,
    ...(data.readingConnections ?? []).map(summary => `${summary.relationship === "hosts" ? "Hosts" : "Contains"} ${summary.label} in this view`)].filter(Boolean).join(" · ");
  return <div title={tooltip} data-graph-entity="true" data-compact-node data-evidence-flow={data.evidenceFlow || undefined} data-finding-owner={data.readingOwner} data-reading-focus={data.readingFocus || undefined}
    data-rollup-container={data.attributes?.rollup_is_container === true ? "true" : undefined}
    style={{ maxWidth: "var(--graph-node-card-width, 200px)", marginTop: anchor && data.roomyName && !data.phoneLayout ? glyphSize(-(ANCHOR_GLYPH_SCALE - COMPACT_GLYPH_SCALE) / 2) : data.readingFocus && !data.phoneLayout ? glyphSize(-(1 - COMPACT_GLYPH_SCALE) / 2) : undefined }} className={`relative flex transition-opacity ${data.dimmed ? "opacity-25" : ""} ${phoneLayoutClass(data)}`}>
    <div ref={glyphRef} data-severity-ring={severity} data-internet-anchor={anchor || undefined} style={{ width: glyph, height: glyph, outline: data.readingFocus ? "2px solid var(--border-strong)" : undefined, outlineOffset: data.readingFocus ? data.phoneLayout ? 2 : 5 : undefined }}
      className={`graph-entity-glyph relative flex shrink-0 items-center justify-center rounded-full ${iconClass} ${anchor ? "border-0 bg-transparent" : `border-2 ${outline} ${bgClass}`} ${data.highlighted && !anchor ? `ring-2 ring-offset-2 ring-offset-[var(--graph-canvas)] ${ringClass}` : ""}`}>
      {severity && <span className="sr-only" data-finding-severity={severity}>{`${severity} severity`}</span>}
      <CompactHandles data={data} source={source} target={target} />
      {anchor ? <GraphInternetGlobe />
        : <GraphPackageGlyph ecosystem={data.nodeType === "package" ? badges.find(badge => badge.kind === "ecosystem")?.value : undefined}
          fallback={<Icon aria-hidden="true" style={{ width: icon, height: icon }} className={iconClass} strokeWidth={1.6} />} />}
      {provider && <GraphProviderMark source={provider} attributes={repository ? undefined : data.attributes} className="graph-provider-mark-node graph-provider-mark-compact absolute" />}
      <Markers data={data} />
      <FindingDisclosure data={data} />
      {held && <span data-testid="graph-held-connections" className="sr-only">{held}</span>}
    </div>
    <CaptionBox wide={data.scopePorts} above={data.captionAbove} phone={Boolean(data.phoneLayout) && !stackedOnPhone(data)}>
    <p data-semantic-name title={fullTitle} className={`mt-[0.3em] ${data.phoneLayout && !data.phoneLinear ? NAME_CLAMP.phone : NAME_CLAMP.desktop} max-w-full font-semibold leading-[1.15] text-foreground`} style={{ fontSize: data.phoneLinear ? "var(--graph-node-label-size, 16px)" : data.phoneLayout ? "calc(var(--graph-node-label-size, 14px) * 0.88)" : "calc(var(--graph-node-label-size, 14px) * var(--graph-node-name-scale, 0.88))" }}>
      <NameWords text={canvasName(preview)} hidden={canvasName(preview) !== fullTitle} />
    </p>
    {canvasName(preview) !== fullTitle && <span className="sr-only">{fullTitle}</span>}
    <span data-graph-caption data-entity-role className="block max-w-full truncate leading-[1.15] text-ink-secondary" style={META}>
      {scope ? scope.visible : typeLine(data, fullTitle)}
    </span>
    {scope && <span className="sr-only">{scope.spoken}</span>}
    {!!data.scopePeers?.length && <div className="absolute bottom-full left-1/2 mb-3 flex -translate-x-1/2 flex-col gap-1">
      {data.scopePeers.map(peer => <button key={peer.id} data-graph-caption type="button" className="nodrag nopan whitespace-nowrap rounded-full border border-outline bg-surface-elevated px-2 py-1 text-[11px] text-ink-secondary"
        onClick={event => { event.stopPropagation(); peer.inspect(); }}>also used by: {peer.label}</button>)}
    </div>}
    {data.seenIn?.length ? <span className="sr-only" data-seen-in>{seenInSummary(data.seenIn)}</span> : null}
    </CaptionBox>
  </div>;
}
