"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { BaseEdge, EdgeLabelRenderer, SmoothStepEdge, useStore, type EdgeProps } from "@xyflow/react";
import {
  ArrowRightLeft, Box, Bug, CirclePlay, Database, Eye, Fingerprint,
  GitBranch, KeyRound, Link2, LogIn, Plug, ShieldCheck, UserRoundCheck, Wrench,
  type LucideIcon,
} from "lucide-react";

import { accessEvidenceQualifier } from "@/lib/graph-access-evidence";
import { scheduleRelationshipLabelLayout } from "@/lib/relationship-label-layout";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";
import { relationshipPath } from "@/lib/relationship-routing";
import { columnEdgePath } from "@/lib/path-card-column";

// Icons supplement the recorded verb; they never replace its meaning or imply
// that a recorded permission has actually been exercised.
const RELATIONSHIP_ICONS: Record<string, LucideIcon> = {
  owns: UserRoundCheck,
  belongs_to: UserRoundCheck,
  uses: Plug,
  uses_framework: Plug,
  contains: Box,
  part_of: Box,
  hosts: Box,
  has_permission: KeyRound,
  can_access: KeyRound,
  used_credential: KeyRound,
  exposes_cred: KeyRound,
  shares_cred: KeyRound,
  authenticates_as: Fingerprint,
  acted_as: Fingerprint,
  assumes: LogIn,
  vulnerable_to: Bug,
  exploitable_via: Bug,
  depends_on: GitBranch,
  inherits: GitBranch,
  delegated_to: GitBranch,
  called: CirclePlay,
  invoked: CirclePlay,
  runs: CirclePlay,
  triggers: CirclePlay,
  stores: Database,
  accessed: Database,
  trace_step: GitBranch,
  protects: ShieldCheck,
  governs: ShieldCheck,
  trusts: ShieldCheck,
  observes: Eye,
  remediates: Wrench,
  configures: Wrench,
  manages: Wrench,
  lateral_path: ArrowRightLeft,
  cross_account_trust: ArrowRightLeft,
};

export function RelationshipBadge({ relationship, children }: {
  relationship: string;
  children: React.ReactNode;
}) {
  return <span className="relationship-badge">
    <RelationshipIcon relationship={relationship} />
    <span>{children}</span>
  </span>;
}

export function RelationshipIcon({ relationship }: { relationship: string }) {
  const Icon = RELATIONSHIP_ICONS[relationship] ?? Link2;
  return <Icon aria-hidden="true" width="1em" height="1em" strokeWidth={1.8} />;
}

/**
 * Every canvas chip is one inline line centred on its edge. The edge's dash
 * carries the evidence tier; the qualifier stays in assistive text, the edge's
 * hover description and the selected link.
 */
export function qualifiedLabel(relationship: string, label: React.ReactNode, data: EdgeProps["data"]): React.ReactNode {
  const qualifier = accessEvidenceQualifier(relationship, data as Parameters<typeof accessEvidenceQualifier>[1]);
  const suffix = ` · ${qualifier}`;
  if (!qualifier || typeof label !== "string" || !label.endsWith(suffix)) return label;
  return <>{label.slice(0, -suffix.length)}<span className="sr-only">{suffix}</span></>;
}

export function RelationshipEdge(props: EdgeProps) {
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const edgeRef = useRef<SVGGElement>(null);
  // The focusable wrapper belongs to React Flow, outside this component.
  useLayoutEffect(() => {
    const wrapper = edgeRef.current?.closest(".react-flow__edge");
    const focus = () => setFocused(true);
    const blur = () => setFocused(false);
    wrapper?.addEventListener("focus", focus);
    wrapper?.addEventListener("blur", blur);
    return () => { wrapper?.removeEventListener("focus", focus); wrapper?.removeEventListener("blur", blur); };
  }, []);
  const relationship = typeof props.data?.relationship === "string" ? props.data.relationship : "";
  const nodes = useStore(state => state.nodes);
  const packageFinding = relationship === "vulnerable_to"
    && nodes.some(node => node.id === props.source && node.data.nodeType === "package")
    && nodes.some(node => node.id === props.target
      && (node.data.entityType === "vulnerability" || node.data.nodeType === "vulnerability"));
  const inspecting = hovered || focused || props.selected;
  const emphasized = inspecting || packageFinding || props.data?.directionEmphasis === true;
  // Endpoint types already explain package → CVE; path emphasis alone must not
  // restore its redundant chip. Explicit inspection still exposes the verb.
  const inspectLabel = inspecting || (!packageFinding && props.data?.pathEmphasis === true);
  const label = (packageFinding || props.data?.quietLabel) && !inspectLabel ? null
    : props.label ?? (inspectLabel && relationship ? relationshipEdgeLabelText(relationship, props.data) : null);
  const zoom = useStore(state => state.transform[2]);
  const labelRef = useRef<HTMLDivElement>(null);
  const columnSource = props.data?.columnFlow === true ? nodes.find(node => node.id === props.source) : undefined;
  const [path, x, y] = columnSource
    ? columnEdgePath(props, columnSource.position.y + (columnSource.measured?.height ?? 0) + 6)
    : relationshipPath(props, nodes.length <= 80 ? nodes.map(node => ({
      id: node.id, x: node.position.x, y: node.position.y,
      width: node.measured?.width ?? 220, height: node.measured?.height ?? 224,
    })) : []);
  useLayoutEffect(() => { scheduleRelationshipLabelLayout(labelRef.current); }, [path, zoom, label, x, y]);
  if (props.data?.isClusterEdge) return <SmoothStepEdge {...props} />;

  return <g ref={edgeRef} data-label-disclosure={packageFinding ? "on-demand" : undefined} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
    {typeof props.data?.hoverDescription === "string" && <title>{props.data.hoverDescription}</title>}
    <BaseEdge id={props.id} path={path} style={props.style}
      {...(emphasized && props.markerStart ? { markerStart: props.markerStart } : {})}
      {...(emphasized && props.markerEnd ? { markerEnd: props.markerEnd } : {})}
      {...(props.interactionWidth !== undefined ? { interactionWidth: props.interactionWidth } : {})} />
    {label != null && <EdgeLabelRenderer>
      <div ref={labelRef} data-edge-id={props.id} data-label-x={x} data-label-y={y} className={`nodrag nopan graph-relationship-label ${props.data?.aggregate ? "graph-aggregate-label" : ""}`} style={{
        position: "absolute",
        transform: `translate(-50%, -50%) translate(${x}px, ${y}px)`,
        fontSize: Math.max(Number(props.labelStyle?.fontSize) || 12, 12.5 / Math.max(zoom, 0.16)),
        pointerEvents: "none",
      }}>
        <RelationshipBadge relationship={relationship}>{qualifiedLabel(relationship, label, props.data)}</RelationshipBadge>
      </div>
    </EdgeLabelRenderer>}
  </g>;
}

export const relationshipEdgeTypes = { smoothstep: RelationshipEdge };
