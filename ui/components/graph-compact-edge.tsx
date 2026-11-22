"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { BaseEdge, EdgeLabelRenderer, Position, useStore, type EdgeProps } from "@xyflow/react";
import { RelationshipBadge } from "@/components/relationship-edge";
import { edgeFamily, edgeFamilyColor, edgeIsDashed } from "@/lib/graph-edge-family";
import { ARC_REACH } from "@/lib/graph-compact-arcs";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";

type Point = { x: number; y: number };

function control(point: Point, position: Position, offset: number): Point {
  if (position === Position.Left) return { x: point.x - offset, y: point.y };
  if (position === Position.Right) return { x: point.x + offset, y: point.y };
  if (position === Position.Top) return { x: point.x, y: point.y - offset };
  return { x: point.x, y: point.y + offset };
}

/** One smooth curve between the two handles; never routed through a gutter. */
export function compactEdgeCurve(props: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition"> & { data?: EdgeProps["data"] }) {
  const source = { x: props.sourceX, y: props.sourceY }, target = { x: props.targetX, y: props.targetY };
  // Each end leaves along its handle: a side handle by 45% of the horizontal run, a top/bottom handle by half the vertical run.
  const sameSide = props.sourcePosition === props.targetPosition;
  const dx = Math.abs(target.x - source.x), dy = Math.abs(target.y - source.y);
  const upright = (position: Position) => position === Position.Top || position === Position.Bottom;
  const reach = (position: Position) => sameSide ? Math.max(110, dy * 0.3) : upright(position) ? Math.max(24, dy * 0.5) : Math.max(24, dx * ARC_REACH);
  let c1 = control(source, props.sourcePosition, reach(props.sourcePosition)), c2 = control(target, props.targetPosition, reach(props.targetPosition));
  // One upright end and one side end: run along the upright axis, then turn into the side.
  if (upright(props.sourcePosition) && !upright(props.targetPosition)) { c1 = { x: source.x, y: source.y + (target.y - source.y) * 0.75 }; c2 = { x: source.x, y: target.y }; }
  if (!upright(props.sourcePosition) && upright(props.targetPosition)) { c1 = { x: target.x, y: source.y }; c2 = { x: target.x, y: target.y - (target.y - source.y) * 0.75 }; }
  // A link whose plain curve would cross a card bends around it: the layout sets both control heights.
  const arc = props.data?.arcDy;
  if (Array.isArray(arc) && arc.length === 2 && !props.data?.phoneLayout && !sameSide) { c1 = { ...c1, y: source.y + Number(arc[0]) }; c2 = { ...c2, y: source.y + Number(arc[1]) }; }
  const mid = { x: (source.x + 3 * c1.x + 3 * c2.x + target.x) / 8, y: (source.y + 3 * c1.y + 3 * c2.y + target.y) / 8 };
  return { path: `M ${source.x},${source.y} C ${c1.x},${c1.y} ${c2.x},${c2.y} ${target.x},${target.y}`, mid };
}

/** An inspected link names its relationship and evidence in full, just above the line: names hang below glyphs. */
function InspectLabel({ id, at, relationship, text, aggregate, inspecting }: { id: string; at: Point; relationship: string; text: React.ReactNode; aggregate: boolean; inspecting: boolean }) {
  const zoom = useStore(state => state.transform[2]);
  return <EdgeLabelRenderer>
    <div data-edge-id={id} data-inspecting={inspecting ? "true" : "false"} className={`nodrag nopan graph-relationship-label ${aggregate ? "graph-aggregate-label" : ""}`}
      style={{ position: "absolute", transform: `translate(-50%, -100%) translate(${at.x}px, ${at.y - 28 / Math.max(zoom, 0.16)}px)`, fontSize: 12.5 / Math.max(zoom, 0.16), pointerEvents: "none", whiteSpace: "nowrap" }}>
      <RelationshipBadge relationship={relationship}>{text}</RelationshipBadge>
    </div>
  </EdgeLabelRenderer>;
}

/** Relationship verb and evidence appear on hover, focus or selection only. */
export function CompactRelationshipEdge(props: EdgeProps) {
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const ref = useRef<SVGGElement>(null);
  useLayoutEffect(() => {
    const wrapper = ref.current?.closest(".react-flow__edge");
    const focus = () => setFocused(true), blur = () => setFocused(false);
    wrapper?.addEventListener("focus", focus);
    wrapper?.addEventListener("blur", blur);
    return () => { wrapper?.removeEventListener("focus", focus); wrapper?.removeEventListener("blur", blur); };
  }, []);
  const relationship = typeof props.data?.relationship === "string" ? props.data.relationship : "";
  const family = edgeFamily(relationship);
  const { path, mid } = compactEdgeCurve(props);
  const spine = props.data?.pathEmphasis === true;
  const inspecting = hovered || focused || Boolean(props.selected);
  // A roll-up link stands for many folded relationships; its count reads at rest, as a summary, not a verb.
  const aggregate = Boolean(props.data?.aggregate) && typeof props.label === "string";
  const text = (inspecting || aggregate) && props.data?.labelVisibility !== "hide"
    ? props.label ?? (relationship ? relationshipEdgeLabelText(relationship, props.data) : null) : null;
  const style = { stroke: edgeFamilyColor(family), strokeWidth: spine ? 2.4 : inspecting ? 2 : 1.4, opacity: spine || inspecting ? 1 : props.data?.passesBehind ? 0.4 : 0.85,
    strokeDasharray: edgeIsDashed(family, props.data) ? "6 4" : undefined, fill: "none" };
  return <g ref={ref} data-relationship={relationship || undefined} data-edge-family={family} data-label-disclosure={relationship === "vulnerable_to" ? "on-demand" : undefined} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
    {typeof props.data?.hoverDescription === "string" && <title>{props.data.hoverDescription}</title>}
    <BaseEdge id={props.id} path={path} style={style}
      {...(props.markerStart ? { markerStart: props.markerStart } : {})}
      {...(props.markerEnd ? { markerEnd: props.markerEnd } : {})}
      {...(props.interactionWidth !== undefined ? { interactionWidth: props.interactionWidth } : {})} />
    {text != null && <InspectLabel id={props.id} at={mid} relationship={relationship} text={text} aggregate={aggregate} inspecting={inspecting} />}
  </g>;
}
