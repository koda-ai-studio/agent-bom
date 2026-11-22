"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { BaseEdge, EdgeLabelRenderer, Position, useInternalNode, useStore, type EdgeProps } from "@xyflow/react";
import { RelationshipBadge } from "@/components/relationship-edge";
import { edgeFamily, edgeFamilyColor, edgeIsDashed } from "@/lib/graph-edge-family";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";

type Point = { x: number; y: number };

function control(point: Point, position: Position, offset: number): Point {
  if (position === Position.Left) return { x: point.x - offset, y: point.y };
  if (position === Position.Right) return { x: point.x + offset, y: point.y };
  if (position === Position.Top) return { x: point.x, y: point.y - offset };
  return { x: point.x, y: point.y + offset };
}

type LanePoint = { dx: number; dy: number; half?: number };
const isLane = (value: unknown): value is LanePoint[] => Array.isArray(value) && value.every(p => typeof p?.dx === "number" && typeof p?.dy === "number");

/** A link that skips ranks runs level through each reserved lane slot, joined by
 * horizontal-tangent curves: one smooth line that never cuts a neighbouring card. */
function laneCurve(source: Point, target: Point, lane: LanePoint[], sourceCentreX: number) {
  const glyphHalf = Math.abs(source.x - sourceCentreX), direction = Math.sign(target.x - source.x) || 1;
  // The lane holds its slot's whole card width, so it only turns in the gaps between cards.
  const slots = lane.flatMap(p => {
    const x = sourceCentreX + p.dx, y = source.y + p.dy, half = p.half ?? glyphHalf;
    return [{ x: x - direction * half, y }, { x: x + direction * half, y }];
  });
  const points = [source, ...slots, target];
  const segments = points.slice(1).map((q, i) => {
    const p = points[i]!, mid = (q.x - p.x) / 2;
    return p.y === q.y ? `L ${q.x},${q.y}` : `C ${p.x + mid},${p.y} ${q.x - mid},${q.y} ${q.x},${q.y}`;
  });
  const m = Math.floor(points.length / 2);
  return { path: `M ${source.x},${source.y} ${segments.join(" ")}`, mid: { x: (points[m - 1]!.x + points[m]!.x) / 2, y: (points[m - 1]!.y + points[m]!.y) / 2 } };
}

/** One smooth curve between the two handles; never routed through a gutter. */
export function compactEdgeCurve(props: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition"> & { data?: EdgeProps["data"] }, sourceCentreX?: number) {
  const source = { x: props.sourceX, y: props.sourceY }, target = { x: props.targetX, y: props.targetY };
  if (sourceCentreX !== undefined && isLane(props.data?.lanePoints) && props.data.lanePoints.length && !props.data.phoneLayout) return laneCurve(source, target, props.data.lanePoints, sourceCentreX);
  // Each end leaves along its handle: a side handle by half the horizontal run, a top/bottom handle by half the vertical run.
  const sameSide = props.sourcePosition === props.targetPosition;
  const dx = Math.abs(target.x - source.x), dy = Math.abs(target.y - source.y);
  const upright = (position: Position) => position === Position.Top || position === Position.Bottom;
  const reach = (position: Position) => sameSide ? Math.max(110, dy * 0.3) : upright(position) ? Math.max(24, dy * 0.5) : Math.max(24, dx * 0.5);
  let c1 = control(source, props.sourcePosition, reach(props.sourcePosition)), c2 = control(target, props.targetPosition, reach(props.targetPosition));
  // One upright end and one side end: run along the upright axis, then turn into the side.
  if (upright(props.sourcePosition) && !upright(props.targetPosition)) { c1 = { x: source.x, y: source.y + (target.y - source.y) * 0.75 }; c2 = { x: source.x, y: target.y }; }
  if (!upright(props.sourcePosition) && upright(props.targetPosition)) { c1 = { x: target.x, y: source.y }; c2 = { x: target.x, y: target.y - (target.y - source.y) * 0.75 }; }
  const mid = { x: (source.x + 3 * c1.x + 3 * c2.x + target.x) / 8, y: (source.y + 3 * c1.y + 3 * c2.y + target.y) / 8 };
  return { path: `M ${source.x},${source.y} C ${c1.x},${c1.y} ${c2.x},${c2.y} ${target.x},${target.y}`, mid };
}

/** An inspected link names its relationship and evidence in full. */
function InspectLabel({ id, at, relationship, text }: { id: string; at: Point; relationship: string; text: React.ReactNode }) {
  const zoom = useStore(state => state.transform[2]);
  return <EdgeLabelRenderer>
    <div data-edge-id={id} data-inspecting="true" className="nodrag nopan graph-relationship-label"
      style={{ position: "absolute", transform: `translate(-50%, -50%) translate(${at.x}px, ${at.y}px)`, fontSize: 12.5 / Math.max(zoom, 0.16), pointerEvents: "none", whiteSpace: "nowrap" }}>
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
  const sourceNode = useInternalNode(props.source);
  const sourceCentreX = sourceNode?.measured.width ? sourceNode.internals.positionAbsolute.x + sourceNode.measured.width / 2 : undefined;
  const { path, mid } = compactEdgeCurve(props, sourceCentreX);
  const spine = props.data?.pathEmphasis === true;
  const inspecting = hovered || focused || Boolean(props.selected);
  const text = inspecting && props.data?.labelVisibility !== "hide"
    ? props.label ?? (relationship ? relationshipEdgeLabelText(relationship, props.data) : null) : null;
  const style = { stroke: edgeFamilyColor(family), strokeWidth: spine ? 2.4 : inspecting ? 2 : 1.4, opacity: spine || inspecting ? 1 : 0.78,
    strokeDasharray: edgeIsDashed(family, props.data) ? "6 4" : undefined, fill: "none" };
  return <g ref={ref} data-relationship={relationship || undefined} data-edge-family={family} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
    {typeof props.data?.hoverDescription === "string" && <title>{props.data.hoverDescription}</title>}
    <BaseEdge id={props.id} path={path} style={style}
      {...(props.markerStart ? { markerStart: props.markerStart } : {})}
      {...(props.markerEnd ? { markerEnd: props.markerEnd } : {})}
      {...(props.interactionWidth !== undefined ? { interactionWidth: props.interactionWidth } : {})} />
    {text != null && <InspectLabel id={props.id} at={mid} relationship={relationship} text={text} />}
  </g>;
}
