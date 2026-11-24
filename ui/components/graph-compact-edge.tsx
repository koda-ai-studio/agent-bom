"use client";

import { COMPACT_GLYPH_SCALE } from "@/lib/graph-compact-glyph";
import { useLayoutEffect, useRef, useState } from "react";
import { BaseEdge, EdgeLabelRenderer, Position, useStore, type EdgeProps } from "@xyflow/react";
import { RelationshipBadge } from "@/components/relationship-edge";
import { edgeFamily, edgeFamilyColor, edgeIsDashed } from "@/lib/graph-edge-family";
import { ARC_REACH } from "@/lib/graph-compact-arcs";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";

/** A resting label clears the largest drawn glyph (the small-graph circle) plus a gap, so it never sits on a card. */
const LABEL_RISE = Math.max(28, Math.ceil((66 * COMPACT_GLYPH_SCALE) / 2) + 8);

type Point = { x: number; y: number };

function control(point: Point, position: Position, offset: number): Point {
  if (position === Position.Left) return { x: point.x - offset, y: point.y };
  if (position === Position.Right) return { x: point.x + offset, y: point.y };
  if (position === Position.Top) return { x: point.x, y: point.y - offset };
  return { x: point.x, y: point.y + offset };
}

/** One smooth curve between the two handles; never routed through a gutter. */
/** How far a phone's same-side link bows out from its handles, in layout units: under half the gap between portrait columns. */
const PHONE_SIDE_REACH = 44;

export function compactEdgeCurve(props: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition"> & { data?: EdgeProps["data"] }) {
  // Several links meeting one side of a glyph end a few units apart (the layout's fan), never on one point.
  const fan = (value: unknown) => typeof value === "number" && Number.isFinite(value) && !props.data?.phoneLayout ? value : 0;
  const source = { x: props.sourceX, y: props.sourceY + fan(props.data?.sourceFan) }, target = { x: props.targetX, y: props.targetY + fan(props.data?.targetFan) };
  // Each end leaves along its handle: a side handle by 45% of the horizontal run, a top/bottom handle by half the vertical run.
  const sameSide = props.sourcePosition === props.targetPosition;
  const dx = Math.abs(target.x - source.x), dy = Math.abs(target.y - source.y);
  const upright = (position: Position) => position === Position.Top || position === Position.Bottom;
  // On a phone a same-side link runs close beside its column, inside the gap before the next column's cards.
  const sideReach = props.data?.phoneLayout ? PHONE_SIDE_REACH : Math.max(110, dy * 0.3);
  const reach = (position: Position) => sameSide ? sideReach : upright(position) ? Math.max(24, dy * 0.5) : Math.max(24, dx * ARC_REACH);
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
function InspectLabel({ id, at, relationship, text, aggregate, inspecting, shift = 0 }: { id: string; at: Point; relationship: string; text: React.ReactNode; aggregate: boolean; inspecting: boolean; shift?: number }) {
  const zoom = useStore(state => state.transform[2]);
  // On a phone the label sits beside the link, on the side away from the captions, rather than over it.
  const anchor = shift > 0 ? `translate(${8 / Math.max(zoom, 0.16)}px, -50%) translate(${at.x}px, ${at.y}px)`
    : shift < 0 ? `translate(calc(-100% - ${8 / Math.max(zoom, 0.16)}px), -50%) translate(${at.x}px, ${at.y}px)`
    : `translate(-50%, -100%) translate(${at.x}px, ${at.y - LABEL_RISE / Math.max(zoom, 0.16)}px)`;
  return <EdgeLabelRenderer>
    <div data-edge-id={id} data-inspecting={inspecting ? "true" : "false"} className={`nodrag nopan graph-relationship-label ${aggregate ? "graph-aggregate-label" : ""}`}
      style={{ position: "absolute", transform: anchor, fontSize: 12.5 / Math.max(zoom, 0.16), pointerEvents: "none", whiteSpace: "nowrap" }}>
      <RelationshipBadge relationship={relationship}>{text}</RelationshipBadge>
    </div>
  </EdgeLabelRenderer>;
}

const STUB_LENGTH = 40;

/** A link with an end outside the frame: a short stub leaving the visible end along its handle. */
function stubCurve(props: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">, offscreen: number, length: number) {
  const source = { x: props.sourceX, y: props.sourceY }, target = { x: props.targetX, y: props.targetY };
  if (offscreen === 3) return { path: `M ${source.x},${source.y}`, mid: source };
  if (offscreen === 2) {
    const end = control(source, props.sourcePosition, length);
    return { path: `M ${source.x},${source.y} L ${end.x},${end.y}`, mid: end };
  }
  const start = control(target, props.targetPosition, length);
  return { path: `M ${start.x},${start.y} L ${target.x},${target.y}`, mid: start };
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
  const inspecting = hovered || focused || Boolean(props.selected);
  // Which ends lie outside the current frame (1 source, 2 target), so a link to an off-screen node
  // reads as a short stub at its visible end instead of a full-height line across the frame.
  const offscreen = useStore(state => {
    const [x, y, zoom] = state.transform;
    const out = (px: number, py: number) => { const sx = px * zoom + x, sy = py * zoom + y; return sx < -8 || sy < -8 || sx > state.width + 8 || sy > state.height + 8; };
    return (out(props.sourceX, props.sourceY) ? 1 : 0) + (out(props.targetX, props.targetY) ? 2 : 0);
  });
  const zoom = useStore(state => offscreen ? state.transform[2] : 1);
  const stubbed = offscreen > 0 && !inspecting;
  const { path, mid } = stubbed ? stubCurve(props, offscreen, STUB_LENGTH / Math.max(zoom, 0.05)) : compactEdgeCurve(props);
  const spine = props.data?.pathEmphasis === true;
  // A roll-up or folded-group link stands for many relationships; its count reads at rest, as a summary.
  // A roll-up link's folded count comes from its recorded aggregate when no text label reached the edge.
  const folded = props.data?.aggregate && typeof (props.data.aggregate as { count?: unknown }).count === "number" ? (props.data.aggregate as { count: number }).count : null;
  const full = props.label ?? (folded !== null ? `${folded.toLocaleString()} relationship${folded === 1 ? "" : "s"}` : null)
    ?? (relationship ? relationshipEdgeLabelText(relationship, props.data) : null);
  const aggregate = Boolean(props.data?.aggregate || props.data?.isClusterEdge) && (typeof props.label === "string" || typeof full === "string");
  // At rest a folded group link shows only its count (×N); its relationship and evidence read on inspection.
  const count = !inspecting && props.data?.isClusterEdge && typeof full === "string" ? full.match(/×\d+/)?.[0] ?? null : null;
  // A link standing for a single relationship carries no summary worth reading at rest; it names itself on inspection.
  const restingSummary = aggregate && (folded === null || folded > 1);
  // A focused attack path names each hop's relationship at rest, as the path card does.
  const text = (inspecting || restingSummary || props.data?.pathLabel === true) && props.data?.labelVisibility !== "hide" ? count ?? full : null;
  const style = { stroke: edgeFamilyColor(family), strokeWidth: spine ? 3.2 : inspecting ? 2.8 : 2.2, opacity: spine || inspecting ? 1 : stubbed || props.data?.passesBehind ? 0.4 : 0.95,
    strokeDasharray: edgeIsDashed(family, props.data) ? "6 4" : undefined, fill: "none" };
  return <g ref={ref} data-relationship={relationship || undefined} data-edge-family={family} data-edge-stub={stubbed || undefined} data-label-disclosure={relationship === "vulnerable_to" ? "on-demand" : undefined} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
    {typeof props.data?.hoverDescription === "string" && <title>{props.data.hoverDescription}</title>}
    {/* A canvas-coloured underlay: where two links cross, the later one cuts a gap through the other, so each reads as one line. */}
    {!stubbed && <path d={path} aria-hidden="true" data-edge-underlay="" style={{ stroke: "var(--graph-canvas)", strokeWidth: style.strokeWidth + 5, fill: "none", pointerEvents: "none" }} />}
    <BaseEdge id={props.id} path={path} style={style}
      {...(props.markerStart ? { markerStart: props.markerStart } : {})}
      {...(props.markerEnd && !(stubbed && offscreen & 2) ? { markerEnd: props.markerEnd } : {})}
      {...(props.interactionWidth !== undefined ? { interactionWidth: props.interactionWidth } : {})} />
    {text != null && <InspectLabel id={props.id} at={mid} relationship={relationship} text={text} aggregate={aggregate} inspecting={inspecting} shift={Number(props.data?.labelShift ?? 0)} />}
  </g>;
}
