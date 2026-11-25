import { storyLanePlacement } from "@/lib/graph-story-lanes";
import { assetKindLabel, assetServiceLabel } from "@/lib/asset-icon-registry";
import { COMPACT_GLYPH_SCALE } from "@/lib/graph-compact-glyph";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns, semanticLayer } from "@/lib/graph-semantic-columns";
import { INTERNET_ANCHOR_ID, internetExposure, withInternetAnchor } from "@/lib/graph-internet-context";
import { workloadImageContext } from "@/lib/graph-workload-image";
import { allEdgesModeled, edgeFamily, edgeFamilyColor } from "@/lib/graph-edge-family";
import { COMPACT_NODE_WIDTH, COMPACT_RANK_GAP, COMPACT_ROW_GAP, compactLayout } from "@/lib/graph-compact-layout";
import { canvasName, prosePreview } from "@/components/graph-compact-node";
import { captionGeometry } from "@/lib/graph-caption-geometry";
import { layoutFrameKey } from "@/lib/graph-compact-arcs";
import { linkEndFans } from "@/lib/graph-compact-fan";
import { enclosingEnvironment, exposureSpine, withoutFrames } from "@/lib/graph-exposure-spine";
import { MarkerType } from "@xyflow/react";

const DENSE_MAP_NODES = 24;
/** Small maps retain direction markers for hover, focus and explicit path inspection. */
const DIRECTION_MARKER_MAX_NODES = 16;
/** Clear space between a boundary frame and the cards inside it, and the room its title takes above them. */
const FRAME_PAD = 56;
const FRAME_TITLE = 72;
/** Height a card occupies under its position: glyph plus a caption of up to two lines. */
const CARD_HEIGHT = 240;
/** A map past one readable page has a tangle to quiet; smaller maps draw every connection. */
const QUIET_MIN_NODES = DENSE_MAP_NODES + 1;
export const SEMANTIC_COLUMN_GAP = COMPACT_RANK_GAP;
export const SEMANTIC_ROW_GAP = COMPACT_ROW_GAP;

function contextOwners(nodes: Node<LineageNodeData>[], edges: Edge[], primary: ReadonlySet<string>) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const owners = new Map<string, string>();
  for (const node of nodes) {
    if (primary.has(node.id) || !["package", "finding", "runtime_evidence"].includes(semanticLayer(node) ?? "")) continue;
    if (node.data.readingOwner && byId.has(node.data.readingOwner)) { owners.set(node.id, node.data.readingOwner); continue; }
    const candidates = new Set(edges.flatMap(edge => {
      const kind = String(edge.data?.relationship ?? "");
      if (edge.target === node.id && (["contains", "vulnerable_to", "exhibits_drift"].includes(kind) || kind === "depends_on" && semanticLayer(node) === "package")) return [edge.source];
      if (edge.source === node.id && kind === "affects") return [edge.target];
      return [];
    }).filter(id => id !== node.id));
    if (candidates.size === 1 && byId.has([...candidates][0]!)) owners.set(node.id, [...candidates][0]!);
  }
  return owners;
}

/** Display nodes drawn beside another node's rank rather than in a backend column. */
function attachedRanks(visible: Node<LineageNodeData>[], edges: Edge[], columns: Map<string, number>) {
  const ids = new Set(visible.map(node => node.id));
  const attached = new Map<string, { to: string; offset: number }>();
  const exposed = edges.filter(edge => edge.source === INTERNET_ANCHOR_ID && ids.has(edge.target)).map(edge => edge.target);
  // The anchor sits in its own column left of each exposed entry; when something already leads into the entry from the
  // column before (an account that contains the gateway), it shares that column instead, so no link into the entry
  // has to pass the anchor's caption.
  const layerOf = new Map(visible.map(node => [node.id, semanticLayer(node)]));
  // A source in a later column does not lead in: an agent hosted on the exposed workload sits right of it.
  const upstream = edges.filter(edge => exposed.includes(edge.target) && ids.has(edge.source) && edge.source !== INTERNET_ANCHOR_ID
    && layerOf.get(edge.source) !== "finding" && (columns.get(edge.source) ?? 0) <= (columns.get(edge.target) ?? 0)).map(edge => edge.source);
  if (ids.has(INTERNET_ANCHOR_ID) && exposed.length) attached.set(INTERNET_ANCHOR_ID, upstream.length
    ? { to: [...new Set(upstream)].join("\n"), offset: 0 } : { to: exposed.join("\n"), offset: -0.5 });
  for (const node of visible) {
    const owner = node.data.displayTargetId;
    if (node.type === "findingGroupNode" && node.data.displayOnly && owner && ids.has(owner)) attached.set(node.id, { to: owner, offset: 0.5 });
  }
  const adjacent = ownerAdjacent(visible, edges, columns);
  // A source file whose only links name moved packages sits one column before them, not at the far left.
  const sources = manifestSources(visible, edges, adjacent);
  for (const [id, owners] of adjacent) {
    const kept = owners.filter(owner => !sources.has(owner));
    if (!attached.has(id)) attached.set(id, { to: (kept.length ? kept : owners).join("\n"), offset: 1 });
  }
  for (const [id, packages] of sources) if (!attached.has(id)) attached.set(id, { to: packages.join("\n"), offset: -1 });
  return attached;
}

function manifestSources(visible: Node<LineageNodeData>[], edges: Edge[], moved: ReadonlyMap<string, string[]>) {
  const out = new Map<string, string[]>();
  for (const node of visible) {
    if (semanticLayer(node) !== "code") continue;
    const links = edges.filter(edge => edge.source !== edge.target && (edge.source === node.id || edge.target === node.id));
    const others = [...new Set(links.map(edge => edge.source === node.id ? edge.target : edge.source))];
    if (others.length && others.every(id => moved.has(id) && (moved.get(id)!.length > 1))) out.set(node.id, others.sort());
  }
  return out;
}

// An exposure inside one layer reads entry first, so the exposed node takes the next rank; a configuring file or job
// reads before what it configures, and an identity before the role it assumes.
const PARENT_FIRST = new Set(["contains", "hosts", "runs", "depends_on", "manages", "owns", "provides_tool", "exposed_to", "configures", "assumes"]);
const CHILD_FIRST = new Set(["part_of", "hosted_on", "belongs_to", "member_of"]);
/** Parent and child of a containment-like or exposure link inside one backend layer; any other link splits no rank. */
function containment(link: { source: string; target: string; data?: Record<string, unknown> | undefined }): [string, string] | null {
  const kind = String(link.data?.relationship ?? "");
  return PARENT_FIRST.has(kind) ? [link.source, link.target] : CHILD_FIRST.has(kind) ? [link.target, link.source] : null;
}

const OWNED_BY_TARGET = new Set(["contains", "depends_on", "hosts", "runs", "uses_framework", "imports"]);
const FINDING_LINKS = new Set(["vulnerable_to", "exhibits_drift"]);

/** A package sits one rank right of its nearest recorded owner or dependent, and a
 * finding one rank right of its asset, instead of across the canvas in their
 * backend column: their links stay short. The backend layer itself is unchanged. */
function ownerAdjacent(visible: Node<LineageNodeData>[], edges: Edge[], columns: Map<string, number>) {
  const layer = new Map(visible.map(node => [node.id, semanticLayer(node)]));
  const owners = new Map<string, string[]>();
  const add = (child: string, owner: string) => owners.set(child, [...(owners.get(child) ?? []), owner]);
  for (const edge of edges) {
    if (!layer.has(edge.source) || !layer.has(edge.target) || edge.source === edge.target) continue;
    const kind = String(edge.data?.relationship ?? "");
    if (layer.get(edge.target) === "package" && OWNED_BY_TARGET.has(kind) && layer.get(edge.source) !== "package") add(edge.target, edge.source);
    if (layer.get(edge.target) === "finding" && FINDING_LINKS.has(kind) && layer.get(edge.source) !== "finding") add(edge.target, edge.source);
    if (layer.get(edge.source) === "finding" && kind === "affects" && layer.get(edge.target) !== "finding") add(edge.source, edge.target);
  }
  const out = new Map<string, string[]>();
  for (const [id, list] of owners) {
    const nearest = Math.max(...list.map(owner => columns.get(owner) ?? 0));
    if (layer.get(id) === "package" && (columns.get(id) ?? 0) - nearest > 1) out.set(id, list);
  }
  // A finding branches right of its asset: always when that asset moved, else when the asset is more than a column away.
  for (const [id, list] of owners) {
    if (layer.get(id) !== "finding") continue;
    const nearest = Math.max(...list.map(owner => columns.get(owner) ?? 0));
    if (list.some(owner => out.has(owner)) || (columns.get(id) ?? 0) - nearest > 1) out.set(id, list);
  }
  return out;
}

/** The name a card draws: a prose finding shows its preview, an image its short digest. */
function shownName(node: Node<LineageNodeData> | undefined, id: string, roomy = false): string {
  const label = node?.data.label ?? id;
  return canvasName(node && semanticLayer(node) === "finding" ? prosePreview(label, roomy) : label);
}

/** Layout units one character of a name takes at the largest size the canvas draws it (the label ceiling). */
const CEILING_CHAR_UNITS = 36 * 0.88 * 0.6;
/** Identifier-like names (a CVE or GHSA id, a package) never end in an ellipsis: their box widens to fit
 * about 22 characters at any zoom. Names with spaces wrap inside the compact box instead. */
const IDENTIFIER_BOX_MAX = 440;
function cardWidth(node: Node<LineageNodeData> | undefined, id: string): number {
  if (!node || !["finding", "package"].includes(semanticLayer(node) ?? "")) return COMPACT_NODE_WIDTH;
  const name = shownName(node, id);
  if (name.includes(" ")) return COMPACT_NODE_WIDTH;
  return Math.round(Math.min(IDENTIFIER_BOX_MAX, Math.max(COMPACT_NODE_WIDTH, name.length * CEILING_CHAR_UNITS + 16)));
}

/** A card whose name wraps to two lines at the largest label size is about 206 units tall; with the clear space
 * between cards it needs this much room under its row, a little more than one row gap. */
/** Room under a two-line name: 236 layout units at the original 0.7 glyph, growing with the glyph so a larger
 * circle pushes its caption down without the caption reaching the card below. */
const TALL_CARD_ROOM = Math.ceil(236 + (COMPACT_GLYPH_SCALE - 0.7) * 200);
function twoLineName(node: Node<LineageNodeData> | undefined, id: string): boolean {
  // Wrap as the card does: between words, and inside an ordinary word after a hyphen or underscore.
  return captionGeometry({ name: shownName(node, id), box: cardWidth(node, id), nameChar: CEILING_CHAR_UNITS }).nameLines.length > 1;
}

/** The last few placements, by graph signature. Results are never mutated after layout. */
const LAYOUT_CACHE = new Map<string, ReturnType<typeof compactLayout>>();
const LAYOUT_CACHE_SIZE = 16;
function remember(signature: string, result: ReturnType<typeof compactLayout>) {
  LAYOUT_CACHE.set(signature, result);
  if (LAYOUT_CACHE.size > LAYOUT_CACHE_SIZE) LAYOUT_CACHE.delete(LAYOUT_CACHE.keys().next().value!);
  return result;
}

/** One left-to-right grammar for every canvas. The backend's selected path
 * owns row zero; every other branch fans around the nodes it connects to. */
export function semanticGraphLayout(nodes: Node<LineageNodeData>[], edges: Edge[], selectedPath?: readonly string[]) {
  // A layout may run again over its own output: drop the frame it drew and restore what framing hid.
  ({ nodes, edges } = withoutFrames(nodes, edges));
  ({ nodes, edges } = withInternetAnchor(nodes, edges));
  // On an exposure map, an environment or account holding everything drawn is a boundary around it, not a root
  // competing with the Internet; a map without the Internet keeps the scope as its first card.
  const frameOf = nodes.some(node => !node.hidden && (node.id === INTERNET_ANCHOR_ID || node.data.connectedScope)) ? enclosingEnvironment(nodes, edges) : null;
  if (frameOf) {
    nodes = nodes.map(node => node.id === frameOf.id ? { ...node, hidden: true, data: { ...node.data, framed: true } } : node);
    edges = edges.map(edge => !edge.hidden && (edge.source === frameOf.id || edge.target === frameOf.id) ? { ...edge, hidden: true, data: { ...edge.data, framed: true } } : edge);
  }
  const visible = nodes.filter(node => !node.hidden);
  const byId = new Map(nodes.map(node => [node.id, node]));
  let primary = selectedPath ?? visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  // With nothing selected, an exposed map reads from the Internet along its recorded links to the worst finding.
  if (!primary.length) primary = exposureSpine(visible, edges);
  if (primary.length && primary[0] !== INTERNET_ANCHOR_ID
    && internetExposure(visible.find(node => node.id === primary[0])?.data.attributes) === true) primary = [INTERNET_ANCHOR_ID, ...primary];
  const onPath = new Set(primary);
  // A map past one readable page keeps the zoom band, so an operator zooming out gets the summary renderer.
  const dense = visible.length > DENSE_MAP_NODES;
  const drawn = edges.filter(edge => !edge.hidden);
  const columns = semanticColumns(visible, drawn, primary);
  const owners = contextOwners(visible, edges, onPath);
  const images = workloadImageContext(visible, edges);
  for (const [id, owner] of images.owners) if (!onPath.has(id)) owners.set(id, owner);
  const arrange = storyLanePlacement(visible, drawn, primary);
  const readableStory = visible.some(node => node.data.connectedScope === true);
  const nameScale = arrange || readableStory ? 1 : 0.88;
  const base = { ids: visible.map(node => node.id), links: drawn, column: (id: string) => columns.get(id) ?? 0, containment,
    // Findings, and the group that folds an asset's findings, sit level with the asset they were found on.
    // A group whose asset is on the spine would sit on the spine's own row and block it, so it fans off the row instead.
    levelLeaf: (id: string) => { const found = byId.get(id); return Boolean(found) && (semanticLayer(found!) === "finding"
      || (found!.type === "findingGroupNode" && !onPath.has(String(found!.data.displayTargetId ?? "")))); },
    spine: primary, attached: attachedRanks(visible, drawn, columns), arrange };
  const boxes = new Map(visible.map(node => [node.id, Math.max(arrange || readableStory ? 300 : 0, cardWidth(node, node.id))]));
  // Placement depends only on the graph's structure and its captions; a re-render that changes nothing else reuses it.
  const signature = JSON.stringify([visible.map(node => [node.id, node.type, node.data.label, node.data.semanticLayer, node.data.readingLabel,
    node.data.displayTargetId, node.data.readingFindings?.count, internetExposure(node.data.attributes)]),
    drawn.map(edge => [edge.id, edge.source, edge.target, edge.data?.relationship, edge.data?.traversable]), primary, nameScale, readableStory, layoutFrameKey()]);
  const { positions, arcs, behind } = LAYOUT_CACHE.get(signature) ?? remember(signature, compactLayout({ ...base,
    caption: id => { const found = byId.get(id);
      if (found?.type === "findingGroupNode") return { name: `Findings (${found.data.readingFindings?.count ?? 0})`, typeLine: "Click to explore", nameScale, readableStory };
      return { name: shownName(found, id, Boolean(arrange)), nameScale, readableStory, typeLine: String(found?.data.readingLabel ?? found?.data.entityType ?? ""), box: boxes.get(id) ?? cardWidth(found, id) }; },
    width: id => boxes.get(id) ?? cardWidth(byId.get(id), id), tall: id => twoLineName(byId.get(id), id) ? TALL_CARD_ROOM : undefined }));
  const pathPairs = new Set(primary.slice(1).map((id, index) => `${primary[index]}\u0000${id}`));
  const fans = linkEndFans(drawn, positions);
  const modeledOnly = allEdgesModeled(drawn);
  const anchored = new Set(drawn.filter(edge => edge.source === INTERNET_ANCHOR_ID).map(edge => edge.target));
  // The Internet arrow takes the glyph's upper left when another link also enters that node, so the two
  // arrowheads never land on one point; nothing hangs above a glyph, so the entry clears every caption.
  const sharedInternetEntry = (edge: Edge) => !arrange && edge.source === INTERNET_ANCHOR_ID
    && drawn.some(other => other.target === edge.target && other.source !== INTERNET_ANCHOR_ID);
  // The exposure chain is coloured even when a pinned path leads the layout from elsewhere.
  const exposureChain = primary[0] === INTERNET_ANCHOR_ID ? primary : exposureSpine(visible, drawn);
  const exposurePairs = new Set(exposureChain.slice(1).map((id, index) => `${exposureChain[index]}\u0000${id}`));
  const resting = visible.length <= DIRECTION_MARKER_MAX_NODES;
  const frame = frameOf ? boundaryFrame(frameOf, visible, positions, boxes, edges.filter(edge => edge.data?.framed === true).length) : null;
  // The Internet stands outside the boundary, level with the first asset it reaches, so its arrow enters from the left.
  const anchorAt = positions.get(INTERNET_ANCHOR_ID);
  const entryAt = positions.get(drawn.find(edge => edge.source === INTERNET_ANCHOR_ID)?.target ?? "");
  // Without a boundary it takes the free slot one column before that asset, so its arrow stays short.
  // When other links already enter that asset from the left, it takes the slot a row above instead, clear of them.
  const entryId = drawn.find(edge => edge.source === INTERNET_ANCHOR_ID)?.target ?? "";
  // Only links arriving from the left compete for that slot; one entering from the right leaves it free.
  const crowdedEntry = drawn.some(edge => edge.target === entryId && edge.source !== INTERNET_ANCHOR_ID
    && (positions.get(edge.source)?.x ?? Infinity) < (entryAt?.x ?? -Infinity));
  const slot = entryAt ? { x: entryAt.x - SEMANTIC_COLUMN_GAP, y: entryAt.y - (crowdedEntry ? SEMANTIC_ROW_GAP : 0) } : null;
  const besideEntry = !frame && anchorAt && slot && ![...positions].some(([id, at]) => id !== INTERNET_ANCHOR_ID
    && Math.abs(at.x - slot.x) < SEMANTIC_COLUMN_GAP / 2 && Math.abs(at.y - slot.y) < SEMANTIC_ROW_GAP / 2) ? slot : null;
  const outside = arrange ? null : frame && anchorAt && entryAt ? { x: frame.position.x - SEMANTIC_COLUMN_GAP * 0.6 - COMPACT_NODE_WIDTH / 2, y: entryAt.y } : besideEntry;
  return {
    nodes: [...(frame ? [frame] : []), ...nodes.map(node => {
      const box = boxes.get(node.id) ?? cardWidth(node, node.id), placed = node.id === INTERNET_ANCHOR_ID && outside ? outside : positions.get(node.id);
      // A wider caption box stays centred on its rank, so its glyph lines up with the others.
      return { ...node, position: placed ? { x: placed.x - (box - COMPACT_NODE_WIDTH) / 2, y: placed.y } : node.position,
      style: { ...node.style, width: box, "--graph-node-name-scale": nameScale, "--graph-node-card-width": `${box}px` },
      data: { ...node.data, evidenceFlow: true, semanticLayout: true, roomyName: Boolean(arrange) || readableStory,
        ...(onPath.has(node.id) ? { semanticPathIndex: primary.indexOf(node.id) } : {}), renderBand: dense ? node.data.renderBand : "detail" as const,
        readingLabel: node.data.readingLabel ?? assetServiceLabel({ nodeType: node.data.nodeType, entityType: node.data.entityType, attributes: node.data.attributes, provider: node.data.dimensions?.cloud_provider }) ?? assetKindLabel({ nodeType: node.data.nodeType, entityType: node.data.entityType, attributes: node.data.attributes }),
        readingFinding: semanticLayer(node) === "finding",
        evidenceFlowContext: node.data.evidenceFlowContext ?? (semanticLayer(node) === "mcp_server" ? (() => {
          const clients = [...new Set(edges.filter(edge => edge.target === node.id && edge.data?.relationship === "uses"
            && byId.get(edge.source)?.data.semanticLayer === "orchestration").map(edge => byId.get(edge.source)!.data.label))].sort();
          return clients.length ? `Client: ${clients.join(", ")}` : "Client link not recorded";
        })() : undefined), semanticOwner: owners.get(node.id), readingOwner: semanticLayer(node) === "finding" ? owners.get(node.id) : undefined,
        imageSubrow: images.owners.has(node.id) && !onPath.has(node.id), evidenceSources: images.sources.get(node.id),
        semanticLayerIssue: semanticLayer(node) === null ? "Semantic layer unavailable" : undefined,
        highlighted: node.data.highlighted || onPath.has(node.id), ...(anchored.has(node.id) ? { internetAnchored: true } : {}) } };
    })],
    edges: edges.map((edge): Edge => {
      const uniformlyModeled = modeledOnly;
      const from = positions.get(edge.source), to = positions.get(edge.target);
      const reverse = Boolean(from && to && from.x > to.x);
      const sameRank = Boolean(from && to && from.x === to.x);
      // On a map with a tangle to quiet, a line that runs back or jumps a rank or a row waits for focus;
      // the selected path and every short forward link stay drawn.
      const roundabout = Boolean(from && to) && (reverse || Math.abs(to!.x - from!.x) > SEMANTIC_COLUMN_GAP * 1.5 || Math.abs(to!.y - from!.y) > SEMANTIC_ROW_GAP);
      const quietUntilFocus = visible.length >= QUIET_MIN_NODES && roundabout && !pathPairs.has(`${edge.source}\u0000${edge.target}`);
      const onExposure = edge.data?.rankedPathWitness !== false && (edge.data?.traversable !== false || edge.source === INTERNET_ANCHOR_ID && edge.data?.displayOnly === true) && exposurePairs.has(`${edge.source}\u0000${edge.target}`);
      const color = edgeFamilyColor(onExposure ? "exposure" : edgeFamily(String(edge.data?.relationship ?? "")));
      const marker = (value: Edge["markerEnd"]) => value && typeof value === "object" ? { ...value, color, width: 14, height: 14 } : value;
      // A small map shows which way every link runs; a larger one keeps the arrows its data recorded.
      // An aggregate or folded link may stand for several directions; it keeps only the arrow its data recorded.
      const directional = !edge.data?.aggregate && edge.data?.isClusterEdge !== true && typeof edge.data?.relationship === "string";
      const markerEnd = edge.markerEnd ?? (resting && directional ? { type: MarkerType.ArrowClosed } : undefined);
      return { ...edge, type: "compact", animated: false, ...(markerEnd ? { markerEnd: marker(markerEnd)! } : {}),
        ...(edge.markerStart ? { markerStart: marker(edge.markerStart)! } : {}), sourceHandle: reverse ? "context" : null,
        targetHandle: reverse || sameRank ? "context" : sharedInternetEntry(edge) ? "above" : null,
        data: { ...edge.data, ...(uniformlyModeled ? { uniformlyModeled } : {}), semanticLayout: true, individualLabel: true, arcDy: outside && edge.source === INTERNET_ANCHOR_ID ? undefined : arcs.get(edge.id), ...fans.get(edge.id), ...(quietUntilFocus ? { quietUntilFocus } : {}), passesBehind: behind.has(edge.id) || undefined, quietLabel: edge.data?.isClusterEdge !== true,
          pathEmphasis: edge.data?.rankedPathWitness !== false && edge.data?.traversable !== false && (pathPairs.has(`${edge.source}\u0000${edge.target}`) || edge.data?.pathEmphasis === true),
          ...(onExposure ? { exposurePath: true } : {}) } };
    }),
  };
}

/** A titled boundary behind every card the environment holds; the Internet stays outside it. */
function boundaryFrame(environment: Node<LineageNodeData>, visible: Node<LineageNodeData>[], positions: Map<string, { x: number; y: number }>,
  boxes: Map<string, number>, links: number): Node<LineageNodeData> | null {
  const inside = visible.filter(node => node.id !== INTERNET_ANCHOR_ID && positions.has(node.id));
  if (!inside.length) return null;
  const left = Math.min(...inside.map(node => positions.get(node.id)!.x - ((boxes.get(node.id) ?? COMPACT_NODE_WIDTH) - COMPACT_NODE_WIDTH) / 2));
  const right = Math.max(...inside.map(node => positions.get(node.id)!.x + ((boxes.get(node.id) ?? COMPACT_NODE_WIDTH) + COMPACT_NODE_WIDTH) / 2));
  const top = Math.min(...inside.map(node => positions.get(node.id)!.y));
  const bottom = Math.max(...inside.map(node => positions.get(node.id)!.y)) + CARD_HEIGHT;
  const x = left - FRAME_PAD, y = top - FRAME_PAD - FRAME_TITLE;
  return { id: `display:frame:${environment.id}`, type: "boundaryFrame", position: { x, y }, draggable: false, selectable: false, focusable: false, zIndex: -1,
    ariaLabel: `${environment.data.label}: environment boundary`,
    style: { width: right - left + FRAME_PAD * 2, height: bottom - top + FRAME_PAD * 2 + FRAME_TITLE },
    data: { ...environment.data, displayOnly: true, frameFor: environment.id, frameLinks: links } };
}
