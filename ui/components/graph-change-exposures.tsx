"use client";

import Link from "next/link";

import { ExposureGroup } from "@/components/graph-change-exposure-group";
import type { GraphEstateHighlightNode, GraphEstateHighlights, GraphEstatePathChange } from "@/lib/api-types";
import { changedNodeHref, changedPathInvestigationHref } from "@/lib/graph-estate-changes";

type Handlers = {
  onInvestigateNode?: ((id: string, label: string) => void) | undefined;
  /** Opens this source's paged full diff, for rows beyond the returned top rows. */
  onOpenDiff?: (() => void) | undefined;
};

type Endpoints = { source?: string | undefined; target?: string | undefined; source_label?: string | undefined; target_label?: string | undefined };

const ROW = "flex items-start justify-between gap-2 text-xs text-ink-secondary";
const TEXT = "min-w-0 break-words [overflow-wrap:anywhere]";
const ACTION = "shrink-0 text-foreground underline underline-offset-4";

const endName = (label: string | undefined, id: string | undefined) => label?.trim() || id || "unnamed";
const pathLabel = (path: Endpoints) => `${endName(path.source_label, path.source)} → ${endName(path.target_label, path.target)}`;
const pathKey = (path: GraphEstatePathChange) => path.hops.join(">");
const nodeKey = (node: GraphEstateHighlightNode) => node.id ?? node.label ?? `${node.source}>${node.target}`;
const nodeLabel = (node: GraphEstateHighlightNode) => (node.kind === "edge" ? pathLabel(node) : node.label || node.id || "unnamed");
/** The entity to focus: the node itself, or a relationship's source endpoint. */
const nodeFocus = (node: GraphEstateHighlightNode) => (node.kind === "edge" ? node.source : node.id);

/** Both endpoints by display name; the raw id is each name's tooltip. */
function EndpointNames({ path }: { path: Endpoints }) {
  return (
    <>
      <span title={path.source}>{endName(path.source_label, path.source)}</span>
      {" → "}
      <span title={path.target}>{endName(path.target_label, path.target)}</span>
    </>
  );
}

function NodeText({ node }: { node: GraphEstateHighlightNode }) {
  if (node.kind !== "edge") return <span className={TEXT}>{nodeLabel(node)}</span>;
  return (
    <span className={TEXT}>
      <EndpointNames path={node} />
      {node.relationship && <span className="text-ink-tertiary"> · {node.relationship.replaceAll("_", " ")}</span>}
    </span>
  );
}

function AddedNodeRow({ node, onInvestigateNode }: { node: GraphEstateHighlightNode } & Handlers) {
  const label = nodeLabel(node);
  return (
    <div className={ROW}>
      <NodeText node={node} />
      {node.id && onInvestigateNode && (
        <button type="button" aria-label={`Investigate ${label}`} onClick={() => onInvestigateNode(node.id!, label)} className={ACTION}>Investigate</button>
      )}
    </div>
  );
}

/** A removed node exists only in the previous snapshot, so it opens there. */
function RemovedNodeRow({ node, previousScanId }: { node: GraphEstateHighlightNode; previousScanId?: string | undefined }) {
  const label = nodeLabel(node);
  const focus = nodeFocus(node);
  return (
    <div className={ROW}>
      <NodeText node={node} />
      {previousScanId && focus && (
        <Link href={changedNodeHref(focus, node.kind === "edge" ? endName(node.source_label, node.source) : label, previousScanId)}
          aria-label={`Open removed control ${label} in the previous snapshot`} className={ACTION}>Open</Link>
      )}
    </div>
  );
}

function PathRow({ path, href, actionLabel, action }: { path: GraphEstatePathChange; href: string | null; actionLabel: string; action: string }) {
  return (
    <div className={ROW}>
      <span className={TEXT}>
        <span className="font-medium text-foreground"><EndpointNames path={path} /></span>
        <span className="text-ink-tertiary"> · {path.hops.length - 1} {path.hops.length === 2 ? "hop" : "hops"} · risk {path.composite_risk.toFixed(1)}</span>
      </span>
      {href && <Link href={href} aria-label={actionLabel} className={ACTION}>{action}</Link>}
    </div>
  );
}

/**
 * New and removed exposure for one compared source. New rows open in `scanId`,
 * the snapshot that recorded them; removed rows open in `previousScanId`, the
 * snapshot that still held them.
 */
export function GraphChangeExposures({ highlights, scanId, previousScanId, onInvestigateNode, onOpenDiff }: {
  highlights: GraphEstateHighlights; scanId?: string | undefined; previousScanId?: string | undefined;
} & Handlers) {
  const findings = highlights.new_critical_findings;
  const added = highlights.new_attack_paths;
  const removed = highlights.removed_attack_paths;
  const controls = highlights.removed_controls;
  const reach = highlights.new_credential_reach;
  const any = [findings, added, removed, controls, reach].some(group => group && group.count > 0);
  if (!any) return null;
  return (
    <div data-testid="graph-changes-exposure" className="space-y-2 rounded-lg border border-outline bg-surface/70 p-2">
      {findings && findings.count > 0 && (
        <ExposureGroup title="New critical finding nodes" count={findings.count} tone="added" rows={findings.top} rowKey={nodeKey} onOpenDiff={onOpenDiff}
          renderRow={node => <AddedNodeRow node={node} onInvestigateNode={onInvestigateNode} />} />
      )}
      {added && added.count > 0 && (
        <ExposureGroup title="New attack paths" count={added.count} lowerBound={added.count_is_lower_bound} tone="added" rows={added.top} rowKey={pathKey}
          onOpenDiff={onOpenDiff}
          renderRow={path => <PathRow path={path} href={changedPathInvestigationHref(path, scanId)} action="Investigate"
            actionLabel={`Investigate path ${pathLabel(path)}`} />} />
      )}
      {reach && reach.count > 0 && (
        <ExposureGroup title="New credential reach" count={reach.count} tone="added" rows={reach.top} rowKey={nodeKey} onOpenDiff={onOpenDiff}
          renderRow={edge => <div className={`${TEXT} text-xs text-ink-secondary`}><EndpointNames path={edge} /></div>} />
      )}
      {removed && removed.count > 0 && (
        <ExposureGroup title="Removed attack paths" count={removed.count} lowerBound={removed.count_is_lower_bound} tone="removed" rows={removed.top}
          rowKey={pathKey} onOpenDiff={onOpenDiff}
          renderRow={path => <PathRow path={path} href={previousScanId ? changedPathInvestigationHref(path, previousScanId) : null} action="Open"
            actionLabel={`Open removed path ${pathLabel(path)} in the previous snapshot`} />} />
      )}
      {controls && controls.count > 0 && (
        <ExposureGroup title="Removed controls" count={controls.count} tone="removed" rows={controls.top} rowKey={nodeKey} onOpenDiff={onOpenDiff}
          renderRow={node => <RemovedNodeRow node={node} previousScanId={previousScanId} />} />
      )}
    </div>
  );
}
