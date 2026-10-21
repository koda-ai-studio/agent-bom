"use client";

import Link from "next/link";

import type { GraphEstateHighlightNode, GraphEstateHighlights, GraphEstatePathChange } from "@/lib/api-types";
import { changedPathInvestigationHref } from "@/lib/graph-estate-changes";

const PREVIEW = 3;

type Handlers = {
  onInvestigateNode?: ((id: string, label: string) => void) | undefined;
};

type Endpoints = { source?: string | undefined; target?: string | undefined; source_label?: string | undefined; target_label?: string | undefined };

const endName = (label: string | undefined, id: string | undefined) => label?.trim() || id || "unnamed";
const pathLabel = (path: Endpoints) => `${endName(path.source_label, path.source)} → ${endName(path.target_label, path.target)}`;

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

function Group({ title, count, lowerBound, tone, children }: {
  title: string; count: number; lowerBound?: boolean | undefined; tone: "added" | "removed"; children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <p className={`text-xs font-medium ${tone === "added" ? "text-red-700 dark:text-red-200" : "text-emerald-700 dark:text-emerald-300"}`}>
        {title} · {count.toLocaleString()}{lowerBound ? "+" : ""}
      </p>
      <ul className="space-y-1">{children}</ul>
    </div>
  );
}

function NodeRow({ node, drill, onInvestigateNode }: { node: GraphEstateHighlightNode; drill: boolean } & Handlers) {
  const label = node.label || node.id || "unnamed";
  return (
    <li className="flex items-start justify-between gap-2 text-xs text-ink-secondary">
      <span className="min-w-0 break-words [overflow-wrap:anywhere]">{label}</span>
      {drill && node.id && onInvestigateNode && (
        <button type="button" aria-label={`Investigate ${label}`} onClick={() => onInvestigateNode(node.id!, label)}
          className="shrink-0 text-foreground underline underline-offset-4">Investigate</button>
      )}
    </li>
  );
}

function PathRow({ path, drill, scanId }: { path: GraphEstatePathChange; drill: boolean; scanId?: string | undefined }) {
  return (
    <li className="flex items-start justify-between gap-2 text-xs text-ink-secondary">
      <span className="min-w-0 break-words [overflow-wrap:anywhere]">
        <span className="font-medium text-foreground"><EndpointNames path={path} /></span>
        <span className="text-ink-tertiary"> · {path.hops.length - 1} {path.hops.length === 2 ? "hop" : "hops"} · risk {path.composite_risk.toFixed(1)}</span>
      </span>
      {drill && (
        <Link href={changedPathInvestigationHref(path, scanId)} aria-label={`Investigate path ${pathLabel(path)}`}
          className="shrink-0 text-foreground underline underline-offset-4">Investigate</Link>
      )}
    </li>
  );
}

/** New and removed exposure for one compared source; a new path opens in the path queue of `scanId`, the snapshot that recorded it. */
export function GraphChangeExposures({ highlights, scanId, onInvestigateNode }: { highlights: GraphEstateHighlights; scanId?: string | undefined } & Handlers) {
  const findings = highlights.new_critical_findings;
  const added = highlights.new_attack_paths;
  const removed = highlights.removed_attack_paths;
  const controls = highlights.removed_controls;
  const reach = highlights.new_credential_reach;
  const any = [findings, added, removed, controls, reach].some(group => group && group.count > 0);
  if (!any) return null;
  return (
    <div data-testid="graph-changes-exposure" className="space-y-2 rounded-lg border border-outline bg-surface/70 p-2">
      {findings && findings.count > 0 && <Group title="New critical finding nodes" count={findings.count} tone="added">
        {findings.top.slice(0, PREVIEW).map(node => <NodeRow key={node.id ?? node.label} node={node} drill onInvestigateNode={onInvestigateNode} />)}
      </Group>}
      {added && added.count > 0 && <Group title="New attack paths" count={added.count} lowerBound={added.count_is_lower_bound} tone="added">
        {added.top.slice(0, PREVIEW).map(path => <PathRow key={path.hops.join(">")} path={path} drill scanId={scanId} />)}
      </Group>}
      {reach && reach.count > 0 && <Group title="New credential reach" count={reach.count} tone="added">
        {reach.top.slice(0, PREVIEW).map(edge => (
          <li key={`${edge.source}>${edge.target}`} className="min-w-0 break-words text-xs text-ink-secondary [overflow-wrap:anywhere]">
            <EndpointNames path={edge} />
          </li>
        ))}
      </Group>}
      {removed && removed.count > 0 && <Group title="Removed attack paths" count={removed.count} lowerBound={removed.count_is_lower_bound} tone="removed">
        {removed.top.slice(0, PREVIEW).map(path => <PathRow key={path.hops.join(">")} path={path} drill={false} />)}
      </Group>}
      {controls && controls.count > 0 && <Group title="Removed controls" count={controls.count} tone="removed">
        {controls.top.slice(0, PREVIEW).map(node => <NodeRow key={node.id ?? node.label} node={node} drill={false} />)}
      </Group>}
    </div>
  );
}
