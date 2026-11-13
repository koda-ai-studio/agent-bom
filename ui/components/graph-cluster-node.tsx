"use client";

import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";

import { severityWords, type ClusterMapNode } from "@/lib/graph-cluster-map";

export type ClusterCardData = { node: ClusterMapNode; narrow: boolean; onPage: (clusterId: string, offset: number) => void };
export type ClusterCardNode = Node<ClusterCardData>;

const tone = (word: string | null | undefined) => (word && ["critical", "high", "medium", "low"].includes(word) ? word : "none");

const SIDES = [["l", Position.Left], ["r", Position.Right], ["t", Position.Top], ["b", Position.Bottom]] as const;

/** Every side can start or end a bundle; the layout picks the facing pair per edge. */
function Handles(_props: { narrow: boolean }) {
  return <>{SIDES.flatMap(([id, position]) => [
    <Handle key={`s${id}`} id={id} type="source" position={position} isConnectable={false} />,
    <Handle key={`t${id}`} id={id} type="target" position={position} isConnectable={false} />,
  ])}</>;
}

/** A group: what it holds, how bad the worst of it is, and whether an attack path runs through it. */
export function ClusterGroupCard({ data }: NodeProps<ClusterCardNode>) {
  const { node, narrow } = data;
  const count = node.member_count ?? 0;
  const shown = node.expanded ? ` · ${node.shown_member_count ?? 0} shown` : "";
  const folded = node.folded_cluster_count ? ` in ${node.folded_cluster_count} groups` : "";
  return <div className="cluster-card" data-testid="cluster-group" data-tone={tone(node.worst_severity)} data-risky={Boolean(node.risky)} data-expanded={Boolean(node.expanded)}
    aria-label={`${node.label}: ${count.toLocaleString()} ${count === 1 ? "member" : "members"}, ${severityWords(node).toLowerCase()}. ${node.expanded ? "Collapse" : "Expand"}.`}>
    <Handles narrow={narrow} />
    <span className="cluster-card-title" title={node.label}>{node.label}</span>
    <span className="cluster-card-meta">{count.toLocaleString()} {count === 1 ? "member" : "members"}{folded}{shown}</span>
    <span className="cluster-card-meta">{severityWords(node)}</span>
    {(node.on_attack_path_count ?? 0) > 0 && <span className="cluster-card-path">{node.on_attack_path_count} on an attack path</span>}
  </div>;
}

/** One shown member of an expanded group; opening it investigates its connections. */
export function ClusterMemberCard({ data }: NodeProps<ClusterCardNode>) {
  const { node, narrow } = data;
  return <div className="cluster-card cluster-member" data-testid="cluster-member" data-tone={tone(node.severity)} data-focused={Boolean(node.focused)}
    aria-label={`${node.label}, ${(node.entity_type ?? "").replace(/_/g, " ")}, ${severityWords(node).toLowerCase()}${node.on_attack_path ? ", on an attack path" : ""}. Investigate.`}>
    <Handles narrow={narrow} />
    <span className="cluster-card-title" title={node.label}>{node.label}</span>
    <span className="cluster-card-meta">{(node.entity_type ?? "").replace(/_/g, " ")} · {node.on_attack_path ? "on an attack path" : severityWords(node)}</span>
  </div>;
}

/** The rest of an expanded group, paged in steps of the member limit. */
export function ClusterMoreCard({ data }: NodeProps<ClusterCardNode>) {
  const { node, narrow, onPage } = data;
  const clusterId = node.cluster_id ?? "";
  return <div className="cluster-card cluster-more" data-testid="cluster-more">
    <Handles narrow={narrow} />
    <span className="cluster-card-meta">{node.label}</span>
    <span className="flex gap-2">
      {node.prev_offset != null && <button type="button" className="nodrag" onClick={event => { event.stopPropagation(); onPage(clusterId, node.prev_offset!); }}>Previous</button>}
      {node.next_offset != null && <button type="button" className="nodrag" onClick={event => { event.stopPropagation(); onPage(clusterId, node.next_offset!); }}>Next {node.limit ?? ""}</button>}
    </span>
  </div>;
}

export const clusterNodeTypes = { cluster: ClusterGroupCard, member: ClusterMemberCard, more: ClusterMoreCard };
