"use client";

import Link from "next/link";
import { GraphFindingContext } from "@/components/graph-finding-context";
import { GraphScopeDetail } from "@/components/graph-scope-detail";
import type { GraphNodeDetailResponse } from "@/lib/api-types";
import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Loader2, Network, Radar } from "lucide-react";

import { GraphRecordedRelationships, GraphRecordedRelationshipScope } from "@/components/graph-recorded-relationships";
import { AdminAssessment } from "@/components/graph-admin-assessment";
import { GraphConsequencePanel } from "@/components/graph-consequence-panel";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { BlastRadiusButton } from "@/components/lineage-detail/overview";
import { NodePathsLink } from "@/components/node-paths-link";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { api } from "@/lib/api";
import {
  evidenceTierLabel,
  mergeGraphNodeDetail,
  nodeIdFromLineageData,
  resolveInvestigationNextAction,
  semanticLayerForNodeType,
} from "@/lib/graph-entity-detail";

/**
 * Shared investigation entity drawer used by security-graph, lineage, mesh,
 * and context lenses. Composes LineageDetailPanel with rubric fields
 * (stable ID, semantic layer, evidence tier, in/out counts, next action)
 * and optional expand / impact actions against the live graph API.
 */
export function GraphEntityDrawer({
  data,
  onClose,
  scanId,
  variant = "overlay",
  onShowBlastRadius,
  blastRadiusActive = false,
  blastRadiusLoading = false,
  onInspectNode,
  onExpandNeighbors,
  onOpenScope,
  onShowImpact,
  remediationHref,
  enrich = true,
  suppliedDetail,
}: {
  data: LineageNodeData;
  onClose: () => void;
  scanId?: string | undefined;
  variant?: "overlay" | "inline" | "docked";
  onShowBlastRadius?: (() => void) | undefined;
  blastRadiusActive?: boolean;
  blastRadiusLoading?: boolean;
  onInspectNode?: ((nodeId: string) => void) | undefined;
  onOpenScope?: (() => void) | undefined;
  onExpandNeighbors?: (() => void) | undefined;
  onShowImpact?: (() => void) | undefined;
  remediationHref?: string | undefined;
  /** When true and scanId is set, refresh node detail from /v1/graph/node. */
  enrich?: boolean;
  /** A parent-owned request; null means pending/unavailable, undefined fetches locally. */
  suppliedDetail?: GraphNodeDetailResponse | null;
}) {
  const [loading, setLoading] = useState(false);
  const nodeId = nodeIdFromLineageData(data);

  const [loadedDetail, setLoadedDetail] = useState<{
    scanId: string;
    response: GraphNodeDetailResponse;
  } | null>(null);
  // Canvas and detail requests may finish in either order. Reapply the richer
  // evidence to each canvas update, but only for the same node and snapshot.
  const localDetail = enrich && loadedDetail && loadedDetail.scanId === scanId && loadedDetail.response.node.id === nodeId
    ? loadedDetail.response : null;
  const detail = suppliedDetail === undefined ? localDetail : suppliedDetail?.node.id === nodeId ? suppliedDetail : null;
  const enriched = useMemo(() => detail ? mergeGraphNodeDetail(data, detail) : data, [data, detail]);

  useEffect(() => {
    setLoadedDetail(null);
    setLoading(false);
    if (suppliedDetail !== undefined || data.rollup?.is_container || data.rollup?.has_children || !enrich || !scanId || !nodeId) return;
    let cancelled = false;
    setLoading(true);
    void api
      .getGraphNode(nodeId, scanId)
      .then((detail) => {
        if (cancelled) return;
        setLoadedDetail({ scanId, response: detail });
      })
      .catch(() => {
        /* keep canvas-local fields when detail fetch fails */
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [data.rollup, enrich, nodeId, scanId, suppliedDetail]);

  const layer = useMemo(
    () => semanticLayerForNodeType(enriched.nodeType, enriched.entityType),
    [enriched.nodeType, enriched.entityType],
  );
  const nextAction = useMemo(
    () =>
      resolveInvestigationNextAction(enriched, {
        scanId,
        remediationHref,
      }),
    [enriched, remediationHref, scanId],
  );
  const evidenceLabel = evidenceTierLabel(enriched);
  if (data.rollup && (data.rollup.is_container || data.rollup.has_children)) return <GraphScopeDetail item={data.rollup} onClose={onClose} onOpenScope={onOpenScope} onInspectRelationships={onExpandNeighbors} scanId={scanId} docked={variant === "docked"} />;

  const relationshipSlot = enrich && scanId && nodeId
    ? <GraphRecordedRelationships key={`${scanId}:${nodeId}`} scanId={scanId} nodeId={nodeId} onInspectNode={onInspectNode} />
    : undefined;
  const showNextAction = nextAction.label !== "Inspect in lineage";

  const locationValue = (...keys: string[]) => {
    for (const key of keys) {
      const value = enriched.attributes?.[key];
      if (typeof value === "string" && value.trim()) return value;
    }
    return undefined;
  };
  const locationFields: [string, string | undefined][] = [
    ["Provider", enriched.dimensions?.cloud_provider || locationValue("provider", "cloud_provider")],
    ["Account/project", locationValue("account_scope", "account_id", "project_id", "subscription_id")],
    ["Environment", enriched.dimensions?.environment || locationValue("environment")],
    ["Region/location", locationValue("region", "location")],
  ];
  const missingLocationFields = locationFields.filter(([, value]) => !value).map(([label]) => label.toLowerCase());
  const headerSlot = (
    <div className="space-y-3 text-xs text-ink-secondary">
      <GraphFindingContext data={enriched} />
      <AdminAssessment attributes={enriched.attributes ?? {}} />
      {enrich && scanId && nodeId && detail && ["agent", "vulnerability", "user", "role", "group", "service_account", "service_principal", "federated_identity", "managed_identity"].includes(String(detail.node.entity_type)) && <GraphConsequencePanel nodeId={nodeId} scanId={scanId} snapshotGeneration={detail?.snapshot_generation}
        findingRoot={enriched.nodeType === "vulnerability"}
        affectedNodeIds={detail ? [...new Set([
          ...detail.edges_out.filter(edge => edge.source === nodeId && edge.relationship === "affects").map(edge => edge.target),
          ...detail.edges_in.filter(edge => edge.target === nodeId && edge.relationship === "vulnerable_to").map(edge => edge.source),
        ])] : []} />}
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        <span className="rounded border border-outline px-1.5 py-0.5 font-mono text-ink-secondary">
          {layer.label}
        </span>
        <span className="rounded border border-outline px-1.5 py-0.5 text-ink-tertiary">
          evidence · {evidenceLabel}
        </span>
        {loading ? (
          <span className="inline-flex items-center gap-1 text-ink-tertiary">
            <Loader2 className="h-3 w-3 animate-spin" />
            syncing
          </span>
        ) : null}
      </div>
      <details className="text-xs text-ink-secondary">
        <summary className="cursor-pointer">Location and evidence source</summary>
        {enriched.countScope === "loaded_graph" && <p className="mt-2">Counts cover linked entities in the graph data loaded for this investigation. They may be incomplete and are not inventory totals.</p>}
        <dl className="mt-2 space-y-1 break-words [overflow-wrap:anywhere]">
          {locationFields.filter(([, value]) => value).map(([label, value]) => (
            <div key={label}><dt className="inline font-semibold">{label}: </dt><dd className="inline">{value}</dd></div>
          ))}
          <div><dt className="inline font-semibold">Evidence sources: </dt><dd className="inline">{enriched.dataSources?.join(", ") || "Unknown"}</dd></div>
          <div><dt className="inline font-semibold">Last seen: </dt><dd className="inline">{enriched.lastSeen || "Unknown"}</dd></div>
        </dl>
        <p className="mt-2">Sources describe recorded observations. They do not establish successful execution or current access; last seen is not a fresh permission check.</p>
        {missingLocationFields.length > 0 && <p className="mt-2">
          {missingLocationFields.length === locationFields.length
            ? "Location metadata is not recorded."
            : `Not recorded: ${missingLocationFields.join(", ")}.`}
        </p>}
        {(enriched.nodeType === "dataStore" || enriched.nodeType === "dataset") && <p className="mt-2">Storage metadata does not establish data contents or successful reads. Inspect permission and runtime receipts separately.</p>}
      </details>
    </div>
  );

  const footerSlot = (
    <div className="space-y-2 border-t border-outline pt-3">
      {onShowBlastRadius && <BlastRadiusButton onClick={onShowBlastRadius} active={blastRadiusActive} loading={blastRadiusLoading} />}
      {nodeId && <NodePathsLink scanId={scanId} nodeId={nodeId} />}
      {showNextAction && <p className="text-[10px] uppercase tracking-[0.16em] text-ink-tertiary">Next action</p>}
      {showNextAction && <Link
        href={nextAction.href}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-600/40 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-800 transition hover:border-emerald-500/60 dark:text-emerald-200"
      >
        {nextAction.label}
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>}
      {onOpenScope && <button type="button" onClick={onOpenScope}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2 text-xs font-medium text-foreground hover:border-outline-strong">
        <Network className="h-3.5 w-3.5" />Explore scope
      </button>}
      {(onExpandNeighbors || onShowImpact) && (
        <div className="grid grid-cols-2 gap-2">
          {onExpandNeighbors ? (
            <button
              type="button"
              onClick={onExpandNeighbors}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2 py-2 text-[11px] font-medium text-foreground transition hover:border-outline-strong"
            >
              <Network className="h-3.5 w-3.5" />
              Expand
            </button>
          ) : (
            <span />
          )}
          {onShowImpact ? (
            <button
              type="button"
              onClick={onShowImpact}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2 py-2 text-[11px] font-medium text-foreground transition hover:border-outline-strong"
            >
              <Radar className="h-3.5 w-3.5" />
              Impact
            </button>
          ) : null}
        </div>
      )}
      {enriched.nodeType === "agent" && (
        <details className="space-y-2 border-t border-outline pt-3 text-xs text-ink-secondary">
          <summary className="cursor-pointer">Gateway controls and limits</summary>
          <p>Read-only discovery cannot stop this agent. Gateway policies apply only to calls routed through the gateway with its authenticated fleet identity.</p>
          <p>Direct cloud calls and other connections remain outside that control. Review the exact identity and business impact before changing a policy.</p>
          <Link href="/fleet" className="inline-flex rounded-lg border border-outline px-3 py-2 font-medium text-foreground hover:bg-surface-muted">
            Review gateway controls
          </Link>
        </details>
      )}
    </div>
  );

  const panel = (
    <LineageDetailPanel
      data={enriched}
      onClose={onClose}
      variant={variant}
      relationshipSlot={relationshipSlot}
      headerSlot={headerSlot}
      footerSlot={footerSlot}
    />
  );
  return enrich && scanId && nodeId
    ? <GraphRecordedRelationshipScope scanId={scanId} nodeId={nodeId}>{panel}</GraphRecordedRelationshipScope>
    : panel;
}
