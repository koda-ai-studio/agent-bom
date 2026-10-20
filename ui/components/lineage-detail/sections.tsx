import type { ReactNode } from "react";
import type { LineageNodeData } from "../lineage-nodes";
import { graphRepositoryContext } from "@/lib/graph-repository-context";
import { Label, Row, TagList, formatValue, prettifyKey } from "./fields";

export function relationshipSection(data: LineageNodeData, relationshipSlot?: ReactNode) {
  const hasRelationships =
    !!relationshipSlot ||
    data.neighborCount != null ||
    data.sourceCount != null ||
    data.incomingEdgeCount != null ||
    data.outgoingEdgeCount != null ||
    data.impactCount != null ||
    data.maxImpactDepth != null;

  return hasRelationships ? (
    <div className="space-y-3">
      {relationshipSlot}
      <details open={!relationshipSlot} className="text-sm text-ink-secondary">
        <summary className="cursor-pointer">Relationship counts</summary>
        <div className="mt-2 space-y-2">
          {data.neighborCount != null && (
            <Row label={data.relationshipCountsPartial ? "Known neighbors" : "Neighbors"} value={data.neighborCount} />
          )}
          {data.sourceCount != null && (
            <Row label={data.relationshipCountsPartial ? "Known incoming neighbors" : "Incoming neighbors"} value={data.sourceCount} />
          )}
          {data.incomingEdgeCount != null && (
            <Row label={data.relationshipCountsPartial ? "Returned incoming edges" : "Incoming edges"} value={data.incomingEdgeCount} />
          )}
          {data.outgoingEdgeCount != null && (
            <Row label={data.relationshipCountsPartial ? "Returned outgoing edges" : "Outgoing edges"} value={data.outgoingEdgeCount} />
          )}
          {data.impactCount != null && (
            <Row
              label="Upstream connections"
              value={data.impactCount}
              className="text-orange-300"
            />
          )}
          {data.maxImpactDepth != null && (
            <Row label="Upstream hops explored" value={data.maxImpactDepth} />
          )}
        </div>
      </details>
    </div>
  ) : null;

}

export function impactSection(data: LineageNodeData) {
  const impactTypes = Object.entries(data.impactByType ?? {}).sort((left, right) => right[1] - left[1]);
  const hasImpact = data.impactCount != null || impactTypes.length > 0;
  const impactCoverage = data.impactCompleteness;
  const impactPartial = Boolean(impactCoverage?.truncated || impactCoverage?.sampled)
    || impactCoverage?.status === "truncated" || impactCoverage?.status === "sampled";
  const impactComplete = impactCoverage?.complete === true && impactCoverage.status === "complete" && !impactPartial;
  return hasImpact ? (
    <div className="space-y-3 text-sm">
      <div className="space-y-1">
        <p className="font-medium text-foreground">Upstream connected entities</p>
        <p className="leading-5 text-ink-secondary">
          Reverse graph connections identify potential dependency impact. They do not establish exploitability, successful actions or observed damage.
        </p>
      </div>
      <div className="space-y-1 text-ink-secondary" data-testid="graph-impact-coverage">
        <p className="font-medium">
          {impactPartial
            ? `Partial traversal · ${impactCoverage?.returned ?? data.impactCount ?? "Unknown"} entities returned`
            : impactComplete ? "Recorded upstream traversal complete" : "Traversal completeness unavailable"}
        </p>
        {data.maxImpactDepth != null && <p>{data.maxImpactDepth} {data.maxImpactDepth === 1 ? "hop" : "hops"} explored</p>}
        {impactPartial && <p>
          {impactCoverage?.reason === "depth_limit"
            ? "Hop limit reached; additional upstream connections may exist."
            : impactCoverage?.reason === "traversal_budget"
              ? "Traversal limit reached; additional upstream connections may exist."
              : "Only part of the upstream graph was returned; additional connections may exist."}
        </p>}
      </div>
      <div className="flex flex-wrap gap-2">
        {impactTypes.map(([key, value]) => (
          <span key={key} className="rounded border border-outline bg-surface-muted px-2 py-1 text-ink-secondary">
            {prettifyKey(key)}: {value}
          </span>
        ))}
        {impactTypes.length === 0 && data.impactCount === 0 && <p className="text-ink-secondary">No upstream entities returned</p>}
      </div>
    </div>
  ) : null;

}

function extraAttributeEntries(data: LineageNodeData) {
  const repository = graphRepositoryContext(data);
  return Object.entries(data.attributes ?? {}).filter(
    ([key]) => {
      if (repository && ["repo_url", "full_name", "provider", "host", "branch", "default_branch", "commit_sha", "repository_commit", "git_commit"].includes(key)) return false;
      return !new Set([
        "agent_type",
        "status",
        "version",
        "ecosystem",
        "description",
        "framework",
        "source",
        "hash",
        "verified",
        "container_image",
        "cloud_provider",
        "resource_id",
        "source_section",
        "rule_id",
        "check_id",
        "recommendation",
        "evidence",
        "path",
        "file_path",
        "line",
        "start_line",
        "end_line",
        "cvss_score",
        "epss_score",
        "is_kev",
        "fixed_version",
        "node_id",
      ]).has(key);
    },
  );

}

export function attributesSection(data: LineageNodeData) {
  const extraAttributes = extraAttributeEntries(data);
  const hasAttributes =
    (data.dataSources?.length ?? 0) > 0 ||
    (data.complianceTags?.length ?? 0) > 0 ||
    extraAttributes.length > 0;

  return hasAttributes ? (
    <div className="space-y-4">
      {data.dataSources && data.dataSources.length > 0 && (
        <TagList
          label="Data Sources"
          tags={data.dataSources}
          tone="blue"
          linkBuilder={(tag) => `/jobs?q=${encodeURIComponent(tag)}`}
        />
      )}

      {data.complianceTags && data.complianceTags.length > 0 && (
        <TagList
          label="Compliance Tags"
          tags={data.complianceTags}
          linkBuilder={(tag) => `/compliance?q=${encodeURIComponent(tag)}`}
        />
      )}

      {extraAttributes.length > 0 && (
        <div className="space-y-2">
          <Label>Attributes</Label>
          <div className="space-y-1.5">
            {extraAttributes.slice(0, 10).map(([key, value]) => (
              <Row
                key={key}
                label={prettifyKey(key)}
                value={formatValue(value)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  ) : null;

}
