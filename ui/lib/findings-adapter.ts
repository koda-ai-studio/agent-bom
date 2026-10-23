import type { Vulnerability, UnifiedFinding } from "@/lib/api";
import { uniqueStrings, type EnrichedVuln } from "@/lib/findings-view";
import type { LaneFinding } from "@/components/finding-lane-table";

function recordString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function recordNumber(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function recordStrings(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && Boolean(item.trim()));
}

function normalizedSeverity(value: string | undefined): Vulnerability["severity"] {
  const normalized = (value ?? "").toLowerCase();
  return normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "none"
    ? normalized
    : "none";
}


export function collectUnifiedFindings(findings: UnifiedFinding[]): LaneFinding[] {
  return findings.map((finding): LaneFinding => {
    const raw = finding as UnifiedFinding & {
      framework_tags?: string[];
      phantom_tools?: string[];
      runtime_evidence?: EnrichedVuln["runtime_evidence"];
      workload_runtime_evidence?: EnrichedVuln["workload_runtime_evidence"];
      effective_reach_band?: string;
      effective_reach_score?: number;
      attack_vector_summary?: string;
    };
    const assetName =
      finding.asset?.name?.trim() ||
      finding.package?.trim() ||
      finding.package_name?.trim() ||
      finding.asset?.identifier ||
      finding.asset?.stable_id ||
      "Unavailable";
    const findingLabel = finding.cve_id || finding.title || finding.id;
    const sourceLabel = uniqueStrings([finding.source, finding.finding_type, ...(finding.scan_sources ?? [])]);
    const evidence = finding.evidence ?? {};
    const packageName = finding.package_name?.trim() || finding.package?.trim() || recordString(evidence, "package_name") || assetName;
    const currentVersion = finding.package_version ?? recordString(evidence, "package_version");
    const serverAsset = finding.asset?.asset_type === "server" || finding.asset?.asset_type === "mcp_server" || finding.entity_type === "server";
    const references = uniqueStrings([
      ...(finding.references ?? []),
      ...recordStrings(evidence, "references"),
    ]);
    const advisorySources = uniqueStrings([
      ...(finding.advisory_sources ?? []),
      ...recordStrings(evidence, "advisory_sources"),
    ]);
    return {
      lane_evidence: { resource: assetName, provider: finding.provider ?? undefined, account: finding.account_ref ?? undefined, environment: finding.environment ?? undefined, rule: recordString(evidence, "rule_id") || recordString(evidence, "check_id"), line: recordNumber(evidence, "line_number"), expected: recordString(evidence, "expected") || recordString(evidence, "control_title"), observed: recordString(evidence, "observed") || recordString(evidence, "evidence"), remediation: finding.remediation_guidance ?? undefined },
      id: findingLabel,
      finding_id: finding.finding_id ?? finding.id,
      finding_group_id: finding.finding_group_id,
      finding_group_key: finding.finding_group_key,
      node_id: finding.node_id ?? undefined,
      finding_node_id: finding.finding_node_id ?? undefined,
      entity_type: finding.entity_type ?? undefined,
      asset_type: finding.asset?.asset_type ?? undefined,
      severity: normalizedSeverity(finding.effective_severity ?? finding.severity),
      summary: raw.attack_vector_summary ?? finding.title ?? finding.description,
      description: finding.description ?? finding.title,
      references,
      advisory_sources: advisorySources,
      cwe_ids: uniqueStrings(finding.cwe_ids ?? []),
      aliases: uniqueStrings([
        ...(finding.aliases ?? []),
        ...(finding.advisory_aliases ?? []),
        ...recordStrings(evidence, "advisory_aliases"),
      ]),
      cvss_score: finding.cvss_score ?? undefined,
      cvss_vector: finding.cvss_vector ?? recordString(evidence, "cvss_vector"),
      cvss_severity: finding.cvss_severity ?? undefined,
      epss_score: finding.epss_score ?? undefined,
      epss_percentile: finding.epss_percentile ?? recordNumber(evidence, "epss_percentile"),
      is_kev: typeof finding.is_kev === "boolean" ? finding.is_kev : undefined,
      cisa_kev: typeof finding.is_kev === "boolean" ? finding.is_kev : undefined,
      kev_date_added: finding.kev_date_added ?? recordString(evidence, "kev_date_added"),
      kev_due_date: finding.kev_due_date ?? recordString(evidence, "kev_due_date"),
      fixed_version: finding.fixed_version ?? undefined,
      current_version: currentVersion,
      published_at: finding.published_at ?? recordString(evidence, "published_at"),
      modified_at: finding.modified_at ?? recordString(evidence, "modified_at"),
      severity_source: finding.severity_source ?? recordString(evidence, "severity_source"),
      confidence: finding.confidence ?? recordNumber(evidence, "confidence"),
      match_confidence_tier:
        finding.match_confidence_tier ?? recordString(evidence, "match_confidence_tier"),
      packages: [packageName],
      agents: finding.affected_agents ?? [],
      sources: sourceLabel.length > 0 ? sourceLabel : ["finding"],
      detection_source: finding.source || undefined,
      repository_relative_path: recordString(evidence, "repository_relative_path"),
      affected_servers: uniqueStrings([...(finding.affected_servers ?? []), ...(serverAsset && assetName !== "Unavailable" ? [assetName] : [])]),
      exposed_credentials: finding.exposed_credentials ?? [],
      reachable_tools: finding.exposed_tools ?? [],
      phantom_tools: raw.phantom_tools ?? [],
      framework_tags: raw.framework_tags ?? finding.compliance_tags ?? [],
      controls: finding.controls ?? [],
      attack_vector_summary: raw.attack_vector_summary ?? (finding.network_exploitable ? "Network exploitable" : undefined),
      impact_category: finding.impact_category ?? finding.finding_type,
      finding_type: finding.finding_type,
      finding_class: finding.finding_class,
      risk_score: finding.risk_score ?? undefined,
      is_direct: finding.is_direct ?? undefined,
      dependency_depth: finding.dependency_depth ?? undefined,
      introduced_via: finding.introduced_via ?? undefined,
      effective_reach_band: raw.effective_reach_band,
      effective_reach_score: raw.effective_reach_score,
      runtime_evidence: raw.runtime_evidence,
      workload_runtime_evidence: raw.workload_runtime_evidence ?? finding.workload_runtime_evidence,
      remediation_items: finding.remediation_guidance
        ? [
            {
              package: packageName,
              ecosystem: finding.asset?.asset_type ?? finding.finding_type ?? "finding",
              current_version: currentVersion ?? "",
              fixed_version: finding.fixed_version ?? null,
              action: "review",
              command: null,
              verify_command: null,
              references: [],
              risk_narrative: finding.remediation_guidance,
            },
          ]
        : [],
      graph_reachable: finding.graph_reachable ?? null,
      graph_min_hop_distance: finding.graph_min_hop_distance ?? null,
      graph_reachable_from_agents: finding.graph_reachable_from_agents ?? [],
      graph_reachable_from: finding.graph_reachable_from ?? [],
      graph_reachable_from_count: finding.graph_reachable_from_count ?? null,
      lifecycle_status: finding.status ?? undefined,
      observation_status: finding.observation_status,
      reconfirmation: finding.reconfirmation,
      unreconfirmed_occurrence_count: finding.unreconfirmed_occurrence_count,
      first_seen: finding.first_seen ?? undefined,
      last_seen: finding.last_seen ?? undefined,
      resolved_at: finding.resolved_at ?? undefined,
      reopened_at: finding.reopened_at ?? undefined,
      scan_count: finding.scan_count,
      last_observed: finding.last_observed ?? finding.last_seen ?? undefined,
      occurrence_count: finding.occurrence_count ?? finding.scan_count,
      occurrences: finding.occurrences,
      occurrences_truncated: finding.occurrences_truncated,
      remediation_versions: finding.remediation_versions ?? undefined,
      package_versions: finding.package_versions,
      package_version_count: finding.package_version_count,
      provenance: finding.provenance ?? undefined,
      owner: finding.owner ?? undefined,
      sla_due_at: finding.sla_due_at ?? undefined,
      scan_id: finding.scan_id,
    };
  });
}
