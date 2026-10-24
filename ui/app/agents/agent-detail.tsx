"use client";

import { FrameworkTagChips } from "@/components/framework-tag-chips";
import { EXPOSED_BY_IMPACT_NOTE, exposedByImpactLabel } from "@/lib/credential-basis";
import { SeverityBadge } from "@/components/severity-badge";
import { type AgentDetailResponse, api, MITRE_ATLAS, OWASP_LLM_TOP10 } from "@/lib/api";
import {
  ArrowLeft,
  Bug,
  ChevronDown,
  ChevronRight,
  Clock3,
  GitBranch,
  KeyRound,
  Link2,
  Loader2,
  Package,
  Server,
  ShieldAlert,
  TerminalSquare,
  Wrench,
} from "lucide-react";
import Link from "next/link";
import { agentBlastPathHref } from "@/lib/agent-links";
import { agentRecordDisplayName } from "@/lib/display-name";
import { useEffect, useState } from "react";
import { safeCommandLine, safeDisplayText, safeDisplayUrl, safeReferenceHref, StatCard } from "./agent-display";

export function AgentDetail({ agentName }: { agentName: string }) {
  const [data, setData] = useState<AgentDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .getAgentDetail(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[color:var(--surface)] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-[color:var(--surface)] p-8">
        <Link href="/agents" className="agents-back-link">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="agents-error-panel">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  const { agent, summary, blast_radius, credentials, fleet } = data;
  const sev = {
    critical: summary.severity_breakdown.critical ?? 0,
    high: summary.severity_breakdown.high ?? 0,
    medium: summary.severity_breakdown.medium ?? 0,
    low: summary.severity_breakdown.low ?? 0,
    unrated: summary.severity_breakdown.unrated ?? 0,
  };
  // The strip must reconcile with the Vulnerabilities tile beside it: anything
  // the API could not band still has to be visible. Zero attributed findings
  // does not establish complete assessment or a clean agent.
  const sevTotal = sev.critical + sev.high + sev.medium + sev.low + sev.unrated;

  const toggleServer = (name: string) => {
    setExpandedServers((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="min-h-screen bg-[color:var(--surface)] text-[color:var(--foreground)]">
      {/* Header */}
      <div className="agents-sticky-header">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <Link href="/agents" className="agents-back-link-sm">
            <ArrowLeft className="w-3.5 h-3.5" /> All Agents
          </Link>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-3">
                <ShieldAlert className="w-6 h-6 text-emerald-400" />
                {agentRecordDisplayName(agent)}
              </h1>
              <div className="flex items-center gap-3 mt-1 text-sm text-[color:var(--text-tertiary)]">
                <span className="bg-[color:var(--surface-elevated)] px-2 py-0.5 rounded text-xs">
                  {agent.agent_type}
                </span>
                {agent.config_path && (
                  <span className="font-mono text-xs truncate max-w-md">
                    {agent.config_path}
                  </span>
                )}
              </div>
            </div>
            <Link
              href={`/agents?name=${encodeURIComponent(agent.name || agentName)}&view=lifecycle`}
              className="agents-scan-action"
            >
              <GitBranch className="w-4 h-4" />
              View Lifecycle Graph
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {fleet && (
          <div className="agents-observed-panel">
            <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-sky-400">Observed state</p>
            <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <div className="agents-stat-card">
                <div className="text-[color:var(--text-tertiary)] text-xs">Lifecycle state</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.lifecycle_state}</div>
              </div>
              <div className="agents-stat-card">
                <div className="text-[color:var(--text-tertiary)] text-xs">Trust score</div>
                <div className="mt-1 text-sm font-semibold text-emerald-400">{fleet.trust_score.toFixed(1)}</div>
              </div>
              <div className="agents-stat-card">
                <div className="text-[color:var(--text-tertiary)] text-xs">Last discovery</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.last_discovery || "not synced yet"}</div>
              </div>
              <div className="agents-stat-card">
                <div className="text-[color:var(--text-tertiary)] text-xs">Last scan</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.last_scan || "not scanned yet"}</div>
              </div>
              <div className="agents-stat-card">
                <div className="text-[color:var(--text-tertiary)] text-xs">Updated</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.updated_at || "unknown"}</div>
              </div>
            </div>
          </div>
        )}
        <div className="agents-inventory-panel">
          <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400">Inventory-first view</p>
          <p className="mt-1 text-sm leading-6 text-[color:var(--text-secondary)]">
            This detail page is valuable before runtime proxy rollout. It shows the configured MCP surface area for
            <span className="mx-1 font-semibold text-[color:var(--foreground)]">{agentRecordDisplayName(agent)}</span>
            using discovery and scan data alone: server transport, exposed tools, env-backed credentials, and attached package risk.
          </p>
        </div>
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard icon={Server} label="MCP Servers" value={summary.total_servers} color="text-blue-400" />
          <StatCard icon={Package} label="Packages" value={summary.total_packages} color="text-[color:var(--text-secondary)]" />
          <StatCard icon={Wrench} label="Tools" value={summary.total_tools} color="text-purple-400" />
          <StatCard icon={KeyRound} label="Credentials" value={summary.total_credentials} color="text-yellow-400" />
          <StatCard icon={Bug} label="Vulnerabilities" value={summary.total_vulnerabilities} color="text-red-400" />
          <div className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-3">
            <div className="text-xs text-[color:var(--text-tertiary)] mb-1">Severity</div>
            <div className="flex items-center gap-2 text-xs">
              {sev.critical > 0 && <span className="text-red-400 font-bold">{sev.critical}C</span>}
              {sev.high > 0 && <span className="text-orange-400 font-bold">{sev.high}H</span>}
              {sev.medium > 0 && <span className="text-yellow-400">{sev.medium}M</span>}
              {sev.low > 0 && <span className="text-blue-400">{sev.low}L</span>}
              {sev.unrated > 0 && (
                <span className="text-[color:var(--text-secondary)]" title="Reported with no CVSS severity — not yet rated">
                  {sev.unrated}U
                </span>
              )}
              {sevTotal === 0 && summary.total_vulnerabilities === 0 && (
                <span className="text-[color:var(--text-secondary)]" title="Only identity-linked findings are counted; assessment coverage may be incomplete">No attributed findings</span>
              )}
              {sevTotal === 0 && summary.total_vulnerabilities > 0 && (
                <span className="text-[color:var(--text-secondary)]">Unrated</span>
              )}
            </div>
          </div>
        </div>

        {/* Exposed Credentials */}
        {credentials.length > 0 && (
          <div className="agents-credential-panel">
            <h3 className="text-sm font-semibold text-yellow-400 flex items-center gap-2 mb-2">
              <KeyRound className="w-4 h-4" /> Exposed Credentials ({credentials.length})
            </h3>
            <div className="flex flex-wrap gap-2">
              {credentials?.map((c) => (
                <span key={c} className="agents-warning-chip">
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* MCP Servers */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" /> MCP Servers
          </h2>
          <div className="space-y-2">
            {agent.mcp_servers?.map((srv) => {
              const isExpanded = expandedServers.has(srv.name);
              const srvPkgs = srv.packages || [];
              const srvTools = srv.tools || [];
              const vulnCount = srvPkgs.reduce(
                (sum, p) => sum + (p.vulnerabilities?.length ?? 0),
                0
              );
              return (
                <div key={srv.name} className="agents-panel">
                  <button
                    onClick={() => toggleServer(srv.name)}
                    className="agents-row-button"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-[color:var(--text-tertiary)]" /> : <ChevronRight className="w-4 h-4 text-[color:var(--text-tertiary)]" />}
                      <span className="font-medium">{srv.name}</span>
                      <span className="agents-mini-badge">
                        {srv.transport || "stdio"}
                      </span>
                      {srv.security_blocked && (
                        <span className="agents-danger-chip">
                          blocked
                        </span>
                      )}
                      {(srv.credential_env_vars?.length ?? 0) > 0 && (
                        <span className="agents-warning-chip !px-1.5 !text-[10px]">
                          {srv.credential_env_vars?.length ?? 0} credential env
                        </span>
                      )}
                      {srv.auth_mode && (
                        <span className="agents-auth-chip">
                          {srv.auth_mode}
                        </span>
                      )}
                      {srv.provenance?.observed_via?.map((source) => (
                        <span
                          key={source}
                          className="agents-emerald-chip"
                        >
                          {source}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-[color:var(--text-tertiary)]">
                      <span>{srvPkgs.length} pkgs</span>
                      <span>{srvTools.length} tools</span>
                      {vulnCount > 0 && (
                        <span className="text-red-400 font-medium">{vulnCount} vulns</span>
                      )}
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="border-t border-[color:var(--border-subtle)] px-4 py-3 space-y-3">
                      <div className="grid gap-3 md:grid-cols-2">
                        {srv.command && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="agents-section-label mb-1">
                              <TerminalSquare className="h-3.5 w-3.5" />
                              Command
                            </div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">
                              {safeCommandLine(srv.command, srv.args)}
                            </div>
                          </div>
                        )}
                        {srv.url && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="agents-section-label mb-1">
                              <Link2 className="h-3.5 w-3.5" />
                              Remote URL
                            </div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">{safeDisplayUrl(srv.url)}</div>
                          </div>
                        )}
                      </div>
                      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                        {srv.config_path && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Config path</div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">{srv.config_path}</div>
                          </div>
                        )}
                        {srv.auth_mode && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Auth mode</div>
                            <div className="text-xs text-[color:var(--text-secondary)]">{srv.auth_mode}</div>
                          </div>
                        )}
                        <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                          <div className="agents-section-label mb-1">
                            <Clock3 className="h-3.5 w-3.5" />
                            Discovery context
                          </div>
                          <div className="text-xs text-[color:var(--text-secondary)]">
                            {fleet?.last_discovery ? `Seen in fleet sync at ${fleet.last_discovery}` : "Discovery-only, not synced through fleet yet"}
                          </div>
                        </div>
                        {srv.provenance && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Provenance</div>
                            <div className="flex flex-wrap gap-1.5">
                              {srv.provenance.observed_via.map((source) => (
                                <span
                                  key={source}
                                  className="agents-emerald-chip"
                                >
                                  {source}
                                </span>
                              ))}
                            </div>
                            <div className="mt-2 space-y-1 text-[11px] text-[color:var(--text-secondary)]">
                              {srv.provenance.last_seen && <div>Last seen: <span className="text-[color:var(--text-secondary)]">{srv.provenance.last_seen}</span></div>}
                              {srv.provenance.last_synced && <div>Last synced: <span className="text-[color:var(--text-secondary)]">{srv.provenance.last_synced}</span></div>}
                              {srv.provenance.source_agents.length > 0 && (
                                <div>
                                  Gateway sources: <span className="text-[color:var(--text-secondary)]">{srv.provenance.source_agents.join(", ")}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      {/* Tools */}
                      {srvTools.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-purple-400 mb-1">Tools</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {srvTools?.map((t) => (
                              <span key={t.name} className="agents-tool-chip">
                                {t.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.security_warnings?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-rose-400 mb-1">Security warnings</h4>
                          <div className="space-y-1">
                            {srv.security_warnings?.map((warning) => (
                              <div key={warning} className="agents-danger-callout">
                                {safeDisplayText(warning)}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.security_intelligence?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-cyan-300">
                            <ShieldAlert className="h-3.5 w-3.5" />
                            Security intelligence
                          </h4>
                          <div className="space-y-2">
                            {srv.security_intelligence?.map((entry) => (
                              <div key={entry.entry_id} className="agents-intel-card">
                                <div className="flex flex-wrap items-start justify-between gap-2">
                                  <div className="min-w-0">
                                    <div className="text-xs font-semibold text-cyan-100">{entry.title}</div>
                                    <div className="mt-1 flex flex-wrap gap-1.5">
                                      <span className="agents-intel-chip">
                                        {entry.confidence}
                                      </span>
                                      {entry.source_type && (
                                        <span className="agents-type-chip">
                                          {entry.source_type}
                                        </span>
                                      )}
                                      {entry.last_verified && (
                                        <span className="agents-small-chip">
                                          Verified {entry.last_verified}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                                <div className="mt-2 text-xs text-[color:var(--text-secondary)]">Recommendation: {entry.default_recommendation}</div>
                                {(entry.remediation_actions?.length ?? 0) > 0 && (
                                  <div className="mt-2 flex flex-wrap gap-1.5">
                                    {entry.remediation_actions?.map((action) => (
                                      <span key={action} className="agents-action-chip">
                                        {action}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {(entry.references?.some((reference) => safeReferenceHref(reference) !== null) ?? false) && (
                                  <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                                    {entry.references?.map((reference, index) => {
                                      const href = safeReferenceHref(reference);
                                      if (!href) return null;
                                      return (
                                        <a
                                          key={`${entry.entry_id}-${reference}`}
                                          href={href}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="text-cyan-300 underline decoration-cyan-800 underline-offset-2 hover:text-cyan-200"
                                        >
                                          Reference {index + 1}
                                        </a>
                                      );
                                    })}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.credential_env_vars?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-yellow-400 mb-1">Credential-backed env vars</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {srv.credential_env_vars?.map((envVar) => (
                              <span key={envVar} className="agents-warning-chip">
                                {envVar}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {srv.security_blocked && (
                        <div className="agents-danger-callout !rounded-lg">
                          This server is marked as blocked or risky by the discovery/security pipeline. Inventory visibility works without
                          runtime proxy; proxy and gateway are the later enforcement layer.
                        </div>
                      )}
                      {/* Packages */}
                      {srvPkgs.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-[color:var(--text-secondary)] mb-1">Packages</h4>
                          <div className="space-y-1">
                            {srvPkgs?.map((pkg) => (
                              <div key={`${pkg.name}@${pkg.version}`} className="flex items-center justify-between text-xs">
                                <span className="font-mono">
                                  {pkg.name}
                                  <span className="text-[color:var(--text-tertiary)]">@{pkg.version}</span>
                                </span>
                                <span className="text-[color:var(--text-tertiary)]">{pkg.ecosystem}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Blast Radius */}
        {blast_radius.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Bug className="w-5 h-5 text-red-400" /> Blast Radius ({blast_radius.length})
            </h2>
            <div className="space-y-2">
              {blast_radius?.map((br, i) => (
                <div key={`${br.vulnerability_id}-${i}`} className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={br.severity} />
                      <Link href={agentBlastPathHref(agent.name || agentName, br)} className="font-mono font-medium text-accent-mint hover:underline" title="Open this agent's attack path for the advisory">
                        {br.vulnerability_id}
                      </Link>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
                      {br.cvss_score && <span>CVSS {br.cvss_score}</span>}
                      {br.is_kev && <span className="text-red-400 font-bold">KEV</span>}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3 text-xs text-[color:var(--text-secondary)]">
                    {br.package && <span>Package: <span className="text-[color:var(--text-secondary)]">{br.package}</span></span>}
                    {br.exposed_credentials.length > 0 && (
                      <span className="text-yellow-400" title={EXPOSED_BY_IMPACT_NOTE}>{exposedByImpactLabel(br.exposed_credentials.length)}</span>
                    )}
                    {(br.exposed_tools ?? br.reachable_tools).length > 0 && (
                      <span className="text-purple-400">{(br.exposed_tools ?? br.reachable_tools).length} tools reachable</span>
                    )}
                  </div>
                  {/* Framework tags */}
                  <div className="flex flex-wrap items-center gap-1 mt-2">
                    <FrameworkTagChips tags={br.owasp_tags} catalog={OWASP_LLM_TOP10} tone="owasp" />
                    <FrameworkTagChips tags={br.atlas_tags} catalog={MITRE_ATLAS} tone="atlas" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
