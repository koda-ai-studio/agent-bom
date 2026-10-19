"use client";

import { Drawer } from "@/components/drawer";
import { StatStrip } from "@/components/stat-strip";
import { Agent } from "@/lib/api";
import { ArrowRight, GitBranch, Key, Link2, Package, Server, Shield, TerminalSquare, Wrench } from "lucide-react";
import Link from "next/link";
import {
  agentCredentialCount,
  agentPackageCount,
  ConfiguredPill,
  DiscoveryEnvelopeCard,
  DiscoveryProvenanceTags,
  safeCommandLine,
  safeDisplayUrl,
} from "./agent-display";

export function AgentDetailDrawer({
  agent,
  open,
  onClose,
}: {
  agent: Agent | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!agent) return null;
  const packages = agentPackageCount(agent);
  const credentials = agentCredentialCount(agent);
  const tools = agent.mcp_servers.reduce((sum, srv) => sum + (srv.tools?.length ?? 0), 0);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow={agent.agent_type}
      title={agent.name}
      subtitle={agent.source ?? agent.config_path}
      headerAside={<ConfiguredPill />}
      size="2xl"
      ariaLabel={`Agent ${agent.name}`}
      footer={
        <div className="flex flex-wrap gap-2">
          <Link
            href={`/agents?name=${encodeURIComponent(agent.canonical_id || agent.stable_id || agent.name)}`}
            className="agents-primary-action"
          >
            <ArrowRight className="h-3.5 w-3.5" />
            Full detail
          </Link>
          <Link
            href={`/agents?name=${encodeURIComponent(agent.canonical_id || agent.stable_id || agent.name)}&view=lifecycle`}
            className="agents-toolbar-action"
          >
            <GitBranch className="h-3.5 w-3.5" />
            Lifecycle graph
          </Link>
        </div>
      }
    >
      <div className="space-y-4" data-testid={`agent-detail-${agent.name}`}>
        <StatStrip
          items={[
            { label: "Servers", value: agent.mcp_servers.length },
            { label: "Packages", value: packages },
            { label: "Tools", value: tools },
            { label: "Credentials", value: credentials, accent: "warn" },
          ]}
        />

        {agent.discovery_provenance ? (
          <div className="agents-elevated-card">
            <div className="agents-section-label mb-2">
              <Shield className="h-3.5 w-3.5" />
              Asset discovery provenance
            </div>
            <DiscoveryProvenanceTags provenance={agent.discovery_provenance} />
          </div>
        ) : null}

        {agent.discovery_envelope ? <DiscoveryEnvelopeCard envelope={agent.discovery_envelope} /> : null}

        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Server className="h-4 w-4 text-[color:var(--text-secondary)]" />
            MCP servers
            <span className="text-xs font-normal text-[color:var(--text-tertiary)]">({agent.mcp_servers.length})</span>
          </h3>
          {agent.mcp_servers.map((srv, index) => {
            const credEnv = srv.credential_env_vars ?? [];
            return (
              <div
                key={`${srv.name}-${index}`}
                className="agents-elevated-card"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-[color:var(--foreground)]">{srv.name}</span>
                    {srv.security_blocked && (
                      <span
                        className="rounded border px-1.5 py-0.5 text-[10px] font-mono"
                        style={{
                          borderColor: "var(--status-danger-border)",
                          backgroundColor: "var(--status-danger-bg)",
                          color: "var(--status-danger)",
                        }}
                      >
                        blocked
                      </span>
                    )}
                    {credEnv.length > 0 && (
                      <span
                        className="rounded border px-1.5 py-0.5 text-[10px] font-mono"
                        style={{
                          borderColor: "var(--status-warn-border)",
                          backgroundColor: "var(--status-warn-bg)",
                          color: "var(--status-warn)",
                        }}
                      >
                        creds
                      </span>
                    )}
                  </div>
                  {srv.transport && (
                    <span className="font-mono text-xs text-[color:var(--text-tertiary)]">{srv.transport}</span>
                  )}
                </div>

                <div className="mt-2">
                  <DiscoveryProvenanceTags provenance={srv.discovery_provenance} />
                </div>

                {srv.command && (
                  <div className="mt-2 flex items-start gap-1.5 font-mono text-xs text-[color:var(--text-tertiary)]">
                    <TerminalSquare className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span className="break-all">{safeCommandLine(srv.command, srv.args)}</span>
                  </div>
                )}
                {srv.url && (
                  <div className="mt-2 flex items-start gap-1.5 font-mono text-xs text-[color:var(--text-tertiary)]">
                    <Link2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span className="break-all">{safeDisplayUrl(srv.url)}</span>
                  </div>
                )}

                <div className="mt-2 flex flex-wrap gap-3 text-xs text-[color:var(--text-tertiary)]">
                  {srv.packages.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Package className="h-3 w-3" />
                      {srv.packages.length} package{srv.packages.length !== 1 ? "s" : ""}
                    </span>
                  )}
                  {srv.tools && srv.tools.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Wrench className="h-3 w-3" />
                      {srv.tools.length} tool{srv.tools.length !== 1 ? "s" : ""}
                    </span>
                  )}
                  {credEnv.length > 0 && (
                    <span className="flex items-center gap-1" style={{ color: "var(--status-warn)" }}>
                      <Key className="h-3 w-3" />
                      {credEnv.length} credential{credEnv.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>

                {credEnv.length > 0 && (
                  <div className="mt-3">
                    <p
                      className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em]"
                      style={{ color: "var(--status-warn)" }}
                    >
                      Credential-backed env vars
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {credEnv.map((envVar) => (
                        <span
                          key={envVar}
                          className="rounded border px-2 py-0.5 text-[11px] font-mono"
                          style={{
                            borderColor: "var(--status-warn-border)",
                            backgroundColor: "var(--status-warn-bg)",
                            color: "var(--status-warn)",
                          }}
                        >
                          {envVar}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {srv.tools && srv.tools.length > 0 && (
                  <div className="mt-3">
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                      Tools
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {srv.tools.map((tool) => (
                        <span
                          key={tool.name}
                          className="agents-chip"
                        >
                          {tool.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Drawer>
  );
}
