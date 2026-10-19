"use client";

import { Agent, type DiscoveryEnvelope, type DiscoveryProvenance, isConfigured } from "@/lib/api";
import { credentialEnvKeys } from "@/lib/credential-key";
import { Shield } from "lucide-react";


export function isMcpServer(server: Agent["mcp_servers"][number]): boolean {
  return (server.surface ?? "mcp-server") === "mcp-server";
}

export function useAgentStats(agents: Agent[]) {
  const configured = agents.filter(isConfigured);
  const notConfigured = agents.filter((a) => !isConfigured(a));
  const totalServers = agents.reduce((s, a) => s + a.mcp_servers.filter(isMcpServer).length, 0);
  const totalPackages = agents.reduce(
    (s, a) => s + a.mcp_servers.reduce((ss, srv) => ss + srv.packages.length, 0),
    0
  );
  const totalCredentials = agents.reduce(
    (s, a) =>
      s +
      a.mcp_servers.reduce(
        (ss, srv) =>
          ss +
          credentialEnvKeys(srv.env).length,
        0
      ),
    0
  );

  // ecosystem breakdown
  const ecosystems: Record<string, number> = {};
  for (const a of agents) {
    for (const srv of a.mcp_servers) {
      for (const pkg of srv.packages) {
        const eco = (pkg as { ecosystem?: string }).ecosystem || "unknown";
        ecosystems[eco] = (ecosystems[eco] || 0) + 1;
      }
    }
  }

  const serversWithCredentials = agents.reduce(
    (count, agent) => count + agent.mcp_servers.filter((srv) => (srv.credential_env_vars?.length ?? 0) > 0 || srv.has_credentials).length,
    0
  );
  const blockedServers = agents.reduce(
    (count, agent) => count + agent.mcp_servers.filter((srv) => srv.security_blocked).length,
    0
  );
  const remoteServers = agents.reduce(
    (count, agent) =>
      count +
      agent.mcp_servers.filter((srv) => {
        const transport = (srv.transport || "").toLowerCase();
        return transport.includes("sse") || transport.includes("http");
      }).length,
    0
  );

  return {
    configured,
    notConfigured,
    totalServers,
    totalPackages,
    totalCredentials,
    ecosystems,
    serversWithCredentials,
    blockedServers,
    remoteServers,
  };
}

export function provenanceTags(provenance?: DiscoveryProvenance): string[] {
  if (!provenance) return [];
  const tags = [
    provenance.source_type,
    provenance.provider,
    provenance.service,
    provenance.observed_via,
    provenance.version_source,
    provenance.confidence,
  ];
  return tags
    .flatMap((value) => (Array.isArray(value) ? value : value ? [value] : []))
    .map((value) => String(value).replaceAll("_", " "))
    .filter((value, index, all) => value && all.indexOf(value) === index)
    .slice(0, 6);
}

export function DiscoveryProvenanceTags({ provenance }: { provenance: DiscoveryProvenance | undefined }) {
  const tags = provenanceTags(provenance);
  if (tags.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {tags.map((tag) => (
        <span key={tag} className="agents-cloud-chip">
          {tag}
        </span>
      ))}
    </div>
  );
}

export function safeReferenceHref(reference: string): string | null {
  try {
    const url = new URL(reference);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

export function safeDisplayUrl(value: string | undefined): string {
  if (!value) return "";
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? `${url.protocol}//${url.host}${url.pathname}` : value;
  } catch {
    return value;
  }
}

export function safeCommandLine(command: string | undefined, args: string[] | undefined): string {
  return [command, ...(args ?? [])]
    .filter((part): part is string => Boolean(part))
    .map((part) => (/(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}/i.test(part) ? "<redacted>" : part))
    .join(" ");
}

export function safeDisplayText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/g, (match) => safeDisplayUrl(match))
    .replace(/(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}/gi, "<redacted>");
}

export function serverCredentialCount(srv: Agent["mcp_servers"][number]): number {
  if (srv.credential_env_vars?.length) return srv.credential_env_vars.length;
  return credentialEnvKeys(srv.env).length;
}

export function agentPackageCount(agent: Agent): number {
  return agent.mcp_servers.reduce((sum, srv) => sum + srv.packages.length, 0);
}

export function agentCredentialCount(agent: Agent): number {
  return agent.mcp_servers.reduce((sum, srv) => sum + serverCredentialCount(srv), 0);
}

export function ConfiguredPill() {
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
      style={{ color: "var(--status-success)" }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--status-success)" }} aria-hidden="true" />
      configured
    </span>
  );
}

export function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-3">
      <div className="flex items-center gap-1.5 text-xs text-[color:var(--text-tertiary)] mb-1">
        <Icon className={`w-3.5 h-3.5 ${color}`} />
        {label}
      </div>
      <div className="text-xl font-bold">{value}</div>
    </div>
  );
}

export const SCAN_MODE_LABEL: Record<string, string> = {
  unknown: "unknown",
  local_only: "local only",
  cloud_read_only: "cloud read-only",
  saas_read_only: "SaaS read-only",
  runtime_probe: "runtime probe",
  container_local: "container (local)",
  endpoint_push: "endpoint push",
};

export const REDACTION_LABEL: Record<string, string> = {
  unknown: "unknown",
  never_collected: "never collected",
  redacted_in_place: "redacted in place",
  central_sanitizer_applied: "central sanitizer",
  not_applicable: "n/a",
};

export function DiscoveryEnvelopeCard({ envelope }: { envelope: DiscoveryEnvelope }) {
  const captureDate = envelope.captured_at ? new Date(envelope.captured_at) : null;
  const captured = captureDate && Number.isFinite(captureDate.getTime()) ? captureDate.toLocaleString() : null;
  const mode = SCAN_MODE_LABEL[envelope.scan_mode] ?? "unknown";
  const redaction = REDACTION_LABEL[envelope.redaction_status] ?? "unknown";
  return (
    <div className="agents-trust-card">
      <div className="agents-section-label mb-2">
        <Shield className="h-3.5 w-3.5" />
        Collection context
      </div>
      <p className="mb-2 text-sm text-[color:var(--text-secondary)]">
        Collector-reported scope and handling. Listed permissions do not prove that every collection call succeeded.
      </p>
      <div className="mb-2 flex flex-wrap gap-1.5">
        <span className="agents-section-chip">
          {mode}
        </span>
        <span className="agents-section-chip">
          redaction: {redaction}
        </span>
      </div>
      {envelope.discovery_scope.length > 0 && (
        <div className="mt-2 text-[11px] text-[color:var(--text-secondary)]">
          <div className="mb-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Scope</div>
          <div className="flex flex-wrap gap-1.5">
            {envelope.discovery_scope.map((s) => (
              <span key={s} className="agents-mono-chip">
                {s}
              </span>
            ))}
          </div>
        </div>
      )}
      {envelope.permissions_used.length > 0 && (
        <details className="mt-2 text-[11px] text-[color:var(--text-secondary)]">
          <summary className="agents-collapse-toggle">
            Reported permissions ({envelope.permissions_used.length})
          </summary>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {envelope.permissions_used.map((p) => (
              <span key={p} className="agents-mono-chip">
                {p}
              </span>
            ))}
          </div>
        </details>
      )}
      <div className="mt-2 text-xs text-[color:var(--text-tertiary)]">
        {captured ? `Captured ${captured}` : "Capture time unknown"} · envelope v{envelope.envelope_version}
      </div>
    </div>
  );
}
