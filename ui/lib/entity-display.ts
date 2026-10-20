import type { ExposureEntityRole } from "@/lib/exposure-path";
import { topologyAgentTypeLabel } from "@/lib/agent-topology-graph";
import { agentDisplayName, serverDisplayName } from "@/lib/display-name";

export type EntityDisplayParts = {
  title: string;
  subtitle?: string | undefined;
};

function titleCaseWords(value: string): string {
  return value
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function parsePackageLabel(label: string): { name: string; version?: string } {
  const at = label.lastIndexOf("@");
  if (at > 0) {
    return {
      name: label.slice(0, at),
      version: label.slice(at + 1),
    };
  }
  return { name: label };
}

export function formatExposureEntityDisplay(
  label: string,
  role: ExposureEntityRole,
  attributes: Record<string, unknown> = {},
): EntityDisplayParts {
  const trimmed = label.trim();
  if (!trimmed) return { title: "Unknown entity" };

  switch (role) {
    case "agent": {
      const agentType =
        typeof attributes.agent_type === "string" ? attributes.agent_type : undefined;
      return {
        title: agentDisplayName(trimmed, typeof attributes.display_name === "string" ? attributes.display_name : null),
        subtitle: agentType ? topologyAgentTypeLabel(agentType) : "AI agent runtime",
      };
    }
    case "server": {
      const transport =
        typeof attributes.transport === "string" ? attributes.transport : undefined;
      return {
        title: serverDisplayName(trimmed, typeof attributes.display_name === "string" ? attributes.display_name : null),
        subtitle: attributes.protocol === "mcp" || attributes.server_type === "mcp" || attributes.is_mcp === true
          ? (transport ? `${transport} MCP server` : "MCP server")
          : (transport ? `${transport} server` : "Server"),
      };
    }
    case "package": {
      const parsed = parsePackageLabel(trimmed);
      const ecosystem =
        typeof attributes.ecosystem === "string" ? attributes.ecosystem : undefined;
      return {
        title: parsed.name,
        subtitle: [parsed.version ? `v${parsed.version}` : null, ecosystem?.toUpperCase()]
          .filter(Boolean)
          .join(" · "),
      };
    }
    case "finding":
      return {
        title: trimmed,
        subtitle: "Vulnerability finding",
      };
    case "credential":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Credential reference",
      };
    case "tool":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "MCP tool capability",
      };
    case "environment":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Deployment environment",
      };
    case "cluster":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Kubernetes cluster",
      };
    default:
      return { title: titleCaseWords(trimmed) };
  }
}

export function formatExposureEntityTitle(
  label: string,
  role: ExposureEntityRole,
  attributes: Record<string, unknown> = {},
): string {
  return formatExposureEntityDisplay(label, role, attributes).title;
}

export function formatExposurePathSequence(
  hops: Array<{ label: string; role: ExposureEntityRole; attributes?: Record<string, unknown> | undefined }>,
): string {
  return hops
    .map((hop) => formatExposureEntityTitle(hop.label, hop.role, hop.attributes ?? {}))
    .join(" → ");
}
