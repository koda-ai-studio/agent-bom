import type { components } from "./api-schema.generated";
import { get } from "./api-transport";

export type AffectedAnswer = components["schemas"]["AffectedResponse"];

/** CVE, GHSA or another prefixed advisory id; anything else is read as a package (`name` or `name@version`). */
const ADVISORY = /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-[A-Z0-9][A-Z0-9._:-]*\d[A-Z0-9._:-]*)$/i;

export function isAdvisoryQuery(query: string): boolean {
  return ADVISORY.test(query.trim()) && !query.includes("@");
}

/** `GET /v1/affected`: findings, exposure window, inventory match and reach for one advisory or package. */
export function getAffected(query: string, signal?: AbortSignal) {
  return get<AffectedAnswer>(`/v1/affected?${new URLSearchParams({ q: query.trim() })}`, { ttlMs: 0, ...(signal ? { signal } : {}) });
}

export const VERDICT_LABEL: Record<AffectedAnswer["verdict"], string> = {
  affected: "Affected",
  possibly_affected: "Possibly affected",
  previously_affected: "Previously affected",
  not_found: "No match found",
};

export const REACH_LABEL: Record<string, string> = {
  agents: "agents", mcp_servers: "MCP servers", tools: "tools", credentials: "credentials", data_stores: "data stores",
  cloud_resources: "cloud resources", identities: "identities",
};
