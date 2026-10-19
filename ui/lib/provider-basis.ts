import { entitySource, type AgentSource } from "@/lib/agent-source";

export interface ProviderMarkBasis {
  inherited: boolean;
  title: string;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/** How a provider mark was established, from the graph's recorded basis only. */
export function providerMarkBasis(source: AgentSource, attributes: Record<string, unknown> | undefined): ProviderMarkBasis {
  const declared = `Source: ${source.label}`;
  if (!text(attributes?.cloud_provider_basis).startsWith("inherited:")) return { inherited: false, title: declared };
  const origin = attributes?.cloud_provider_source;
  const record = origin && typeof origin === "object" ? origin as Record<string, unknown> : {};
  const label = text(record.label);
  const type = text(record.entity_type).replace(/_/g, " ");
  const from = label ? ` from ${source.label}${type ? ` ${type}` : ""} ${label}` : "";
  return { inherited: true, title: `${declared} · inherited${from}` };
}

/** A roll-up scope's provider, from the server payload and never from its name. */
export function scopeProvider(item: { cloud_provider?: string | undefined }): AgentSource | null {
  const provider = text(item.cloud_provider);
  return provider ? entitySource({ dimensions: { cloud_provider: provider } }) : null;
}
