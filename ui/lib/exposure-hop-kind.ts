import { assetKind, type AssetKind } from "@/lib/asset-icon-registry";
import type { ExposureEntityRef, ExposureEntityRole } from "@/lib/exposure-path";

/** Registry kind for a hop that records no entity type; the role is only a styling bucket. */
export const ROLE_ASSET_KIND: Record<ExposureEntityRole, AssetKind> = {
  agent: "agent",
  server: "mcp_server",
  package: "package",
  finding: "vulnerability",
  credential: "credential",
  tool: "tool",
  environment: "environment",
  cluster: "cluster",
  unknown: "unknown",
};

/** One glyph per entity kind on every path surface: the recorded kind, then the entity type, then the role. */
export function exposureHopAssetKind(hop: Pick<ExposureEntityRef, "assetKind" | "entityType" | "role">): AssetKind {
  if (hop.assetKind) return hop.assetKind;
  if (hop.entityType) {
    const kind = assetKind({ entityType: hop.entityType });
    if (kind !== "unknown") return kind;
  }
  return ROLE_ASSET_KIND[hop.role] ?? "unknown";
}
