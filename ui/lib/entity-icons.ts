import { ASSET_KINDS, assetKind, type EntityIcon } from "@/lib/asset-icon-registry";

export type LineageNodeType =
  | "provider"
  | "agent"
  | "server"
  | "package"
  | "vulnerability"
  | "misconfiguration"
  | "credential"
  | "tool"
  | "model"
  | "framework"
  | "dataset"
  | "container"
  | "cloudResource"
  | "org"
  | "account"
  | "user"
  | "group"
  | "role"
  | "policy"
  | "serviceAccount"
  | "servicePrincipal"
  | "federatedIdentity"
  | "environment"
  | "fleet"
  | "cluster"
  | "sharedServer"
  | "managedIdentity"
  | "accessGrant"
  | "accessPolicy"
  | "driftIncident"
  | "dataStore"
  | "directory"
  | "sourceFile"
  | "configFile"
  | "codeModule"
  | "ciJob"
  | "apiGateway"
  | "toolCall"
  | "blueprint";

export type { EntityIcon };

const LINEAGE_NODE_TYPES: readonly LineageNodeType[] = [
  "provider", "agent", "server", "package", "vulnerability", "misconfiguration", "credential", "tool", "model",
  "framework", "dataset", "container", "cloudResource", "org", "account", "user", "group", "role", "policy",
  "serviceAccount", "servicePrincipal", "federatedIdentity", "environment", "fleet", "cluster", "sharedServer",
  "managedIdentity", "accessGrant", "accessPolicy", "driftIncident", "dataStore", "directory", "sourceFile",
  "configFile", "codeModule", "ciJob", "apiGateway", "toolCall", "blueprint",
];

/**
 * Lineage node type → glyph, derived from the asset icon registry so a node,
 * its legend row and every other surface share one glyph per kind.
 */
export const ENTITY_ICONS = Object.fromEntries(
  LINEAGE_NODE_TYPES.map((type): [LineageNodeType, EntityIcon] => [type, ASSET_KINDS[assetKind({ nodeType: type })].icon]),
) as Record<LineageNodeType, EntityIcon>;

export function entityIcon(nodeType: LineageNodeType | string | undefined): EntityIcon {
  if (nodeType && Object.hasOwn(ENTITY_ICONS, nodeType)) return ENTITY_ICONS[nodeType as LineageNodeType];
  return ASSET_KINDS.unknown.icon;
}
