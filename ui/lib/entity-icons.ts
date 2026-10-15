import type { ComponentType, CSSProperties } from "react";
import {
  BadgeCheck,
  Bot,
  Box,
  Braces,
  BrainCircuit,
  BriefcaseBusiness,
  Bug,
  Building2,
  Container,
  Cloud,
  Cpu,
  Database,
  DraftingCompass,
  Earth,
  FileCode,
  FileCog,
  Fingerprint,
  Folder,
  Handshake,
  IdCard,
  KeyRound,
  Library,
  MonitorSmartphone,
  Package,
  ScrollText,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  ShipWheel,
  Siren,
  Table,
  Ticket,
  User,
  UserCog,
  Users,
  Webhook,
  Workflow,
  Wrench,
  Zap,
} from "lucide-react";

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

export type EntityIcon = ComponentType<{
  className?: string;
  style?: CSSProperties;
}>;

/**
 * Single source of truth for entity-type → icon. The lineage node renderers,
 * the cluster pills, the on-canvas legend, and the graph chrome all read from
 * this map so the glyph shown on a node is byte-for-byte the glyph shown in the
 * legend row for the same type. Every type gets a DISTINCT, on-meaning Lucide
 * icon (enforced by tests/graph-visual-identity.test.ts).
 *
 * Non-obvious picks: container is the shipping-container glyph and cluster the
 * helm wheel that steers them, so neither reads as the package cube;
 * environment is a region/estate globe, not a generic layer stack; an API
 * gateway is the webhook/endpoint glyph; account is a billing and isolation
 * boundary; fleet is a set of managed endpoints; cloudResource is the compute
 * and service catch-all. Box stays reserved for unknown types so a missing
 * mapping is visible.
 */
export const ENTITY_ICONS: Record<LineageNodeType, EntityIcon> = {
  provider: Cloud,
  agent: Bot,
  server: Server,
  sharedServer: Share2,
  package: Package,
  vulnerability: Bug,
  misconfiguration: ShieldAlert,
  credential: KeyRound,
  tool: Wrench,
  model: BrainCircuit,
  framework: Library,
  dataset: Table,
  container: Container,
  cloudResource: Cpu,
  org: Building2,
  account: BriefcaseBusiness,
  user: User,
  group: Users,
  role: IdCard,
  policy: ScrollText,
  serviceAccount: UserCog,
  servicePrincipal: Fingerprint,
  federatedIdentity: Handshake,
  environment: Earth,
  fleet: MonitorSmartphone,
  cluster: ShipWheel,
  managedIdentity: BadgeCheck,
  accessGrant: Ticket,
  accessPolicy: ShieldCheck,
  driftIncident: Siren,
  dataStore: Database,
  directory: Folder,
  sourceFile: FileCode,
  configFile: FileCog,
  codeModule: Braces,
  ciJob: Workflow,
  apiGateway: Webhook,
  toolCall: Zap,
  blueprint: DraftingCompass,
};

export function entityIcon(
  nodeType: LineageNodeType | string | undefined,
): EntityIcon {
  if (nodeType && nodeType in ENTITY_ICONS) {
    return ENTITY_ICONS[nodeType as LineageNodeType];
  }
  return Box;
}
