import type { ComponentType, CSSProperties } from "react";
import {
  Activity, AppWindow, Archive, BadgeCheck, Bot, Boxes, CircleDashed, Braces, BrainCircuit, BrickWall, BriefcaseBusiness, Bug, Building2,
  Cable, CalendarClock, Cloud, CloudCog, Container, Cpu, Database, Disc3, DraftingCompass, Earth, FileCode, FileCog,
  FileStack, Fingerprint, FlaskConical, Folder, FolderGit2, FolderInput, FolderOutput, Gpu, Handshake, HardDrive, IdCard, Inbox, KeyRound,
  Library, MemoryStick, MessageSquareText, MonitorSmartphone, Network, Package, PlugZap, ScrollText, Server, Share2,
  ShieldAlert, ShieldCheck, ShipWheel, Siren, Sparkles, SquareFunction, Table, Ticket, User, UserCog, Users, Vault,
  Warehouse, Webhook, Workflow, Wrench, Zap,
} from "lucide-react";

/**
 * The one registry from an asset to its glyph. A vendor's native resource type
 * (Lambda, Azure Functions, Cloud Functions, Workers…) normalises to a semantic
 * kind, and each kind owns exactly one glyph. The vendor logo is a separate
 * badge and never replaces the glyph. Every surface resolves icons here.
 */
export type EntityIcon = ComponentType<{ className?: string; style?: CSSProperties }>;

interface KindSpec { label: string; icon: EntityIcon }

export const ASSET_KINDS = {
  provider: { label: "Provider", icon: Cloud },
  org: { label: "Org", icon: Building2 },
  account: { label: "Account", icon: BriefcaseBusiness },
  environment: { label: "Env", icon: Earth },
  fleet: { label: "Fleet", icon: MonitorSmartphone },
  cluster: { label: "Cluster", icon: ShipWheel },
  vm: { label: "VM", icon: Cpu },
  gpu_compute: { label: "GPU compute", icon: Gpu },
  function: { label: "Function", icon: SquareFunction },
  workload: { label: "Workload", icon: Container },
  image: { label: "Image", icon: Disc3 },
  registry: { label: "Registry", icon: Boxes },
  job: { label: "Job", icon: CalendarClock },
  api_gateway: { label: "Gateway", icon: Webhook },
  network: { label: "Network", icon: Network },
  firewall: { label: "Firewall", icon: BrickWall },
  bucket: { label: "Bucket", icon: Archive },
  stage: { label: "Stage", icon: FolderInput },
  database: { label: "Database", icon: Database },
  warehouse: { label: "Warehouse", icon: Warehouse },
  table: { label: "Table", icon: Table },
  data_share: { label: "Share", icon: FolderOutput },
  queue: { label: "Queue", icon: Inbox },
  cache: { label: "Cache", icon: MemoryStick },
  disk: { label: "Disk", icon: HardDrive },
  secret: { label: "Secret store", icon: Vault },
  integration: { label: "Integration", icon: Cable },
  model: { label: "Model", icon: BrainCircuit },
  endpoint: { label: "Endpoint", icon: PlugZap },
  ai_service: { label: "AI service", icon: Sparkles },
  ml_workspace: { label: "ML workspace", icon: FlaskConical },
  dataset: { label: "Dataset", icon: FileStack },
  prompt: { label: "Prompt", icon: MessageSquareText },
  observability: { label: "Observability", icon: Activity },
  agent: { label: "Agent", icon: Bot },
  mcp_server: { label: "Server", icon: Server },
  shared_server: { label: "Shared", icon: Share2 },
  tool: { label: "Tool", icon: Wrench },
  tool_call: { label: "Tool call", icon: Zap },
  framework: { label: "Framework", icon: Library },
  user: { label: "User", icon: User },
  group: { label: "Group", icon: Users },
  role: { label: "Role", icon: IdCard },
  policy: { label: "Policy", icon: ScrollText },
  service_account: { label: "Service", icon: UserCog },
  service_principal: { label: "Principal", icon: Fingerprint },
  federated_identity: { label: "Federated", icon: Handshake },
  managed_identity: { label: "Identity", icon: BadgeCheck },
  credential: { label: "Cred ref", icon: KeyRound },
  access_grant: { label: "Grant", icon: Ticket },
  access_policy: { label: "Access policy", icon: ShieldCheck },
  repository: { label: "Repository", icon: FolderGit2 },
  application: { label: "Application", icon: AppWindow },
  directory: { label: "Folder", icon: Folder },
  source_file: { label: "Source", icon: FileCode },
  config_file: { label: "Config file", icon: FileCog },
  code_module: { label: "Module", icon: Braces },
  ci_job: { label: "CI job", icon: Workflow },
  blueprint: { label: "Blueprint", icon: DraftingCompass },
  package: { label: "Package", icon: Package },
  vulnerability: { label: "CVE", icon: Bug },
  misconfiguration: { label: "Finding", icon: ShieldAlert },
  drift_incident: { label: "Drift", icon: Siren },
  cloud_resource: { label: "Cloud", icon: CloudCog },
  unknown: { label: "Entity", icon: CircleDashed },
} as const satisfies Record<string, KindSpec>;

export type AssetKind = keyof typeof ASSET_KINDS;

/** Default kind per backend entity type and per lineage node type. */
const ENTITY_KIND: Record<string, AssetKind> = {
  provider: "provider", org: "org", account: "account", environment: "environment", fleet: "fleet", cluster: "cluster",
  agent: "agent", server: "mcp_server", sharedServer: "shared_server", tool: "tool", tool_call: "tool_call",
  toolCall: "tool_call", model: "model", dataset: "dataset", framework: "framework", package: "package",
  external_import: "package", container: "workload", cloud_resource: "cloud_resource", cloudResource: "cloud_resource",
  resource: "cloud_resource", data_store: "database", dataStore: "database", api_gateway: "api_gateway",
  apiGateway: "api_gateway", application: "application", user: "user", group: "group", role: "role", policy: "policy",
  service_account: "service_account", serviceAccount: "service_account", service_principal: "service_principal",
  servicePrincipal: "service_principal", federated_identity: "federated_identity", federatedIdentity: "federated_identity",
  managed_identity: "managed_identity", managedIdentity: "managed_identity", credential: "credential",
  credential_ref: "credential", access_grant: "access_grant", accessGrant: "access_grant", access_policy: "access_policy",
  accessPolicy: "access_policy", blueprint: "blueprint", vulnerability: "vulnerability",
  misconfiguration: "misconfiguration", drift_incident: "drift_incident", driftIncident: "drift_incident",
  directory: "directory", source_file: "source_file", sourceFile: "source_file", config_file: "config_file",
  configFile: "config_file", code_module: "code_module", codeModule: "code_module", ci_job: "ci_job", ciJob: "ci_job",
};

/** Generic labels when only the entity type is known; a subtype earns its kind's label. */
const ENTITY_LABEL: Record<string, string> = {
  container: "Container", cloud_resource: "Cloud", cloudResource: "Cloud", resource: "Cloud",
  data_store: "Data", dataStore: "Data", server: "Server", model: "Model", dataset: "Dataset",
};

// Only asset-shaped entities read vendor subtypes; identities, findings and
// code keep their entity kind whatever a collector wrote in resource_type.
const SUBTYPED = new Set([
  "cloud_resource", "cloudResource", "resource", "data_store", "dataStore", "api_gateway", "apiGateway", "server",
  "model", "dataset", "container", "application", "agent", "cluster", "config_file", "configFile",
]);

const SUBTYPE_FIELDS = ["resource_type", "resource_kind", "cloud_service", "service", "kubernetes_kind", "asset_type"];

/** Exact native types whose words would otherwise match a broader rule. */
const EXACT: Record<string, AssetKind> = {
  server: "mcp_server", agent: "agent", tool: "tool", package: "package", framework: "framework",
  cortex_function: "ai_service", cortex_search_service: "ai_service", openai_deployment: "model",
  hosted_model: "model", model_artifact: "model", repository: "repository", ai_foundry_project: "ml_workspace",
  share: "data_share", task: "job", pipe: "job", stage: "stage", external_stage: "stage", internal_stage: "stage", cluster: "cluster",
  container_image: "image", spcs_service: "workload", prompt_template: "prompt", key_vault: "secret",
};

/** Ordered keyword rules over the normalised native type; first match wins. */
const RULES: Array<[RegExp, AssetKind]> = [
  [/(^|_)policy$/, "policy"],
  [/security_group|firewall|waf|web_acl|network_acl/, "firewall"],
  [/api_?gateway|apigee|api_management|apigatewayv2|api_shield|rest_api/, "api_gateway"],
  [/endpoint/, "endpoint"],
  [/trac(e|es|ing)(_|$)|observation|(^|_)spans?$|run_tree/, "observability"],
  [/gpu|dgx/, "gpu_compute"],
  [/function_app|lambda|cloud_?functions?|(^|_)functions?$|workers?(_script)?$|edge_function/, "function"],
  [/(^|_)sqs|(^|_)sns|pubsub|pub_sub|servicebus|service_bus|event_?hub|kinesis|(^|_)queues?$|(^|_)topics?$/, "queue"],
  [/redshift|bigquery|synapse|(^|_)warehouses?$/, "warehouse"],
  [/secret|kms|(^|_)vault$/, "secret"],
  [/registry|ecr_repository|(^|_)(ecr|acr|gcr)$/, "registry"],
  [/(^|_)images?$/, "image"],
  [/(^|_)s3(_|$)|bucket|storage_accounts?|storage_container|(^|_)blob|(^|_)r2(_|$)|(^|_)volumes?$/, "bucket"],
  [/(^|_)(eks|aks|gke)(_|$)|kubernetes_cluster|container_cluster|(^|_)clusters?$/, "cluster"],
  [/deployment$|(^|_)pods?$|stateful_set|daemon_set|replica_set|ecs_(service|task)|fargate|cloud_run|app_runner|container_apps?$|container_instance|inference_service|(^|_)app_service|web_app/, "workload"],
  [/(^|_)rds(_|$)|(^|_)db(_|$)|(^|_)kv(_|$)|dynamo|cosmos|sql_database|sql_server|sql_instance|spanner|firestore|postgres|mysql|aurora|(^|_)databases?$/, "database"],
  [/(^|_)tables?$/, "table"],
  [/(^|_)ec2(_|$)|virtual_machine|compute_instance|(^|_)vms?$|(^|_)instances?$|gpu_vm|virtual_server|(^|_)hosts?$/, "vm"],
  [/vpc|vnet|virtual_network|subnet|compute_network|(^|_)lb$|load_balancer|(^|_)[ae]lb(_|$)|forwarding_rule|url_map|backend_service|target_https?_prox|cloudfront|cdn|dns|(^|_)zones?$|elastic_ip|public_ip|reserved_ip|router|nat_gateway|ingress/, "network"],
  [/disk|ebs/, "disk"],
  [/cache|redis|memorystore/, "cache"],
  [/knowledge_base|training_dataset|search_index|(^|_)datasets?$/, "dataset"],
  [/model/, "model"],
  [/cognitive|openai_account|gemini|cortex|(^|_)bedrock$|(^|_)assistants?$/, "ai_service"],
  [/agent/, "agent"],
  [/workspace|foundry|notebook_instance|workbench|experiment/, "ml_workspace"],
  [/notebook$/, "source_file"],
  [/service_(app|identity|account)|api_service/, "service_account"],
  [/(^|_)users?$/, "user"],
  [/(^|_)groups?$/, "group"],
  [/(^|_)apps?$|application/, "application"],
  [/(^|_)jobs?$|(^|_)tasks?$|(^|_)pipes?$|state_machine|step_function|workflow/, "job"],
  [/(^|_)shares?$/, "data_share"],
  [/repositor/, "repository"],
  [/integration/, "integration"],
  [/prompt/, "prompt"],
  [/(^|_)(organization|org)$/, "org"],
  [/(^|_)(project|resource_group|subscription|account)$/, "account"],
];

const VENDOR_PREFIX = /^(aws|azurerm|azure|google|gcp|cloudflare|vercel|databricks|snowflake|microsoft|k8s|kubernetes|supabase|okta|langfuse|langsmith|modal|fireworks|nebius|coreweave|nvidia)_/;

const GPU_CLOUDS = ["modal", "fireworks", "nebius", "coreweave", "nvidia"];

/** A native type whose meaning depends on the vendor (a Supabase project is its Postgres; a Langfuse project holds traces). */
const VENDOR_EXACT: Record<string, Record<string, AssetKind>> = {
  supabase: { project: "database" },
  vercel: { project: "application" },
  langfuse: { project: "observability" },
  langsmith: { project: "observability" },
  modal: { sandbox: "gpu_compute" },
  fireworks: { deployment: "endpoint" },
};

/** On a GPU cloud a VM is GPU compute. */
const VENDOR_REMAP: Record<string, Partial<Record<AssetKind, AssetKind>>> = Object.fromEntries(
  GPU_CLOUDS.map((vendor) => [vendor, { vm: "gpu_compute" }]),
);

/**
 * Fallback rule for a resource type nobody mapped yet: the vendor's dominant
 * kind (an observability vendor's assets are trace sources, a GPU cloud's are
 * compute), else the entity's own kind. Either way the result is flagged
 * `fallback`, so coverage gaps stay visible in tests and never render blank.
 */
const VENDOR_DEFAULT: Record<string, AssetKind> = {
  ...Object.fromEntries(GPU_CLOUDS.map((vendor) => [vendor, "gpu_compute" as AssetKind])),
  langfuse: "observability", langsmith: "observability", supabase: "database", okta: "federated_identity",
  vercel: "application", cloudflare: "network",
};

function vendorOf(attributes: Record<string, unknown> | undefined): string {
  for (const key of ["cloud_provider", "provider", "vendor"]) {
    const value = attributes?.[key];
    if (typeof value === "string" && value.trim()) return value.trim().toLowerCase();
  }
  return "";
}

/** `AWS::Lambda::Function`, `azurerm_linux_function_app` and `StatefulSet` become comparable snake_case words. */
export function normalizeResourceType(value: string): string {
  const words = value.trim().replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return words.replace(VENDOR_PREFIX, "");
}

export function kindForResourceType(value: string, vendor = ""): AssetKind | null {
  const word = normalizeResourceType(value);
  if (!word) return null;
  const vendorKind = VENDOR_EXACT[vendor]?.[word];
  if (vendorKind) return vendorKind;
  let kind: AssetKind | null = EXACT[word] ?? null;
  if (!kind) for (const [pattern, ruled] of RULES) if (pattern.test(word)) { kind = ruled; break; }
  return kind ? VENDOR_REMAP[vendor]?.[kind] ?? kind : null;
}

export interface AssetKindInput {
  /** Backend `entity_type` (snake_case). */
  entityType?: string | undefined;
  /** Lineage node type (camelCase); used when no entity type is known. */
  nodeType?: string | undefined;
  attributes?: Record<string, unknown> | undefined;
  /** Recorded provider (e.g. `dimensions.cloud_provider`) when attributes carry none. */
  provider?: string | null | undefined;
}

export interface ResolvedAssetKind {
  kind: AssetKind;
  /** `subtype`: from a recorded vendor type; `entity`: from the entity type; `fallback`: nothing recognised. */
  basis: "subtype" | "entity" | "fallback";
}

function subtypeValues(attributes: Record<string, unknown> | undefined): string[] {
  return SUBTYPE_FIELDS.map((field) => attributes?.[field]).filter((value): value is string => typeof value === "string" && Boolean(value.trim()));
}

export function resolveAssetKind({ entityType, nodeType, attributes, provider }: AssetKindInput): ResolvedAssetKind {
  const type = entityType && Object.hasOwn(ENTITY_KIND, entityType) ? entityType : nodeType ?? entityType ?? "";
  const entityKind = Object.hasOwn(ENTITY_KIND, type) ? ENTITY_KIND[type]! : undefined;
  if (!entityKind) return { kind: "unknown", basis: "fallback" };
  if (!SUBTYPED.has(type)) return { kind: entityKind, basis: "entity" };
  if (type === "container") {
    const recorded = attributes?.container_kind;
    if (recorded === "image" || recorded === "workload") return { kind: recorded, basis: "subtype" };
  }
  const subtypes = subtypeValues(attributes);
  const vendor = vendorOf(attributes) || (provider ?? "").trim().toLowerCase();
  for (const value of subtypes) {
    const kind = kindForResourceType(value, vendor);
    if (kind) return { kind, basis: "subtype" };
  }
  if (!subtypes.length) return { kind: entityKind, basis: "entity" };
  return { kind: VENDOR_DEFAULT[vendor] ?? entityKind, basis: "fallback" };
}

export function assetKind(input: AssetKindInput): AssetKind {
  return resolveAssetKind(input).kind;
}

export function assetIcon(input: AssetKindInput): EntityIcon {
  return ASSET_KINDS[assetKind(input)].icon;
}

export function assetKindLabel(input: AssetKindInput): string {
  const resolved = resolveAssetKind(input);
  if (resolved.basis === "subtype") return ASSET_KINDS[resolved.kind].label;
  const type = input.entityType && Object.hasOwn(ENTITY_KIND, input.entityType) ? input.entityType : input.nodeType ?? "";
  return ENTITY_LABEL[type] ?? ASSET_KINDS[resolved.kind].label;
}

/** The kind label only when a recorded subtype refines the entity (a server that is an endpoint, a container that is an image). */
export function assetSubtypeLabel(input: AssetKindInput): string | undefined {
  const resolved = resolveAssetKind(input);
  const type = input.entityType && Object.hasOwn(ENTITY_KIND, input.entityType) ? input.entityType : input.nodeType ?? "";
  if (resolved.basis !== "subtype") return undefined;
  const generic = ENTITY_LABEL[type] ?? ASSET_KINDS[ENTITY_KIND[type] ?? "unknown"].label;
  const label = ASSET_KINDS[resolved.kind].label;
  return label === generic ? undefined : label;
}

export function assetKindIcon(kind: AssetKind): EntityIcon {
  return ASSET_KINDS[kind].icon;
}
