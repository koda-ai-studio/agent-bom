import { describe, expect, it } from "vitest";
import { Box, Boxes, CircleDashed, Container, Package, Package2, PackageOpen } from "lucide-react";

import {
  ASSET_KINDS,
  assetIcon,
  assetKind,
  assetKindIcon,
  assetKindLabel,
  resolveAssetKind,
  type AssetKind,
} from "@/lib/asset-icon-registry";
import { ENTITY_ICONS, type LineageNodeType } from "@/lib/entity-icons";
import { EntityType } from "@/lib/graph-schema";
import { entitySource } from "@/lib/agent-source";

// Every (entity_type, resource_type) pair the demo estate API emits, collected
// from GET /v1/graph on the seeded demo estate.
const DEMO_PAIRS: Array<[string, string]> = [
  ["access_policy", "bedrock_guardrail"], ["agent", "agent"], ["agent", "bedrock_agent"], ["agent", "vertex_agent"],
  ["application", "ai_foundry_project"], ["application", "repository"], ["ci_job", "workflow"], ["cloud_resource", "ec2"],
  ["cloud_resource", "function"], ["cloud_resource", "function_app"], ["cloud_resource", "instance"],
  ["cloud_resource", "key_vault"], ["cloud_resource", "rds"], ["cloud_resource", "s3"], ["cloud_resource", "virtual_machine"],
  ["cloud_resource", "warehouse"], ["cluster", "cluster"], ["config_file", "prompt_template"],
  ["container", "container_image"], ["container", "deployment"], ["data_store", "bucket"], ["data_store", "database"],
  ["data_store", "share"], ["data_store", "sql_database"], ["data_store", "stage"], ["data_store", "storage_account"],
  ["data_store", "table"], ["dataset", "ai_search_index"], ["dataset", "bedrock_knowledge_base"],
  ["dataset", "training_dataset"], ["framework", "framework"], ["model", "azure_openai_deployment"],
  ["model", "foundation_model"], ["model", "hosted_model"], ["model", "model_artifact"], ["model", "sagemaker_model"],
  ["model", "vertex_model"], ["package", "package"], ["role", "iam_role"], ["role", "role"],
  ["server", "cognitive_services_account"], ["server", "cortex_function"], ["server", "cortex_search_service"],
  ["server", "gemini_api"], ["server", "sagemaker_endpoint"], ["server", "server"], ["server", "spcs_service"],
  ["server", "vertex_endpoint"], ["service_account", "service_account"], ["service_principal", "service_principal"],
  ["tool", "tool"],
];

// Native resource types per vendor → the one semantic kind they must share.
const VENDOR_CASES: Array<[string, string, string, AssetKind]> = [
  ["aws", "cloud_resource", "AWS::Lambda::Function", "function"],
  ["aws", "cloud_resource", "aws_lambda_function", "function"],
  ["azure", "cloud_resource", "function_app", "function"],
  ["azure", "cloud_resource", "azurerm_linux_function_app", "function"],
  ["gcp", "cloud_resource", "google_cloudfunctions2_function", "function"],
  ["gcp", "cloud_resource", "cloudfunctions.googleapis.com/CloudFunction", "function"],
  ["cloudflare", "cloud_resource", "cloudflare_workers_script", "function"],
  ["cloudflare", "cloud_resource", "worker", "function"],
  ["vercel", "cloud_resource", "vercel_function", "function"],
  ["vercel", "cloud_resource", "edge_function", "function"],
  ["aws", "data_store", "AWS::S3::Bucket", "bucket"],
  ["aws", "cloud_resource", "s3", "bucket"],
  ["azure", "data_store", "storage_account", "bucket"],
  ["azure", "data_store", "Microsoft.Storage/storageAccounts", "bucket"],
  ["azure", "data_store", "azurerm_storage_container", "bucket"],
  ["gcp", "data_store", "google_storage_bucket", "bucket"],
  ["cloudflare", "data_store", "cloudflare_r2_bucket", "bucket"],
  ["vercel", "data_store", "vercel_blob", "bucket"],
  ["snowflake", "data_store", "stage", "stage"],
  ["databricks", "data_store", "volume", "bucket"],
  ["aws", "api_gateway", "AWS::ApiGateway::RestApi", "api_gateway"],
  ["aws", "cloud_resource", "aws_apigatewayv2_api", "api_gateway"],
  ["azure", "cloud_resource", "azurerm_api_management", "api_gateway"],
  ["azure", "cloud_resource", "Microsoft.ApiManagement/service", "api_gateway"],
  ["gcp", "cloud_resource", "apigee_organization", "api_gateway"],
  ["gcp", "cloud_resource", "google_api_gateway_gateway", "api_gateway"],
  ["cloudflare", "cloud_resource", "api_shield", "api_gateway"],
  ["aws", "cloud_resource", "aws_sqs_queue", "queue"],
  ["aws", "cloud_resource", "AWS::SNS::Topic", "queue"],
  ["azure", "cloud_resource", "azurerm_servicebus_queue", "queue"],
  ["gcp", "cloud_resource", "google_pubsub_topic", "queue"],
  ["cloudflare", "cloud_resource", "cloudflare_queue", "queue"],
  ["aws", "cloud_resource", "rds", "database"],
  ["aws", "data_store", "aws_db_instance", "database"],
  ["aws", "data_store", "AWS::DynamoDB::Table", "database"],
  ["azure", "data_store", "sql_database", "database"],
  ["azure", "data_store", "azurerm_cosmosdb_account", "database"],
  ["gcp", "data_store", "google_sql_database_instance", "database"],
  ["cloudflare", "data_store", "cloudflare_d1_database", "database"],
  ["vercel", "data_store", "vercel_postgres", "database"],
  ["snowflake", "data_store", "database", "database"],
  ["snowflake", "cloud_resource", "warehouse", "warehouse"],
  ["aws", "data_store", "aws_redshift_cluster", "warehouse"],
  ["gcp", "data_store", "google_bigquery_dataset", "warehouse"],
  ["databricks", "cloud_resource", "sql_warehouse", "warehouse"],
  ["snowflake", "data_store", "table", "table"],
  ["snowflake", "data_store", "share", "data_share"],
  ["aws", "cloud_resource", "ec2", "vm"],
  ["aws", "cloud_resource", "AWS::EC2::Instance", "vm"],
  ["azure", "cloud_resource", "virtual_machine", "vm"],
  ["azure", "cloud_resource", "azurerm_linux_virtual_machine", "vm"],
  ["gcp", "cloud_resource", "google_compute_instance", "vm"],
  ["gcp", "cloud_resource", "instance", "vm"],
  ["aws", "cloud_resource", "aws_eks_cluster", "cluster"],
  ["azure", "cloud_resource", "azurerm_kubernetes_cluster", "cluster"],
  ["gcp", "cloud_resource", "google_container_cluster", "cluster"],
  ["databricks", "cloud_resource", "cluster", "cluster"],
  ["kubernetes", "container", "deployment", "workload"],
  ["kubernetes", "container", "Pod", "workload"],
  ["kubernetes", "container", "StatefulSet", "workload"],
  ["aws", "cloud_resource", "aws_ecs_service", "workload"],
  ["gcp", "cloud_resource", "google_cloud_run_service", "workload"],
  ["azure", "cloud_resource", "container_app", "workload"],
  ["snowflake", "server", "spcs_service", "workload"],
  ["aws", "container", "container_image", "image"],
  ["aws", "cloud_resource", "aws_ecr_repository", "registry"],
  ["azure", "cloud_resource", "azurerm_container_registry", "registry"],
  ["gcp", "cloud_resource", "google_artifact_registry_repository", "registry"],
  ["azure", "cloud_resource", "key_vault", "secret"],
  ["aws", "cloud_resource", "aws_secretsmanager_secret", "secret"],
  ["aws", "cloud_resource", "AWS::KMS::Key", "secret"],
  ["gcp", "cloud_resource", "google_secret_manager_secret", "secret"],
  ["kubernetes", "cloud_resource", "Secret", "secret"],
  ["aws", "cloud_resource", "aws_vpc", "network"],
  ["azure", "cloud_resource", "azurerm_virtual_network", "network"],
  ["gcp", "cloud_resource", "google_compute_network", "network"],
  ["aws", "cloud_resource", "aws_lb", "network"],
  ["cloudflare", "cloud_resource", "zone", "network"],
  ["aws", "cloud_resource", "aws_security_group", "firewall"],
  ["azure", "cloud_resource", "azurerm_network_security_group", "firewall"],
  ["gcp", "cloud_resource", "google_compute_firewall", "firewall"],
  ["aws", "cloud_resource", "aws_wafv2_web_acl", "firewall"],
  ["aws", "model", "foundation_model", "model"],
  ["azure", "model", "azure_openai_deployment", "model"],
  ["databricks", "model", "registered_model", "model"],
  ["aws", "server", "sagemaker_endpoint", "endpoint"],
  ["gcp", "server", "vertex_endpoint", "endpoint"],
  ["databricks", "server", "serving_endpoint", "endpoint"],
  ["azure", "server", "online_endpoint", "endpoint"],
  ["azure", "server", "cognitive_services_account", "ai_service"],
  ["gcp", "server", "gemini_api", "ai_service"],
  ["snowflake", "server", "cortex_function", "ai_service"],
  ["aws", "agent", "bedrock_agent", "agent"],
  ["aws", "dataset", "bedrock_knowledge_base", "dataset"],
  ["azure", "application", "ai_foundry_project", "ml_workspace"],
  ["azure", "cloud_resource", "azurerm_machine_learning_workspace", "ml_workspace"],
  ["databricks", "cloud_resource", "workspace", "ml_workspace"],
  ["snowflake", "cloud_resource", "task", "job"],
  ["snowflake", "cloud_resource", "pipe", "job"],
  ["databricks", "cloud_resource", "job", "job"],
  ["aws", "cloud_resource", "state_machine", "job"],
  ["github", "application", "repository", "repository"],
  ["mcp", "server", "server", "mcp_server"],
  ["supabase", "cloud_resource", "supabase.project", "database"],
  ["supabase", "cloud_resource", "project", "database"],
  ["supabase", "data_store", "storage_bucket", "bucket"],
  ["supabase", "cloud_resource", "edge_function", "function"],
  ["vercel", "application", "project", "application"],
  ["vercel", "cloud_resource", "deployment", "workload"],
  ["okta", "cloud_resource", "okta_user", "user"],
  ["okta", "cloud_resource", "app", "application"],
  ["okta", "cloud_resource", "service_app", "service_account"],
  ["okta", "cloud_resource", "group", "group"],
  ["langfuse", "cloud_resource", "trace", "observability"],
  ["langfuse", "cloud_resource", "project", "observability"],
  ["langsmith", "cloud_resource", "tracing_project", "observability"],
  ["modal", "cloud_resource", "function", "function"],
  ["modal", "cloud_resource", "sandbox", "gpu_compute"],
  ["fireworks", "server", "deployment", "endpoint"],
  ["fireworks", "model", "model", "model"],
  ["nebius", "cloud_resource", "instance", "gpu_compute"],
  ["nebius", "cloud_resource", "mk8s_cluster", "cluster"],
  ["coreweave", "cloud_resource", "virtual_server", "gpu_compute"],
  ["coreweave", "cloud_resource", "cks_cluster", "cluster"],
  ["nvidia", "server", "nim_endpoint", "endpoint"],
  ["nvidia", "cloud_resource", "dgx_cloud_instance", "gpu_compute"],
  ["cloudflare", "data_store", "kv_namespace", "database"],
  ["databricks", "cloud_resource", "notebook", "source_file"],
  ["aws", "role", "iam_role", "role"],
  ["snowflake", "role", "role", "role"],
];

const ALL_KINDS = Object.keys(ASSET_KINDS) as AssetKind[];

describe("asset icon registry", () => {
  it("gives every semantic kind exactly one glyph that no other kind shares", () => {
    const owners = new Map<unknown, AssetKind[]>();
    for (const kind of ALL_KINDS) owners.set(ASSET_KINDS[kind].icon, [...(owners.get(ASSET_KINDS[kind].icon) ?? []), kind]);
    expect([...owners.values()].filter((kinds) => kinds.length > 1)).toEqual([]);
    expect(ALL_KINDS.filter((kind) => ASSET_KINDS[kind].icon === CircleDashed)).toEqual(["unknown"]);
    for (const kind of ALL_KINDS) expect(ASSET_KINDS[kind].label.trim()).not.toBe("");
  });

  it("draws only the container as an isometric box, so a package never reads as a container", () => {
    const boxGlyphs = new Set<unknown>([Box, Boxes, Container, Package, Package2, PackageOpen]);
    expect(ALL_KINDS.filter((kind) => boxGlyphs.has(ASSET_KINDS[kind].icon))).toEqual(["workload"]);
  });

  it("gives a container image, a running container, a registry, a package and a server distinct glyphs", () => {
    const glyphs = (["image", "workload", "registry", "package", "mcp_server", "vm"] as AssetKind[]).map((kind) => ASSET_KINDS[kind].icon);
    expect(new Set(glyphs).size).toBe(glyphs.length);
    expect(assetIcon({ entityType: "container" })).not.toBe(assetIcon({ entityType: "package" }));
    expect(assetIcon({ entityType: "container", attributes: { container_kind: "image" } })).not.toBe(assetIcon({ entityType: "package" }));
    expect(assetIcon({ entityType: "container" })).not.toBe(assetIcon({ entityType: "server" }));
  });

  it("maps distinct backend entity types to distinct glyphs except declared aliases", () => {
    const aliases: Record<string, string> = { external_import: "package", credential_ref: "credential", resource: "cloud_resource" };
    const owners = new Map<unknown, string[]>();
    for (const entityType of Object.values(EntityType) as string[]) {
      if (Object.hasOwn(aliases, entityType)) {
        expect(assetIcon({ entityType })).toBe(assetIcon({ entityType: aliases[entityType] }));
        continue;
      }
      const icon = assetIcon({ entityType });
      owners.set(icon, [...(owners.get(icon) ?? []), entityType]);
    }
    expect([...owners.values()].filter((types) => types.length > 1)).toEqual([]);
  });

  it.each(VENDOR_CASES)("maps %s %s %s to the %s kind", (vendor, entityType, resourceType, kind) => {
    const resolved = resolveAssetKind({ entityType, attributes: { resource_type: resourceType, cloud_provider: vendor } });
    expect(resolved.kind).toBe(kind);
    expect(resolved.basis).not.toBe("fallback");
    expect(assetIcon({ entityType, attributes: { resource_type: resourceType, cloud_provider: vendor } })).toBe(ASSET_KINDS[kind].icon);
  });

  it("covers every owner-named kind with its own glyph", () => {
    const named: AssetKind[] = [
      "function", "api_gateway", "bucket", "queue", "database", "warehouse", "vm", "cluster", "workload", "image", "role",
      "user", "service_account", "secret", "network", "model", "endpoint", "dataset", "agent", "mcp_server", "tool", "package",
      "vulnerability", "misconfiguration",
    ];
    for (const kind of named) expect(ASSET_KINDS[kind]?.icon).toBeDefined();
  });

  it("resolves every demo estate entity and resource type without a fallback", () => {
    const fallbacks = DEMO_PAIRS.filter(([entityType, resourceType]) =>
      resolveAssetKind({ entityType, attributes: { resource_type: resourceType } }).basis === "fallback");
    expect(fallbacks).toEqual([]);
  });

  it("resolves every backend entity type to a specific kind", () => {
    const unknown = Object.values(EntityType).filter((entityType) => resolveAssetKind({ entityType }).kind === "unknown");
    expect(unknown).toEqual([]);
  });

  it("reads the recorded container subtype before any resource type", () => {
    expect(resolveAssetKind({ entityType: "container", attributes: { container_kind: "image", resource_type: "deployment" } }).kind).toBe("image");
    expect(resolveAssetKind({ entityType: "container", attributes: { container_kind: "workload" } }).kind).toBe("workload");
    expect(assetKindLabel({ entityType: "container", attributes: { container_kind: "workload" } })).toBe("Workload");
    expect(assetKindLabel({ entityType: "container", attributes: { container_kind: "image" } })).toBe("Image");
  });

  it.each([
    ["supabase", false], ["vercel", false], ["okta", true], ["langfuse", false], ["langsmith", false], ["modal", false],
    ["fireworks", false], ["nebius", false], ["coreweave", false], ["nvidia", false], ["snowflake", true], ["aws", true],
    ["azure", true], ["gcp", true], ["databricks", true], ["cloudflare", false], ["kubernetes", true],
  ])("gives %s a vendor badge (bundled official logo: %s)", (vendor, logo) => {
    const source = entitySource({ nodeType: "cloudResource", dimensions: { cloud_provider: vendor } });
    expect(source?.id).toBe(vendor);
    expect(Boolean(source?.src)).toBe(logo);
    expect(source?.monogram.trim()).not.toBe("");
  });

  it("falls back to the vendor's own kind, then the entity kind, for an unknown resource type", () => {
    const unknown = (vendor: string) => resolveAssetKind({ entityType: "cloud_resource", attributes: { resource_type: "zz_new_thing", cloud_provider: vendor } });
    expect(unknown("langfuse")).toEqual({ kind: "observability", basis: "fallback" });
    expect(unknown("langsmith")).toEqual({ kind: "observability", basis: "fallback" });
    for (const vendor of ["modal", "fireworks", "nebius", "coreweave", "nvidia"]) expect(unknown(vendor).kind).toBe("gpu_compute");
    expect(unknown("supabase").kind).toBe("database");
    expect(unknown("okta").kind).toBe("federated_identity");
    expect(unknown("vercel").kind).toBe("application");
    expect(unknown("cloudflare").kind).toBe("network");
    expect(unknown("aws")).toEqual({ kind: "cloud_resource", basis: "fallback" });
    for (const vendor of ["supabase", "okta", "langfuse", "modal"]) {
      expect(resolveAssetKind({ entityType: "role", attributes: { cloud_provider: vendor } }).kind).toBe("role");
    }
  });

  it("keeps an unrecognised cloud subtype honest: a generic cloud glyph flagged as fallback", () => {
    expect(resolveAssetKind({ entityType: "cloud_resource", attributes: { resource_type: "quantum_annealer" } }))
      .toEqual({ kind: "cloud_resource", basis: "fallback" });
    expect(resolveAssetKind({ entityType: "not-a-type" })).toEqual({ kind: "unknown", basis: "fallback" });
  });

  it("never lets a resource type relabel an identity, finding or code entity", () => {
    expect(resolveAssetKind({ entityType: "ci_job", attributes: { resource_type: "workflow" } }).kind).toBe("ci_job");
    expect(resolveAssetKind({ entityType: "vulnerability", attributes: { resource_type: "bucket" } }).kind).toBe("vulnerability");
    expect(resolveAssetKind({ entityType: "service_account", attributes: { resource_type: "function" } }).kind).toBe("service_account");
  });

  it("accepts lineage node types as well as backend entity types", () => {
    for (const nodeType of Object.keys(ENTITY_ICONS) as LineageNodeType[]) {
      expect(resolveAssetKind({ nodeType }).kind, nodeType).not.toBe("unknown");
      expect(assetIcon({ nodeType })).toBe(ENTITY_ICONS[nodeType]);
    }
  });
});

describe("Snowflake stage", () => {
  it("is its own kind, never drawn or labelled as a bucket", () => {
    for (const resource_type of ["stage", "external_stage", "internal_stage"]) {
      const input = { entityType: "data_store", attributes: { resource_type }, provider: "snowflake" };
      expect(assetKind(input)).toBe("stage");
      expect(assetKindLabel(input)).toBe("Stage");
      expect(assetIcon(input)).not.toBe(assetKindIcon("bucket"));
    }
    expect(assetKind({ entityType: "data_store", attributes: { resource_type: "s3" }, provider: "aws" })).toBe("bucket");
  });
});
