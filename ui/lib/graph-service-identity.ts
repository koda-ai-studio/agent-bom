import type { AssetKind, AssetKindInput } from "@/lib/asset-icon-registry";

type ServiceRule = readonly [AssetKind, RegExp, string];

// Match recorded native resource/service metadata only. Display names, node IDs,
// adjacent accounts and inferred reach never establish a service identity.
const SERVICES: Record<string, readonly ServiceRule[]> = {
  aws: [
    ["cluster", /^eks(?:_|$)/, "Amazon EKS"],
    ["bucket", /^s3(?:_|$)/, "Amazon S3 bucket"],
    ["vm", /^ec2(?:_|$)/, "Amazon EC2 instance"],
    ["role", /^iam(?:_role)?$/, "AWS IAM role"],
    ["api_gateway", /^(api_gateway|apigatewayv2|rest_api)/, "Amazon API Gateway"],
    ["database", /^rds(?:_|$)|^db_instance$/, "Amazon RDS instance"],
    ["database", /^dynamodb(?:_|$)/, "Amazon DynamoDB table"],
    ["function", /^lambda(?:_|$)/, "AWS Lambda function"],
    ["registry", /^ecr(?:_|$)/, "Amazon ECR repository"],
  ],
  azure: [
    ["cluster", /^(aks|kubernetes_cluster|container_service_managed_clusters)/, "Azure Kubernetes Service"],
    ["bucket", /^storage_container$|^blob(?:_|$)/, "Azure Blob container"],
    ["bucket", /^storage_accounts?$/, "Azure Storage account"],
    ["vm", /^(linux_|windows_)?virtual_machine(?:_|$)/, "Azure virtual machine"],
    ["secret", /^key_vault(?:_|$)/, "Azure Key Vault"],
    ["api_gateway", /^api_management(?:_|$)/, "Azure API Management"],
  ],
  gcp: [
    ["cluster", /^(gke|container_cluster|kubernetes_cluster)(_|$)/, "Google Kubernetes Engine"],
    ["bucket", /^storage_bucket$/, "Google Cloud Storage bucket"],
    ["vm", /^(compute_)?instance$/, "Google Compute Engine instance"],
    ["database", /^sql_database_instance$/, "Google Cloud SQL instance"],
    ["warehouse", /^bigquery(?:_|$)/, "Google BigQuery dataset"],
  ],
  snowflake: [["warehouse", /^warehouse$/, "Snowflake warehouse"], ["database", /^database$/, "Snowflake database"]],
  databricks: [["cluster", /^cluster$/, "Databricks cluster"], ["warehouse", /^sql_warehouse$/, "Databricks SQL warehouse"]],
};

/** A more specific label only when the recorded vendor and semantic kind agree. */
export function recordedServiceLabel(input: AssetKindInput, kind: AssetKind, nativeTypes: string[]): string | undefined {
  const attributes = input.attributes ?? {};
  const vendors = [input.provider, attributes.cloud_provider, attributes.provider, attributes.vendor]
    .filter((value): value is string => typeof value === "string" && Boolean(value.trim()))
    .map(value => value.trim().toLowerCase());
  if (!vendors.length || new Set(vendors).size !== 1 || !Object.hasOwn(SERVICES, vendors[0]!)) return undefined;
  const labels = new Set(SERVICES[vendors[0]!]?.filter(([expectedKind, pattern]) =>
    expectedKind === kind && nativeTypes.some(value => pattern.test(value))).map(([, , label]) => label));
  return labels.size === 1 ? [...labels][0] : undefined;
}
