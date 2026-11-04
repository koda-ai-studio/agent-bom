import { describe, expect, it } from "vitest";
import { assetKindLabel } from "@/lib/asset-icon-registry";

describe("recorded service identity on graph nodes", () => {
  it.each([
    ["aws", "cluster", "aws_eks_cluster", "Amazon EKS"],
    ["aws", "data_store", "AWS::S3::Bucket", "Amazon S3 bucket"],
    ["aws", "cloud_resource", "ec2", "Amazon EC2 instance"],
    ["aws", "role", "iam_role", "AWS IAM role"],
    ["aws", "api_gateway", "AWS::ApiGateway::RestApi", "Amazon API Gateway"],
    ["azure", "cluster", "azurerm_kubernetes_cluster", "Azure Kubernetes Service"],
    ["azure", "data_store", "azurerm_storage_container", "Azure Blob container"],
    ["gcp", "cluster", "google_container_cluster", "Google Kubernetes Engine"],
    ["gcp", "data_store", "google_storage_bucket", "Google Cloud Storage bucket"],
    ["snowflake", "cloud_resource", "warehouse", "Snowflake warehouse"],
    ["databricks", "cluster", "cluster", "Databricks cluster"],
  ])("keeps %s %s %s specific", (provider, entityType, resource_type, label) => {
    expect(assetKindLabel({ entityType, attributes: { cloud_provider: provider, resource_type } })).toBe(label);
  });

  it("uses the recorded service when a collector supplies a broad native type", () => {
    expect(assetKindLabel({ entityType: "cluster", attributes: { cloud_provider: "aws", resource_type: "container_cluster", service: "eks" } })).toBe("Amazon EKS");
    expect(assetKindLabel({ entityType: "data_store", attributes: { cloud_provider: "aws", service: "S3" } })).toBe("Amazon S3 bucket");
  });

  it("does not manufacture a service from a cloud alone or resource name", () => {
    expect(assetKindLabel({ entityType: "cluster", attributes: { cloud_provider: "aws", name: "payments-eks" } })).toBe("Cluster");
    expect(assetKindLabel({ entityType: "data_store", attributes: { name: "customer-s3-bucket" } })).toBe("Data");
    expect(assetKindLabel({ entityType: "cloud_resource", attributes: { cloud_provider: "aws", service: "future_service" } })).toBe("Cloud");
  });

  it("does not choose a brand when recorded providers conflict", () => {
    expect(assetKindLabel({ entityType: "data_store", provider: "azure", attributes: { cloud_provider: "aws", resource_type: "s3" } })).toBe("Bucket");
    expect(assetKindLabel({ entityType: "data_store", attributes: { cloud_provider: "aws", provider: "azure", resource_type: "s3" } })).toBe("Bucket");
  });

  it("keeps the generic kind when recorded service fields disagree", () => {
    expect(assetKindLabel({ entityType: "data_store", attributes: { cloud_provider: "aws", resource_type: "rds", service: "dynamodb" } })).toBe("Database");
  });

  it("keeps findings and code distinct from the service described in their evidence", () => {
    expect(assetKindLabel({ entityType: "misconfiguration", attributes: { cloud_provider: "aws", resource_type: "s3" } })).toBe("Finding");
    expect(assetKindLabel({ entityType: "package", attributes: { cloud_provider: "aws", resource_type: "s3" } })).toBe("Package");
  });
});
