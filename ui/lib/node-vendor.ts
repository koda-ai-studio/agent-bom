const NOT_VENDORS = new Set(["", "mcp", "local", "unknown", "none", "agent", "runtime", "framework", "sensor"]);
const ACCOUNT_FIELDS = ["account_id", "account_scope", "account", "subscription_id", "project_id"] as const;

/** The vendor and account a collector recorded on a node; never inferred from its id or name. */
export function nodeVendorAccount(node: { attributes?: Record<string, unknown> | undefined; dimensions?: { cloud_provider?: string | null | undefined } | undefined }): { vendor: string; account: string } {
  const attributes = node.attributes ?? {};
  const vendor = [attributes.cloud_provider, attributes.provider, node.dimensions?.cloud_provider]
    .map(value => (typeof value === "string" ? value.trim().toLowerCase() : ""))
    .find(value => value && !NOT_VENDORS.has(value)) ?? "";
  const account = ACCOUNT_FIELDS.map(field => attributes[field]).find(value => typeof value === "string" && value.trim());
  return { vendor, account: typeof account === "string" ? account : "" };
}
