import { vendorSourceFor } from "@/lib/agent-source";

/**
 * The attack-path queue's vendor scope, carried in the URL as `cross_vendor`:
 * `any` lists every path whose source and target nodes are recorded in
 * different vendors; `source>target` narrows by vendor, `*` meaning any.
 */
export const CROSS_VENDOR_PARAM = "cross_vendor";

const VENDOR = /^(\*|[a-z0-9_.-]{1,64})$/;

export function parseCrossVendor(raw: string | null | undefined): string {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "any" || value === "*>*") return "any";
  const [source, target, ...rest] = value.split(">");
  return !rest.length && source && target && VENDOR.test(source) && VENDOR.test(target) ? value : "";
}

/** `[source, target]` of a scope, `""` meaning any vendor. */
export function scopeVendors(scope: string): [string, string] {
  if (!scope || scope === "any") return ["", ""];
  const [source = "", target = ""] = scope.split(">");
  return [source === "*" ? "" : source, target === "*" ? "" : target];
}

export function crossVendorRequest(scope: string): { crossVendor?: true; sourceVendor?: string; targetVendor?: string } {
  if (!scope) return {};
  const [sourceVendor, targetVendor] = scopeVendors(scope);
  return { crossVendor: true, ...(sourceVendor ? { sourceVendor } : {}), ...(targetVendor ? { targetVendor } : {}) };
}

// Vendor (company) names where the bundled mark is labelled with a product name, or no mark is bundled.
const VENDOR_NAMES: Record<string, string> = { anthropic: "Anthropic", huggingface: "Hugging Face", openai: "OpenAI" };

export function vendorDisplayName(vendor: string): string {
  return VENDOR_NAMES[vendor] ?? vendorSourceFor(vendor)?.label ?? (vendor ? vendor[0]!.toUpperCase() + vendor.slice(1) : "Unknown vendor");
}

export function vendorPairLabel(source: string, target: string): string {
  return `${vendorDisplayName(source)} → ${vendorDisplayName(target)}`;
}

export function crossVendorScopeLabel(scope: string): string | null {
  if (!scope) return null;
  const [source, target] = scopeVendors(scope);
  if (!source && !target) return "Cross-vendor paths";
  return `Cross-vendor · ${source ? vendorDisplayName(source) : "any vendor"} → ${target ? vendorDisplayName(target) : "any other vendor"}`;
}
