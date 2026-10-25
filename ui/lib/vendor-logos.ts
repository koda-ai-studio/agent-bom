import { ASSET_BASE } from "@/lib/asset-base";
/**
 * Vendor brand marks shipped under `public/logos/`. `vendorLogo(provider)`
 * resolves a provider/account string to its SVG path (served from the app
 * root) or `null` when there is no known mark. Rendering is intentionally left
 * to follow-up PRs — this only exposes the assets + a normalizing lookup so
 * callers don't hand-roll provider→logo mapping.
 */

export type VendorId = "aws" | "gcp" | "azure" | "snowflake" | "github" | "claude" | "cursor";

const LOGO_PATH: Record<VendorId, string> = {
  aws: `${ASSET_BASE}/logos/aws.svg`,
  gcp: `${ASSET_BASE}/logos/gcp.svg`,
  azure: `${ASSET_BASE}/logos/azure.svg`,
  snowflake: `${ASSET_BASE}/logos/snowflake.svg`,
  github: `${ASSET_BASE}/logos/github.svg`,
  claude: `${ASSET_BASE}/logos/claude.svg`,
  cursor: `${ASSET_BASE}/logos/cursor.svg`,
};

/** Common provider aliases normalize onto a canonical VendorId. */
const ALIASES: Record<string, VendorId> = {
  aws: "aws",
  "amazon": "aws",
  "amazon web services": "aws",
  gcp: "gcp",
  google: "gcp",
  "google cloud": "gcp",
  "google cloud platform": "gcp",
  azure: "azure",
  microsoft: "azure",
  "microsoft azure": "azure",
  snowflake: "snowflake",
  github: "github",
  "github actions": "github",
  claude: "claude",
  anthropic: "claude",
  cursor: "cursor",
};

/** Resolve a provider/account label to its brand-mark path, or null. */
export function vendorLogo(provider: string | null | undefined): string | null {
  if (!provider) return null;
  const key = provider.trim().toLowerCase();
  const id = (ALIASES[key] ?? (key in LOGO_PATH ? (key as VendorId) : undefined));
  return id ? LOGO_PATH[id] : null;
}
