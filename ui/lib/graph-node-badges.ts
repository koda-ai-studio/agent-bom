import type { LineageNodeType } from "@/lib/entity-icons";
import type { LegendItem } from "@/lib/graph-utils";
import type { NodeDimensions } from "@/lib/graph-schema";
import type { NodeRiskAssessment } from "@/lib/node-risk-assessment";

/**
 * Node badges are read from recorded node fields only. An unrecognised value
 * produces no badge rather than a guessed tier, ecosystem or provider.
 */
export type NodeBadgeKind = "provider" | "environment" | "ecosystem";
export type RingSeverity = "critical" | "high" | "medium" | "low";

export interface NodeBadge {
  kind: NodeBadgeKind;
  value: string;
  label: string;
  raw: string;
  description: string;
}

export interface SeverityRing {
  severity: RingSeverity;
  description: string;
}

export interface NodeBadgeInput {
  nodeType: LineageNodeType | string;
  severity?: string | undefined;
  ecosystem?: string | undefined;
  vulnCount?: number | undefined;
  dimensions?: NodeDimensions | undefined;
  attributes?: Record<string, unknown> | undefined;
  riskAssessment?: NodeRiskAssessment | undefined;
}

const ENVIRONMENT_TIERS: Record<string, { value: string; label: string; legend: string }> = {
  prod: { value: "prod", label: "PROD", legend: "Production environment" },
  staging: { value: "staging", label: "STAGING", legend: "Staging environment" },
  dev: { value: "dev", label: "DEV", legend: "Development or test environment" },
};
const ENVIRONMENT_ALIASES: Record<string, keyof typeof ENVIRONMENT_TIERS> = {
  prod: "prod", production: "prod", prd: "prod", live: "prod",
  staging: "staging", stage: "staging", stg: "staging", preprod: "staging", "pre-prod": "staging", uat: "staging",
  dev: "dev", development: "dev", test: "dev", testing: "dev", qa: "dev", sandbox: "dev",
};

const ECOSYSTEMS: Record<string, { value: string; label: string }> = {
  npm: { value: "npm", label: "npm" },
  pypi: { value: "pypi", label: "PyPI" },
  golang: { value: "golang", label: "Go" },
  go: { value: "golang", label: "Go" },
  maven: { value: "maven", label: "Maven" },
  cargo: { value: "cargo", label: "crates.io" },
  "crates.io": { value: "cargo", label: "crates.io" },
  nuget: { value: "nuget", label: "NuGet" },
  gem: { value: "gem", label: "RubyGems" },
  rubygems: { value: "gem", label: "RubyGems" },
  composer: { value: "composer", label: "Packagist" },
  packagist: { value: "composer", label: "Packagist" },
  hex: { value: "hex", label: "Hex" },
  pub: { value: "pub", label: "Pub" },
  cocoapods: { value: "cocoapods", label: "CocoaPods" },
  swift: { value: "swift", label: "Swift" },
  conda: { value: "conda", label: "conda" },
  deb: { value: "deb", label: "Debian" },
  debian: { value: "deb", label: "Debian" },
  rpm: { value: "rpm", label: "RPM" },
  apk: { value: "apk", label: "Alpine" },
  alpine: { value: "apk", label: "Alpine" },
};

const PROVIDERS: Record<string, { value: string; label: string }> = {
  coreweave: { value: "coreweave", label: "CoreWeave" },
  crusoe: { value: "crusoe", label: "Crusoe" },
  database: { value: "database", label: "Database" },
  huggingface: { value: "huggingface", label: "Hugging Face" },
  lambda: { value: "lambda", label: "Lambda" },
  mlflow: { value: "mlflow", label: "MLflow" },
  nebius: { value: "nebius", label: "Nebius" },
  ollama: { value: "ollama", label: "Ollama" },
  openai: { value: "openai", label: "OpenAI" },
  runpod: { value: "runpod", label: "RunPod" },
  vastai: { value: "vastai", label: "Vast.ai" },
  wandb: { value: "wandb", label: "W&B" },
  okta: { value: "okta", label: "Okta" },
  entra: { value: "entra", label: "Entra" },
  supabase: { value: "supabase", label: "Supabase" },
  vercel: { value: "vercel", label: "Vercel" },
  nvidia: { value: "nvidia", label: "NVIDIA" },
  modal: { value: "modal", label: "Modal" },
  langchain: { value: "langchain", label: "LangChain" },
  langgraph: { value: "langgraph", label: "LangGraph" },
  langfuse: { value: "langfuse", label: "Langfuse" },
  langsmith: { value: "langsmith", label: "LangSmith" },
  clickhouse: { value: "clickhouse", label: "ClickHouse" },
  github: { value: "github", label: "GitHub" },
  cloudflare: { value: "cloudflare", label: "Cloudflare" },
  fireworks: { value: "fireworks", label: "Fireworks AI" },

  aws: { value: "aws", label: "AWS" },
  azure: { value: "azure", label: "Azure" },
  gcp: { value: "gcp", label: "GCP" },
  google: { value: "gcp", label: "GCP" },
  "google-cloud": { value: "gcp", label: "GCP" },
  snowflake: { value: "snowflake", label: "Snowflake" },
  kubernetes: { value: "kubernetes", label: "K8s" },
  k8s: { value: "kubernetes", label: "K8s" },
  databricks: { value: "databricks", label: "Databricks" },
};

/** Where a node runs; packages, findings and files inherit it from their host. */
const ENVIRONMENT_TYPES = new Set<string>([
  "environment", "cluster", "container", "cloudResource", "dataStore", "apiGateway",
  "agent", "server", "sharedServer", "account", "fleet", "model", "dataset",
]);
const PROVIDER_EXCLUDED_TYPES = new Set<string>([
  "vulnerability", "misconfiguration", "driftIncident", "package", "tool", "toolCall",
  "credential", "sourceFile", "configFile", "codeModule", "directory",
]);
const ECOSYSTEM_TYPES = new Set<string>(["package", "framework", "codeModule"]);
const FINDING_TYPES = new Set<string>(["vulnerability", "misconfiguration", "driftIncident"]);
const RING_SEVERITIES = new Set<string>(["critical", "high", "medium", "low"]);

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function purlType(value: unknown): string {
  const match = /^pkg:([a-z0-9.+-]+)\//i.exec(text(value));
  return match ? match[1]!.toLowerCase() : "";
}

function environmentBadge(data: NodeBadgeInput): NodeBadge | null {
  if (!ENVIRONMENT_TYPES.has(data.nodeType)) return null;
  const raw = text(data.dimensions?.environment) || text(data.attributes?.environment);
  const tier = ENVIRONMENT_TIERS[ENVIRONMENT_ALIASES[raw.toLowerCase()] ?? ""];
  if (!tier) return null;
  return { kind: "environment", value: tier.value, label: tier.label, raw, description: `Environment: ${raw}` };
}

function ecosystemBadge(data: NodeBadgeInput): NodeBadge | null {
  if (!ECOSYSTEM_TYPES.has(data.nodeType)) return null;
  const candidates = [
    text(data.ecosystem), text(data.dimensions?.ecosystem), text(data.attributes?.ecosystem),
    purlType(data.attributes?.purl), purlType(data.attributes?.package_url),
  ];
  for (const raw of candidates) {
    const known = ECOSYSTEMS[raw.toLowerCase()];
    if (known) return { kind: "ecosystem", ...known, raw, description: `Package ecosystem: ${known.label}` };
  }
  return null;
}

function providerBadge(data: NodeBadgeInput): NodeBadge | null {
  if (PROVIDER_EXCLUDED_TYPES.has(data.nodeType)) return null;
  const candidates = [
    text(data.dimensions?.cloud_provider), text(data.attributes?.cloud_provider), text(data.attributes?.provider),
  ];
  for (const raw of candidates) {
    const known = PROVIDERS[raw.toLowerCase()];
    if (known) return { kind: "provider", ...known, raw, description: `Cloud provider: ${known.label}` };
  }
  return null;
}

function severityRing(data: NodeBadgeInput): SeverityRing | null {
  if (FINDING_TYPES.has(data.nodeType)) return null;
  const severity = text(data.severity).toLowerCase();
  if (!RING_SEVERITIES.has(severity)) return null;
  const linked = data.vulnCount ?? 0;
  if (linked <= 0 && data.riskAssessment?.status !== "assessed") return null;
  const detail = linked > 0 ? ` · ${linked} linked finding${linked === 1 ? "" : "s"}` : " · assessed risk";
  return { severity: severity as RingSeverity, description: `Recorded severity: ${severity}${detail}` };
}

export function nodeBadges(data: NodeBadgeInput): { badges: NodeBadge[]; ring: SeverityRing | null } {
  const badges = [providerBadge(data), environmentBadge(data), ecosystemBadge(data)]
    .filter((badge): badge is NodeBadge => badge !== null);
  return { badges, ring: severityRing(data) };
}

export const NODE_BADGE_CLASSES: Record<NodeBadgeKind, Record<string, string> & { default: string }> = {
  provider: {
    default: "border-violet-300 bg-violet-500/10 text-violet-800 dark:border-violet-800 dark:text-violet-200",
  },
  environment: {
    default: "border-outline-strong bg-surface-muted text-ink-secondary",
    prod: "border-rose-300 bg-rose-500/10 text-rose-800 dark:border-rose-800 dark:text-rose-200",
    staging: "border-amber-300 bg-amber-500/10 text-amber-800 dark:border-amber-800 dark:text-amber-200",
    dev: "border-sky-300 bg-sky-500/10 text-sky-800 dark:border-sky-800 dark:text-sky-200",
  },
  ecosystem: {
    default: "border-outline-strong bg-surface-muted text-ink-secondary",
  },
};

export function nodeBadgeClass(badge: Pick<NodeBadge, "kind" | "value">): string {
  const styles = NODE_BADGE_CLASSES[badge.kind];
  return styles[badge.value] ?? styles.default;
}

/** The full ring is reserved for findings and CVEs; it is their one severity signal on the canvas. */
export const SEVERITY_RING_CLASSES: Record<RingSeverity, string> = {
  critical: "border-[color:var(--severity-ring-critical)]",
  high: "border-[color:var(--severity-ring-high)]",
  medium: "border-[color:var(--severity-ring-medium)]",
  low: "border-[color:var(--severity-ring-low)]",
};

/** A finding's recorded severity when it is one of the four rated tiers. */
export function findingRingSeverity(data: Pick<NodeBadgeInput, "nodeType" | "severity">): RingSeverity | null {
  if (!FINDING_TYPES.has(data.nodeType)) return null;
  const severity = text(data.severity).toLowerCase();
  return RING_SEVERITIES.has(severity) ? severity as RingSeverity : null;
}

const RING_ORDER: RingSeverity[] = ["critical", "high", "medium", "low"];
const KIND_ORDER: NodeBadgeKind[] = ["provider", "environment", "ecosystem"];

function badgeLegendLabel(badge: NodeBadge): string {
  if (badge.kind === "environment") return ENVIRONMENT_TIERS[badge.value]?.legend ?? badge.label;
  return `${badge.label} ${badge.kind === "provider" ? "provider" : "ecosystem"}`;
}

/** Legend rows for the badges actually rendered on the given nodes. */
export function badgeLegendItems(nodes: Array<{ data?: unknown }>): LegendItem[] {
  const badges = new Map<string, NodeBadge>();
  const findings = new Set<RingSeverity>();
  for (const node of nodes) {
    const data = node.data as Partial<NodeBadgeInput> | undefined;
    if (!data || typeof data.nodeType !== "string") continue;
    const result = nodeBadges(data as NodeBadgeInput);
    for (const badge of result.badges) badges.set(`${badge.kind}:${badge.value}`, badge);
    const finding = findingRingSeverity(data as NodeBadgeInput);
    if (finding) findings.add(finding);
  }
  const ordered = [...badges.values()].sort((left, right) =>
    KIND_ORDER.indexOf(left.kind) - KIND_ORDER.indexOf(right.kind) || left.label.localeCompare(right.label));
  return [
    ...ordered.map((badge): LegendItem => ({
      label: badgeLegendLabel(badge), color: "", layer: "badge", kind: "badge",
      badge: { kind: badge.kind, value: badge.value, label: badge.label },
    })),
    // A visible finding earns the whole ring scale, so every tier can be read from one key.
    ...(findings.size ? RING_ORDER : []).map((severity): LegendItem => ({
      label: `${severity.charAt(0).toUpperCase()}${severity.slice(1)} finding`,
      color: "", layer: "badge", kind: "badge", ring: severity,
      description: "The ring around a finding or CVE is its severity; scores are in the tooltip and inspector",
    })),
  ];
}
