/**
 * One display-name resolver per entity kind. Every surface (overview, graph,
 * agents, remediation, drawers) names an agent or server through these, so one
 * entity never shows as "langchain-service", "Langchain Service" and
 * "LangChain Service Agent" on three pages. A recorded display name wins;
 * otherwise the identifier is formatted the same way everywhere, without
 * inventing words (no " service" / " connector" suffixes).
 */

const TOKEN_CASING: Record<string, string> = {
  ai: "AI",
  api: "API",
  aws: "AWS",
  cli: "CLI",
  db: "DB",
  gcp: "GCP",
  github: "GitHub",
  gitlab: "GitLab",
  iam: "IAM",
  ide: "IDE",
  langchain: "LangChain",
  llamaindex: "LlamaIndex",
  llm: "LLM",
  mcp: "MCP",
  openai: "OpenAI",
  pii: "PII",
  postgres: "PostgreSQL",
  rag: "RAG",
  s3: "S3",
  sql: "SQL",
  ui: "UI",
};

function formatToken(token: string): string {
  const known = TOKEN_CASING[token.toLowerCase()];
  if (known) return known;
  return token.charAt(0).toUpperCase() + token.slice(1);
}

/** Scoped, path-like or address-like ids (`project:…`, ARNs, URIs, `user@host`, dotted names). */
const ID_SEPARATORS = /[:/@.]/;
/** A generated hash or hex id token, e.g. `a1157c3d9e`. */
const HASH_TOKEN = /^(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{6,}$/i;

/** Whether a name is an identifier that must render exactly as recorded, never re-cased. */
export function isVerbatimIdentifier(id: string): boolean {
  return ID_SEPARATORS.test(id) || id.split(/[-_]+/).some(token => HASH_TOKEN.test(token));
}

/** Canonical formatting of a slug; a name with spaces or an identifier is shown as recorded. */
export function formatEntityId(id: string): string {
  const trimmed = id.trim();
  if (!trimmed) return "";
  if (/\s/.test(trimmed) || isVerbatimIdentifier(trimmed)) return trimmed;
  return trimmed.split(/[-_]+/).filter(Boolean).map(formatToken).join(" ");
}

function recordedName(recorded: string | null | undefined): string {
  return typeof recorded === "string" ? recorded.trim() : "";
}

export function agentDisplayName(id: string, recorded?: string | null): string {
  return recordedName(recorded) || formatEntityId(id) || "Unknown agent";
}

/** An agent row's name: the API's resolved ``display_name`` when present, else the same rule locally. */
export function agentRecordDisplayName(agent: { name: string; display_name?: string | null | undefined; enrollment_name?: string | null | undefined }): string {
  return recordedName(agent.display_name) || agentDisplayName(agent.name, agent.enrollment_name);
}

export function serverDisplayName(id: string, recorded?: string | null): string {
  return recordedName(recorded) || formatEntityId(id) || "Unknown server";
}

/** The raw identifier, shown beside the display name only when it adds information. */
export function entityIdHint(id: string, displayName: string): string | undefined {
  const trimmed = id.trim();
  return trimmed && trimmed !== displayName ? trimmed : undefined;
}
