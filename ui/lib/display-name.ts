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

/** Canonical formatting of a slug identifier; a name with spaces is already a display name. */
export function formatEntityId(id: string): string {
  const trimmed = id.trim();
  if (!trimmed) return "";
  if (/\s/.test(trimmed)) return trimmed;
  return trimmed.split(/[-_]+/).filter(Boolean).map(formatToken).join(" ");
}

function recordedName(recorded: string | null | undefined): string {
  return typeof recorded === "string" ? recorded.trim() : "";
}

export function agentDisplayName(id: string, recorded?: string | null): string {
  return recordedName(recorded) || formatEntityId(id) || "Unknown agent";
}

export function serverDisplayName(id: string, recorded?: string | null): string {
  return recordedName(recorded) || formatEntityId(id) || "Unknown server";
}

/** The raw identifier, shown beside the display name only when it adds information. */
export function entityIdHint(id: string, displayName: string): string | undefined {
  const trimmed = id.trim();
  return trimmed && trimmed !== displayName ? trimmed : undefined;
}
