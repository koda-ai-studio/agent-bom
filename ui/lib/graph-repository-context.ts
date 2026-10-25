import { ASSET_BASE } from "@/lib/asset-base";
import type { AgentSource } from "@/lib/agent-source";

type RepositoryInput = { nodeType: string; entityType?: string | undefined; attributes?: Record<string, unknown> | undefined };
const text = (value: unknown) => typeof value === "string" ? value.trim() : "";
const HOSTS: Record<string, AgentSource> = {
  github: { id: "github", label: "GitHub", src: `${ASSET_BASE}/logos/github.svg`, monogram: "GH", accent: "#70809c" },
  gitlab: { id: "gitlab", label: "GitLab", src: null, monogram: "GL", accent: "#70809c" },
  bitbucket: { id: "bitbucket", label: "Bitbucket", src: null, monogram: "BB", accent: "#70809c" },
};

/** Repository overlays explicitly mark roots; names and URLs never establish type. */
export function graphRepositoryContext(data: RepositoryInput) {
  const attrs = data.attributes ?? {};
  if (!(data.nodeType === "directory" && (attrs.is_repo_root === true || attrs.is_repo_trust === true))
    && !(data.entityType === "application" && attrs.is_repo_trust === true)) return null;
  const provider = text(attrs.provider).toLowerCase();
  const source = Object.hasOwn(HOSTS, provider) ? HOSTS[provider]! : null;
  let remote = "";
  try {
    const url = new URL(text(attrs.repo_url));
    if (url.protocol === "https:" || url.protocol === "http:") remote = `${url.protocol}//${url.host}${url.pathname}`;
  } catch { /* Missing or non-HTTP remotes remain unavailable, never echoed raw. */ }
  return {
    slug: text(attrs.full_name) || text(attrs.repo_full_name),
    source,
    host: source?.label ?? (remote ? new URL(remote).hostname : "Remote not recorded"),
    remote,
    branch: text(attrs.branch),
    defaultBranch: text(attrs.default_branch),
    commit: text(attrs.commit_sha) || text(attrs.repository_commit) || text(attrs.git_commit),
  };
}
