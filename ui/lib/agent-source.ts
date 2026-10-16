/** Agent identity comes from recorded source fields, never its display name. */
export interface AgentSource {
  id: string;
  label: string;
  src: string | null;
  monogram: string;
  accent: string;
  darkMark?: boolean;
}

type SourceInput = {
  nodeType?: string | undefined;
  agentType?: string | undefined;
  attributes?: Record<string, unknown> | undefined;
  dataSources?: string[] | undefined;
};

const BRANDS: Record<string, AgentSource> = {
  claude: { id: "claude", label: "Claude", src: "/logos/claude.svg", monogram: "Cl", accent: "#c76b4e" },
  cursor: { id: "cursor", label: "Cursor", src: "/logos/cursor.svg", monogram: "Cu", accent: "#8170d5" },
  openai: { id: "openai", label: "OpenAI", src: "/logos/openai.svg", monogram: "OA", accent: "#169c88", darkMark: true },
  windsurf: { id: "windsurf", label: "Windsurf", src: "/logos/windsurf.svg", monogram: "W", accent: "#158d96" },
  copilot: { id: "copilot", label: "GitHub Copilot", src: "/logos/copilot.svg", monogram: "Co", accent: "#7565d8" },
  snowflake: { id: "snowflake", label: "Snowflake", src: "/logos/snowflake.svg", monogram: "Sn", accent: "#278dbe" },
  aws: { id: "aws", label: "AWS", src: "/logos/aws.svg", monogram: "AWS", accent: "#bd790f" },
  azure: { id: "azure", label: "Azure", src: "/logos/azure.svg", monogram: "Az", accent: "#168bd1" },
  gcp: { id: "gcp", label: "Google Cloud", src: "/logos/gcp.svg", monogram: "GC", accent: "#4285c4" },
  github: { id: "github", label: "GitHub", src: "/logos/github.svg", monogram: "GH", accent: "#70809c" },
};

// Product types are more specific than collector or hosting metadata.
const TYPES: Record<string, [string, string]> = {
  "claude-desktop": ["claude", "Claude Desktop"], "claude-code": ["claude", "Claude Code"],
  cursor: ["cursor", "Cursor"], windsurf: ["windsurf", "Windsurf"],
  "codex-cli": ["openai", "OpenAI Codex"], codex: ["openai", "OpenAI Codex"],
  "vscode-copilot": ["copilot", "VS Code Copilot"], "copilot-cli": ["copilot", "GitHub Copilot CLI"],
  "cortex-code": ["snowflake", "Cortex Code"], "snowflake-cli": ["snowflake", "Snowflake CLI"],
  "amazon-q": ["aws", "Amazon Q"],
};

// Clearly labeled monograms where no source-owned logo is bundled.
const MONOGRAMS: Record<string, [string, string, string]> = {
  "gemini-cli": ["Gemini CLI", "G", "#4285c4"], cline: ["Cline", "Cl", "#5e82c2"],
  goose: ["Goose", "Go", "#99814e"], continue: ["Continue", "Cn", "#5b9075"],
  zed: ["Zed", "Z", "#728299"], openclaw: ["OpenClaw", "OC", "#c46c74"],
  "roo-code": ["Roo Code", "R", "#9a794a"], "docker-mcp": ["Docker MCP", "D", "#278bd0"],
  "jetbrains-ai": ["JetBrains AI", "JB", "#a566c4"], junie: ["Junie", "J", "#9b6ec8"],
  tabnine: ["Tabnine", "T", "#8872c9"], "sourcegraph-cody": ["Sourcegraph Cody", "Cy", "#c47248"],
  aider: ["Aider", "A", "#6f8c52"], "replit-agent": ["Replit Agent", "Re", "#c87645"],
  void: ["Void", "V", "#708c85"], aide: ["Aide", "Ai", "#688fc0"],
  trae: ["Trae", "Tr", "#52977e"], pieces: ["Pieces", "P", "#6f8eab"],
  "mcp-cli": ["MCP CLI", "MCP", "#7b8495"],
};

function lookup(value: unknown): AgentSource | null {
  if (typeof value !== "string") return null;
  const key = value.trim().toLowerCase();
  if (Object.hasOwn(TYPES, key)) {
    const [brand, label] = TYPES[key]!;
    return { ...BRANDS[brand]!, label };
  }
  if (Object.hasOwn(MONOGRAMS, key)) {
    const [label, monogram, accent] = MONOGRAMS[key]!;
    return { id: key, label, monogram, accent, src: null };
  }
  const alias = key === "anthropic" ? "claude" : key;
  return Object.hasOwn(BRANDS, alias) ? BRANDS[alias]! : null;
}

export function agentSource(data: SourceInput): AgentSource | null {
  if (data.nodeType && data.nodeType !== "agent") return null;
  const typed = lookup(data.agentType) ?? lookup(data.attributes?.agent_type);
  if (typed) return typed;
  const declared = [data.attributes?.vendor, data.attributes?.provider, data.attributes?.source]
    .map(lookup).filter((source): source is AgentSource => source !== null);
  const sources = declared.length ? declared : (data.dataSources ?? []).map(lookup).filter((source): source is AgentSource => source !== null);
  // Several collected sources do not establish one vendor identity.
  return sources.length && new Set(sources.map(source => source.id)).size === 1 ? sources[0]! : null;
}
