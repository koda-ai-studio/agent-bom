import type { LineageNodeData } from "@/components/lineage-nodes";

/** Presentation only: full canonical labels remain in the tooltip and inspector. */
export function mcpNodeCaption(data: LineageNodeData, title: string) {
  if (data.nodeType === "package") {
    const name = title.replace(/^@[^/]+\//, "").replace(/@[^@]+$/, "");
    const version = data.version ?? title.match(/@([^@/]+)$/)?.[1];
    return { title: name, meta: ["Package", version].filter(Boolean).join(" · ") };
  }
  if (data.nodeType === "server" || data.nodeType === "sharedServer") {
    return { title, meta: ["MCP server", data.identityContext].filter(Boolean).join(" · ") };
  }
  if (["misconfiguration", "vulnerability"].includes(data.nodeType)) {
    return { title, meta: [data.severity, "Finding"].filter(Boolean).join(" · ") };
  }
  return { title, meta: data.nodeType === "agent" ? "Client" : data.nodeType === "credential" ? "Credential reference" : "Tool" };
}
