import { assetKindLabel } from "@/lib/asset-icon-registry";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** Presentation only: full canonical labels remain in the tooltip and inspector. */
export function mcpNodeCaption(data: LineageNodeData, title: string) {
  const caption = baseCaption(data, title);
  return data.flowNote ? { ...caption, meta: `${caption.meta} · ${data.flowNote}` } : caption;
}

function baseCaption(data: LineageNodeData, title: string) {
  if (data.displayOnly && data.readingLabel) return { title, meta: data.readingLabel };
  if (data.nodeType === "package") {
    const name = title.replace(/^@[^/]+\//, "").replace(/@[^@]+$/, "");
    const version = data.version ?? title.match(/@([^@/]+)$/)?.[1];
    return { title: name, meta: ["Package", version].filter(Boolean).join(" · ") };
  }
  if (data.nodeType === "server" || data.nodeType === "sharedServer") {
    return { title, meta: ["MCP server", data.identityContext].filter(Boolean).join(" · ") };
  }
  if (["misconfiguration", "vulnerability"].includes(data.nodeType)) {
    // Preserve complete advisory identifiers. Long prose is a preview; the
    // canonical title remains in the node tooltip, accessible name and drawer.
    const preview = data.nodeType === "misconfiguration" && title.length > 56 && title.includes(" ")
      ? `${title.slice(0, 53).replace(/\s+\S*$/, "")}…` : title;
    return { title: preview, meta: [data.severity, "Finding"].filter(Boolean).join(" · ") };
  }
  // Say which kind of Service this is: ClusterIP routes stay inside the cluster.
  if (data.attributes?.kubernetes_kind === "Service" && typeof data.attributes.service_type === "string") {
    const type = data.attributes.service_type;
    return { title, meta: `Kubernetes service · ${type === "ClusterIP" || type === "ExternalName" ? `${type} (internal)` : type}` };
  }
  return { title, meta: data.nodeType === "agent" ? "Client" : data.nodeType === "credential" ? "Credential reference" : assetKindLabel({ nodeType: data.nodeType, entityType: data.entityType, attributes: data.attributes }) };
}
