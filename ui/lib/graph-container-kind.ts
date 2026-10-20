import { assetIcon } from "@/lib/asset-icon-registry";
import type { EntityIcon, LineageNodeType } from "@/lib/entity-icons";

/** The recorded subtype of a `container` node: an image artifact or a running workload. */
export type ContainerKind = "image" | "workload";

/** Reads only the backend's `container_kind` attribute; labels and ids never decide it. */
export function containerKind(nodeType: LineageNodeType | string | undefined, attributes?: Record<string, unknown>): ContainerKind | undefined {
  if (nodeType !== "container") return undefined;
  const kind = attributes?.container_kind;
  return kind === "image" || kind === "workload" ? kind : undefined;
}

/** The registry glyph for a node, refined by its recorded subtype (image vs workload, bucket vs database…). */
export function nodeGlyph(nodeType: LineageNodeType | string | undefined, attributes?: Record<string, unknown>, entityType?: string, provider?: string | null): EntityIcon {
  return assetIcon({ nodeType, entityType, attributes, provider });
}
