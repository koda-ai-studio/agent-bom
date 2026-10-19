import { Disc3 } from "lucide-react";

import { entityIcon, type EntityIcon, type LineageNodeType } from "@/lib/entity-icons";

/** The recorded subtype of a `container` node: an image artifact or a running workload. */
export type ContainerKind = "image" | "workload";

export const CONTAINER_KIND_LABELS: Record<ContainerKind, string> = { image: "Image", workload: "Workload" };

/** Reads only the backend's `container_kind` attribute; labels and ids never decide it. */
export function containerKind(nodeType: LineageNodeType | string | undefined, attributes?: Record<string, unknown>): ContainerKind | undefined {
  if (nodeType !== "container") return undefined;
  const kind = attributes?.container_kind;
  return kind === "image" || kind === "workload" ? kind : undefined;
}

export function containerKindLabel(nodeType: LineageNodeType | string | undefined, attributes?: Record<string, unknown>): string | undefined {
  const kind = containerKind(nodeType, attributes);
  return kind ? CONTAINER_KIND_LABELS[kind] : undefined;
}

/** The glyph for a node: images get the disk-image glyph so they never read as the workload running them. */
export function nodeGlyph(nodeType: LineageNodeType | string | undefined, attributes?: Record<string, unknown>): EntityIcon {
  return containerKind(nodeType, attributes) === "image" ? Disc3 : entityIcon(nodeType);
}
