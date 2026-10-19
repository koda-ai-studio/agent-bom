import type { ReactNode } from "react";
import type { LineageNodeData } from "../lineage-nodes";

export type LineageDetailProps = {
  data: LineageNodeData;
  onClose: () => void;
  onShowBlastRadius?: (() => void) | undefined;
  blastRadiusActive?: boolean;
  blastRadiusLoading?: boolean;
  /** overlay/docked become a full-screen dialog on mobile; inline stays in flow. */
  variant?: "overlay" | "inline" | "docked";
  relationshipSlot?: ReactNode;
  headerSlot?: ReactNode;
  footerSlot?: ReactNode;
};

export type TabId = "overview" | "relationships" | "impact" | "attributes";
