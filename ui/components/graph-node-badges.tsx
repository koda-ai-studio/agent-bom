import type { ReactNode } from "react";

import {
  FINDING_SIGNAL_CLASSES,
  SEVERITY_RING_CLASSES,
  nodeBadgeClass,
  type NodeBadge,
  type RingSeverity,
  type SeverityRing,
} from "@/lib/graph-node-badges";

type ChipBadge = Pick<NodeBadge, "kind" | "value" | "label"> & { description?: string };

/** One chip, shared by node cards and legend rows so both render identically. */
export function NodeBadgeChip({ badge }: { badge: ChipBadge }) {
  return (
    <span
      title={badge.description}
      aria-label={badge.description}
      data-node-badge={badge.kind}
      style={{ fontSize: "var(--graph-node-meta-size, 11px)", lineHeight: 1.3 }}
      className={`inline-flex items-center rounded border px-1.5 py-px text-[11px] font-semibold leading-4 tracking-wide ${nodeBadgeClass(badge)}`}
    >
      {badge.label}
    </span>
  );
}

/** The entity type label followed by its chips, on one wrapping line. */
export function NodeBadgeRow({ badges, children }: { badges: NodeBadge[]; children: ReactNode }) {
  if (badges.length === 0) return <>{children}</>;
  return (
    <div className="flex max-w-full flex-wrap items-center justify-center gap-x-1.5 gap-y-1" data-testid="graph-node-badges">
      {children}
      {badges.map((badge) => <NodeBadgeChip key={`${badge.kind}:${badge.value}`} badge={badge} />)}
    </div>
  );
}

/** Small dot at 1:30 on an asset glyph that links to findings; the glyph must be `relative`. The full ring stays reserved for findings. */
export function FindingSignalDot({ ring }: { ring: SeverityRing }) {
  return (
    <span
      role="img"
      aria-label={ring.description}
      title={ring.description}
      data-finding-signal={ring.severity}
      className={`graph-finding-signal pointer-events-none absolute rounded-full ${FINDING_SIGNAL_CLASSES[ring.severity]}`}
    />
  );
}

/** Legend swatch for a finding's severity ring. */
export function SeverityRingSwatch({ severity }: { severity: RingSeverity }) {
  return <span aria-hidden="true" className={`inline-block h-3.5 w-3.5 rounded-full border-[3px] ${SEVERITY_RING_CLASSES[severity]}`} />;
}

/** Legend swatch for an asset's linked-findings dot, drawn on a neutral disc like the node. */
export function FindingSignalSwatch({ severity }: { severity: RingSeverity }) {
  return <span aria-hidden="true" className="relative inline-block h-3.5 w-3.5 rounded-full border border-outline-strong"><span className={`absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full ${FINDING_SIGNAL_CLASSES[severity]}`} /></span>;
}
