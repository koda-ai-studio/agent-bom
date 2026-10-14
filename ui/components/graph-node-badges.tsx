import {
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
      className={`inline-flex items-center rounded border px-1.5 py-px text-[11px] font-semibold leading-4 tracking-wide ${nodeBadgeClass(badge)}`}
    >
      {badge.label}
    </span>
  );
}

export function NodeBadgeRow({ badges }: { badges: NodeBadge[] }) {
  if (badges.length === 0) return null;
  return (
    <div className="mt-1 flex max-w-full flex-wrap justify-center gap-1" data-testid="graph-node-badges">
      {badges.map((badge) => <NodeBadgeChip key={`${badge.kind}:${badge.value}`} badge={badge} />)}
    </div>
  );
}

/** Ring drawn just outside an entity glyph; the glyph must be `relative`. */
export function SeverityRingMark({ ring }: { ring: SeverityRing }) {
  return (
    <span
      role="img"
      aria-label={ring.description}
      title={ring.description}
      data-severity-ring={ring.severity}
      className={`pointer-events-none absolute -inset-[7px] rounded-full border-[3px] ${SEVERITY_RING_CLASSES[ring.severity]}`}
    />
  );
}

export function SeverityRingSwatch({ severity }: { severity: RingSeverity }) {
  return <span aria-hidden="true" className={`inline-block h-3.5 w-3.5 rounded-full border-[3px] ${SEVERITY_RING_CLASSES[severity]}`} />;
}
