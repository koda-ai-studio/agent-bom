import Link from "next/link";
import { Network } from "lucide-react";

import type { AdvisoryAffectedRow, AffectedProvenance, AffectedVerdict } from "@/lib/advisory-affected";
import { securityGraphHref } from "@/lib/page-links";
import { affectedAssetLabel } from "./affected-asset-identity";

const VERDICT_LABEL: Record<AffectedVerdict, string> = {
  affected: "Affected",
  possibly_affected: "Possibly affected — verify distro advisory",
  not_affected: "Not affected",
};

const VERDICT_CLASS: Record<AffectedVerdict, string> = {
  affected: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]",
  possibly_affected: "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  not_affected: "border-outline bg-surface-muted text-ink-secondary",
};

const PROVENANCE_LABEL: Record<AffectedProvenance, string> = {
  operator_advisory: "Operator advisory",
  feed: "Feed",
  scan: "Scan",
};

export function provenanceLabel(row: AdvisoryAffectedRow): string {
  return PROVENANCE_LABEL[row.provenance] ?? row.provenance;
}

export function rowKey(row: AdvisoryAffectedRow): string {
  return `${row.scan_id}|${row.graph.package_node_id}|${row.asset_label}`;
}

export function VerdictBadge({ row }: { row: AdvisoryAffectedRow }) {
  return (
    <span data-testid="verdict-badge" data-verdict={row.verdict} title={row.verdict_detail ?? undefined}
      className={`inline-flex max-w-full items-center rounded-md border px-2 py-0.5 text-left text-xs font-medium ${VERDICT_CLASS[row.verdict]}`}>
      {VERDICT_LABEL[row.verdict]}
    </span>
  );
}

export function VerdictDetail({ row }: { row: AdvisoryAffectedRow }) {
  return row.verdict_detail ? <p className="mt-1 break-words text-xs leading-5 text-ink-secondary">{row.verdict_detail}</p> : null;
}

function patchTarget(row: AdvisoryAffectedRow): string {
  if (row.verdict === "possibly_affected") return "verify distro advisory";
  if (row.verdict === "not_affected") return "Not needed";
  return row.fixed_version ?? "No fixed version published";
}

export function PatchTarget({ row }: { row: AdvisoryAffectedRow }) {
  const exact = row.verdict === "affected" && row.fixed_version;
  return <span data-testid="patch-target" className={`break-words text-xs ${exact ? "font-mono text-foreground" : "text-ink-secondary"}`}>{patchTarget(row)}</span>;
}

export function BlastRadiusLink({ row }: { row: AdvisoryAffectedRow }) {
  const node = row.graph.package_node_id || row.graph.server_node_id;
  if (!node) return null;
  return (
    <Link href={securityGraphHref({ scan: row.scan_id ?? undefined, node })}
      aria-label={`Blast radius for ${row.package.name} ${row.installed_version} on ${affectedAssetLabel(row)}`}
      className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2 py-0.5 text-xs font-medium text-ink-secondary hover:border-outline-strong hover:text-foreground">
      <Network className="h-3.5 w-3.5" aria-hidden /> Blast radius
    </Link>
  );
}
