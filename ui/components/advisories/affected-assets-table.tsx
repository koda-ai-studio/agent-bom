import Link from "next/link";
import { Network } from "lucide-react";

import type { AdvisoryAffectedRow, AffectedProvenance, AffectedVerdict } from "@/lib/advisory-affected";
import { securityGraphHref } from "@/lib/page-links";

import { formatUtc } from "./advisory-format";

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

export function VerdictBadge({ row }: { row: AdvisoryAffectedRow }) {
  return (
    <span data-testid="verdict-badge" data-verdict={row.verdict} title={row.verdict_detail ?? undefined}
      className={`inline-flex max-w-full items-center rounded-md border px-2 py-0.5 text-xs font-medium ${VERDICT_CLASS[row.verdict]}`}>
      {VERDICT_LABEL[row.verdict]}
    </span>
  );
}

function patchTarget(row: AdvisoryAffectedRow): string {
  if (row.verdict === "possibly_affected") return "verify distro advisory";
  if (row.verdict === "not_affected") return "Not needed";
  return row.fixed_version ?? "No fixed version published";
}

function graphHref(row: AdvisoryAffectedRow): string | null {
  const node = row.graph.package_node_id || row.graph.server_node_id;
  return node ? securityGraphHref({ scan: row.scan_id ?? undefined, node }) : null;
}

const th = "px-3 py-2 font-medium";

/** One row per asset × package for the advisory; the table scrolls inside its own container. */
export function AffectedAssetsTable({ rows }: { rows: AdvisoryAffectedRow[] }) {
  return (
    <div className="relative max-w-full overflow-x-auto rounded-xl border border-outline">
      <table aria-label="Affected assets" className="w-full min-w-[62rem] text-left text-sm">
        <thead className="bg-surface-muted text-xs text-ink-tertiary">
          <tr>
            <th scope="col" className={th}>Asset</th>
            <th scope="col" className={th}>Package</th>
            <th scope="col" className={th}>Installed</th>
            <th scope="col" className={th}>Patch target</th>
            <th scope="col" className={th}>Verdict</th>
            <th scope="col" className={th}>Provenance</th>
            <th scope="col" className={th}>Last observed</th>
            <th scope="col" className={th}><span className="sr-only">Graph</span></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-outline">
          {rows.map(row => {
            const href = graphHref(row);
            const identity = row.package.purl ?? row.package.cpe;
            return (
              <tr key={`${row.scan_id}|${row.graph.package_node_id}|${row.asset_label}`} className="align-top">
                <td className="max-w-[16rem] px-3 py-2">
                  <p className="truncate font-medium text-foreground" title={row.asset_label}>{row.asset_label}</p>
                  <p className="truncate text-xs text-ink-tertiary" title={row.asset.agent}>{row.asset.agent}</p>
                </td>
                <td className="max-w-[14rem] px-3 py-2">
                  <p className="truncate font-mono text-xs text-foreground" title={identity}>{row.package.name}</p>
                  <p className="text-xs text-ink-tertiary">{row.package.ecosystem}</p>
                </td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-foreground">{row.installed_version}</td>
                <td data-testid="patch-target" className={`whitespace-nowrap px-3 py-2 text-xs ${row.verdict === "affected" && row.fixed_version ? "font-mono text-foreground" : "text-ink-secondary"}`}>{patchTarget(row)}</td>
                <td className="min-w-[17rem] max-w-[22rem] px-3 py-2">
                  <VerdictBadge row={row} />
                  {row.verdict_detail ? <p className="mt-1 text-xs leading-5 text-ink-secondary">{row.verdict_detail}</p> : null}
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-secondary">{PROVENANCE_LABEL[row.provenance] ?? row.provenance}</td>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-secondary">{formatUtc(row.last_observed_at)}</td>
                <td className="whitespace-nowrap px-3 py-2 text-right">
                  {href ? (
                    <Link href={href} aria-label={`Blast radius for ${row.package.name} ${row.installed_version} on ${row.asset_label}`}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2.5 py-1 text-xs font-medium text-ink-secondary hover:border-outline-strong hover:text-foreground">
                      <Network className="h-3.5 w-3.5" aria-hidden /> Blast radius
                    </Link>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
