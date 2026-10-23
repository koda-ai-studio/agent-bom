import Link from "next/link";

import { findingRemediationHref, packageNameFromLabel, packageRemediationHref, pathFindingId } from "@/lib/investigation-step-links";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

const text = (value: unknown) => (typeof value === "string" && value.trim() ? value.trim() : undefined);

/** The selected path's fix, answered in place: what to upgrade, where, and a link to the full remediation queue. */
export function PathFixPanel({ path, nodes, findingId }: { path: AttackPath; nodes: UnifiedNode[]; findingId?: string | undefined }) {
  const advisory = nodes.find((node) => node.entity_type === "vulnerability" || node.entity_type === "misconfiguration");
  const pkg = nodes.find((node) => node.entity_type === "package");
  const servers = nodes.filter((node) => node.entity_type === "server").map((node) => node.label);
  const agents = nodes.filter((node) => node.entity_type === "agent").map((node) => node.label);
  const cve = path.vuln_ids[0] ?? advisory?.label ?? "this finding";
  const fixed = text(advisory?.attributes?.fixed_version);
  const guidance = text(advisory?.attributes?.remediation) ?? text(advisory?.attributes?.recommendation);
  const packageFinding = Boolean(pkg && advisory?.entity_type === "vulnerability");
  const name = text(pkg?.attributes?.name) ?? (pkg ? packageNameFromLabel(pkg.label) : undefined);
  const version = text(pkg?.attributes?.version) ?? (pkg && pkg.label.lastIndexOf("@") > 0 ? pkg.label.slice(pkg.label.lastIndexOf("@") + 1) : undefined);
  const where = [servers.length ? `on ${servers.join(", ")}` : "", agents.length ? `used by ${agents.join(", ")}` : ""].filter(Boolean).join(", ");
  return (
    <section role="region" aria-label={`Fix · ${cve}`} className="rounded-xl border border-outline bg-surface p-4 text-sm">
      <h3 className="font-semibold text-foreground">Fix · {cve}</h3>
      {!packageFinding ? (
        <p className="mt-1 text-foreground">{guidance ?? "No remediation guidance is recorded. Review the finding evidence, choose an applicable control, then rescan."}</p>
      ) : name && fixed ? (
        <p className="mt-1 text-foreground">Upgrade {name}{version ? ` from ${version}` : ""} to {fixed}{where ? ` ${where}` : ""}.</p>
      ) : (
        <p className="mt-1 text-ink-secondary">No fixed version is recorded for {cve}{name ? ` in ${name}` : ""}. Check the advisory or apply a compensating control{where ? ` ${where}` : ""}.</p>
      )}
      <p className="mt-1 text-xs text-ink-secondary">{packageFinding ? "This path only. Other occurrences of the package and their owners are listed in Remediation." : "Recorded guidance requires review. Rescan after changes; guidance alone does not verify a fix."}</p>
      {packageFinding && name ? (
        <Link href={packageRemediationHref(pkg?.label)} className="mt-2 inline-flex rounded-lg border border-outline bg-surface px-3 py-2 text-xs font-medium hover:bg-surface-muted">
          Open {name} in Remediation →
        </Link>
      ) : null}
      <Link href={findingRemediationHref(pathFindingId(path, nodes, findingId))} className="mt-2 inline-flex rounded-lg border border-outline bg-surface px-3 py-2 text-xs font-medium hover:bg-surface-muted">
        Open finding workflow →
      </Link>
    </section>
  );
}
