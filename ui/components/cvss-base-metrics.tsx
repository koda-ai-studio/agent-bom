import type { ExploitStoryHow } from "@/lib/api-exploit-story";

type Cvss = NonNullable<ExploitStoryHow["cvss"]>;
type Metric = [label: string, value: string | null | undefined];

function MetricRows({ title, metrics }: { title: string; metrics: Metric[] }) {
  return <tbody className="border-t border-outline">
    <tr><th colSpan={2} scope="rowgroup" className="bg-surface-muted px-3 py-2 text-left text-xs font-semibold text-foreground">{title}</th></tr>
    {metrics.map(([label, value]) => <tr key={label}>
      <th scope="row" className="px-3 py-1.5 text-left font-normal text-ink-secondary">{label}</th>
      <td className="px-3 py-1.5 text-right font-medium text-foreground">{value ? value[0]!.toUpperCase() + value.slice(1).replaceAll("_", " ") : "Not recorded"}</td>
    </tr>)}
  </tbody>;
}

function impactMetrics(impact: Cvss["impact"] | null | undefined): Metric[] {
  return [["Confidentiality", impact?.confidentiality], ["Integrity", impact?.integrity], ["Availability", impact?.availability]];
}

/** Show decoded advisory fields without inferring deployment reachability. */
export function CvssBaseMetrics({ cvss, initiallyOpen = false }: { cvss: ExploitStoryHow["cvss"]; initiallyOpen?: boolean }) {
  if (!cvss) return <p className="text-xs text-ink-secondary">No CVSS base metrics recorded.</p>;
  const v4 = cvss.version === "4.0";
  const prerequisites: Metric[] = [
    ["Attack vector", cvss.attack_vector], ["Attack complexity", cvss.attack_complexity],
    ...(v4 ? [["Attack requirements", cvss.attack_requirements] as Metric] : []),
    ["Privileges required", cvss.privileges_required], ["User interaction", cvss.user_interaction],
    ...(!v4 ? [["Scope", cvss.scope] as Metric] : []),
  ];
  return <details open={initiallyOpen} className="group min-w-0 rounded-lg border border-outline bg-surface">
    <summary className="cursor-pointer rounded-lg px-3 py-3 text-sm text-foreground hover:bg-surface-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-mint">
      <span className="font-semibold">CVSS v{cvss.version} base metrics</span>
      <span className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs font-normal text-ink-secondary">
        <span>Attack vector: {cvss.attack_vector[0]!.toUpperCase() + cvss.attack_vector.slice(1)}</span>
        {cvss.score != null && <span>Score: {cvss.score} / 10</span>}
      </span>
    </summary>
    <div className="space-y-2 border-t border-outline p-3">
    <div className="overflow-hidden rounded-lg border border-outline bg-surface">
      <table className="w-full text-sm" aria-label={`CVSS v${cvss.version} base metrics`}>
        <MetricRows title="Exploitability metrics" metrics={prerequisites} />
        <MetricRows title={v4 ? "Vulnerable system impact" : "Impact metrics"} metrics={impactMetrics(cvss.impact)} />
        {v4 && <MetricRows title="Subsequent system impact" metrics={impactMetrics(cvss.subsequent_impact)} />}
      </table>
    </div>
    <p className="break-all font-mono text-xs text-ink-secondary">{cvss.vector}</p>
    <p className="text-xs leading-5 text-ink-secondary">Advisory conditions, not verified deployment reachability. Network does not by itself mean internet-accessible; impact metrics do not establish observed losses.</p>
    </div>
  </details>;
}
