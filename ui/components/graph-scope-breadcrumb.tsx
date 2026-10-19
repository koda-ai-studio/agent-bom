import { GraphProviderMark } from "@/components/graph-provider-mark";
import type { ScopeCrumb } from "@/lib/graph-scope-crumbs";
import { scopeProvider } from "@/lib/provider-basis";

/** One investigation-scope breadcrumb, carrying the scope's provider mark when recorded. */
export function ScopeBreadcrumbChip({ crumb, onClick }: { crumb: ScopeCrumb; onClick: () => void }) {
  const provider = scopeProvider({ cloud_provider: crumb.cloudProvider });
  return (
    <button type="button" onClick={onClick} className="graph-chip-neutral inline-flex items-center gap-1.5">
      {provider && <GraphProviderMark source={provider} attributes={{ cloud_provider_basis: crumb.cloudProviderBasis }} className="graph-provider-mark-inline h-5 w-5" />}
      {crumb.label}
    </button>
  );
}

/** " · [mark] Google Cloud" after a scope's type, from the roll-up payload only. */
export function ScopeProviderSuffix({ item, size = "h-6 w-6" }: {
  item: { cloud_provider?: string | undefined; cloud_provider_basis?: string | undefined };
  size?: string;
}) {
  const provider = scopeProvider(item);
  if (!provider) return null;
  return <>
    <span aria-hidden="true">{" · "}</span>
    <GraphProviderMark source={provider} attributes={{ cloud_provider_basis: item.cloud_provider_basis }} className={`graph-provider-mark-inline ${size}`} />
    <span>{provider.label}</span>
  </>;
}
