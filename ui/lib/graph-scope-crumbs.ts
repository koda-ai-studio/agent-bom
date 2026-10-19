export type ScopeCrumb = {
  id: string;
  label: string;
  cloudProvider?: string | undefined;
};

type NamedScope = { id: string; label: string; cloud_provider?: string | undefined } | null | undefined;

/** Fill a crumb's name and provider from the server; an unchanged stack keeps its identity. */
export function nameScopeCrumbs<T extends ScopeCrumb>(stack: T[], named: NamedScope): T[] {
  if (!named?.label) return stack;
  const provider = named.cloud_provider || undefined;
  let changed = false;
  const next = stack.map(crumb => {
    if (crumb.id !== named.id) return crumb;
    const label = crumb.label === crumb.id ? named.label : crumb.label;
    if (label === crumb.label && provider === crumb.cloudProvider) return crumb;
    changed = true;
    return { ...crumb, label, cloudProvider: provider };
  });
  return changed ? next : stack;
}
