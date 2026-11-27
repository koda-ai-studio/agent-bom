/** Recorded scope stays out of the canvas: a header line, never a frame the layout must route around. */
export function GraphScopeBreadcrumb({ label, className = "" }: { label: string | null; className?: string }) {
  if (!label) return null;
  return <p data-scope-breadcrumb className={`truncate text-xs text-ink-secondary ${className}`} title={label}>{label}</p>;
}
