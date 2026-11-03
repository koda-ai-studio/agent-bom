"use client";

export function PathPreviewControl({ preview, shown, loaded, onShowAll }: {
  preview: boolean; shown: number; loaded: number; onShowAll: () => void;
}) {
  if (!preview) return null;
  return <div className="my-3 space-y-2 text-xs text-ink-secondary" aria-label="Representative path preview">
    <p title="Different findings and assets are shown first. Row numbers retain their original queue rank.">Representative preview · {shown} of {loaded} loaded paths</p>
    <button type="button" className="graph-page-action" onClick={onShowAll}>Show all loaded paths in ranked order</button>
  </div>;
}
