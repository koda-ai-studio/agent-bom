import type { ReactNode } from "react";

/**
 * One compact row above the investigation content: title and focus, the
 * lifecycle steps, and a collapsed menu for secondary controls. Content —
 * the ranked paths — stays the hero instead of sitting under stacked bands.
 */
export function InvestigationPageHeader({ focus, context, steps, menu }: {
  focus: string;
  context?: ReactNode;
  steps?: ReactNode;
  menu?: ReactNode;
}) {
  return (
    <header className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex min-w-0 flex-1 basis-64 items-baseline gap-3">
          <h1 className="shrink-0 text-xl font-semibold tracking-tight text-foreground">Investigation</h1>
          <p className="min-w-0 truncate text-sm text-ink-secondary" title={focus}>{focus}</p>
        </div>
        {steps ? <div className="min-w-0 max-w-full [&_nav]:max-w-full [&_nav]:overflow-x-auto [&_ol]:flex-nowrap [&_li]:shrink-0">{steps}</div> : null}
        {menu}
      </div>
      {context}
    </header>
  );
}
