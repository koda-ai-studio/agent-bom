/** Scope caveats for the investigation queue, as compact one-line notes rather than full-width bands. */
export function InvestigationNotices({ question, sharedPathMissing, sourceSnapshot, relatedFinding, scenario }: {
  question: boolean;
  sharedPathMissing: boolean;
  sourceSnapshot: string | null;
  relatedFinding: boolean;
  scenario: boolean;
}) {
  if (!question && !sharedPathMissing && !sourceSnapshot && !relatedFinding && !scenario) return null;
  const note = "rounded-md border px-2.5 py-1 text-xs";
  return (
    <div className="flex flex-wrap gap-2">
      {sourceSnapshot ? (
        <p role="note" aria-label="Source snapshot" className={`${note} border-sky-500/30 bg-sky-500/10 text-sky-900 dark:text-sky-200`}>
          No path for this finding in the current estate. Showing the snapshot it was found in ({sourceSnapshot}).
        </p>
      ) : null}
      {relatedFinding ? (
        <p role="note" aria-label="Finding association" className={`${note} border-sky-500/30 bg-sky-500/10 text-sky-900 dark:text-sky-200`}>
          Related package and advisory paths. This scope does not establish a link to the selected finding record.
        </p>
      ) : null}
      {sharedPathMissing ? (
        <p role="status" className={`${note} border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200`}>
          The shared path is not in this loaded queue page. Load more paths or inspect its retained evidence scope; the currently shown path is a different result.
        </p>
      ) : null}
      {question ? (
        <p role="status" className={`${note} border-outline text-ink-secondary`}>
          Question filters apply to the loaded ranked paths. Load another page to widen this search; an empty page does not establish complete coverage.
        </p>
      ) : null}
      {scenario ? (
        <p className={`${note} border-sky-500/30 bg-sky-500/10 text-sky-900 dark:text-sky-200`}>
          Attack Paths remains observed-only. Open Estate, Cloud, Repository, Identity, or Lineage to compare this scenario&apos;s modeled state.
        </p>
      ) : null}
    </div>
  );
}
