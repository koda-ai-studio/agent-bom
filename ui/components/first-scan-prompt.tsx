import Link from "next/link";
import { ArrowRight } from "lucide-react";

export function FirstScanPrompt() {
  return (
    <section aria-labelledby="first-evidence-title" className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-outline bg-surface p-4">
      <div className="min-w-0 max-w-2xl">
        <h2 id="first-evidence-title" className="font-semibold">Start with evidence</h2>
        <p className="mt-1 text-sm leading-6 text-ink-secondary">No scan evidence is recorded in this overview window. Connect a source or scan a project to begin. This is not a clean security verdict.</p>
      </div>
      <Link href="/get-started" className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-emerald-700 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600">
        Get started <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </Link>
    </section>
  );
}
