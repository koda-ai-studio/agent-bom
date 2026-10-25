import { STATIC_DEMO_QUICKSTART_URL, STATIC_DEMO_READ_ONLY_MESSAGE, isStaticDemo } from "@/lib/static-demo";

/** Shell-wide notice in the public static demo: sample data only, writes disabled. */
export function StaticDemoBanner() {
  if (!isStaticDemo()) return null;
  return (
    <aside
      role="note"
      aria-label="Read-only demo"
      data-testid="static-demo-banner"
      className="mb-4 flex flex-col gap-2 rounded-lg border border-[color:var(--accent)]/40 bg-[color:var(--accent)]/10 px-3 py-2 text-sm text-foreground sm:flex-row sm:items-center sm:justify-between [overflow-wrap:anywhere]"
    >
      <p>
        <span className="font-semibold">{STATIC_DEMO_READ_ONLY_MESSAGE}</span>{" "}
        <span className="text-ink-secondary">Every account, asset and finding here is labelled sample data; scans, settings and sign-in are turned off.</span>
      </p>
      <a
        href={STATIC_DEMO_QUICKSTART_URL}
        className="shrink-0 font-semibold text-[color:var(--accent)] underline underline-offset-2"
      >
        Open the quick start
      </a>
    </aside>
  );
}
