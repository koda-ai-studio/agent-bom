"use client";

export function PathStat({
  label,
  value,
  tone = "zinc",
}: {
  label: string;
  value: string;
  tone?: "zinc" | "red" | "amber" | "blue";
}) {
  const toneClass =
    tone === "red"
      ? "border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-200"
      : tone === "amber"
        ? "border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-200"
        : tone === "blue"
          ? "border-sky-500/20 bg-sky-500/10 text-sky-700 dark:text-sky-200"
          : "border-outline bg-surface/80 text-ink-secondary";

  return (
    <div className={`rounded-xl border px-3 py-2 ${toneClass}`}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary">
        {label}
      </p>
      <p className="mt-1 font-mono text-sm text-foreground">{value}</p>
    </div>
  );
}

export function PathTagList({
  label,
  tags,
  wide = false,
}: {
  label: string;
  tags: string[];
  wide?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border border-outline bg-surface/70 p-3 ${wide ? "lg:col-span-4" : ""}`}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {tags.map((tag) => (
          <span
            key={`${label}-${tag}`}
            className="graph-chip-elevated"
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  );
}
