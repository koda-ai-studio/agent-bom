/**
 * One definition of "frameworks covered", shared by the overview and the
 * compliance page. Control frameworks are scored pass/fail; risk mappings
 * (OWASP / MITRE catalogs) report applicability only. Both pages count only
 * frameworks that are enabled for the current scan context.
 */
export type FrameworkCoverageInput = {
  kind: "scored" | "applicability";
  disabled?: boolean | undefined;
  pass: number;
  warn: number;
  fail: number;
};

export type FrameworkCoverageCounts = {
  tracked: number;
  controlFrameworks: number;
  evaluatedControlFrameworks: number;
  riskMappings: number;
};

export function frameworkCoverageCounts(frameworks: readonly FrameworkCoverageInput[]): FrameworkCoverageCounts {
  const enabled = frameworks.filter((framework) => !framework.disabled);
  const control = enabled.filter((framework) => framework.kind === "scored");
  return {
    tracked: enabled.length,
    controlFrameworks: control.length,
    evaluatedControlFrameworks: control.filter((framework) => framework.pass + framework.warn + framework.fail > 0).length,
    riskMappings: enabled.length - control.length,
  };
}

function plural(count: number, noun: string): string {
  return `${count.toLocaleString()} ${noun}${count === 1 ? "" : "s"}`;
}

export function controlFrameworksLabel(count: number): string {
  return plural(count, "control framework");
}

export function riskMappingsLabel(count: number): string {
  return plural(count, "risk mapping");
}

/** "12 control frameworks · 4 risk mappings" — the same sentence on every page. */
export function formatFrameworkCoverage(counts: FrameworkCoverageCounts): string {
  return `${controlFrameworksLabel(counts.controlFrameworks)} · ${riskMappingsLabel(counts.riskMappings)}`;
}
