import type { FindingTriageDecision } from "@/lib/api";

export type ReachabilityFilter = "" | "reachable" | "unreachable" | "unassessed";
export type TriageFilter = "" | FindingTriageDecision | "untriaged";

export const DOMAIN_FILTERS: { key: string; label: string }[] = [
  { key: "all", label: "All domains" },
  { key: "cspm", label: "CSPM" },
  { key: "vuln", label: "Vuln mgmt" },
  { key: "aspm", label: "ASPM" },
  { key: "dspm", label: "DSPM" },
  { key: "aispm", label: "AISPM" },
];

const PROVIDER_OPTIONS = ["aws", "azure", "gcp", "snowflake", "databricks"];

export const WINDOW_OPTIONS: { value: number; label: string }[] = [
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 365, label: "Last 12 months" },
  { value: 0, label: "All time" },
];

export function FindingsAdvancedFilters({
  windowDays,
  domainFilter,
  providerFilter,
  accountFilter,
  environmentFilter,
  ownerFilter,
  slaFilter,
  reachabilityFilter,
  triageFilter,
  setWindowDays,
  setDomainFilter,
  setProviderFilter,
  setAccountFilter,
  setEnvironmentFilter,
  setOwnerFilter,
  setSlaFilter,
  setReachabilityFilter,
  setTriageFilter,
  clearAdvancedFilters,
  activeFilterCount,
  setFiltersOpen
}: {
  windowDays: number;
  domainFilter: string;
  providerFilter: string;
  accountFilter: string;
  environmentFilter: string;
  ownerFilter: string;
  slaFilter: "" | "overdue" | "due" | "unassigned";
  reachabilityFilter: ReachabilityFilter;
  triageFilter: TriageFilter;
  setWindowDays: (value: number) => void;
  setDomainFilter: (value: string) => void;
  setProviderFilter: (value: string) => void;
  setAccountFilter: (value: string) => void;
  setEnvironmentFilter: (value: string) => void;
  setOwnerFilter: (value: string) => void;
  setSlaFilter: (value: "" | "overdue" | "due" | "unassigned") => void;
  setReachabilityFilter: (value: ReachabilityFilter) => void;
  setTriageFilter: (value: TriageFilter) => void;
  clearAdvancedFilters: () => void;
  activeFilterCount: number;
  setFiltersOpen: (open: boolean) => void;
}) {
  return (
    <div
      role="dialog"
      aria-label="Advanced filters"
      data-testid="findings-filters-popover"
      className="absolute right-0 z-40 mt-2 flex w-[min(22rem,90vw)] flex-col gap-3 rounded-xl border border-outline bg-surface p-3 shadow-xl"
    >
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Time window</span>
        <select
          value={windowDays}
          onChange={(e) => setWindowDays(Number(e.target.value))}
          data-testid="findings-window-select"
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
        >
          {WINDOW_OPTIONS.map(({ value, label }) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Domain</span>
        <div className="flex flex-wrap items-center gap-1">
          {DOMAIN_FILTERS.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              onClick={() => setDomainFilter(key)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                domainFilter === key
                  ? "border-accent-mint bg-surface-muted text-foreground"
                  : "border-outline text-ink-secondary hover:border-outline-strong hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Cloud</span>
        <select
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
        >
          <option value="">Any provider</option>
          {PROVIDER_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p.toUpperCase()}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Account</span>
        <input
          type="text"
          placeholder="e.g. aws:123456789012"
          value={accountFilter}
          onChange={(e) => setAccountFilter(e.target.value)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Environment</span>
        <input
          type="text"
          placeholder="e.g. prod"
          value={environmentFilter}
          onChange={(e) => setEnvironmentFilter(e.target.value)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Owner</span>
        <input
          type="text"
          placeholder="e.g. payments-security"
          value={ownerFilter}
          onChange={(e) => setOwnerFilter(e.target.value)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">SLA</span>
        <select
          value={slaFilter}
          onChange={(e) => setSlaFilter(e.target.value as "" | "overdue" | "due" | "unassigned")}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
        >
          <option value="">Any SLA</option>
          <option value="overdue">Overdue</option>
          <option value="due">Due later</option>
          <option value="unassigned">No SLA</option>
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Reachability</span>
        <select
          value={reachabilityFilter}
          onChange={(e) => setReachabilityFilter(e.target.value as ReachabilityFilter)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
        >
          <option value="">Any reachability</option>
          <option value="reachable">Reachable</option>
          <option value="unreachable">Unreachable</option>
          <option value="unassessed">Unassessed</option>
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Triage</span>
        <select
          value={triageFilter}
          onChange={(e) => setTriageFilter(e.target.value as TriageFilter)}
          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
        >
          <option value="">Any triage state</option>
          <option value="not_affected">Not affected</option>
          <option value="affected">Affected</option>
          <option value="under_investigation">Under investigation</option>
          <option value="untriaged">Untriaged</option>
        </select>
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-outline pt-2">
        <button
          type="button"
          onClick={clearAdvancedFilters}
          disabled={activeFilterCount === 0}
          className="rounded-lg px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          Clear all
        </button>
        <button
          type="button"
          onClick={() => setFiltersOpen(false)}
          className="rounded-lg border border-outline bg-surface-elevated px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:border-outline-strong"
        >
          Done
        </button>
      </div>
    </div>
  );
}
