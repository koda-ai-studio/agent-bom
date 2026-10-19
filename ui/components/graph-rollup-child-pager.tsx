import type { GraphRollupPagination } from "@/lib/api-types";

/** Server-side paging for a roll-up level (top-level scopes or a drill-down's direct children) larger than one page. */
export function GraphRollupChildPager({
  pagination,
  onPage,
  scope = "children",
}: {
  pagination?: GraphRollupPagination | undefined;
  onPage: (offset: number) => void;
  scope?: "children" | "top_level";
}) {
  if (!pagination || (pagination.offset === 0 && !pagination.has_more)) return null;
  const { offset, returned, total, limit } = pagination;
  const pageSize = limit ?? returned;
  const first = returned > 0 ? offset + 1 : offset;
  const noun = scope === "top_level" ? "top-level scopes" : "direct children";
  const short = scope === "top_level" ? "scopes" : "children";
  return (
    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-ink-secondary" data-testid="graph-rollup-child-pager">
      <span>
        Showing {first.toLocaleString()}–{(offset + returned).toLocaleString()} of {total.toLocaleString()} {noun}
      </span>
      <button
        type="button"
        className="graph-chip-neutral disabled:cursor-not-allowed disabled:opacity-40"
        aria-label={`Previous ${short}`}
        disabled={offset === 0}
        onClick={() => onPage(Math.max(0, offset - pageSize))}
      >
        Previous
      </button>
      <button
        type="button"
        className="graph-chip-neutral disabled:cursor-not-allowed disabled:opacity-40"
        aria-label={`Next ${short}`}
        disabled={!pagination.has_more || pagination.next_offset === null}
        onClick={() => {
          if (pagination.next_offset !== null) onPage(pagination.next_offset);
        }}
      >
        Next
      </button>
    </div>
  );
}
