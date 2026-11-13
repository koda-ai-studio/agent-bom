import type { AgentListParams, AgentSortKey } from "@/lib/api-inventory";

export const AGENT_PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_AGENT_PAGE_SIZE = 50;
export const AGENT_FACETS = ["type", "status", "source"] as const;
export type AgentFacet = (typeof AGENT_FACETS)[number];

const SORT_KEYS: readonly AgentSortKey[] = ["name", "servers", "packages", "credentials", "findings"];
// Param names the agents route itself owns (detail view); list state never writes them.
const LIST_PARAM_KEYS = ["q", "type", "status", "source", "sort", "order", "page", "size"];

export interface AgentListState {
  q: string;
  type: string[];
  status: string[];
  source: string[];
  sort: AgentSortKey | null;
  order: "asc" | "desc";
  page: number;
  pageSize: number;
}

function positiveInt(raw: string | null, fallback: number): number {
  const value = Number(raw);
  return raw != null && Number.isInteger(value) && value >= 1 ? value : fallback;
}

export function readAgentListState(params: URLSearchParams): AgentListState {
  const sort = params.get("sort");
  const validSort = SORT_KEYS.includes(sort as AgentSortKey) ? (sort as AgentSortKey) : null;
  const size = positiveInt(params.get("size"), DEFAULT_AGENT_PAGE_SIZE);
  return {
    q: (params.get("q") ?? "").slice(0, 200),
    type: params.getAll("type").filter(Boolean),
    status: params.getAll("status").filter(Boolean),
    source: params.getAll("source").filter(Boolean),
    sort: validSort,
    order: params.get("order") === "asc" ? "asc" : params.get("order") === "desc" ? "desc" : validSort === "name" ? "asc" : "desc",
    page: positiveInt(params.get("page"), 1),
    pageSize: (AGENT_PAGE_SIZES as readonly number[]).includes(size) ? size : DEFAULT_AGENT_PAGE_SIZE,
  };
}

/** URL for the list state, keeping any param the list does not own. */
export function agentListSearch(state: AgentListState, current: URLSearchParams): string {
  const params = new URLSearchParams();
  current.forEach((value, key) => {
    if (!LIST_PARAM_KEYS.includes(key)) params.append(key, value);
  });
  if (state.q.trim()) params.set("q", state.q.trim());
  for (const facet of AGENT_FACETS) for (const value of state[facet]) params.append(facet, value);
  if (state.sort) {
    params.set("sort", state.sort);
    params.set("order", state.order);
  }
  if (state.page > 1) params.set("page", String(state.page));
  if (state.pageSize !== DEFAULT_AGENT_PAGE_SIZE) params.set("size", String(state.pageSize));
  return params.toString();
}

export function agentListApiParams(state: AgentListState): AgentListParams {
  return {
    limit: state.pageSize,
    offset: (state.page - 1) * state.pageSize,
    q: state.q,
    type: state.type,
    status: state.status,
    source: state.source,
    sort: state.sort,
    order: state.order,
  };
}

/** Header click: a new column starts at its natural order (names A-Z, counts high-first); the same column flips. */
export function nextAgentSort(state: AgentListState, key: AgentSortKey): Pick<AgentListState, "sort" | "order"> {
  if (state.sort === key) return { sort: key, order: state.order === "asc" ? "desc" : "asc" };
  return { sort: key, order: key === "name" ? "asc" : "desc" };
}

export function toggleFacet(state: AgentListState, facet: AgentFacet, value: string): AgentListState {
  const selected = state[facet];
  const next = selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value];
  return { ...state, [facet]: next, page: 1 };
}
