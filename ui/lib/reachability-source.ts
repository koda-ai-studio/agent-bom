export type ReachabilitySourceFields = {
  graph_reachable_from_agents?: string[] | null | undefined;
  graph_reachable_from?: string[] | null | undefined;
};

/** First node that reaches the finding: an agent when one does, else any inbound path source. */
export function reachabilitySource(row: ReachabilitySourceFields): string | null {
  const agent = row.graph_reachable_from_agents?.find((value) => value.trim());
  if (agent) return agent;
  return row.graph_reachable_from?.find((value) => value.trim()) ?? null;
}

/** Short, readable tail of a graph node id (``kubernetes:workload:ns/app`` -> ``app``). */
export function reachabilitySourceLabel(source: string): string {
  const tail = source.split(/[:/]/).filter(Boolean).at(-1);
  return tail || source;
}
