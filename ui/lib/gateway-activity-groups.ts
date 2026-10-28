import type { GatewayActivity } from "./gateway-activity";

/** Reported origin tuples are grouping context, never verified fleet identity. */
export function activityOrigin(event: GatewayActivity) {
  const provenance = event.submission_provenance;
  const source = provenance?.submission_source_id || event.source_id || "";
  const session = provenance?.submission_session_id || event.session_id || "";
  const reportedSource = provenance?.reported_source_id || "";
  const reportedSession = provenance?.reported_session_id || "";
  return {
    source, session, reportedSource, reportedSession,
    key: JSON.stringify([event.tenant_id, provenance?.submitter_principal_id || "", provenance?.authentication_method || "",
      source, session, reportedSource, reportedSession, event.agent_id, event.identity_id, event.profile_id,
      source || reportedSource ? "" : event.event_id]),
  };
}

export function activityGroups(events: GatewayActivity[]) {
  const groups = new Map<string, { key: string; event: GatewayActivity; total: number; blocked: number; warnings: number; tools: Set<string> }>();
  for (const event of events) {
    const { key } = activityOrigin(event);
    const group = groups.get(key) ?? { key, event, total: 0, blocked: 0, warnings: 0, tools: new Set<string>() };
    group.total += 1;
    if (event.decision === "deny") group.blocked += 1;
    else if (event.decision === "warn" || event.development_mode || /\.(warned|dev_bypass)$/.test(event.event_type)) group.warnings += 1;
    if (event.tool) group.tools.add(JSON.stringify([event.upstream, event.tool]));
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => b.blocked - a.blocked || b.warnings - a.warnings || b.total - a.total || a.key.localeCompare(b.key));
}
