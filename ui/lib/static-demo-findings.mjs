/** Query the bundled sample inventory; no live API or user data is involved. */
const CLASSES = { vulnerability: "vulnerability", malicious_package: "vulnerability", misconfiguration: "misconfiguration", secret: "secret", identity: "identity", pii_exposure: "pii" };
const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
const text = value => String(value ?? "").toLowerCase();
const values = value => Array.isArray(value) ? value.map(text) : value ? [text(value)] : [];
const domains = row => values(row.domains ?? row.domain ?? (row.finding_type === "vulnerability" ? "vuln" : null));
const findingClass = row => row.finding_class ?? CLASSES[row.finding_type] ?? "unclassified";

function matches(row, params, omit, snapshotAt) {
  const wanted = key => key === omit ? "" : params.get(key);
  for (const key of ["severity", "lane", "provider", "account", "environment", "owner", "scan_id"]) {
    const expected = wanted(key);
    if (expected && expected !== "all" && text(row[key]) !== text(expected)) return false;
  }
  if (wanted("finding_class") && findingClass(row) !== wanted("finding_class")) return false;
  if (wanted("domain") && !domains(row).includes(text(wanted("domain")))) return false;
  if (wanted("status") && wanted("status") !== "all" && (row.status ?? "open") !== wanted("status")) return false;
  if (wanted("kev") && Boolean(row.is_kev ?? row.cisa_kev) !== ["1", "true"].includes(wanted("kev"))) return false;
  if (wanted("q") && !text([row.id, row.cve_id, row.title, row.description, row.package_name, ...(row.affected_servers ?? []), ...(row.affected_agents ?? [])].join(" ")).includes(text(wanted("q")))) return false;
  if (wanted("framework") && !values(row.applicable_frameworks ?? row.framework_tags ?? row.compliance_tags).some(tag => tag === text(wanted("framework")) || tag.startsWith(`${text(wanted("framework"))}-`))) return false;
  if (wanted("control") && !values(row.controls ?? row.compliance_tags).some(tag => tag === text(wanted("control")) || tag.endsWith(`-${text(wanted("control"))}`))) return false;
  if (wanted("reachability") && (row.reachability ?? "unassessed") !== wanted("reachability")) return false;
  if (wanted("triage") && (row.triage?.status ?? row.triage_status ?? "untriaged") !== wanted("triage")) return false;
  const now = Date.parse(snapshotAt ?? "");
  const due = Date.parse(row.sla_due_at ?? "");
  if (wanted("sla") === "unassigned" && Number.isFinite(due)) return false;
  if (wanted("sla") === "overdue" && !(due < now)) return false;
  if (wanted("sla") === "due" && !(due >= now && due <= now + 7 * 86400000)) return false;
  const days = Number(wanted("window_days"));
  const observed = Date.parse(row.last_observed ?? row.last_seen ?? snapshotAt ?? "");
  if (days > 0 && Number.isFinite(now) && Number.isFinite(observed) && observed < now - days * 86400000) return false;
  return true;
}

function groupRows(rows, enabled) {
  if (!enabled) return rows;
  const groups = new Map();
  for (const row of rows) {
    const key = findingClass(row) === "vulnerability" ? JSON.stringify([row.cve_id ?? row.id, row.package_name, row.ecosystem]) : row.id;
    const group = groups.get(key);
    if (!group) groups.set(key, { ...row, occurrence_count: 1, occurrences: [{ ...row }] });
    else {
      group.occurrence_count++;
      group.occurrences.push({ ...row });
      group.domains = [...new Set([...domains(group), ...domains(row)])];
      if ((RANK[row.severity] ?? 0) > (RANK[group.severity] ?? 0)) group.severity = row.severity;
    }
  }
  return [...groups.values()];
}

export function queryStaticFindings(body, apiPath) {
  if (!body || !Array.isArray(body.findings)) throw new Error("The sample findings dataset is unavailable.");
  const params = new URL(apiPath, "https://demo.invalid").searchParams;
  const source = (body.findings ?? []).map(row => ({ ...row, scan_id: row.scan_id ?? body.scan_id }));
  const grouped = params.get("group_occurrences") === "true";
  const filtered = groupRows(source.filter(row => matches(row, params, null, body.snapshot_at)), grouped);
  const sort = params.get("sort") ?? "effective_reach";
  // Use recorded ranking signals. A generic risk score is not effective reach.
  const numeric = value => Number.isFinite(Number(value)) ? Number(value) : 0;
  const primary = row => sort === "severity" ? RANK[row.severity] ?? 0
    : sort === "cvss" ? numeric(row.cvss_score)
      : numeric(row.effective_reach_score ?? row.effective_reach?.composite);
  filtered.sort((a, b) => primary(b) - primary(a) || numeric(b.cvss_score) - numeric(a.cvss_score)
    || (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) || text(a.id).localeCompare(text(b.id)));
  const limit = Math.max(1, Math.min(1000, Number(params.get("limit")) || 50));
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const facets = {};
  for (const field of ["lane", "severity", "status", "finding_class", "domain"]) {
    const population = groupRows(source.filter(row => matches(row, params, field, body.snapshot_at)), grouped);
    facets[field] = field === "lane" ? Object.fromEntries(["vulnerabilities", "cloud", "iac", "secrets", "identity", "data", "other"].map(key => [key, 0])) : field === "severity" ? Object.fromEntries(Object.keys(RANK).map(key => [key, 0])) : {};
    for (const row of population) {
      const keys = field === "domain" ? domains(row) : [field === "finding_class" ? findingClass(row) : row[field] ?? (field === "status" ? "open" : "unknown")];
      for (const key of new Set(keys)) facets[field][key] = (facets[field][key] ?? 0) + 1;
    }
  }
  const findings = filtered.slice(offset, offset + limit);
  return { ...body, findings, total: filtered.length, count: findings.length, limit, offset, sort, grouped,
    has_more: offset + findings.length < filtered.length, next_cursor: null, facets,
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, domain: { basis: "multi_label", sums_to_total: false } },
  };
}
