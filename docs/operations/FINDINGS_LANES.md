# Findings lanes

Open **Findings** to start with Vulnerabilities. Select Cloud config, IaC,
Secrets, Identity, or Data to use that lane's evidence columns. Other retains
runtime, policy, and unclassified findings. All findings is the cross-lane queue
with links to Overview and Investigation.

Tabs show **issue groups**, under the current time window and filters. Package
advisories group their asset occurrences; cloud checks group by provider,
benchmark version, finding type, and control. Expand resource occurrences to
inspect the affected assets. The cloud row displays a representative resource;
use its evidence drawer for investigation. IaC uses repository evidence rather
than a declared cloud provider to identify code-side configuration findings.

A dash means a count is unavailable or refreshing. `≥` marks a bounded lower
count, not a complete total. Severity includes an explicit unrated bucket;
severity-source labels distinguish benchmark mappings, rule severity, and
collector-supplied ratings. Missing source metadata remains unreported.

## Query and export

Use the same tenant credentials as the dashboard:

```bash
curl -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  'http://localhost:8422/v1/findings?lane=iac&group_occurrences=true&include_facets=true'
```

The JSON response contains findings, pagination, and issue-group lane counts.
Follow `next_cursor` to continue; retain the same lane and other filters.
Available lane keys are `vulnerabilities`, `cloud`, `iac`, `secrets`, `identity`,
`data`, and `other`. Omit `lane` to query all findings. Existing `finding_class`
and posture-domain filters remain independent and intersect with the lane.

For headless use, pass `lane` to MCP `findings_query`. For a downloadable
NDJSON report, submit `{"lane":"iac"}` to `POST /v1/reports`, then follow the
returned job's status and authenticated download link. Reports retain individual
asset occurrences. The Findings page's OpenVEX export also retains its current
lane filter; only eligible triage decisions become VEX statements.

Lane selection and filters are encoded in the page URL. Existing finding,
framework, control, and scope deep links preserve their cross-lane scope unless
a lane is explicitly selected. Lane changes do not change the finding evidence
drawer's triage or control mappings.

Cloud config shows check results separately from severity: `CIS_FAIL` and
`CLOUD_BEST_PRACTICE_FAIL` display **Failed**; their `*_ERROR` counterparts display
**Not evaluated**. These are findings, not an inventory of all evaluated checks.
Passed checks are outside this queue, and an empty queue does not prove a pass.
A failed check is not itself a verdict on every GRC control mapped to it.
