# Share a scan impact brief

Turn saved scan evidence into a self-contained HTML brief for review, with
separate counts for affected asset IDs, linked agent IDs, finding occurrences,
finding groups and recorded paths. Engineers can expand the source rows behind
prioritized findings and before/after changes.

## First command → artifact → next step

From a fresh Python environment, install the published package and produce a
brief from the bundled sample:

```bash
pip install agent-bom
agent-bom scan --demo --offline -f json -o example-scan.json
agent-bom report impact example-scan.json --limit 5 -o impact-brief.html
```

Run the commands separately: the fictional demo deliberately exits `1` with
blocking findings, after writing its JSON. Inspect the report if a command
fails; a missing artifact or incomplete scan is not a clean result. The
`report impact` command does not scan, contact a provider,
start an MCP tool or modify an installation. Open `impact-brief.html` in a
browser. It contains no scripts, remote fonts, images, tracking or uploads.
The light/dark layout follows the browser preference and supports printing.
Use a new output path each time; existing evidence is never overwritten.

Review the scope and missing-identity counts before sharing the file. Expand
**Inspect source receipt** to see the sanitized finding row and its JSON
pointer in the original scan. Assign an owner, check applicability, approve
the change separately, and collect new evidence in the same scope.

## Explain one finding in 90 seconds

Open the brief and use these four steps for a review with an engineering lead
or security manager. The duration is a suggested presentation length, not a
measured time-to-value claim.

1. **Set the scope.** Read **Evidence coverage** and expand **Inspect scope,
   gaps and source digest**. Name the scanned scope and any missing evidence.
   Affected assets, linked agents, occurrences and paths are separate counts;
   do not add them into a single total.
2. **Show the evidence.** Pick one item under **What to review first** and open
   **Inspect source receipt**. Explain the affected component, recorded finding
   and source pointer. Follow its graph relationships when available, retaining
   their evidence type and direction. A recorded path does not prove exploitation.
3. **Ask for a decision.** Use the recorded remediation to propose a next step.
   Confirm the service owner and business criticality with the team. These are
   human inputs: the brief orders rows by severity and does not calculate
   business loss, exploit likelihood or an automatic business priority.
4. **Define completion.** Agree who will check applicability, approve the
   change and collect fresh evidence. With no baseline, say that change has
   not been assessed; even a later missing finding does not establish a fix.

A useful spoken summary is: “This scan records **[finding]** on **[asset]**.
The evidence supports **[relationship or exposure]**; **[gap]** remains
unknown. We propose **[action]**, owned by **[confirmed owner]**, and will
verify it with **[specific evidence]**.” Leave unconfirmed fields unknown.

For your own repository, run `agent-bom scan . -f json -o project-scan.json`,
then `agent-bom report impact project-scan.json --limit 5 -o project-impact.html`.
This scan can contact advisory services; inspect collection coverage and the
artifact before sharing. See the [first-run guide](../FIRST_RUN.md) for offline
database preparation and scan boundaries. The command does not send the brief.

## Compare retained scans

```bash
agent-bom report impact after.json --before before.json --limit 10 -o impact-change.html
agent-bom report impact after.json --before before.json --format json -o impact-change.json
```

Both inputs must be Agent-Bom AI-BOM scan JSON (`schema_version: "1.0"`),
with distinct scan IDs, ordered timezone-aware timestamps and the same
recorded canonical identity scheme. If tenant labels are present, they must
match. A local file's label does not authenticate a tenant or grant access to
the control plane. Inputs without authenticated provenance remain local
evidence supplied by the operator.

The change view separates newly recorded, retained, changed and **not
observed** occurrence IDs. Changed is a subset of retained, not an additional
finding count. A change can include source metadata; it is not necessarily a
change in risk. Each bounded change includes its before/after source row and
pointer. Matching recorded scope names and scan sources are reported only
when both inputs also record complete collection without coverage issues.
Otherwise scope comparability stays unverified.

**Not observed does not mean fixed.** Package upgrades can change occurrence
IDs, collection can be incomplete, and scanner coverage can differ. This
report never marks findings resolved or verifies a deployment. Use
[installed-package verification](PACKAGE_REMEDIATION_VERIFICATION.md) for its
explicitly bounded installed-metadata check and retain independent change and
runtime evidence for broader claims.

## Counting and evidence rules

- Asset totals count explicit canonical/stable asset IDs. Equal names are not
  merged; missing IDs are reported separately. These are recorded identities,
  not proof of distinct physical machines or effective authorities.
- Finding rows, unique occurrence IDs and finding-group IDs are different
  quantities. Exact duplicate rows count once per occurrence; conflicting
  duplicate IDs are rejected before aggregation.
- Linked agent totals use explicit `agent_server_links[].agent_ref` values.
  The report does not infer links from names, run graph traversal or turn a
  relationship into evidence of successful execution.
- Recorded paths are counted separately by their own IDs. Missing path data
  is unknown, not zero. Bounded path receipts retain direction and source
  evidence in the expandable scope section.
- Priorities use recorded severity, then occurrence ID for deterministic
  ordering. Recommendations and confidence basis are source values; missing
  values stay unknown. Business consequence and exploitability are not
  inferred from a score or a framework mapping.

## Bounds and sharing

Each input is limited to 20 MB and each finding/path collection to 20,000
rows. `--limit` accepts 1–50 and bounds priorities, path details and each
change category; counts still cover every validated input row. A source row
larger than 64 KB is represented by an explicit omission and its digest.
Included receipt strings are redacted and limited to 4,000 characters.

Source SHA-256 values bind sorted compact ASCII JSON, not raw file bytes or
an authenticated author. The original inputs remain the complete evidence;
keep them privately alongside the brief. Redaction is best effort: asset
names, conditions and other operational context can still be sensitive.
Review the artifact before sending it to anyone. The command itself sends
nothing and collects no usage telemetry.

Invalid JSON, duplicate JSON keys, conflicting identities, incompatible
comparison inputs or an existing output path cause an error. They do not
produce a successful empty/clean report. An exit code of zero means the
artifact was written, not that findings were fixed.
