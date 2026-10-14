# Product scenarios

Start with a question, run the workflow, and inspect its evidence. The image
below uses the **Reference evidence lab — modeled local infrastructure**:
real parser and local gateway execution, a published advisory, and explicit
modeled infrastructure. It is not a customer incident or live-cloud proof.

## Scan a repository before shipping

From the repository you want to inspect:

```bash
agent-bom scan . -f json -o scan.json
agent-bom report compliance-narrative scan.json
```

The first command produces inventory, findings, and coverage for the selected
project. The second turns that saved evidence into a compliance narrative.
Review incomplete collectors before treating an absence of findings as a clean
result. Use the [first-run guide](FIRST_RUN.md) for SARIF and CI gates.

## Follow an image-processing exposure

An AppSec engineer receives an advisory affecting an image-processing service.
The actionable question is whether the affected package belongs to a workload
with a route to a sensitive asset.

The [reference lab](../examples/reference-evidence-lab/README.md) follows
`CVE-2023-4863` through a pinned Pillow dependency, image SBOM, Kubernetes
manifest, MCP configuration, and modeled identity. The shared graph shows the
recorded relationships and their direction. Select a node or relationship to
inspect its source, then open the scoped findings and remediation.

<img src="images/correlation-path-live.png" alt="Pillow advisory investigation with eight ordered entities, remediation action, and per-hop evidence" width="900" />

This is a structural exposure supported by the lab inputs, not execution of an
exploit. The lab observes an allowed local gateway call, then checks that graph
enforcement blocks another call before the upstream tool runs. That proves the
local enforcement decision, not removal of the vulnerable deployment.

The upstream [Pillow 10.0.1 release notes](https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html)
document updated wheels containing libwebp 1.3.2 for this advisory. The lab
matches package versions; it does not inspect a running service's libwebp binary.

## Verify the package change

From a repository checkout, run the offline before/after replay:

```bash
uv run python scripts/replay_package_remediation.py --output /tmp/package-replay.json
```

The real dependency parser and scanner read two isolated manifests. Pillow
9.0.0 matches the pinned advisory; 10.0.1 crosses that advisory's fixed-version
boundary. Neither package is installed or executed. The JSON receipt records
both results and the limited advisory coverage. This historical version pair
is a reproducible test case, not a current upgrade recommendation.

In an actual environment, rebuild and redeploy using a supported version,
collect a fresh SBOM and runtime identity, and re-run correlation. Close the
exposure only when the new evidence supports that decision. Retain the prior
scan and receipts for the audit trail.

[Run the complete lab](../examples/reference-evidence-lab/README.md) ·
[Start a self-hosted control plane](registry/DOCKER_HUB_UI_README.md) ·
[Evidence and graph contract](graph/CONTRACT.md)

Synthetic layout fixtures remain in the [capture protocol](CAPTURE.md) for UI
regression coverage. They are separate from these reproducible scenario claims.

## Compare recorded scan history

In a self-hosted control plane, run repeated scans of the same explicit target,
then open **Overview → Changes over time**. Select the history window and scan
scope to see newly detected findings, findings no longer detected, and median
open-finding and evidence ages. The table links each observation to its scan's
findings. History loads when this section opens.

Comparisons require compatible scope, measurement version and complete collection.
Partial scans and legacy records without comparison metadata show unavailable
changes. A missing finding does not prove remediation: verification remains a
separate audited workflow. Ages use recorded timestamps; evidence age is measured
at scan completion, and missing timestamps remain unavailable. Imported standalone
reports do not establish historical trends. Scan history has a separate scope from
the aggregate posture summary.

## Follow one component

Open **Inventory → Packages**, select a component, then follow **Findings →
Compliance**. The component identifier and retained snapshot stay in scope.
The captures below are synthetic UI states from the packaged product routes.

| Step | Inspect | Captures |
|---|---|---|
| Component | Recorded relationships, sources, timestamps and unknown collection coverage | [Light](images/component-detail-light-live.png) · [Dark](images/component-detail-dark-live.png) |
| Findings | Directly linked finding records in this component snapshot | [Light](images/component-findings-light-live.png) · [Dark](images/component-findings-dark-live.png) |
| Controls | Applicability mapping marked **Mapped · Not evaluated**, with exportable evidence | [Light](images/component-controls-light-live.png) · [Dark](images/component-controls-dark-live.png) |

For a parser-backed scan and changed-input rescan, run the
[connected-BOM example](../examples/connected-bom/README.md). It uses a different
bounded advisory fixture and explicitly synthetic cloud topology. A finding no
longer present after the input change is not proof that a deployment was repaired.

## Explore connections and inspect evidence

These graph enhancements are available in current source; the pinned `0.108.4`
release predates them. In **Investigation → Explore connections**, select a
snapshot and search for a package or agent. Start with its bounded neighborhood,
then use **Show more connections** or **Expand** to inspect related entities.

**Repository — connect source, configuration and dependencies.** A sample
service links its source imports, deployment configuration and CI job to the
published container, two vulnerable packages and a CI misconfiguration. The
fixture models configured relationships; it does not establish that the CI job
ran or that a workload was deployed.

<picture><source media="(prefers-color-scheme: light)" srcset="images/graph-repository-light-live.png"><img src="images/graph-repository-dark-live.png" alt="Sample repository linking source, deployment configuration and a CI job to a container, vulnerable npm and PyPI packages, their advisories and a CI misconfiguration" width="1440"></picture>

**Environment — see agents alongside their infrastructure.** A sample
production AI environment holds two agents and an internet-facing model-serving
workload. Follow each to its MCP server, vulnerable package, KEV-listed
advisory, exposed API key and the customer data store that key can reach.
Badges show the provider, environment tier and package ecosystem; rings show
the worst linked finding.

<picture><source media="(prefers-color-scheme: light)" srcset="images/graph-environment-light-live.png"><img src="images/graph-environment-dark-live.png" alt="Sample production AI environment where two agents and a model-serving workload reach vulnerable packages, a KEV-listed advisory, an exposed API key and a customer data store" width="1440"></picture>

**Cloud estate — inspect accounts, workloads, identities and data.** A sample
account exposes a workload through a public API gateway; the workload carries a
critical advisory and authenticates as a role with permission to a PII bucket.
Misconfigurations sit beside the assets they affect. Configuration does not
prove reachability or effective access.

<picture><source media="(prefers-color-scheme: light)" srcset="images/graph-cloud-light-live.png"><img src="images/graph-cloud-dark-live.png" alt="Sample cloud account where a public API gateway exposes a workload with a critical advisory that authenticates as a role permitted to read a PII bucket" width="1440"></picture>

These three views use explicitly labeled synthetic UI fixtures. Each is captured
through its actual **View & layers** preset; none is live-cloud evidence.

**Start with one component.** The selected package stays beside its MCP server
and vulnerability. The inspector links to that package's findings in the same
snapshot. This capture uses labeled synthetic UI fixtures.

<picture><source media="(prefers-color-scheme: light)" srcset="images/context-map-light-live.png"><img src="images/context-map-live.png" alt="Selected Next.js package with its MCP server, vulnerability and scoped findings action" width="1440"></picture>

**Open the relationship evidence.** Select an arrow to inspect its direction,
snapshot, first/last seen timestamps and source receipt. In the reference lab
below, a repository pin, an image SBOM and a modeled Kubernetes workload resolve
to one `pillow@9.0.0`; its advisory link came from the bundled scanner.
It does not establish a cloud execution or downstream effect.

<picture><source media="(prefers-color-scheme: light)" srcset="images/graph-relationship-light-live.png"><img src="images/graph-relationship-dark-live.png" alt="Repository pin, image SBOM and Kubernetes workload resolving to one pillow package linked to KEV-listed CVE-2023-4863, with the advisory receipt open" width="1440"></picture>

**Follow the finding into action.** Switch to **Find a path** to investigate
recorded finding paths, then use the scoped findings and remediation links.
Re-scan the same scope before closing the finding. Missing receipts remain
missing evidence; graph connectivity alone does not prove successful access.

[See the full reference graph](images/correlation-graph-live.png) ·
[Inspect the mobile view](images/correlation-path-mobile-live.png) ·
[Run the reference lab](../examples/reference-evidence-lab/README.md)
