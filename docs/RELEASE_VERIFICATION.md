# Release Verification

`agent-bom` release tags publish verifiable release assets, not just package
files.

For each tagged GitHub Release, expect:

- Python distribution files: `agent_bom-<version>.tar.gz`, `agent_bom-<version>-py3-none-any.whl`
- Sigstore bundles for each distribution: `*.sigstore.json`
- SLSA provenance bundles for each distribution: `*.intoto.jsonl`
- CycloneDX SBOM: `agent-bom-sbom.cdx.json`

## Release matrix

Run this matrix before tagging a release that will back a hosted POC or a
customer self-hosted deployment. The goal is to prove the exact artifact shape
that users will touch: package install, CLI, API, UI, hosted preflight, and
signed release evidence.

| Surface | Command | Release bar |
|---|---|---|
| Pre-tag preflight | `scripts/preflight_release.sh <version>` | Runs the managed-file checks below plus `check_release_tag_is_new.py`: the version is not already tagged or published and the changelog documents it (this is what caught the 0.99.0 re-tag). |
| Exact main CI | `uv run python scripts/check_release_main_ci.py --repo koda-ai-studio/agent-bom --sha "$(git rev-parse HEAD)" --branch main --workflow ci.yml` | Candidate equals current `main` and its exact `CI/CD Pipeline` main-push run is completed successfully; pending, canceled, stale, or PR-only runs fail closed. |
| Exact main runtime acceptance | `uv run python scripts/check_release_main_ci.py --repo koda-ai-studio/agent-bom --sha "$(git rev-parse HEAD)" --branch main --workflow runtime-acceptance.yml` | The same main SHA has a successful push run and completed `Gateway ingest and replica reconnect` job. Missing, skipped, stale, failed, or pending runtime evidence blocks tagging. |
| Version alignment | `uv run python scripts/check_release_consistency.py` | Package, docs, OpenAPI, Docker, Helm, and integration versions agree. |
| Evidence matrix | `uv run python scripts/check_release_evidence_matrix.py` | Every published surface retains a named pre- or post-publish verification path. |
| Product contract | `uv run python scripts/check_product_surface_contract.py` | README/product-surface claims match generated metrics and exposed surfaces. |
| API schema | `uv run python scripts/generate_v1_schemas.py --check` | Published v1 schemas match the Pydantic models. |
| CLI docs | `uv run python scripts/check_cli_reference_alignment.py` | CLI reference and implemented command tree agree. |
| Security guards | `uv run python scripts/check_exception_sanitization.py` and `uv run python scripts/check_provisioning_readonly.py` | API/gateway/runtime errors are sanitized and cloud provisioning stays read-only. |
| Backend tests | `uv run pytest -q` | Python 3.11/3.12/3.13/3.14 CI must pass; local focused suites should cover changed areas. |
| UI build | `cd ui && npm run typecheck && npm run lint && npm run build && npm run bundle:check && npm run test:run` | The dashboard builds, tests pass, and client JS stays under budget. |
| Dashboard bundle | `make build-ui` | Runs the export build (`NEXT_EXPORT=1`) and copies it to `src/agent_bom/ui_dist` with CSP hashes. **Required before the package build** — the UI-build row above leaves nothing in `src/agent_bom/ui_dist`, and `ui_dist` is gitignored, so a `uv build` without this step produces a dashboard-less wheel and a dashboard-less image. |
| Package build | `make release-build` | Builds the dashboard, wheel, and sdist, then rejects any wheel missing the schemas, dashboard index, CSP manifest, or CSP script hashes. |
| Packaged dashboard | `uv run python scripts/verify_release_wheel.py dist` | Every wheel includes the dashboard and CSP manifest; compiled Docker and Action install pins match the wheel version. |
| PyPI smoke | `python -m venv /tmp/agent-bom-smoke && /tmp/agent-bom-smoke/bin/pip install agent-bom==<version> && /tmp/agent-bom-smoke/bin/agent-bom --version` | Published package installs in a fresh environment. |
| Registry surface freshness (post-publish) | `gh workflow run surface-freshness.yml` | Compares distribution surfaces with the latest published release and its exact packaged MCP schemas. Inspect the `surface-freshness-evidence` artifact and drift issue; asynchronous rebuild acceptance is not release completion. |
| Quickstart E2E | `agent-bom quickstart --run --offline --force --sample-dir /tmp/agent-bom-quickstart` | Generates a sample inventory report and reads back its saved graph. Offline package-CVE lookup is explicitly skipped; zero CVEs is not a clean verdict. Review `scan_run` and `coverage_warnings`, then scan your own repository. Run `agent-bom scan --demo --offline` separately for bundled CVE proof. |
| Hosted preflight | `python scripts/deploy/hosted_poc_preflight.py --write-secret` | Hosted compose has an HTTPS URL, no unauth mode, non-placeholder secrets, private API/UI binds, and safe CORS. |

Do not publish a release as hosted-ready when any required line above is red.
After publishing, do not mark the release complete or close required-surface
incidents while a required surface is stale or unmonitored. Registry rebuilds
may finish asynchronously; rerun the check until required surfaces reflect the released version and expected
inventory. Advisory results remain visible and do not establish hosted readiness.

Schema expectations come from an isolated installation of the exact published
PyPI version, checked against the release tag's tool names. The extractor runs
without publishing credentials, checkout imports, or user pip configuration.
A hosted server card with the same version string can still contain newer code;
it is observed deployment evidence, never the schema expectation. Deployment
Freshness reports that mismatch separately. Reconcile the hosted artifact to
the published release before retrying; do not publish a candidate to silence it.

The JSON report distinguishes `all_fresh` from `all_required_fresh`. Smithery
remains advisory under the existing OAuth publication policy; its actual result
stays visible. A Glama API inventory that contradicts its public schema remains
a required failure even when the indexed release description matches. Use the
provider's supported Sync Server control and rerun verification; unresolved
Directory API discrepancies require provider repair, not a local bypass.

Glama Directory API reads require bearer authentication ([provider reference](https://glama.ai/mcp/reference)).
Configure `GLAMA_API_KEY` as a managed GitHub Actions secret for registry and
surface verification; never commit its value. The verifier sends it only to
`https://glama.ai/api/mcp/`, rejects redirects, and leaves public page requests
anonymous. Rotate or revoke the key in Glama and update/remove the Actions
secret together. This integration does not assume provider keys expire or
claim they are short-lived. Missing credentials do not waive freshness checks.

### Protected MCP deployment and registry recovery

Run `gh workflow run deployment-freshness.yml` after deploying the exact
published release; inspect the completed run and its drift issue before closing
an incident. A recorded alert or public server card does not prove authenticated
MCP calls succeed. Verify anonymous rejection and authenticated initialization,
tool inventory, and a read-only call with a current credential separately.

Agent-Bom HTTP MCP accepts operator-provisioned bearer credentials with an
absolute expiry of at most one hour. Rotate the credential and deadline together,
update its clients, and restart the process through the operator's credential
workflow. Ordinary restarts must retain the original deadline. See
[MCP authentication](MCP_SERVER.md#sse-transport-remote--multi-client).

[Smithery protected URL publishing](https://smithery.ai/docs/build/publish)
requires OAuth. The bearer-only MCP server does not supply an OAuth issuer;
a metadata declaration cannot supply that capability. Configure an authorized
OAuth-compatible upstream and prove its login/token/refresh flow before running
`gh workflow run publish-registries.yml`. Missing configuration fails manual,
scheduled, and release-triggered runs. Do not disable authentication or restore
an automatic grant just to make a catalog scan pass.

### Source-to-published storefront transition

Source-built manifests and the Docker Hub storefront track the source version
being prepared. The storefront uses lifecycle-neutral wording until its image
is published. Copy-paste commands that fetch released artifacts instead track
`PUBLISHED_VERSION`, so README Action references, pull-only image pins and Helm
install commands continue to name an available release during preparation.

After publication, the release workflow opens a follow-up pull request using
`python scripts/bump-version.py --published <version>` to advance those
copy-paste surfaces and the Docker MCP pin. Review that generated update and
verify the published artifacts before merging it.

The protected release workflow then renders a temporary published copy with
`scripts/render_docker_storefront.py`, promotes exactly the matching version to
`Current stable version (pinned)`, validates that rendered file with
`AGENT_BOM_RELEASE_FINALIZE=1`, and sends only that rendered copy to Docker Hub.
The renderer rejects missing, duplicate, or unresolved neutral rows, and a
failed Docker Hub update blocks the publishing job. The checked-in neutral
file is not mutated by CI. Release completion still requires the post-publish
surface-freshness gate above; a successful tag alone is insufficient.

## Browser behavioral lock-in

The route-catalog smoke opens every packaged route and rejects framework errors,
404s, and enabled buttons without accessible names. Page-local E2E tests cover
representative actions; this matrix does not claim one browser test per control.

| Workspace | Browser behavior proved |
|---|---|
| Global shell | Theme state, sidebar collapse/expand, focus command, and command-palette navigation |
| Overview and Findings | Shared seeded counts, deep-link query state, finding-class/severity filtering, and pagination |
| Jobs | Source-to-job evidence links, persisted observed stage timing, and explicit unavailable telemetry when progress is empty |
| Investigation graphs | Dark/light/mobile rendering, fit, selection, auto-layout, reset/edit lock, drag persistence, zoom, and large-estate roll-up navigation |
| Remediation | Compact campaign disclosure, priority explanation, package detail, re-verification mutation, and mobile containment |
| Compliance | Detail/heatmap switching, status/search filtering, and evidence-pack download request |
| Scan and export | Scan submission through completed result and graph JSON download |
| Connections and gateway | Connector wizard progression and live-feed state changes |

Run the focused browser set with:

```bash
cd ui
npx playwright test e2e/route-catalog-smoke.spec.ts e2e/jobs-workflow.spec.ts \
  e2e/lineage-graph-readability.spec.ts e2e/security-graph-cockpit.spec.ts \
  e2e/workspace-actions.spec.ts e2e/overview-findings-reconciliation.spec.ts \
  e2e/scan-export.spec.ts e2e/connections-screenshot.spec.ts \
  e2e/gateway-live-feed-card.spec.ts
```

## Download release assets

```bash
TAG=v0.111.0
VERSION="${TAG#v}"
mkdir -p /tmp/agent-bom-release && cd /tmp/agent-bom-release
gh release download "$TAG" --repo koda-ai-studio/agent-bom
```

## Verify Python release signatures

Verify the wheel or source distribution against the Sigstore bundle generated by
release CI:

```bash
cosign verify-blob "agent_bom-${VERSION}-py3-none-any.whl" \
  --bundle "agent_bom-${VERSION}-py3-none-any.whl.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/(msaad00|koda-ai-studio)/agent-bom/\.github/workflows/release\.yml@.*$'
```

Do the same for the source tarball if you consume that artifact:

```bash
cosign verify-blob "agent_bom-${VERSION}.tar.gz" \
  --bundle "agent_bom-${VERSION}.tar.gz.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/(msaad00|koda-ai-studio)/agent-bom/\.github/workflows/release\.yml@.*$'
```

## Inspect SLSA provenance

The release job exports GitHub Attestations as `.intoto.jsonl` bundles so the
provenance is attached to the GitHub Release, not hidden inside Actions only.

```bash
head -n 5 "agent_bom-${VERSION}-py3-none-any.whl.intoto.jsonl"
```

If you want to verify provenance directly from GitHub Attestations instead of
using the exported bundle:

```bash
gh attestation verify "agent_bom-${VERSION}-py3-none-any.whl" \
  --repo koda-ai-studio/agent-bom
```

## Inspect the self-SBOM

Release CI also publishes a CycloneDX SBOM for the Python environment used to
build the release:

```bash
jq -r '.metadata.component.name, .metadata.component.version' agent-bom-sbom.cdx.json
```

You can also run `agent-bom` against that SBOM directly:

```bash
agent-bom sbom agent-bom-sbom.cdx.json -f json
```

## Release CI image scan gate

After `agentbom/agent-bom:<tag>` and `agentbom/agent-bom-ui:<tag>` are pushed
to Docker Hub, release CI:

1. Verifies the UI tag is pullable (`docker manifest inspect` in
   `docker-publish-ui`) so compose/Helm pins cannot race a missing Hub tag
2. Pulls the published API/runtime image and runs a Trivy gate before minting
   the GitHub Release

```bash
# Image tags use the package version without the Git tag's leading v.
VERSION="${TAG#v}"
docker pull "agentbom/agent-bom:${VERSION}"
docker pull "agentbom/agent-bom-ui:${VERSION}"
```

| Step | Tool | Default policy |
|---|---|---|
| Pre-publish candidate | `agent-bom image` in `container-gate` | fail on fixable `MEDIUM+`, `.image-scan-ignore` allowlist |
| Pre-publish dashboard | `Dashboard release gate` in `container-gate` | fail if the candidate image has no packaged `ui_dist`, or if `GET /` does not return the dashboard document |
| Post-publish UI tag | `docker manifest inspect` in `docker-publish-ui` | fail if `agentbom/agent-bom-ui:<tag>` is not pullable |
| Post-publish registry image | Trivy in `published-image-scan-gate` | fail on `CRITICAL,HIGH`, `--ignore-unfixed`, same allowlist |

Override the published-image threshold with the repository variable
`RELEASE_IMAGE_SCAN_FAIL_SEVERITIES` (comma-separated Trivy severities, e.g.
`CRITICAL` or `CRITICAL,HIGH,MEDIUM`).

Local dry-run against a release candidate image:

```bash
docker build -t agent-bom:release-test .
trivy image --severity CRITICAL,HIGH --ignore-unfixed --ignorefile .image-scan-ignore agent-bom:release-test
```

Trivy SARIF from the release job is uploaded to the GitHub Security tab under
category `release-published-image-trivy`.

## Air-gap vulnerability database preload

Air-gapped scans use a **pre-synced local SQLite cache** (`vulns.db`), not live
OSV/GHSA calls. The preload path is:

| Step | Command / artifact | Next step |
|---|---|---|
| 1. Sync on a connected bastion | `agent-bom db update` | Produces `~/.agent-bom/db/vulns.db`; the OSV all-ecosystems download can exceed 1 GB and the settled database can grow to multiple GB as feeds expand. |
| 2. Verify freshness | `agent-bom db status` | Confirm OSV/Alpine/Debian/EPSS/KEV/NVD rows and sync timestamps (a capped NVD run shows partial) |
| 3. Bundle for transfer | `scripts/release/bundle-vuln-db.sh dist/airgap` | Writes `vulns.db`, `known_exploited_vulnerabilities.json`, `epss_scores-current.csv.gz`, and `sha256sums.txt` |
| 4. Import on disconnected host | `cd dist/airgap && sha256sum -c sha256sums.txt` then copy the bundle directory | Mount or copy to the runtime DB path (same directory for sidecar KEV/EPSS feeds) |
| 5. Point runtime at the cache | `AGENT_BOM_DB_PATH=/var/lib/agent-bom/vulns.db` | Sidecar feeds resolve from the DB parent dir, or set `AGENT_BOM_VULN_DB_BUNDLE_DIR` explicitly |
| 6. Disable network refresh | `AGENT_BOM_VULN_DB_OFFLINE=1` or CLI `--offline` | Scans use the bundled cache only; rerun step 1–4 on a schedule |
| 7. Smoke scan | `agent-bom agents --offline /workspace` | Expect `Vuln data: … local cache (offline — network skipped)` and KEV/EPSS enrichment from the bundle |

Docker pilot compose already wires `AGENT_BOM_DB_PATH` to a named volume —
preload by copying `vulns.db` into that volume before the first scan. Helm
operators can start from
`deploy/helm/agent-bom/examples/airgap-vuln-db-values.yaml` (Secret-mounted
`vulns.db` + offline env flags).

Image import for disconnected registries remains in
[`site-docs/deployment/airgapped-image-bundle.md`](../site-docs/deployment/airgapped-image-bundle.md);
combine that image bundle with the `vulns.db` bundle above for full offline
scanning.

Verify the air-gap vuln-DB bundle on a connected bastion before transfer:

```bash
scripts/release/bundle-vuln-db.sh dist/airgap
cd dist/airgap
sha256sum -c sha256sums.txt
AGENT_BOM_DB_PATH="$PWD/vulns.db" AGENT_BOM_VULN_DB_OFFLINE=1 \
  uv run pytest -q tests/test_enrichment_cache.py::test_offline_kev_loads_from_bundled_path
```

On the disconnected host, mount the whole `dist/airgap` directory (not only
`vulns.db`) so KEV/EPSS sidecar feeds resolve next to the DB path.

## Inspect scanner accuracy evidence

Release candidates also carry a checked-in scanner accuracy baseline:

```bash
uv run python scripts/generate_accuracy_baseline.py --check
jq '.runtime_red_team, .finding_state_accounting' docs/accuracy-baseline.json
```

The baseline separates active unresolved findings from VEX-suppressed,
fixed-verified, accepted-risk, and false-positive states. It is intentionally
not a claim of customer-wide real-world false-positive or false-negative rates;
those require a published external corpus.

## Inspect graph epic proof

Graph release claims are backed by the closure artifact in
[`docs/graph/SECURITY_GRAPH_EPIC_PROOF.md`](graph/SECURITY_GRAPH_EPIC_PROOF.md):

```bash
python scripts/check_graph_epic_proof.py
pytest tests/test_graph_schema_ui_parity.py tests/test_graph_edge_counts.py tests/test_graph_visual_snapshot.py tests/test_effective_reach.py tests/test_evidence_policy.py
```

## What this proves

- the distribution artifacts were signed by GitHub Actions OIDC via Sigstore
- the build provenance is available as SLSA attestations
- the release includes a self-SBOM that can be inspected or rescanned later
- the published Docker image passed a Trivy gate at the configured severity threshold before the GitHub Release was minted
- air-gapped operators can preload `vulns.db`, mount it at `AGENT_BOM_DB_PATH`, and run with `AGENT_BOM_VULN_DB_OFFLINE=1`
- scanner accuracy claims are backed by a versioned local evidence artifact
- graph readability/trust claims are linked to deterministic, checked-in proof

This is the release trust baseline. Runtime trust, container attestations, and
registry-specific provenance still live in their own workflows and docs.

Repository transfers do not rewrite certificate identities. The default verifier accepts the current `koda-ai-studio` release workflow and the historical `msaad00` release workflow so older signed artifacts remain verifiable. Other repositories and workflow names fail verification unless an operator explicitly configures a different trust policy.

## Publishing registries

How to publish agent-bom to each MCP ecosystem platform.

### Prerequisites

- agent-bom is already published on [PyPI](https://pypi.org/project/agent-bom/) (automated via release CI)
- Docker images are published to Docker Hub and GHCR (automated via release CI)
- MCP server supports both **stdio** and **SSE/streamable-http** transports

---

### 1. Smithery

Smithery runs agent-bom as a Smithery-managed remote MCP surface. Its public
catalog API exposes the listing, deployment URL, and tool inventory; the remote
transport itself is OAuth-gated by Smithery and does not expose agent-bom's raw
`/health` route. Do not use `https://server.smithery.ai/.../mcp` as an upstream
publish URL or health endpoint.

#### Step 1: Keep the protected MCP deployment healthy

The primary SSE/streamable-http server is deployed on Railway at
`https://agent-bom-mcp.up.railway.app` (automated via `deploy-mcp-sse.yml`).
Remote deployments require `AGENT_BOM_MCP_BEARER_TOKEN` and
`AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT` in the service's secure environment. The
expiry must include a timezone and fall within the next hour. Provision a new
credential and deadline through your own credential-management workflow (Agent-Bom
does not issue them), update the client through
its supported secure credential settings, and restart to load the replacement.
Do not generate a new expiry at boot for an unchanged token. The MCP server does
not expose an embedded OAuth issuer; registry capability inspection must use an
operator-provisioned credential. Keep TLS at your ingress or platform edge.

The daily deployment-freshness workflow requires an authenticated MCP `initialize`
exchange with the configured bearer token and a 401/403 rejection for the same
anonymous request, then checks the public server card
against the exact published tool schemas. Public health or metadata alone cannot
close a protected-deployment drift alert. It also probes Smithery through
`https://api.smithery.ai/servers/agentbom/agent-bom` for catalog liveness,
remote deployment metadata, and the exact released tool inventory.

#### Step 2: Publish to Smithery

**Option A — Web UI**:
1. Go to https://smithery.ai/servers/new
2. Namespace: `agentbom`
3. Server ID: `agent-bom`
4. Follow Smithery's managed remote flow for the `agentbom/agent-bom` listing.
5. Click **Continue**

**Option B — Automated**:
The `publish-registries.yml` workflow parses the static server-card tool names
from the immutable release commit, then compares that contract with both the
live server card and Smithery's public catalog before publishing. It also
compares the catalog's input schemas and public description with the live
release-bound server card. If names, schemas, description, and the latest
successful upstream URL already match, the workflow skips a duplicate
deployment. If capabilities, listing metadata, or the upstream changed, it
creates an external release using:
- `SMITHERY_API_TOKEN`: a publisher token belonging to the account that owns the
  `agentbom` namespace. Store it as a GitHub Actions secret; never put it in
  source files or use the protected MCP deployment bearer token here.

`SMITHERY_MCP_URL` is retained only for the external-upstream publish mode. It
must never point at Smithery's hosted proxy URL. Freshness monitoring no longer
depends on that variable; it uses the Smithery catalog API directly.

Protected URL publishing requires an authorized external OAuth upstream.
Agent-Bom's bearer-only MCP transport does not supply an OAuth issuer; dashboard
SSO and discovery metadata do not provide this client authorization flow.
Configure and verify the upstream's approved client, scopes, token audience,
expiry and refresh behavior before running `gh workflow run publish-registries.yml`.
Do not add the upstream bearer token to Smithery `configSchema`: Smithery reserves
the `Authorization` header for OAuth. See the
[protected MCP recovery checks](RELEASE_VERIFICATION.md#protected-mcp-deployment-and-registry-recovery).

If a capability scan pauses as `AUTH_REQUIRED`, the workflow reads the release
through Smithery's authenticated API and attempts a bounded callback through
`scripts/authorize_smithery_release.py`. This helper does not issue tokens or grant client access.
It can complete only an already-authorized flow that exposes `/oauth/authorize`
on the configured upstream HTTPS origin and redirects directly to
`https://server.smithery.ai/oauth/callback`. Interactive login, additional
redirects, and authorization endpoints on another origin are unsupported by this
helper; use the upstream's approved authorization process and verify its result.
Never add automatic grants to satisfy the helper. OAuth state is not logged.
The workflow avoids duplicate active releases and fails if authorization remains
required or the exact released catalog does not converge.

#### Verification

After publishing, check:

```bash
curl -fsSL https://api.smithery.ai/servers/agentbom/agent-bom \
  | jq '{qualifiedName, remote, deploymentUrl, tool_count: (.tools | length)}'
```

---

### 2. Official MCP Registry

`publish-mcp-registry.yml` uses GitHub OIDC. The canonical name is
`io.github.koda-ai-studio/agent-bom`, matching the current repository owner.
The former `io.github.msaad00/agent-bom` listing is a separate legacy identity;
repository redirects do not transfer registry publishing permission.

#### Manual submission

```bash
python3 scripts/check_mcp_registry_identity.py
python3 scripts/check_mcp_registry_identity.py --published --repository koda-ai-studio/agent-bom
```

The first command checks the source identity; the second reads the exact
manifest version from PyPI and checks package ownership before OIDC is requested.
Neither command publishes. The workflow validates on a successful release and
publishes only when `MCP_REGISTRY_PUBLISH_ENABLED=true`, or when an operator
explicitly dispatches it with `publish=true`.

For PyPI-backed MCP Registry publishing, keep the ownership marker in the
file referenced by `project.readme` in `pyproject.toml`, not only in
`README.md`:

```md
<!-- mcp-name: io.github.koda-ai-studio/agent-bom -->
```

After a namespace change, publish a new package version with this marker before
publishing its registry entry. Do not retag an existing release or assume that
editing the repository README changes an already published wheel's metadata.
The old listing remains historical; no registry migration or deletion is implied.

#### Verification

```bash
curl -fsSL 'https://registry.modelcontextprotocol.io/v0.1/servers/io.github.koda-ai-studio%2Fagent-bom/versions/latest'
```

Check the name, active/latest status, version, repository URL and PyPI installation
arguments against `integrations/mcp-registry/server.json`. A missing entry or a
stale version is incomplete distribution, even if other catalogs are current.
The Surface Freshness workflow checks the official registry using the manifest
from the exact published release and includes it in `all_required_fresh`.
Registry metadata is discovery evidence; the separate installed-package MCP
smoke and exact tool-schema checks establish the advertised server surface.

OIDC namespace rules and package publication order follow the
[official registry publishing guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx).

---

### 3. ClawHub / OpenClaw

Automated via `publish-registries.yml` using `CLAWHUB_TOKEN`. The exact
release version is retried every six hours, and ClawHub's already-published
response is treated as an idempotent success. This also recovers publication
when GitHub replaces an older pending workflow run in its concurrency queue.

The public ClawHub surface is intentionally curated. Release automation publishes only:
- `agent-bom-scan`
- `agent-bom-registry`
- `agent-bom-compliance`
- `agent-bom-runtime`

See [`integrations/openclaw/README.md`](../integrations/openclaw/README.md) for the
curated publish set and rationale. The oversized omnibus root skill is kept in-repo
but is not part of the public ClawHub release surface.

#### Manual publish

```bash
npm install -g clawhub@latest
clawhub login --token "$CLAWHUB_TOKEN" --no-browser
clawhub publish integrations/openclaw/scan \
  --slug agent-bom-scan --name "agent-bom scan" \
  --version "0.111.0"
```

Release automation uses the same official `clawhub` CLI flow, not a custom
multipart API shim, so local publishing and CI stay aligned.

#### Verification

```bash
clawhub install agent-bom-scan
```

---

### 4. Glama

Glama indexes the repository README and builds the MCP schema from
`integrations/glama/Dockerfile`. Glama synchronizes linked GitHub repositories
automatically at least daily. `publish-registries.yml` verifies the exact
released version and MCP tool set immediately after a release and every six
hours; it does not call an undocumented provider endpoint or report stale data
as published.

For an immediate provider-side refresh, open the server's admin page and use
**Sync Server**, then dispatch **Publish to Registries** again. Verification
requires both the released version marker and the exact MCP tool-name set
parsed from the immutable release commit; the live server card is checked
independently against the same contract. When Glama's machine inventory is
reachable, its input schemas must also match the live release-bound server
card. A user-visible Schema page match with an unreachable machine inventory
is reported as degraded rather than full parity. The same applies when the API
returns an empty inventory: an exact public Schema match proves that indexed
contract, but does not establish Directory API recovery. Inspect
`inventory_source` and `directory_api` in the freshness JSON for the original
API status, tool count and schema comparison before retrying or reporting a
provider issue as resolved.

A Glama hosted release is separate from directory synchronization. Creating
one remains a maintainer action in Glama: configure the Dockerfile build,
deploy and pass the build test, then create and publish the Glama release.

```bash
python scripts/check_glama_listing.py \
  --expected 0.111.0
```

---

### 5. Docker Hub

Automated via `.github/workflows/release.yml` on each tag push.

Images published:
- `agentbom/agent-bom:{version}`
- `agentbom/agent-bom:latest`
- `agentbom/agent-bom-ui:{version}`
- `agentbom/agent-bom-ui:latest`

The Git tag remains `v{version}`. Docker Hub image tags are published without the `v` prefix.

`latest` is also refreshed independently by `.github/workflows/refresh-latest-container.yml`.
That workflow checks out the newest released tag, rebuilds it with current Alpine packages,
and republishes only `latest`. This keeps the floating tag current for base-image security
fixes without rewriting immutable semver image tags.

The daily `.github/workflows/container-rescan.yml` job should be treated as the alerting
surface for post-release base-image drift. It scans `latest` for fixable `MEDIUM+` and
`UNKNOWN` image findings, uploads SARIF into GitHub Security, and opens or updates the
automated base-image vulnerability issue when new actionable findings appear.

---

### 6. Docker Images

Automated via `.github/workflows/publish-mcp.yml` after each release.

Images published:
- `agentbom/agent-bom:{tag}` — CLI, API, scanner jobs, gateway, and MCP server

---

### 7. Creating a Release

Tag push triggers the full pipeline automatically:

```bash
git tag v0.111.0
git push origin v0.111.0
```

This triggers:
1. **release.yml** → PyPI + Docker Hub + Sigstore signing + SBOM + provenance + GitHub Release
2. **publish-mcp.yml** → GHCR stdio + SSE containers (via workflow_run)
3. **publish-registries.yml** → Smithery + ClawHub (via workflow_run)
4. **publish-mcp-registry.yml** → Official MCP Registry (via workflow_run)
5. **deploy-mcp-sse.yml** → Railway deployment (called from the release workflow)

#### Source version vs published version

`python scripts/bump-version.py X.Y.Z` prepares the next release: package,
chart, Dockerfiles, manifests, and source-built Compose image tags. It does
**not** move copy-paste surfaces users run against a registry — GitHub Action
refs, pull-only Compose/Kubernetes image pins, Helm and air-gap bundle
commands, consumer pre-commit `rev:` and the README "Latest release" line.
Those track `PUBLISHED_VERSION`, so docs on `main` never point at a tag or image
that does not exist yet.

After every publish job succeeds, the release run opens a
`chore/post-release-pins-vX.Y.Z` PR that runs
`python scripts/bump-version.py --published X.Y.Z` (and syncs the Docker MCP
submission pin). Merge it to advance the docs. `scripts/check_version_alignment.py`
fails if `PUBLISHED_VERSION` is ahead of the source version or, when release tags
are available locally, names a tag that does not exist.

#### Release checkouts run their own tag

Because pull-only pins track `PUBLISHED_VERSION`, a checkout of tag `vX` still
pins the previous release in `deploy/docker-compose.pilot.yml` and
`deploy/k8s/*.yaml`. Moving those pins to `X` before tagging would make `main`
name an image that does not exist until the release run publishes it, so the
release flow does not do that. Instead:

- every image in `deploy/docker-compose.pilot.yml` reads
  `${AGENT_BOM_IMAGE_TAG:-<published>}`, and the self-host instructions (README,
  [`DEPLOY_PLATFORM.md`](DEPLOY_PLATFORM.md)) clone `--branch vX` and set
  `AGENT_BOM_IMAGE_TAG=X` together;
- [`deploy/k8s/README.md`](../deploy/k8s/README.md) shows the same substitution
  for raw manifests;
- `scripts/check_version_alignment.py` (run by CI and the release
  `version-guard` job) fails if a pilot image ignores the override, and treats
  the documented `--branch vX` / `AGENT_BOM_IMAGE_TAG=X` values as copy-paste
  pins that track `PUBLISHED_VERSION`.

The GitHub Action follows the same rule without an override: with
`agent-bom-version` empty, `koda-ai-studio/agent-bom@vX` installs `agent-bom==X` (the
version in the action ref's `pyproject.toml`). Installation fails if that version
cannot be installed; network, index or dependency-resolution errors never select
a different release. For an unpublished ref, use `install-from-source: 'true'` or
select a published `agent-bom-version` explicitly.

#### Pre-tag release smoke

```bash
./scripts/release_smoke.sh
AGENT_BOM_RELEASE_SMOKE_FINDINGS_BENCH=1 ./scripts/release_smoke.sh   # optional read bench
```

Proves install, offline demo scan and CSV export. When
`AGENT_BOM_RELEASE_SMOKE_API_URL` is set, it also probes `${URL}/healthz` for JSON
liveness (`/health` is the same probe).

Each GitHub Release should include these verification assets alongside the
wheel and source tarball:

- `agent-bom-sbom.cdx.json`
- `dist/*.sigstore.json`
- `dist/*.intoto.jsonl`

Use [the release matrix](#release-matrix) for the exact
verification flow against a tagged release.

Release operators should also review:

- [`docs/IMAGE_SECURITY.md`](IMAGE_SECURITY.md)
- [`docs/GOLDEN_IMAGE_PROGRAM.md`](GOLDEN_IMAGE_PROGRAM.md)
- [`docs/security/image-exceptions.yaml`](security/image-exceptions.yaml)

For dependency-heavy or security-driven releases, also verify:

- notable upgrade PRs include a short release-note summary
- major dependency bumps were reviewed for breaking changes before merge
- any user-visible install, auth, or deployment changes are called out in the GitHub Release notes
- deployed health/version/freshness surfaces still report the same release version after publish

---

### Platform Status

| Platform | Entry File | Automated | Trigger |
|----------|-----------|-----------|---------|
| **PyPI** | `pyproject.toml` | release.yml | tag push |
| **Docker Hub** | `Dockerfile` | release.yml | tag push |
| **GHCR (stdio)** | `Dockerfile.mcp` | publish-mcp.yml | workflow_run |
| **GHCR (SSE)** | `deploy/docker/Dockerfile.sse` | publish-mcp.yml | workflow_run |
| **Smithery** | workflow API | publish-registries.yml | workflow_run |
| **Glama directory** | `glama.json` + `integrations/glama/Dockerfile` | provider sync + strict verification | provider daily sync / publish-registries.yml every 6 hours |
| **ClawHub** | curated `integrations/openclaw/*/SKILL.md` set | publish-registries.yml | workflow_run |
| **MCP Registry** | `integrations/mcp-registry/server.json` | publish-mcp-registry.yml | workflow_run |
| **Railway** | `deploy/docker/Dockerfile.sse` | deploy-mcp-sse.yml | release workflow_call / workflow_dispatch |

#### Daily schema verification

Both freshness monitors compare marketplace input schemas with the public server
card after validating its version and tool names against the published release.
New releases bind the expected names to the immutable default-profile metadata
and the `MCP default tools` metric. Older releases without that metadata retain
their full-catalog contract. A smaller next-release default must not make the
currently published full catalog appear stale. Custom full-profile deployments
and the default marketplace endpoint have distinct expected catalogs.
The Railway release gate uses the same default-profile count. During a rolling
deployment, it retries old-version responses and incomplete contracts within the
same bounded attempt budget as transport failures. An HTTP 200 alone does not
pass the gate: the exact version, tool count, and schemas must match before the
budget is exhausted.
Smithery's catalog API omits some root schema fields. The checker verifies those
constraints from the complete schemas embedded in Smithery's public page, while
requiring its server identity, tool names, and shared schema fields to agree with
the catalog. Missing or inconsistent complete evidence counts as drift even when
all tool names match. If the server card is unavailable or cannot be
bound to the release, the monitors do not close the drift issue. This is catalog
evidence; it does not replace an authenticated MCP protocol check.
