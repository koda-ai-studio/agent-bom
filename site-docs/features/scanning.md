# Scanning & Discovery

## Auto-discovery

agent-bom discovers MCP clients and their configured servers by reading config files from 20 supported clients:

| Client | Config path |
|--------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/...` |
| Roo Code | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/...` |
| Codex CLI | `~/.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` |
| Goose | `~/.config/goose/config.yaml` |
| Cortex Code | `~/.snowflake/cortex/mcp.json` |
| Continue | `~/.continue/config.json` |
| Zed | `~/.config/zed/settings.json` |
| Amazon Q | VS Code globalStorage |
| JetBrains AI | `~/Library/Application Support/JetBrains/*/mcp.json` |
| Junie | `~/.junie/mcp/mcp.json` |
| OpenClaw | `~/.openclaw/openclaw.json` |
| Project-level | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` |

Linux paths use `~/.config/` equivalents.

## Vulnerability sources

| Source | Data |
|--------|------|
| [OSV](https://osv.dev) | Primary CVE database — covers PyPI, npm, Go, Maven, etc. |
| [NVD](https://nvd.nist.gov) | CVSS base scores (v3.1, then v3.0, then v2) |
| [EPSS](https://www.first.org/epss/) | Exploit probability scores (0.0–1.0) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities catalog |
| [GitHub Advisories](https://github.com/advisories) | Supplemental advisory data |
| Commercial vuln API | Optional enrichment when a vendor API token is configured |

### Severity basis

Online (OSV API) and `--offline` (local DB) scans derive severity from an
advisory with one precedence, so `--fail-on-severity` gates do not depend on
mode:

1. CVSS base score from the OSV `severity` array — v3.x, then v4.0, then v2.
2. Otherwise a CVSS score or vector in the advisory's vendor blocks
   (`database_specific`, `severity_vectors`, `affected[]`), v3.x before v4.0.
3. A CVSS score sets the severity band (`severity_source: cvss`); the reported
   `cvss_vector` is the one that produced the score, so its prefix
   (`CVSS:3.1/`, `CVSS:4.0/`) names the basis.
4. Otherwise the advisory's own label (`severity_source: osv_database`, …).
5. Otherwise a conservative namespace fallback (for example GHSA → medium,
   `severity_source: ghsa_heuristic`).

Local databases synced before this precedence keep their stored scores until the
next `agent-bom db update`.

### Declared version ranges

A range is never reported as a version. Without a lockfile, a `package.json`
spec such as `^4.0.0`, `5.0.0 || ^7.0.0`, or `*` (and the same in transitive
registry metadata, `npx pkg@^1`, install commands, PyPI specifiers, and
Terraform provider constraints) keeps the raw spec in `declared_version`, is
marked `floating_reference`, and is resolved online to the version a fresh
install selects — the `latest` dist-tag when it satisfies the range, else the
highest satisfying release. When nothing satisfies it, the registry is
unreachable, or the scan is `--offline`, the version stays `unknown`, has no
purl, and no advisory is matched against the range's lower bound. Git, URL,
file, alias, and workspace specs are never resolved to a registry version.

### Python projects without a lockfile

Python dependencies are resolved by the first source that applies:

1. A lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`, or fully pinned
   `requirements.txt`) — exact versions.
2. The project's own virtualenv — a child directory holding `pyvenv.cfg`
   (`.venv`, `venv`, `env`, …) or `$VIRTUAL_ENV` when it is inside the project.
   Installed `*.dist-info/METADATA` headers give exact versions, transitives
   included, with `version_source: installed_environment`. Nothing is
   executed, and links that leave the project are skipped.
3. Online, declared ranges are resolved transitively from PyPI JSON
   metadata (`requires_dist`) with `version_source: resolved_at_scan`. Each
   name gets the newest non-yanked, non-pre-release release satisfying every
   constraint. Environment markers are evaluated for CPython 3.12 on Linux
   x86_64. Distributions are never downloaded or built. The run records a note,
   not a coverage gap. Requirements that cannot be resolved (not on PyPI, no
   satisfying release, registry error, sdist-only release without metadata, or
   the resolution budget) are named in a coverage gap, and the run is partial.
   All unlocked projects in one scan share one resolution budget,
   `AGENT_BOM_PYPI_RESOLUTION_BUDGET_SECONDS` (default `15`), so registry
   lookups never stretch a scan or an MCP tool call.
4. `--offline` with neither a lockfile nor a virtualenv records the gap
   "transitive dependencies not resolved offline". The run is partial.

### Reproducible matching evidence

The committed, mutation-tested range benchmark currently covers 207 comparable
OSV advisories, 19,161 affected-version checks, and 576 fixed-version checks
with zero false negatives and zero false positives. The benchmark removes the
explicit affected-version list before exercising range logic, uses advisory
fixed releases as its defensible negative set, and fails under a deliberately
reintroduced multi-window bug. See the
[machine-readable result](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/CVE_MATCHING_ACCURACY.json) and
[`scripts/cve_matching_accuracy.py`](https://github.com/koda-ai-studio/agent-bom/blob/main/scripts/cve_matching_accuracy.py).
This is a reproducible range-matcher baseline, not a universal scanner-accuracy
claim.

## Credential exposure detection

Config files are parsed for server definitions. Environment variable **values** are automatically redacted — only key names are reported. Patterns detected:

- AWS keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- OpenAI / Anthropic API keys
- JWTs, bearer tokens
- Connection strings with embedded passwords
- Private keys (PEM headers)

## Container image scanning

```bash
agent-bom image python:3.12-slim
```

Uses agent-bom's native image scanning pipeline to enumerate OS and language packages within container images.

### Pulling without a Docker daemon

`agent-bom image <ref>` fetches the image straight from its registry over the
OCI distribution API — every request is a read-only `GET` (plus a token
request). Credentials are looked up only when the registry asks for them:
`--registry-user`/`--registry-pass` on `scan` (or `AGENT_BOM_REGISTRY_USER` /
`AGENT_BOM_REGISTRY_PASS`), then `~/.docker/config.json` (`auths`,
`credHelpers`, `credsStore`; `DOCKER_CONFIG` is honoured). Only the credential's
source is reported, never its value. For a multi-arch image the platform comes
from the index: `linux/amd64` unless `--platform` names another; an unknown
platform fails with the list of available ones.

Every manifest and blob is checked against its digest. Layers are downloaded
one at a time into a temporary file and go through the same bounds as archive
scans (table below); a layer that cannot be downloaded or read — including
`tar+zstd` layers, which the walk does not decompress — is a named coverage gap.
Blob redirects to a CDN are followed over HTTPS only, without the registry
credential. Plain HTTP is accepted only for a registry on `localhost` (local CLI only).
Manifest and referrers bodies stop reading at 8 MB, manifest digests are
verified for `sha256` and `sha512` (any other algorithm is rejected), and a
redirect host that asks for credentials never receives the registry's.

| `--pull-mode` | Behaviour |
|---|---|
| `auto` (default) | A reference without a registry host (`acme/app:dev`) that the local daemon already holds is scanned from the daemon, so it never resolves to a same-named Docker Hub image (the choice is kept in the report notes). Otherwise registry first; the local Docker daemon only if the registry pull fails (the reason is printed and kept in the report). |
| `registry` | Registry only; never the daemon. |
| `daemon` | `docker save` through the local daemon; never the registry. |

`--offline` never contacts a registry, so offline image scans use the daemon or
`--tar`.

### Server-side image scans

API scan jobs (`POST /v1/scan` with `images`) and the MCP `scan` tool scan a
reference someone else supplied, so they use a stricter registry policy than
the local CLI:

- HTTPS only — plain HTTP is never used, not even for `localhost`.
- Loopback, private, link-local, CGNAT and cloud-metadata registries are
  refused: address literals before any request, DNS answers at connect time
  (the same pinned egress check as webhook delivery).
- Anonymous pulls only: the server's `~/.docker/config.json`, credential
  helpers and `AGENT_BOM_REGISTRY_USER`/`AGENT_BOM_REGISTRY_PASS` are never
  sent.
- `AGENT_BOM_REGISTRY_ALLOWLIST` (comma-separated `host` or `host:port`), when
  set, is the only set of registries a scan may contact.
- A base image named by an image label or annotation is fetched only from the
  allowlist, or — without one — from the scanned image's own registry;
  otherwise its attribution is `skipped-by-policy`.
- No Docker daemon fallback unless the operator sets
  `AGENT_BOM_IMAGE_PULL_MODE=daemon`.
- Error messages omit the upstream HTTP status.

### Signatures, attestations and base image

For an image scanned by reference, agent-bom looks up its cosign signature
(`sha256-<digest>.sig`) and the artifacts attached to its digest (OCI
referrers API or tag schema, cosign `.att`/`.sbom` tags, BuildKit attestation
manifests in the index):

```bash
agent-bom image ghcr.io/org/app:1.4 --cosign-key cosign.pub --require-signature
```

| Signature status | Meaning |
|---|---|
| `verified` | A signature over this image's digest verified with `--cosign-key`, or a Sigstore image bundle verified against the configured exact signer identity and issuer. |
| `invalid` | A signature fails the configured key/signer policy, its cryptographic proof fails, or it names another digest. |
| `present-unverified` | A signature artifact exists without a configured trust policy, or uses unsupported legacy evidence. Presence alone is not evidence of trust. |
| `unsigned` | The registry has no signature or bundle for the digest. |
| `unknown` | Not looked up (archive scans, offline scans, a local image without a registry digest) or the lookup failed. |

`--require-signature` exits 1 unless the status is `verified`, which needs a
cosign public key (`--cosign-key` or `AGENT_BOM_IMAGE_COSIGN_KEY`) or both
`AGENT_BOM_IMAGE_SIGNER_IDENTITY` and `AGENT_BOM_IMAGE_SIGNER_ISSUER` with the
`agent-bom[sigstore]` extra. Keyless verification checks supported Cosign DSSE
image-signature bundles offline against cached/bundled Sigstore roots; keep
that trust material current. General attestations are listed, not treated as
verified image signatures. See the repository's `docs/IMAGE_SECURITY.md` for
the first command, trust refresh and report evidence.

The base image is named only from the OCI `org.opencontainers.image.base.name`
and `org.opencontainers.image.base.digest` annotations or labels. When the
registry is reachable, agent-bom fetches that base and, if its layers are an
exact prefix of the image's, marks every package occurrence `layer_origin:
base` or `app` (a package the base shipped at the same version stays `base`
even after an app-layer `apt` rewrites the package database). A base whose
layers do not match — rebuilt, or the tag moved — is reported as
`layer-digest-mismatch` and nothing is attributed. No rebase target is
suggested: that would need a scan of the candidate base.

### Secrets in image layers

Text files in every layer are scanned with the same patterns, skip rules and
redaction as `agent-bom secrets`; binaries, OS package trees (`usr/share`,
`usr/lib`, CA bundles, package databases), files larger than
`AGENT_BOM_IMAGE_SECRET_MAX_FILE_BYTES` (1 MiB) and files past
`AGENT_BOM_IMAGE_SECRET_MAX_FILES` (20,000 per image) are skipped and counted.
Image config `ENV` values and build-history steps (where build args land) are
scanned too. Each finding names the image, the layer digest and the path; a
secret deleted or overwritten by a later layer is still reported with
`in_final_filesystem: false`, because it remains in that layer's blob.
The native parser reads Debian dpkg, Alpine apk, modern SQLite RPM databases,
and legacy RPM BerkeleyDB/NDB databases without requiring a scanner binary.
Malformed legacy RPM databases fail the scan instead of producing a clean
zero-package result.

For an installed CPython runtime, inspect its release lookup and any observed
backport alongside the package findings:

```bash
agent-bom image python:3.14.8-alpine3.23 -f json -o runtime-findings.json
```

Online scans verify the release against its upstream CPython header, then use
OSV's repository Git-tag query. The JSON package's `version_provenance.evidence`
records the lookup source, tag, timestamp and advisory count. Offline, failed,
malformed or incomplete lookups retain `runtime_advisory_coverage_unknown`;
zero findings in that state do not establish a complete assessment.

An exact installed `tarfile.py` source match can identify the reviewed CPython
3.14.8 backport for CVE-2026-87910. The report retains the advisory ID, source
hash, layer and upstream fix instead of reporting that advisory as active.
Imported hash claims do not establish this result, and replacing or deleting
the measured module invalidates it. This is source-file evidence, not runtime
attestation, application exploitability, or proof that every upstream advisory
has been published. Review remaining findings and coverage warnings before
using the image in a deployment.

### Large images

Image layers are streamed rather than held in memory: an uncompressed layer is
read in place and a compressed one is inflated in 1 MiB chunks to a temporary
file, so peak memory does not grow with layer size. Each bound below is checked
while the layer is read. A layer that crosses one is skipped, recorded as a
coverage warning naming the layer and reason, and the scan run is reported as
`partial`, never clean.

| Env var | Default | Bound |
|---|---|---|
| `AGENT_BOM_OCI_SCAN_TIMEOUT_SECONDS` | `900` | Wall-clock budget for reading one image's layers; `0` disables it. Layers not read in time are reported with reason `oci_scan_time_budget`. |
| `AGENT_BOM_OCI_MAX_LAYER_COMPRESSED_BYTES` | 2 GiB | Compressed size of one layer inside a `docker save` tarball or pulled from a registry (checked before download and while streaming). |
| `AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES` | 5 GiB | Uncompressed bytes of one layer (also caps temporary disk use per layer). |
| `AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO` | `100` | Uncompressed-to-compressed ratio; decompression stops at the limit. |
| `AGENT_BOM_OCI_MAX_LAYER_MEMBERS` | `1000000` | Tar entries walked in one layer. |
| `AGENT_BOM_OCI_MAX_METADATA_MEMBER_BYTES` | 512 MiB | One package-metadata file (dpkg status, RPM database, lockfile, manifest) read into memory. |
| `AGENT_BOM_OCI_MAX_JAR_UNCOMPRESSED_BYTES` | 512 MiB | Uncompressed size of one Java archive inspected for Maven metadata. |

Temporary layer files are written to the system temporary directory (`TMPDIR`)
and removed as soon as the layer has been read.

When the `docker save` archive yields no packages, `agent-bom image` falls back
to `docker export`. The exported root filesystem is scanned as one layer with
the same extractors and the same bounds; a bound it crosses is recorded with
the layer name `docker-export` and the run is reported as `partial`.

### Kernel-header CVEs

Kernel-header packages are versioned with the distro kernel, so they match the
upstream kernel CVE stream: on `php:8.3.30-cli`, `linux-libc-dev` alone matched
3,513 of 4,424 findings. Console output folds them into one group per image
distro release, with the full severity breakdown:

```text
  Kernel-header group linux-libc-dev@6.12.74-2 (debian 13) · 3513 CVEs: 297 critical · 1495 high · 1718 medium · 3 low
    3 KEV (CVE-2026-31431, CVE-2026-53266, CVE-2026-53362) · 297 critical (…) shown as rows · 3213 collapsed — -f json, sarif or cyclonedx lists every CVE
```

KEV and critical kernel-header CVEs are never collapsed: they are named on the
group line and stay as their own rows. JSON, SARIF, CycloneDX and every other
machine-readable format keep each CVE.

Packages are recognised per ecosystem and per `os-release` ID family, never by
name alone:

| Distro family (`ID`) | Ecosystem | Packages |
|---|---|---|
| `debian`, `ubuntu` | deb | `linux-libc-dev`, `linux-headers-*` |
| `rhel`, `centos`, `rocky`, `almalinux`, `ol`, `fedora`, `amzn` | rpm | `kernel-headers`, `kernel-devel` |
| `sles`, `sled`, `opensuse`, `opensuse-leap`, `opensuse-tumbleweed` | rpm | `linux-glibc-devel`, `kernel-devel`, `kernel-default-devel` |
| `alpine` | apk | `linux-headers` |

A package with one of these names on another distro, in another ecosystem, or
on an image whose distro could not be detected is shown individually.

The default OS result remains precision-first and reports distro-confirmed
advisories. To include unfixed, pending, no-DSA, and end-of-life distro
advisories for an exhaustive review, run:

```bash
AGENT_BOM_INCLUDE_UNFIXED=1 agent-bom image python:3.12-slim
```

The artifact is the same findings report with lower-confidence unfixed distro
rows included; review their match-confidence tier before using them as a CI
block. Language-package coverage is unaffected by this switch.

The default filter always leaves a receipt: the JSON summary carries
`suppressed_unfixed_os_findings` (the number of findings the policy removed,
distinct from operator or VEX suppressions in `suppressed_vulnerabilities`),
`coverage_warnings` carries a `scan_note` with reason `unfixed_os_suppressed`,
and the console closes with "No fixable vulnerabilities found; N unfixed
OS-package finding(s) suppressed" instead of a clean verdict.

RHEL and other supported RPM distributions retain findings whose fix could not
be resolved; missing fix metadata is not a vendor "won't fix" verdict. RHEL
advisories are filtered to the observed Enterprise Linux major release before
version comparison and fix extraction. For example:

```bash
agent-bom image registry.access.redhat.com/ubi9/ubi-minimal:9.2 -f json -o image-findings.json
```

Review the package versions and fix recommendations in `image-findings.json`;
findings without a resolved fix require investigation or mitigation.

### Source-built language runtimes

Official language images build the runtime from source, so no distro package
database records it. The image config `Env` does: `PHP_VERSION`,
`PYTHON_VERSION`, `NODE_VERSION`, `GOLANG_VERSION`, `RUBY_VERSION`, and the
Eclipse Temurin `JAVA_VERSION=jdk-21.0.12.1+1` form. Each becomes a `generic`
runtime component with a CPE identity (`php:php`, `python:python`,
`nodejs:node.js`, `golang:go`, `ruby-lang:ruby`, `oracle:openjdk`):

```bash
agent-bom image php:8.3-cli -f cyclonedx -o php-sbom.json
```

The component's `discovery_provenance.source` is `binary` when the runtime
binary (for example `/usr/local/bin/php`) survives in the final layer view, and
`image-env` when only the environment declares it. Env values must match a
strict version grammar. An env-only runtime that duplicates an installed distro
package of the same upstream release is dropped rather than counted twice.
Runtime components are matched against the local NVD CPE applicability data
(`agent-bom db update --source nvd`) by exact vendor and product at the
`nvd_cpe_candidate` tier. Image tarballs passed to `agent-bom fs` get the same
detection. Plain directory and VM-mount scans read the same runtimes from
installed files instead; see [Hosts, VM snapshots and the GPU stack](#hosts-vm-snapshots-and-the-gpu-stack).

## Operator (emergency) advisories

When a disclosure is public but feeds have not published it yet, declare it
and match it against saved scans without rescanning:

```bash
agent-bom db advisory add --file advisory.json
agent-bom db advisory match --format json
```

The advisory names products by `ecosystem` + `name` or by `cpe_product`
(`vendor:product`) with `introduced`/`fixed` ranges per release branch.
Findings carry `provenance: operator_advisory` and the branch's fixed version.
`match` reads the most recent saved scan (or `--report PATH`); it exits 2 when
no saved scan exists or a version cannot be ordered, because that is not a
clean result. When a feed record with the same ID or alias is already on the
package, the feed record wins and the operator advisory is listed under
`superseded`. The control plane exposes the same flow per tenant at
`POST/GET /v1/intel/operator-advisories` and
`GET /v1/intel/operator-advisories/{id}/matches` (newest stored scan per
target), and the MCP `intel_lookup` tool includes the declared record and its
matches. Advisories persist in the control-plane store (SQLite, or Postgres
with tenant row-level security).

Distributions backport fixes without changing the upstream version, so a
distro package that ships a `cpe_product` (for `php:php`: Debian `php8.x-*`
built from source `php8.x`, Alpine `php8x-*` except PECL extensions, RPM `php`
and its core subpackages) is never compared against the upstream ranges. When
the local DB holds a distro feed record for the advisory's CVE and that
package's release (Debian tracker, Alpine secdb, distro OSV rows), the distro
verdict decides it: affected with the distro's fixed version, or clean. Without
one it is listed under `indeterminate` with reason `distro_backport_unverified`
and a detail such as "distro package php8.2-cli 8.2.29-1~deb12u1 ships php;
verify against the distribution's advisory", and `match` exits 2. The mapping
from CPE product to distro packages is explicit
(`src/agent_bom/scanners/cpe_distro_packages.py`); unlisted products map to nothing.

### Am I affected?

`GET /v1/intel/advisories/{id}/affected` (and the read-only MCP tool
`affected_assets`) answers for one advisory, declared or from the local feed
with NVD CPE ranges, across the tenant's newest stored scan of each target:
affected rows with the fixed version to patch to, possibly affected distro
packages with the reason to verify the distribution's advisory, and not
affected rows, with graph node ids for the blast radius. Possibly-affected
results are listed but never counted as confirmed vulnerabilities in severity
totals or gates. The operator runbook is
[Respond to a new CVE](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/RESPOND_TO_A_NEW_CVE.md).

### Daily re-match

Set `AGENT_BOM_ADVISORY_REMATCH=1` on the API server to re-match stored
inventory once per `AGENT_BOM_ADVISORY_REMATCH_INTERVAL_SECONDS` (default
86400, minimum 300) against operator advisories and local-feed advisories
updated since each tenant's cursor. No host is rescanned. Each finding records
`first_seen` and `new_since_published` (the matched scan completed before the
advisory was published). If the feed or store is unreachable, or a version
cannot be ordered, the run is `incomplete` and the cursor does not move. Distro
packages awaiting their distro record are counted in `indeterminate_distro` on
a complete run instead, since a retry cannot resolve them. This
replica's last run is in `GET /v1/system/health` under `advisory_rematch`; the
tenant's cursor, last run and recent findings are in
`GET /v1/intel/operator-advisories` under `rematch`.

## Hosts, VM snapshots and the GPU stack

```bash
agent-bom fs /mnt/vm-snapshot -f json -o host-findings.json
```

`agent-bom fs` (and agentless VM side-scans of a mounted snapshot) also
inventories components that no distro package database records. Versions are
read from files only; no binary on the scanned root is executed, symlinked
paths are not followed, and every read stops at a fixed byte limit.

| Component | Read from | CPE identity |
|---|---|---|
| NVIDIA GPU driver | `/proc/driver/nvidia/version` (loaded module), else `libcuda.so.<version>` | `nvidia:gpu_display_driver` (`target_sw=linux`) |
| CUDA toolkit | `/usr/local/cuda*/version.json` or `version.txt` | `nvidia:cuda_toolkit` |
| NVIDIA Container Toolkit | `nvidia-container-toolkit` / `libnvidia-container` packages, else `libnvidia-container.so.<version>` | `nvidia:nvidia_container_toolkit` |
| PHP, CPython, Node.js, Go, Ruby, JDK built into `/usr/local` or `/opt` | installed headers, `rbconfig.rb`, `go/VERSION`, JDK `release`; PHP and Node binary version strings | `php:php`, `python:python`, `nodejs:node.js`, `golang:go`, `ruby-lang:ruby`, `oracle:openjdk` |

Image scans apply the same GPU rules to each layer, excluding
`/proc` and `/usr/local/cuda*/compat` forward-compatibility libraries.

When a distro package already records the same release (for example
`nvidia-driver-550` or `nvidia-container-toolkit`), that package carries the CPE
and no second component is added. A loaded kernel module whose version differs
from the installed package (pending reboot) is reported as its own component.
The CPE is exported in JSON, CycloneDX (`cpe`), SPDX 2 (`cpe23Type`) and
SPDX 3 (`cpe23`) and appears on the package's graph node under the scanned host.

Findings come from NVD CPE ranges in the local database and, online, from
NVIDIA CSAF bulletins. A CSAF finding is reported only when the bulletin lists
a Linux fix on the component's own driver branch, for example R550 or R535.
NVD rows that apply only through a separate platform condition, such as some
Windows-only CUDA advisories, are not yet distinguished from Linux rows.

## IaC and cloud posture

When a CloudFormation template contains unreadable or malformed containers,
the scan keeps findings from valid resources and emits a coverage warning for
checks it could not evaluate. Inspect `coverage_warnings` and `scan_run.outcome`
in the JSON report before treating a scan as complete. This static check does
not resolve CloudFormation references or establish deployed cloud posture.

Use `agent-bom iac` as the pre-cloud gate for Terraform, CloudFormation,
Kubernetes, Helm-rendered manifests, Dockerfiles, Compose files and Docker
daemon configuration. Use `agent-bom
cis-benchmark` as the runtime posture check for deployed cloud state. The
combined workflow catches proposed misconfiguration before apply and drift
after deployment.

See [Cloud Posture and IaC Gates](cloud-posture.md) for the recommended lane
split and CI example.

### Accepting one IaC finding

To accept a single finding on purpose, put a marker with a reason on the
offending line or the line directly above it:

```yaml
# agent-bom: ignore[GHA-002] published template: callers pin this workflow
uses: example-org/example-action@v1
```

The marker names one or more rule ids (`ignore[GHA-002,GHA-004]`), and the
reason is required: a marker without one suppresses nothing. Accepted findings
leave the active results and the severity gate, and the scan result keeps them
in `suppressed` so they stay reviewable.

## Agent SDK source inventory

Scan imports without importing or executing the target application:

```bash
agent-bom scan --ai-inventory ./my-agent --no-discover -o agent-report.json
```

Inspect `ai_inventory.components` and `ai_inventory.unique_sdks` in the JSON
artifact, then scan the project's dependency manifests with `--project` to
establish package versions and advisory matches. Python and JS/TS AST analysis
also reports the corresponding framework labels.

| SDK | Python import → PyPI package | JS/TS package |
|---|---|---|
| OpenAI Agents SDK | `agents` → `openai-agents` | `@openai/agents` |
| Google ADK | `google.adk` → `google-adk` | `@google/adk` |
| Claude Agent SDK | `claude_agent_sdk` → `claude-agent-sdk` | `@anthropic-ai/claude-agent-sdk` |
| Strands Agents | `strands` → `strands-agents` | `@strands-agents/sdk` |
| Amazon Bedrock AgentCore | `bedrock_agentcore` → `bedrock-agentcore` | Not covered by this import rule |
| Azure AI Agents | `azure.ai.agents` → `azure-ai-agents` | `@azure/ai-agents` |
| Microsoft Agent Framework | `agent_framework` → `agent-framework-core` | Not covered by this import rule |
| NVIDIA NeMo Agent Toolkit | `nat` → `nvidia-nat` | Not covered by this import rule |
| OpenClaw plugin SDK | Not covered by this import rule | `openclaw/plugin-sdk/*` → `openclaw` |
| LlamaIndex | `llama_index` → `llama-index-core` | `llamaindex` |

Import evidence identifies SDK use; it does not establish live execution,
cloud permissions, deployed agents, or complete workflow topology. General
cloud clients such as `boto3`, `azure.identity`, and `google.cloud` do not alone
identify an agent framework. Similar names such as `strands_helpers` or
`@google/adk-helpers` do not match these SDK rules.

OpenClaw config/MCP discovery and skill scanning are separate surfaces. Audit an
OpenClaw skill directory with `agent-bom skills scan ./skills --format json`;
this reads `SKILL.md`, including OpenClaw metadata and declared dependencies,
and produces findings without loading or executing the skills. Review findings
and coverage before allowing a skill to run. NVIDIA NeMo Guardrails imports are
also recognized as guardrail evidence; that does not establish effective enforcement.

Project and repository scans automatically enable AI inventory for supported source languages, including JavaScript-only and TypeScript-only projects. CLI, API repository scans, and MCP repository scans preserve package identity and source-file evidence in `ai_inventory`.
