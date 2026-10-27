# Image Security

`agent-bom` release images are treated as governed security artifacts, not just build outputs.

## Scan a specific platform

```bash
agent-bom image <image:tag> --platform linux/amd64 --format json --output image-report.json
```

A registry pull selects that platform's manifest from the image index (the
default is `linux/amd64`). When the scan falls back to the Docker daemon
(`--pull-mode daemon`, or a failed registry pull), the platform is passed to
Docker pull, archive save, and the stopped container used by the
filesystem-export fallback; Docker must then support `save --platform`.
Signature, attestation, base-image and layer-secret evidence, and the
server-side registry policy, are described in `site-docs/features/scanning.md`.

## Trust boundaries for image scans

- `--require-signature` passes only for a signature `verified` with a cosign
  public key (`--cosign-key` / `AGENT_BOM_IMAGE_COSIGN_KEY`) or an exact keyless
  signer policy. Without either trust policy the gate fails closed. A
  signature artifact that was found but not verified is `present-unverified`
  and is never treated as trusted.
- API scan jobs and the MCP `scan` tool pull anonymously over HTTPS only, refuse
  loopback, private, link-local, CGNAT and metadata registries, honour
  `AGENT_BOM_REGISTRY_ALLOWLIST`, and do not use the Docker daemon unless the
  operator sets `AGENT_BOM_IMAGE_PULL_MODE=daemon`.
- In `auto` mode a reference without a registry host that the local daemon
  holds is scanned locally rather than resolved to Docker Hub.
- Image labels, annotations and history are author-controlled: secrets in them
  are redacted and reported, and MCP results mark them untrusted. Review the report's findings and coverage before
using its exit status as a policy gate; an extraction error is not a clean scan.

## Supply-chain lookup limits

Signature and referrer discovery share a 30-second elapsed budget, at most 64
HTTP requests and 16 MiB of response data. Each network operation is limited by
the remaining time; checks between streamed chunks stop a response that crosses
the budget. Authentication responses are capped at 64 KiB. Discovery retains at
most 50 unique referrers and 16 cosign signatures per subject digest, with each
signature payload capped at 256 KiB. Duplicate signature payloads are fetched
once per digest lookup.

Keyless verification reads at most 16 unique Sigstore bundle payloads, each
at most 1 MiB, within the same aggregate discovery budget.

A crossed limit or failed evidence download records an incomplete-coverage
warning and an `unknown` signature verdict. It does not establish that the image
is unsigned, and `--require-signature` fails closed. MCP image scans preserve
these warnings across their worker-thread boundary. Registry scans retain the
verified manifest digest, including SHA-512, for evidence lookup and image
identity; changing a tag cannot overwrite an earlier digest's identity.
Malformed registry manifests, descriptors and image configs are rejected before
interpretation. Invalid child digests cannot become tag or cross-repository
lookups. Malformed optional evidence remains `unknown` with a coverage warning.

## Verify a keyless image signature

Install `agent-bom[sigstore]`, then select the expected certificate identity and
OIDC issuer from the publisher's documented signing policy:

```bash
AGENT_BOM_IMAGE_SIGNER_IDENTITY='https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1.0' \
AGENT_BOM_IMAGE_SIGNER_ISSUER='https://token.actions.githubusercontent.com' \
  agent-bom image ghcr.io/example/project:1.0 --require-signature --format json --output image-report.json
```

Review `metadata.image.signature` in the report. A verified result binds the
exact identity and issuer, certificate chain, transparency inclusion proof and
signed time to a Cosign image-signature DSSE statement naming the image digest.
General provenance statements do not satisfy the image-signature gate. Legacy
certificate annotations without a supported bundle remain unverified. Do not
configure a public key and keyless policy together.

Verification is offline against Sigstore's local trust cache or bundled trust
material; it does not refresh roots or query Rekor. Operators must keep this
material current. An explicit refresh outside a scan can be run with:

```bash
python -c 'from sigstore.models import ClientTrustConfig; ClientTrustConfig.production()'
```

That operator command contacts Sigstore's TUF metadata service. Missing optional
dependencies, unavailable trust material and incomplete discovery produce an
`unknown` verdict and fail the signature gate. API/MCP servers use only their
operator-configured signer policy; request data cannot change it.

## Release policy

Every public runtime image must:

- use a pinned base image digest
- build reproducibly from versioned source
- pass smoke tests
- generate SBOM attestations
- pass native `agent-bom image` extraction and vulnerability scanning
- pass external image validation gates
- document any temporary CVE exception with an owner and expiry

## Current release gates

The release pipeline currently enforces:

- `agent-bom` self-scan gate
- Container image scan gate
- Docker image smoke test
- SBOM generation
- Sigstore signing for Python distributions
- Docker provenance and SBOM attestations

Relevant workflows:

- `.github/workflows/release.yml`
- `.github/workflows/container-rescan.yml`

## Exception policy

Temporary exceptions are allowed only when all of the following are true:

1. the vulnerability is inherited from the runtime base or an unavoidable transitive dependency
2. no patched version is available in the supported upstream lineage
3. the exception is documented with owner, reason, review date, and expiry
4. the exception is revisited on every base refresh and release

Active image exceptions are tracked in [`docs/security/image-exceptions.yaml`](security/image-exceptions.yaml).

The generated image ignore file remains the scanner input today, but the YAML registry is the human-reviewed source of truth for why an exception exists.

Current no-fix medium findings may remain visible in Docker Scout until the
upstream base image publishes patched packages. They must still have structured
exceptions with short review windows, and release operators should remove the
matching generated ignore entries as soon as a fixed base digest or safe package
upgrade is available.

## Stable release bar

The target for a "most stable" public release is:

- no unresolved public `CRITICAL` vulnerabilities in the default runtime image
- no unresolved public `HIGH` vulnerabilities with a known fix
- no image release when native package extraction fails
- no release when image scan results differ materially across supported architectures without explanation

If a public image still carries an unresolved `CRITICAL`, the release is not treated as a clean security release even if the risk is documented.

## Incomplete-coverage warnings (end-of-life OS releases)

Advisory data sources stop carrying end-of-life distro releases. When that
happens, the local vulnerability DB holds (near-)zero advisory rows for the
release even though the image is full of packages from it — so a scan can report
a deceptively low or zero vulnerability count for a release that is, in reality,
unpatched and unsupported.

`agent-bom` detects this after distro detection and emits a loud, structured
warning so the result is never mistaken for a clean bill of health. The check is
data-source-agnostic and threshold-based: for any detected `ecosystem:release`
(for example `debian:10`, `ubuntu:18.04`, `alpine:v3.9`) where the image carries
many OS packages of that release but the local DB has (near-)zero advisory rows
*while it clearly carries the same distro family at other releases*, the release
is flagged as uncovered. The family gate keeps the check quiet for a default
online scan against an empty local DB, where every release legitimately has zero
local rows and the remote API is the live source.

The warning surfaces on every output:

- **Console** — a red "Incomplete vulnerability coverage" panel in the scan
  summary plus an inline warning line.
- **JSON report** — a `coverage_warnings` array (also mirrored under
  `summary.coverage_warnings`). Each entry is
  `{ecosystem, release, reason, detail, package_count, advisory_rows}`.
- **Scan summary / warnings** — counted in the standard "scan completed with N
  warning(s)" line.

The warning is informational only: it does not change version matching, advisory
selection, or suppression. The per-release matching is correct; the data is
absent. Re-scan against a source that tracks end-of-life releases for a complete
result.

## Multi-arch requirements

Every supported architecture must be validated independently:

- `linux/amd64`
- `linux/arm64`

For each architecture we want:

- identical release policy
- independent image scan results
- independent SBOM and provenance
- parity review for package drift and CVE drift

## Near-term follow-ups

- add a generated sync step from `docs/security/image-exceptions.yaml` into the image scanner ignore file
- sign and attest Docker images directly, not just Python artifacts and BuildKit attestations
- add Docker Scout as an explicit release gate
- add promoted golden base images per architecture
