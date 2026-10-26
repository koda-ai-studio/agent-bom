# Cloud Posture and IaC Gates

agent-bom treats cloud posture as two connected checks over the same evidence
model:

1. **Pre-cloud IaC gates** catch misconfigurations before Terraform,
   CloudFormation, Kubernetes, or Docker changes reach an account or cluster.
2. **Runtime cloud posture checks** verify the deployed account or service
   state after drift, console changes, inherited policies, and provider-side
   defaults exist.

Use both lanes when possible. The IaC lane is the default pull-request and
release gate because it is fast, read-only, and blocks unsafe changes before
deployment. The runtime lane is the drift and assurance check because it sees
what actually exists in the cloud.

## Pre-cloud lane

Run the focused IaC scanner before apply:

```bash
agent-bom iac Dockerfile k8s/ infra/main.tf --format sarif --output agent-bom-iac.sarif
```

In GitHub Actions, use the `iac` scan type or the `iac` input:

```yaml
- uses: koda-ai-studio/agent-bom@v0
  with:
    scan-type: iac
    scan-ref: infra/main.tf,k8s/
    format: sarif
    upload-sarif: true
    severity-threshold: high
```

The IaC scanner is read-only. It analyzes local files and emits findings,
policy context, SARIF, JSON, or other report formats without applying
infrastructure.

Supported pre-cloud inputs include:

- Terraform
- CloudFormation
- Kubernetes manifests and Helm-rendered output
- Dockerfiles and Containerfiles (`Dockerfile*`, `*.dockerfile`, `Containerfile*`)
- Docker Compose files (`compose.yaml`, `docker-compose*.yml`)
- Docker daemon configuration (`daemon.json`)

### Docker rules

| Family | Checks |
|---|---|
| `DOCKER-001`..`026` | Final-stage user is root or unset; `:latest`/untagged or digest-less base; secrets in `ENV`/`ARG`; credential files (`.env`, SSH keys, `.npmrc`, keystores, `.aws/credentials`) copied into a layer; `ADD` of local archives or remote URLs; `curl \| sh`; `sudo`; `chmod 777` and `COPY --chmod=777`; `COPY --chown=0`; `EXPOSE 22` and port ranges; `RUN --network=host`; package installs without cache cleanup, without `--no-install-recommends`, or without apt/apk version pins; `pip install` without `--no-cache-dir`; relative `WORKDIR`; `SHELL` override; a `CMD`/`ENTRYPOINT` overridden later in its stage; no `HEALTHCHECK`; `COPY . .` without `.dockerignore`. |
| `COMPOSE-001`..`011` | `privileged`; Docker socket mount; host network, PID, IPC, UTS or user namespace; `ALL`/`SYS_ADMIN`/other escape capabilities; seccomp/AppArmor `unconfined` or `label:disable`; sensitive host paths (`/`, `/etc`, `/proc`, `/sys`, `/root`, `/var/lib/docker`, `.ssh`, ...) bind-mounted; `user: root`; no `no-new-privileges`; literal secrets in `environment`. |
| `DOCKERD-001`..`008` | TCP API without `tlsverify`; non-loopback `insecure-registries`; `icc` not disabled; no `userns-remap` (not required for rootless); `live-restore` off; `no-new-privileges` off; `experimental` on; `log-driver: none`. Missing keys take dockerd's default. |

Dockerfiles are read as BuildKit reads them: continuation lines are joined and
reported at the instruction's first line, heredoc bodies stay with their
`RUN`, and runtime checks look only at the final build stage (following
`FROM <stage>`). `RUN --mount=type=secret` and `--mount=type=cache` are the
safe patterns and are not flagged. A `daemon.json` is scanned when it sits in
a `docker/` directory (`/etc/docker`, `~/.config/docker`) or when you name it
directly (`agent-bom iac path/to/daemon.json`); other tools' `daemon.json`
files are left alone.

## Runtime posture lane

Run cloud benchmark checks against the actual environment when operator
credentials are available (demo-estate CIS is curated sample data, not a live
connect):

```bash
agent-bom cloud aws --cis
agent-bom cloud azure --cis
agent-bom cloud gcp --cis
agent-bom scan --snowflake --snowflake-cis-benchmark
```

These checks are for deployed state, not planned state. They catch drift and
environment properties that do not appear in a pull request, such as:

- manually changed identity or logging settings
- inherited organization, subscription, or project policy
- cloud-provider defaults
- resources created outside the reviewed IaC path
- service posture that depends on account-level configuration

Connected accounts can also be scanned on a recurring schedule from the control
plane. That makes posture near-continuous at the chosen cadence: new resources
or deployments are discovered on the next run, removed resources appear in graph
history/diff as deleted evidence, and findings are regenerated from the latest
read-only inventory.

The default mode is scheduled polling. When an operator wires the optional event
queues, agent-bom can also consume AWS CloudTrail/EventBridge events from SQS,
Azure Activity Log/Event Grid events from Storage Queue, and GCP Cloud Asset or
Audit Log events from Pub/Sub. Those consumers are bounded, provider-scoped, and
re-evaluate the affected resource class through the same read-only connection.
If no event queue is configured, the connection falls back to scheduled or
manual scans.

## How to read the result

The useful question is not "IaC or CSPM?" It is:

| Moment | Best command | What it proves |
|---|---|---|
| Before merge | `agent-bom iac ...` | Proposed infrastructure does not introduce known high-risk misconfiguration |
| Before apply | `agent-bom iac ... --format sarif` in CI | The exact deployment artifact passed the gate |
| After deploy | `agent-bom cloud <aws|azure|gcp> --cis` or the Snowflake scan flags above | The live environment still satisfies benchmark expectations |
| During investigation | graph exposure paths and findings APIs | Misconfiguration, packages, agents, credentials, and runtime evidence can be reviewed together |

## Boundary

agent-bom does not apply Terraform, mutate CloudFormation stacks, or change
cloud settings as part of posture scanning. It reports evidence and exits with
deterministic codes so the operator, CI system, or control plane can decide
whether to block, approve, or open a remediation workflow.

The current CSPM/CIS lane should be positioned as read-only inventory,
benchmark checks, IaC misconfiguration detection, scheduled drift visibility,
and graph-backed attack paths. Full DSPM requires classifier-backed content
inspection and data-access resolution; Snowflake has the deepest metadata,
grant, tag, and lineage coverage today, while other stores remain
metadata/posture based unless imported classifier evidence is present.
