# Deploy agent-bom anywhere

agent-bom is one product with one control plane (API + UI) and a stateless
scanner. You can run that control plane wherever you want it — on a laptop, on
your own Kubernetes cluster, or as a hosted service where you operate the
control plane and customers connect read-only. This guide covers all three
tiers, each with the exact command.

## One script, pick your host

```bash
scripts/deploy/install.sh list          # all targets
scripts/deploy/install.sh pilot         # laptop Docker pilot
```

### Local pilot (fastest proof)

Run the pilot from a release tag checkout and set `AGENT_BOM_IMAGE_TAG` to that
tag, so the containers run the same release as the checked-out files:

```bash
git clone --depth 1 --branch v0.112.1 https://github.com/koda-ai-studio/agent-bom.git && cd agent-bom
AGENT_BOM_IMAGE_TAG=0.112.1 scripts/deploy/install.sh pilot
# Dashboard → http://localhost:3000
# API       → http://localhost:8422/docs
```

Without the variable, `deploy/docker-compose.pilot.yml` runs the image version it
pins. Those pins name the latest release that was already published when the
files were committed, so on a tag checkout they can trail that tag by one
release; they never name an image that has not been published.

Optional curated demo estate (showcase graph + offline scan on API start):

```bash
AGENT_BOM_DEMO_ESTATE=1 scripts/deploy/install.sh pilot
# or: agent-bom api --demo-estate
curl -fsS http://127.0.0.1:8422/v1/demo-estate/status | jq
```

Demo data never mixes with product data. With demo estate on, every local store
(graph, control plane, assets, analytics, history, caches) resolves under a
dedicated demo directory: `AGENT_BOM_DEMO_STATE_DIR`, default
`<state dir>/demo-estate` (`~/.agent-bom/demo-estate` locally). The API refuses
to start if an explicit store path (`AGENT_BOM_DB`, `AGENT_BOM_GRAPH_DB`,
`--persist`, ...) points into the product state directory. The startup summary
prints the directory as `Demo data`.

The status response reports whether the demo graph is the synthetic `showcase`
(`aligned`), missing (`unavailable`), or `blocked` because the demo's store
already holds non-demo graph data. A blocked demo seeds nothing and never
names or links that data.

Local SQLite state under either directory is bounded: the current-estate
projection cache is swept on store construction and the scan analytics mirror
is pruned on write. See [Local state hygiene](STORAGE_BACKENDS.md#local-state-hygiene)
for the rules, `agent-bom db prune`, and `agent-bom report prune --apply --compact`.

### Confirm storage readiness

```bash
curl -fsS http://127.0.0.1:8422/readyz
```

A `{"status":"ready"}` response confirms the configured API/auth dependencies
and supported graph storage can serve their readiness probes. `/health` remains
a liveness check; it does not qualify storage. Route traffic only after
`/readyz` returns 200. A 503 with `graph_storage_unavailable` requires checking
graph database access, schema and deployment permissions before retrying.
Readiness never returns database paths or raw exception details.

In demo estate mode the seed runs after startup: `/readyz` returns 503 with
`demo_estate_seeding` and `/health` stays 200 with `"demo_seed": "pending"`
until it lands, then reports `"complete"`. Reads before that see partial
counts; the dashboard shows a seeding notice and reloads once the seed lands.
Outside demo mode `demo_seed` is `null`.

SQLite initializes a fresh empty graph through the ordinary per-file bootstrap;
no scan data is required. Initial schema repair/index work can add cold-start
cost. Later probes check table access without loading graphs, counting nodes or
repeating migrations. A failed SQLite storage probe retires its initialization
cache so a later probe can initialize an operator-restored file, including a
restore that preserves its inode. The failing probe still returns 503.
PostgreSQL probes its initialized graph tables with a
one-second statement timeout. Storage checks run off the API event loop.
Readiness checks availability, not graph completeness, capacity or every page's
integrity. The experimental Neptune adapter has no bounded readiness contract
and returns `graph_readiness_unsupported` (503); SQLite/PostgreSQL are the
supported backends for readiness-gated deployments.

### Docker on a VM (team pilot)

```bash
cp .env.example .env
# Postgres secrets: write files under deploy/secrets/ (never .env) — see .env.example
scripts/deploy/install.sh docker
```

Production-shaped single host (Docker secrets, split networks):

```bash
scripts/deploy/install.sh platform-docker
```

### AWS / EKS (recommended production installer)

```bash
cd deploy/terraform/platform-eks
cp terraform.tfvars.example terraform.tfvars
# Configure cluster mode, split secret names, region, domain, and optional Helm values.
cd ../../..
scripts/deploy/install.sh eks
```

For a fresh cluster, follow the module's cluster-first bootstrap to install
External Secrets Operator and its ClusterSecretStore before the full apply.
Set the required non-secret credential generation and advance it for every
coordinated secret rotation.

### Azure / AKS

agent-bom does not ship a `platform-aks` Terraform root yet. On a cluster you
already manage:

```bash
scripts/deploy/install.sh aks --profile enterprise-demo
scripts/deploy/install.sh connect azure    # per subscription
```

Helm overlay: `deploy/helm/agent-bom/examples/aks-collector-workload-identity-values.yaml`

### GCP / GKE

```bash
scripts/deploy/install.sh gke --profile enterprise-demo
scripts/deploy/install.sh connect gcp       # per project
```

Helm overlay: `deploy/helm/agent-bom/examples/gke-collector-workload-identity-values.yaml`

### Any Kubernetes (Helm profile)

```bash
python3 scripts/install_helm_profile.py --list
scripts/deploy/install.sh helm production
```

### Snowflake

**Self-hosted POV** (API + UI in your infra, Snowflake as read-only source):

```bash
scripts/deploy/install.sh snowflake
scripts/deploy/install.sh connect snowflake
```

Guide: [`site-docs/deployment/snowflake-pov.md`](../site-docs/deployment/snowflake-pov.md)

**Native App + SPCS** (customer Snowflake account, in-account scanner/MCP):

```bash
scripts/deploy/install.sh snowflake-native
# → docs/snowflake-native-app/INSTALL.md
```

---

## Credential and evidence boundaries

Across every tier the posture is the same:

- **Read-only on your cloud.** The scanner inventories accounts with read-only
  roles (`SecurityAudit` / `ViewOnlyAccess`). Opt-in disk side-scans use a separate
  grant to create and clean up temporary cloud resources.
- **Keyless where possible.** Cloud access is via assumable roles bound to OIDC
  / IRSA, not long-lived keys. Secrets live in your secret manager and are
  referenced, never minted into Terraform state or kubeconfigs on disk.
- **Your data stays in your control plane.** Normalized evidence is stored in the configured control plane.
  Optional enrichment and export destinations have their own egress boundary;
  opt-in disk side-scans have a separate temporary-resource grant.

## The control-plane / collector seam

The product is built around a single architectural seam:

```
   control plane  ──────────────  collector / connect
   (API + UI + Postgres + graph)   (read-only cloud roles)
   you always run this             points at the cloud you scan
```

This seam is what makes "deploy anywhere" work. The **control plane** is the
same chart/image in all three tiers. The **collector side** is just read-only
connect roles (`deploy/terraform/connect-*`). In the hosted tier the control
plane runs in one account and connected clouds apply a read-only connect role
pointing back to it; in the self-hosted tiers both sides live in your account.

---

## Tier 1 — Self-hosted anywhere (laptop / VM, fastest)

API + UI + Postgres with Docker Compose. Best for trying the full product, a
single-team pilot, or an air-gapped VM.

**Step 1 — generate the mounted secret files first.** `docker compose up`
hard-fails with a bare "secret file not found" if you skip this:

```bash
make secrets            # writes deploy/secrets/* (idempotent)
# equivalent: python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
```

**Step 2 — bring the stack up:**

```bash
cp .env.example .env    # ports / non-secret URL only
make fullstack-up       # == docker compose -f deploy/docker-compose.fullstack.yml up --build -d
```

Prefer to write the secret files by hand? Generate all seven with `openssl` /
Fernet as documented in [`deploy/secrets/README.md`](../deploy/secrets/README.md),
`chmod 0644` them (world-readable — compose bind-mounts preserve host perms and
the non-root postgres/API container users must read `/run/secrets/*`; the host
filesystem is the trust boundary on a single-tenant self-host VM), then run the
compose command above.

> **Re-running a failed first `up`?** The Postgres init scripts (`init.sql`,
> app-role bootstrap) run **only against an empty data volume**. A stack that
> half-initialized (e.g. an unreadable secret aborted init) leaves a stale
> volume that init will *not* re-stamp. Wipe it before retrying:
> `docker compose -f deploy/docker-compose.fullstack.yml down && docker volume rm deploy_postgres-data`
> (use the volume name from `docker volume ls`; the compose-project prefix
> varies), then `make secrets` and bring the stack up again.

Postgres and control-plane secrets are Docker secret files only — never `.env`
or compose env. The API uses separate `agent_bom_app` (tenant-bound DML) and
`agent_bom_maintenance` (scoped cross-tenant work) connections; it never uses
the image bootstrap/admin role.

Then open:

- Dashboard → <http://localhost:3000>
- API docs → <http://localhost:8422/docs>

The packaged Compose stacks intentionally own their bundled Postgres service;
they do not advertise an untested "remove the database service" shortcut. For
an operator-managed Postgres/RDS deployment, use the Helm
[`byo-postgres-values.yaml`](../deploy/helm/agent-bom/examples/byo-postgres-values.yaml)
overlay and its separately provisioned app, maintenance, and migration/admin
Secrets. A custom Compose override is outside the packaged deployment contract
until it replaces the API URLs, secret mounts, migration service, and Postgres
dependency together and passes `docker compose config` plus a live startup
smoke.

For a production-shaped single host (Docker secrets, internal-only Postgres,
split networks) use `deploy/docker-compose.platform.yml`.

---

## Tier 2 — Kubernetes / EKS

### Option A — staged Terraform on EKS (recommended)

The [`platform-eks`](../deploy/terraform/platform-eks/) root module provisions
or references EKS, calls `aws/baseline` for RDS + IRSA + S3 backups, syncs
pre-populated runtime/auth Secrets Manager entries, waits for all four
Kubernetes targets, runs the RDS-master migration, and then starts the Helm
workloads. Optionally it also mints the read-only connect role the scanner
assumes. Secret names enter Terraform; secret values do not.

```bash
cd deploy/terraform/platform-eks
cp terraform.tfvars.example terraform.tfvars   # set secret names, region, domain, cluster mode
terraform init
```

Fresh-cluster mode has an explicit prerequisite stage: target the VPC/EKS
modules first, install External Secrets Operator plus the
`aws-secrets-manager` ClusterSecretStore, then set
`external_secrets_prerequisites_ready=true` for the full apply. Existing
clusters must already have those components. Secret-value rotation is also
coordinated: update Secrets Manager, increment the non-secret
`runtime_credentials_generation`, and apply so reconciliation, role-password
alignment, migrations, and pod rollout happen in that order.

```bash
# Fresh-cluster mode only:
terraform apply -target=module.vpc -target=module.eks
# Install External Secrets Operator and aws-secrets-manager ClusterSecretStore.

# After prerequisites exist in either mode, set
# external_secrets_prerequisites_ready=true, then:
terraform apply
terraform output how_to_reach_it
```

Two modes, selected by one variable:

| `create_cluster` | You provide | Module provisions |
|------------------|-------------|-------------------|
| `true` | pre-populated app/maintenance/auth secret names, region | VPC + EKS + node group + RDS/IRSA/S3 + secret sync + Helm; the node SG is authorized to RDS automatically |
| `false` | secret names, `cluster_name`, `vpc_id`, `private_subnet_ids`, and `db_allowed_security_group_ids` or `db_allowed_cidr_blocks` | RDS/IRSA/S3 + secret sync + Helm onto your existing cluster |

Set `create_aws_connect_role = true` to also create the keyless, read-only role
the scanner uses to inventory the AWS account. See the
[module README](../deploy/terraform/platform-eks/README.md) for prerequisites
(secret payloads, ingress controller, cert-manager, External Secrets Operator)
and the full
variable/output reference.

### Option B — Helm onto a cluster you already manage

If you manage cluster provisioning yourself (any Kubernetes, not just EKS),
install the chart directly:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  --values deploy/helm/agent-bom/examples/eks-production-values.yaml
```

The [`examples/`](../deploy/helm/agent-bom/examples/) directory ships values for
EKS, AKS, GKE, BYO-Postgres, SQLite pilots, collector-only workloads, and more.
On AWS you can still run `aws/baseline` on its own for RDS/IRSA/S3. Its
`helm_values_hint` is workload-only and is valid only after an independent
operator-controlled stage has created the four split Kubernetes Secrets.

**Schema migrations:** for Helm installs against Postgres, the chart's
`pre-install,pre-upgrade` hook runs the packaged Alembic plus idempotent
runtime-role credential reconciliation automatically
(`controlPlane.migrations.enabled`, on by default). A normal `helm upgrade`
does not require a manual `alembic upgrade head`. See
[Control-Plane Helm — migration contract](../site-docs/deployment/control-plane-helm.md)
for the one-time `init.sql` stamp path and the non-Helm override.

For **Compose** (`deploy/docker-compose.fullstack.yml`,
`deploy/docker-compose.platform.yml`, and overlays that layer the platform
profile), a one-shot `migrate` service runs the same contract before `api`
starts: stamp baseline `20260416_01` when the volume was first created from
`init.sql`, then `alembic upgrade head`. Image upgrades therefore apply schema
changes on `docker compose up` without a manual Alembic step. The migrate
container requires the explicit Postgres bootstrap/admin URL and its separate
password file; the API stays on `agent_bom_app` (DML) plus the independently
scoped maintenance connection.

Graph migration `20260923_02` adds snapshot generations and indexes for bounded
relationship pages. Apply it before starting the new graph store. Drain old
graph writers during the upgrade: mixed writer versions cannot reliably
invalidate paging cursors when a snapshot is replaced. Image rollback alone
does not undo this migration; restore the matching backup or validate the
database rollback separately. This storage foundation does not yet enable
paged exploration in the dashboard.

---

## Tier 3 — Operator-hosted / gated POC

The operator-hosted tier is the same control plane chart, operated centrally,
with invited customers connecting read-only across the control-plane /
collector seam:

1. **You run the control plane** — deploy the chart (Tier 2) in your account,
   behind your ingress and identity provider. For customer-0 and design
   partners, keep access invite-only with operator-minted tenants and keys.
2. **Customers connect read-only** — each customer applies a connect module
   (`deploy/terraform/connect-aws`, `connect-azure`, `connect-gcp`,
   `connect-snowflake`) that mints a read-only role trusting your hosted
   scanner principal:

   ```bash
   cd deploy/terraform/connect-aws
   terraform apply \
     -var 'trusted_principal_arns=["arn:aws:iam::<your-hosted-account>:role/agent-bom-scanner"]'

   terraform output role_arn               # hand this to the hosted control plane
   terraform output -raw external_id       # confused-deputy guard
   ```

3. **The scanner assumes the role** — your control plane inventories the
   customer account using only that read-only role. No keys leave the customer
   account; no customer data is mutated.

This is the same primitive used by `create_aws_connect_role` in the EKS module,
just pointed at a hosted scanner instead of a local one.

Start with the smaller hosted POC runbook for invite-only hosted evaluations:
[`HOSTED_POC.md`](HOSTED_POC.md). The recommended first proof is one AWS VM
behind HTTPS with
`deploy/docker-compose.hosted-poc.yml` layered on top of the platform compose
so Caddy is the only public listener. The Snowflake Native App lane remains an
enterprise customer-owned install path.

---

## Connect your cloud (zero keys)

Once the control plane is up (any tier above), connecting an account is four
steps and **never** involves a static access key or your laptop's base identity.
The control plane reads a customer cloud by **assuming that account's read-only
role** (`sts:AssumeRole` + ExternalId); it only needs its own workload identity
to make that call. That identity is provisioned automatically by the deploy.

**(a) Deploy the control plane — it gets a keyless identity automatically.**

| Target | Control-plane identity (keyless) | Provisioned by |
|--------|----------------------------------|----------------|
| EKS | IRSA role on the scanner/control-plane ServiceAccount | `platform-eks` / `aws/baseline` (`scanner_role_arn`) |
| Self-managed k8s on EC2 / ECS | Node instance profile / ECS task role (AWS SDK default chain) | your node/task role — grant it `sts:AssumeRole` on the connect roles |
| AKS | Azure workload identity federated to the pod SA | `connect-azure` + Helm `cloud.azure.clientId/tenantId` |
| GKE | GCP Workload Identity; the KSA impersonates the read-only SA | `connect-gcp` + Helm `cloud.gcp.impersonateSa` |

On EKS the scanner IRSA role is minted with a least-privilege `sts:AssumeRole`
policy scoped to the connection-role name pattern (`agent-bom-readonly*` /
`abom-readonly*`) so it can assume those roles in **any** target account —
`aws/baseline` variable `connect_role_arns`. Narrow it to explicit ARNs, or set
`[]` to disable cross-account assume.

**(b) Read the control plane's identity ARN — this is what target accounts trust.**

```bash
# EKS staged Terraform
terraform -chdir=deploy/terraform/platform-eks output -raw scanner_role_arn
# aws/baseline standalone
terraform -chdir=deploy/terraform/aws/baseline output -raw scanner_role_arn
```

For EC2/ECS it is the node instance-profile / ECS task role ARN; for AKS/GCP it
is the workload-identity principal your `connect-azure` / `connect-gcp` apply
prints. This is the value the read-only role in each target account will trust.

**(c) In each target account, create the read-only role trusting THAT identity + ExternalId.**

One account (Terraform or the 1-click CloudFormation Launch Stack the wizard
generates):

```bash
cd deploy/terraform/connect-aws
terraform apply -var 'trusted_principal_arns=["<CONTROL_PLANE_IDENTITY_ARN>"]'
terraform output role_arn               # hand to the wizard
terraform output -raw external_id       # confused-deputy guard
```

All accounts at once — the AWS Organizations **StackSet** with auto-deploy, so
new accounts enroll automatically (never account-by-account):

```bash
aws cloudformation create-stack-set \
  --stack-set-name agent-bom-readonly \
  --template-body file://deploy/cloudformation/agent-bom-readonly-role.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ExternalId,ParameterValue="$EXTERNAL_ID" \
               ParameterKey=TrustedPrincipalArn,ParameterValue="<CONTROL_PLANE_IDENTITY_ARN>"
```

See [`deploy/cloudformation/README.md`](../deploy/cloudformation/README.md) for
the full StackSet flow, and [`connect-*`](../deploy/terraform/) for the Azure
management-group and GCP org/folder equivalents.

**(d) Connect in the UI.** Open **Connections**, paste the `role_arn` +
`ExternalId`, and scan. The control plane assumes the role with short-lived STS
— no key ever leaves the target account, nothing is mutated.

> **Zero-key throughout.** The one exception to workload identity is Snowflake,
> which has no cloud workload identity and uses key-pair (never password) auth
> supplied via a Secret reference. Everything else is keyless. The
> laptop/local-credential path (`aws sso login`, `az login`,
> `gcloud auth application-default login`) exists for **dev only** — never wire a
> personal base identity into a running control plane.

Full read-only contract (what is read, why it stays least-privilege) lives in
[`CLOUD_CONNECT.md`](CLOUD_CONNECT.md); the identity model is in
[`SECURITY_ARCHITECTURE.md` § Control-plane identity](SECURITY_ARCHITECTURE.md#control-plane-identity).

## Choosing a tier

| Need | Tier |
|------|------|
| Fastest look at the full product | 1 — Docker Compose |
| Single team / air-gapped VM | 1 — Docker Compose (or `docker-compose.platform.yml`) |
| Production on AWS | 2A — staged `platform-eks` Terraform |
| Production on an existing/any cluster | 2B — Helm |
| Invite-only operator-hosted pilot | 3 — Operator-hosted + connect roles |
| Gated pilot link | [`HOSTED_POC.md`](HOSTED_POC.md) |

## Related

- [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) — multicloud collector federation
- [`platform-eks` module](../deploy/terraform/platform-eks/README.md) — staged EKS secret sync, migration, and workloads
- [`aws/baseline` module](../deploy/terraform/aws/baseline/README.md) — RDS/IRSA/S3/Secrets
- [`connect-*` modules](../deploy/terraform/) — read-only cloud connect roles
- [Helm chart](../deploy/helm/agent-bom/) — control-plane chart + examples

## Container images — do I need both?

agent-bom publishes two images. They are a deployment-flexibility split, **not a hard requirement** for the dashboard to work.

| Image | Base | What's inside | When to pull it |
|---|---|---|---|
| `agentbom/agent-bom` | Python 3.14 Alpine (~150 MB) | FastAPI/Starlette + scanner + cloud SDKs + MCP server, plus the pre-built Next.js dashboard as static assets. | Always. Single-host pilots and `pip install` users only need this one. |
| `agentbom/agent-bom-ui` | Node 24 Debian slim (~250 MB) | Next.js standalone server only. No Python, no cloud SDKs, no MCP runtime. | K8s deployments that want the UI tier scaled / deployed / restricted independently of the API tier. |

### Why the API image alone serves the dashboard

The `agent-bom serve` process mounts `ui_dist/` as static files when present in the install (`src/agent_bom/api/server.py`, `_mount_dashboard`). What ships where:

| Artifact | Contains the dashboard? | How to confirm |
|---|---|---|
| `agent_bom-<version>-py3-none-any.whl` (PyPI) | Yes. `[tool.setuptools.package-data]` ships `ui_dist/**`. | `unzip -l agent_bom-*.whl \| grep -c ui_dist` |
| `agentbom/agent-bom` (API image) | Yes, in every release **after 0.97.5** — release CI carries the built dashboard into the image build context and the `container-gate` job fails the release if it is absent. Images up to and including **0.97.5 do not**: `agent-bom serve` prints `Dashboard  Not bundled` and every UI route 404s. | `docker run --rm --entrypoint python agentbom/agent-bom:<tag> -c "import agent_bom,pathlib;print((pathlib.Path(agent_bom.__file__).parent/'ui_dist'/'index.html').is_file())"` |
| `agentbom/agent-bom-ui` (UI image) | Yes — it *is* the dashboard, as a standalone Next.js server. Pull it for the tier-split reasons below, not because the API image needs it. | `docker run --rm -p 3000:3000 agentbom/agent-bom-ui:<tag>` |

When the assets are present the dashboard answers at the same origin as the API — no second container, no reverse proxy, no separate ingress.

Note that `GET /` returns `200` either way: without the bundled assets it serves the JSON API service card rather than the dashboard document. Check for the packaged `index.html` (above) or request a UI route such as `/vulns`, which 404s when the dashboard is missing.

```bash
pip install 'agent-bom[api]'
agent-bom serve --port 8422        # API at :8422, UI at the same port
```

The Docker quickstart works the same way — `docker run --rm -p 8422:8422 agentbom/agent-bom serve` is enough for a pilot. The UI image is purely additive.

### Why the second image exists at all

Reasons that hold up:

1. **Independent scaling.** UI is light SSR + static; API does CPU-heavy scanning. Kubernetes wants different replica counts and different HPA / KEDA triggers (see [`scaling-slo.md`](../site-docs/deployment/scaling-slo.md)). Co-locating them forces every UI scale event to also start a Python interpreter.
2. **Smaller attack surface for the UI tier.** No `boto3` / `azure-*` / `google-cloud-*` SDKs reachable from the UI container, no MCP subprocess, no cloud creds in scope. The ExternalSecrets / IRSA bindings can stay scoped to the API Deployment alone.
3. **Independent dep churn.** UI deps (recharts, lucide-react, react-virtual) update fast and noisy; backend deps (boto3, OSV libs) update slow and quiet. Two images means UI patch releases ship without forcing a backend image rebuild.
4. **Different runtimes.** A combined image would carry both Python 3.14 and Node 24 — roughly doubles the image footprint and the security-advisory surface.

Reasons that **do not** hold up:

- *"You need the UI image for the dashboard to work."* — not on releases after 0.97.5. The wheel bundles the dashboard, and so does the API image; the table above gives the one-line check for whichever artifact you are holding. On 0.97.5 and earlier the API image genuinely did not, so those tags need the UI image (or a `pip install 'agent-bom[api]'` deployment) to get a dashboard.

### Practical operator guidance

**Single-process default**: pull `agentbom/agent-bom` only. The wheel bundles the dashboard and so does the API image on releases after 0.97.5, so it serves at the same origin as the API. This is the right answer for `agent-bom serve`, dev, CI, air-gapped registry mirrors, and API-only pilots.

**Pull both** when you specifically want one of these properties:

- the UI tier scales / restarts / rolls out **separately** from the API (different HPA / KEDA / PDB)
- the UI tier sits behind a **different ingress, gateway, or auth boundary** than the API
- the UI tier needs a **smaller attack-surface container** with no Python, no cloud SDKs, no MCP subprocess in scope (the second image is intentionally minimal)
- a separate UI image lets your release cadence ship UI patches without re-rolling the backend image

If none of those properties matter for your deployment, the second image is just bytes you don't need to pull, scan, or sign. The packaged Docker Compose and Helm examples still use the split API + UI shape because they model the multi-replica production layout.

The Helm chart (`deploy/helm/agent-bom`) deploys both by default because the production EKS preset assumes the multi-replica case. To run API-only, set `controlPlane.ui.enabled=false` and the chart skips the UI Deployment, Service, and HPA.

## Endpoint fleet rollout

For discovering MCP servers and AI agents on employee workstations:

```bash
# Jamf / Intune / Kandji pushes this command
agent-bom agents --format json --output /var/log/agent-bom/scan.json
```

**How it works:**
1. MDM pushes `agent-bom` as a scheduled script (daily/weekly)
2. Runs locally on each endpoint — reads config files, extracts package metadata
3. Outputs JSON scan results to a local file
4. MDM collects the JSON file (not the configs, not the credentials)
5. Results shipped to fleet API for centralized visibility

**What stays on the endpoint:** config files, credential values, source code.
**What leaves:** agent names, server names, package names/versions, CVE IDs, blast radius metadata.

**Credential safety:**
- `sanitize_env_vars()` replaces ALL sensitive values with `***REDACTED***` before any output
- Triple-layer detection: key name patterns + value regex + base64/entropy analysis
- Secret scanner shows only first 8 characters as preview, never the full value
- PII findings show `[PII]`, never actual data

For managed proxy onboarding on the same endpoints, generate a rollout bundle instead of hand-editing every client config:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
```

That bundle includes:
- a macOS/Linux shell bootstrap script
- a Windows PowerShell bootstrap script
- Jamf and Kandji shell wrappers
- Intune install and detect PowerShell wrappers
- a `fleet-sync.env` file for the shipped timer/service assets
- a rendered launchd plist for managed macOS rollout

The generated bootstrap scripts install or upgrade `agent-bom`, then run `agent-bom runtime configure --apply` with the control-plane policy/audit settings you chose, so supported JSON MCP clients no longer need manual config edits.

For packaged rollout beyond shell scripts, the repo now also ships:

- `scripts/build-pkg.sh` for macOS `.pkg` assembly from a generated endpoint bundle
- `scripts/build-msi.ps1` for Windows `.msi` assembly via WiX from the same bundle
- `scripts/render_homebrew_formula.py` for publishing a version-pinned Homebrew formula into your tap/release pipeline
- static Jamf / Intune / Kandji templates under `deploy/endpoints/`

## Verify a connected source

Use this path to check whether the selected image can collect from your account
without copying long-lived cloud credentials into agent-bom. Start with one
provider, then repeat the same contract for the others.

```bash
# 1. Run the control plane in your infrastructure.
cp .env.example .env
make secrets  # generate all required mounted secret files
scripts/deploy/install.sh platform-docker

# 2. In the account being scanned, create the provider's read-only identity.
scripts/deploy/install.sh connect aws       # or azure | gcp | snowflake

# 3. Register the printed role/principal output in Dashboard → Connections,
#    test the connection, then choose Run inventory.

# 4. Verify the control plane, authentication, and evidence path.
scripts/deploy/install.sh onboard \
  --url http://localhost:8422 \
  --api-key "$(cat deploy/secrets/api_key)"
```

The expected artifact is not merely a successful credential test: Connections
shows the source as live, the inventory job completes under Jobs, and its
resources and identities appear in Security graph. Findings remain empty when
the connected estate has no supported issue; an empty finding count must not be
presented as an empty inventory.

| Provider | Customer-owned credential boundary | First inventory evidence |
|----------|------------------------------------|--------------------------|
| AWS | STS role with external ID or workload identity | accounts, IAM, compute, storage, network |
| Azure | `DefaultAzureCredential` / workload identity with Reader grants | subscriptions, identities, resources, network |
| GCP | ADC or impersonated service account with viewer/security-review grants | projects, IAM, compute, storage, network |
| Snowflake | key-pair role with read-only metadata grants | roles, users, grants, databases, schemas, objects |

Do not paste cloud keys into the browser. Workers resolve workload identity or
mounted credential files inside the customer deployment. Baseline connect
modules are read-only; deeper content inspection is a separate explicit grant.

```
  ┌─────────────┐     read-only      ┌──────────────────┐
  │ Control     │◀──── connect ──────│ AWS / Azure /    │
  │ plane       │                    │ GCP / Snowflake  │
  │ API+UI+graph│                    └──────────────────┘
  └──────┬──────┘
         │ fleet sync (workstations, MCP configs)
         ▼
  ┌─────────────┐
  │ Endpoints   │
  │ + K8s pods  │
  └─────────────┘
```

For `deploy/terraform/platform-eks`, use customer-managed encrypted remote
state, for example S3 with SSE-KMS, versioning, locked-down IAM, and state
locking. Secret names and infrastructure identifiers enter state; runtime
secret values do not. Do not commit, ticket, or share local state artifacts
without review and redaction.

## Optional enrichment and deployment limits

Core inventory, scanning and compliance do not require an LLM. Optional
[AI enrichment](AI_ENRICHMENT.md) uses the configured model endpoint and
credentials; review that endpoint's data boundary before enabling it.

Connection cadence is opt-in through `AGENT_BOM_CONNECTIONS_SCHEDULER` and
`scan_interval_minutes`. Continuous mode additionally requires a provider
event queue; a Helm scanner CronJob is a separate collection path. The full
staged platform Terraform module is EKS-specific; AKS/GKE use the documented
collector and Helm paths. Self-hosted tenant isolation does not by itself
establish a managed multi-customer service or its operating capacity.

## Air-gapped vulnerability database preload

Disconnected estates need a **transferred `vulns.db`** plus offline runtime
flags. The product does not phone home for advisories when
`AGENT_BOM_VULN_DB_OFFLINE=1` or `--offline` is set; it reads whatever cache
you mount at `AGENT_BOM_DB_PATH` (default `~/.agent-bom/db/vulns.db`).

| Step | First command → artifact | Next step |
|---|---|---|
| Sync (connected bastion) | `agent-bom db update` → `~/.agent-bom/db/vulns.db` | `agent-bom db status` to confirm source freshness |
| Bundle | `scripts/release/bundle-vuln-db.sh dist/airgap` → `vulns.db` + checksum | Transfer through your approved file path |
| Docker runtime | `docker run -v /path/to/vulns.db:/var/lib/agent-bom/vulns.db:ro -e AGENT_BOM_DB_PATH=/var/lib/agent-bom/vulns.db -e AGENT_BOM_VULN_DB_OFFLINE=1 …` | `agent-bom agents --offline /workspace` smoke |
| Helm control plane | `kubectl create secret generic agent-bom-vuln-db --from-file=vulns.db=dist/airgap/vulns.db` then `-f deploy/helm/agent-bom/examples/airgap-vuln-db-values.yaml` | Roll API + scanner pods; rescans use the mounted cache only |
| Refresh cadence | Repeat sync + bundle on a connected host | Replace the mounted `vulns.db` on your maintenance window |

`deploy/docker-compose.pilot.yml` already sets `AGENT_BOM_DB_PATH` on the API
service volume — seed that volume with a pre-synced `vulns.db` before bringing
the stack up. Image import for disconnected registries is documented in
[`site-docs/deployment/airgapped-image-bundle.md`](../site-docs/deployment/airgapped-image-bundle.md).

The air-gap Helm profile disables `/docs` and `/redoc` because their interactive
renderers load browser assets from public CDNs. Use the checked-in
[`docs/openapi/v1.yaml`](openapi/v1.yaml) contract with an approved offline API
viewer, or inspect the YAML directly.
