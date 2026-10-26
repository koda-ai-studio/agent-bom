# AWS connection reference

Use this guide for the provider grant, collected evidence and coverage limits.
Return to [cloud connections](../CLOUD_CONNECT.md) for shared onboarding.

## 3. AWS — connect in two steps

**Grant** (read-only, managed): attach the AWS-managed **`SecurityAudit`** policy
(or `ViewOnlyAccess`) to the principal agent-bom will use. That single policy
covers every action the scanner needs.

**Authenticate** via the standard boto3 chain — pick one, no secrets in agent-bom:
- a named profile (`AWS_PROFILE`), or
- env keys (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`), or
- an instance/EKS/ECS role, or SSO.

```bash
export AGENT_BOM_AWS_INVENTORY=1            # opt-in (per-provider, symmetric)
export AGENT_BOM_AWS_ORG_INVENTORY=1        # fan out across every member account
export AWS_PROFILE=abom-readonly            # SecurityAudit-attached profile
agent-bom agents --preset enterprise --aws --aws-cis-benchmark
```

**What it reads** (all read-only): S3, EC2 + security groups, IAM
roles/users/policies and the permission edges between them, RDS, DynamoDB,
Lambda, EKS, ELB/ALB/NLB, VPCs, KMS, Secrets Manager (metadata only), CloudFront,
ECR, Redshift, SNS/SQS — plus AWS **Organizations** (OU tree → accounts → SCPs)
for multi-account estates, and **59 CIS checks**.

**Org scale (cross-account fan-out):** with `AGENT_BOM_AWS_ORG_INVENTORY=1` the
connector enumerates every member account of the organization, assumes a
read-only role in each via `sts:AssumeRole` from the management /
delegated-admin account (keyless, short-lived, ExternalId-capable), and runs the
inventory + CIS benchmark against each — partitioned in the graph by account
under the org → OU `CONTAINS` tree so cross-account attack paths correlate. This
is the AWS analogue of `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS` and
`AGENT_BOM_GCP_ALL_PROJECTS`. Partial-permission tolerant: an account that denies
the role is skipped with a warning, never a hard failure; the report's
`aws_organization.account_scan` block summarises accounts scanned / skipped /
errored. A defensive `AGENT_BOM_AWS_MAX_ACCOUNTS` cap (default 200) bounds blast
radius.

> **Read-only role expectation.** The conventional `OrganizationAccountAccessRole`
> is full-admin and is *not* used. Deploy a least-privilege read-only role
> (SecurityAudit / ViewOnlyAccess) named `agent-bom-readonly` to every account —
> a CloudFormation **StackSet** targeting the org/OUs is the supported pattern.
> Override the name with `AGENT_BOM_AWS_ORG_ROLE_NAME`, the trust ExternalId with
> `AGENT_BOM_AWS_ORG_EXTERNAL_ID`. The role's trust policy grants
> `sts:AssumeRole` only to the management/delegated-admin principal running the
> scan.

> **Control-plane identity (the *caller*, not the role).** When you onboard a
> connection through the Connections wizard, the control plane assumes the
> read-only role for you via `sts:AssumeRole`. That call is made by the control
> plane's **own** identity — the *caller* — which is separate from the read-only
> role the connection points at. If the control plane has no base credentials,
> Test/scan fails with **"Control plane has no AWS credentials to assume the
> role"** — the connection's role is fine; the caller has no identity. Provide one:
>
> - **Production:** run the control plane with an **EC2 instance profile** or
>   **IRSA** (EKS) — no static keys. This is the recommended, keyless path.
> - **Local / dev:** configure standard AWS credentials for the control-plane
>   process (`AWS_PROFILE` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).
> - The caller identity also needs **`sts:AssumeRole`** permission on the target
>   role; for a **same-account** role, the base identity needs `sts:AssumeRole`
>   too (cross-account is covered by the role's trust policy + ExternalId).

**Why read-only is enough:** the connector calls only `List*`/`Describe*`/`Get*`
and `sts:GetCallerIdentity`. The exact action set is declared as permission
constants in `cloud/aws_inventory.py` (`_AWS_*_PERMISSIONS`) and
`cloud/aws_organizations.py` (`_AWS_ORG_PERMISSIONS`). Secret *values* are never
read — only existence and rotation state.

**Secure-by-default provisioning** (`deploy/terraform/connect-aws`): the read-only
role gets a **unique, non-guessable name** (`abom-readonly-<random hex>`) and an
**always-enforced, high-entropy `sts:ExternalId`** — generated automatically when
you don't supply one and surfaced via a *sensitive* `external_id` output. The
confused-deputy condition can never be silently omitted, and a predictable
principal name can't be squatted or targeted. Both have override variables for
operators who need a fixed name or a BYO External ID.

**One SDK, proven current:** AWS support uses a single dependency (`boto3`, the
`aws` extra). A guard test (`tests/test_aws_boto3_client_coverage.py`) scrapes
every `.client("…")` the code uses and asserts each is a real service in the
pinned boto3 — so a typo or too-old pin fails CI, not production.

---

## 1b. Generate the read-only AWS grant

The first path works from the installed wheel and does not require a source
checkout or Terraform:

```bash
pip install agent-bom
agent-bom connect aws --emit --out agent-bom-aws-readonly.json
```

The command writes a deployable CloudFormation template to the named file and
prints the next `agent-bom connect aws` command to stderr. Review and deploy the
template in AWS, then use its role ARN and the generated ExternalId to establish
the connection. The emitted baseline is read-only and least-privilege; content
reads remain explicit `--deep-scan` opt-ins.

### Other grant methods (pick what your rights allow)

The **same read-only grant** can be minted three ways. Choose based on who is
allowed to change IAM / RBAC in your org — not based on what agent-bom prefers.

| Method | When to use | Where |
|--------|-------------|--------|
| **Packaged emit (start here)** | You installed agent-bom from PyPI and want a reviewable deploy artifact | `agent-bom connect aws --emit --out agent-bom-aws-readonly.json` |
| **CloudShell** | No local Terraform; you can open the vendor browser shell | Same recipes, framed for AWS CloudShell / Azure Cloud Shell / Google Cloud Shell / Snowsight |
| **Repository Terraform (optional)** | Platform/SRE has a source checkout, owns apply rights, and wants Terraform state | `deploy/terraform/connect-*` + Connections wizard **Terraform** tab |

`agent-bom connect <provider>` prints all three. The control-plane Connections
wizard lets you copy the matching script. Secondary vendors (Databricks,
CoreWeave, HF, W&B, …) stay under `scripts/provision/` until they join the
brokered catalog.

With connection flags, `connect` is safe to chain (`agent-bom connect aws &&
<next step>`): it exits `0` only after the read-only credential actually
verified, and on failure it exits non-zero and prints the same curated,
secret-free reason the API and the Connections drawer show — never "see server
logs". Codes are in
[`site-docs/reference/exit-codes.md`](../../site-docs/reference/exit-codes.md).

---

## 7b. Agentless EBS disk side-scan (opt-in, scoped role)

The disk side-scan snapshots a target EBS volume, attaches a temp volume to an
**in-account collector** instance, mounts it read-only, and returns a
metadata-only result — package SBOM, matched CVEs, and secret *type/location*
(never values, never file contents). Snapshot → volume → mount are always torn
down in a guaranteed cleanup; a pre-run sweep reaps anything a prior crash
stranded. No disk image or block data leaves the account.

It is OFF unless `AGENT_BOM_SIDESCAN=1`. Run it from the collector (or any host
with the scoped snapshot role) with:

```bash
AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan \
  --volume-id vol-0abc123 \
  --collector-instance-id i-0def456 \
  --availability-zone us-east-1a \
  --region us-east-1
```

Use `--instance-id i-...` instead of `--volume-id` to scan every EBS volume
attached to an instance, or `--image-id ami-...` to scan an AMI (a tagged temp
volume is created from the AMI's root EBS snapshot; the AMI and its snapshot are
never modified or deleted; encrypted AMI snapshots also need KMS use on their
key). Packages and CVEs are reported per owning instance and project onto the
EC2 instance node in the graph; `-f json` emits the `side_scan_results` records
(see [CLOUD_CONNECT.md](../CLOUD_CONNECT.md#side-scan-coverage-packages-and-cves-per-vm-and-machine-images)). `--no-secrets` returns SBOM + CVEs only;
`--no-sweep-orphans` skips the pre-run stranded-snapshot sweep. With the flag
unset the command prints how to enable it and exits non-zero — it never starts a
snapshot implicitly.

Azure Managed Disk and GCP Persistent Disk inventory also emits
`side_scan_targets` records with provider, target id, location, size, encryption,
and execution state. Those records are graph-visible workload-disk targets.
The repository defines a versioned provider-neutral lifecycle/evidence contract
and concrete Azure Managed Disk and GCP Persistent Disk adapters that accept
already-authenticated SDK clients. Separate least-privilege Terraform modules
grant the snapshot/temp-disk/collector lifecycle. Both providers now ship a CLI
executor — `agent-bom cloud side-scan --provider azure|gcp` drives the same
snapshot → temp-disk → collector-mount → SBOM/CVE/secret → guaranteed-cleanup
lifecycle as AWS EBS, resolving scoped snapshot/temp-disk credentials from the provider's
default chain (never embedded). No live credentialed smoke is claimed for any
provider yet (`credentialed_smoke=false`). An opt-in scheduler auto-trigger
re-runs the same executor for each configured target on a cadence — off unless
both `AGENT_BOM_SIDESCAN_SCHEDULER` (the loop gate) and `AGENT_BOM_SIDESCAN`
(the executor gate) are set — so a CWPP side-scan keeps evaluating without a
manual call.

All provider lifecycle implementations must persist explicit
`disabled`/`denied`/`partial`/`failed`/`scan_complete` state and separate cleanup
state. A scan is complete only after owned temporary resources are deleted;
zero findings are scoped to the scanned disk and never assert that a workload is
clean. Snapshot operations remain opt-in because they are not read-only.
`side_scan_lifecycle.py` supplies the versioned records, deterministic ownership
tags, stale-worker protection, and tenant-scoped SQLite or Postgres lifecycle
persistence (with ephemeral memory only by explicit opt-out). The
injected-SDK adapters consume that state; the `side-scan --provider azure|gcp`
CLI executor (`run_provider_side_scan`) drives them, and the opt-in scheduler
loop (`api/side_scan_scheduler.py`) re-runs configured targets on a cadence
through the same executor and the same durable lifecycle store.
