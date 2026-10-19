# GCP connection reference

Use this guide for the provider grant, collected evidence and coverage limits.
Return to [cloud connections](../CLOUD_CONNECT.md) for shared onboarding.

## 5. GCP — connect with read-only inventory and IAM review roles

**Grant** (read-only, predefined): bind the scanner service account to
**`roles/viewer`** for inventory, **`roles/iam.securityReviewer`** for IAM,
**`roles/cloudasset.viewer`** for resource-local policies, and
**`roles/serviceusage.serviceUsageConsumer`** for Cloud Asset API quota attribution.
Together they provide read-only relationship and policy visibility. For fleet-wide scans, grant the same roles
at the organization or folder level and enable project fan-out.

**Authenticate** through Application Default Credentials — no password, pick
one:
- `gcloud auth application-default login` for an operator-run scan, or
- service account impersonation (`AGENT_BOM_GCP_IMPERSONATE_SA`), or
- Workload Identity Federation for CI/Kubernetes without a key file.

```bash
export AGENT_BOM_GCP_INVENTORY=1
export AGENT_BOM_GCP_ALL_PROJECTS=1        # fan out across org/folders/projects
export AGENT_BOM_GCP_IMPERSONATE_SA=agent-bom-readonly@PROJECT_ID.iam.gserviceaccount.com
agent-bom cloud gcp --project PROJECT_ID --cis
```

**What it reads:** projects, folders, organization hierarchy, IAM policies and
service accounts, Cloud Run, Vertex AI, GKE, Compute Engine, Artifact Registry,
Cloud SQL, Cloud Storage, Pub/Sub, KMS, Secret Manager metadata, VPC/firewall
posture, logging posture, and CIS checks.

**Org scale:** with `AGENT_BOM_GCP_ALL_PROJECTS=1` the connector discovers the
organization → folders → projects hierarchy, runs each project scan separately,
and writes graph nodes under the right org/folder/project parent so exposures
stay drillable at tenant scale. `AGENT_BOM_GCP_MAX_PROJECTS` bounds the run.

> **Mass-onboarding grant.** Rather than granting the read-only role set per
> project, bind them **once at the organization or folder** so a single grant
> covers every project the fan-out reaches — the GCP analogue of the AWS
> Organizations StackSet (§3) and the Azure management-group scope (§4). The
> `connect-gcp` module does this with `iam_binding_scope = "organization"` (or
> `"folder"`); the bindings stay strictly read-only.

**Secure-by-default provisioning** (`deploy/terraform/connect-gcp`): the module
mints a unique read-only service account and binds only `roles/viewer`,
`roles/iam.securityReviewer`, `roles/cloudasset.viewer`, and
`roles/serviceusage.serviceUsageConsumer` — at the project by default, or
org/folder-wide via `iam_binding_scope` for fleet onboarding. Optional Workload Identity Federation
is locked to a scoped `attribute_condition`, pinned audiences, and a specific
`principalSet`; broad wildcard federation is rejected.

**Why read-only is enough:** the connector uses list/get style APIs and IAM
policy reads. Secret Manager values, object contents, and table rows are not
read. Missing optional APIs degrade to provider warnings so partial permissions
are visible without turning one blocked service into a failed estate scan.

---

### Incomplete GCP bucket IAM reads

Run `agent-bom scan --gcp-cis-benchmark --gcp-project PROJECT_ID -f json -o report.json`
and inspect check `5.1`. A bucket whose IAM policy cannot be read leaves its
compliance unknown: a transient read failure, disabled API or disabled billing
cannot produce PASS. The evidence states the inspected/total bucket count and
separates project-state failures from missing `storage.buckets.getIamPolicy`.
Restore the indicated API, billing or permission prerequisite, then rescan.
Known public buckets remain FAIL even when other bucket reads are incomplete.
