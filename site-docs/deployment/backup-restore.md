# Backup And Restore Runbook

> **You do not need to read this unless** you are operating the packaged
> Postgres backup CronJob (`controlPlane.backup.enabled=true`) or
> rehearsing a restore. Snowflake-native deployments use the warehouse
> durability and recovery model instead and do not need this page.

This runbook covers the packaged Postgres backup path for self-hosted control
planes. It applies when `controlPlane.backup.enabled=true` in the Helm chart.
Snowflake-native deployments use the warehouse durability and recovery model
instead.

## What Is Backed Up

The backup CronJob runs `pg_dump --enable-row-security --format=custom` against
`AGENT_BOM_POSTGRES_MAINTENANCE_URL` with scoped `app.bypass_rls=1` and uploads the resulting dump to S3-compatible
storage. It excludes `public.agent_bom_tenant_binding_keys`: the maintenance
role must not read the schema-owner-only tenant-binding authority. Preserve
those keys in the operator's separate encrypted secret-recovery channel;
this dump alone is not a complete recovery package. Preserve cluster roles,
application credentials and audit/encryption secrets separately as well.

Packaged implementation:

- Helm template: `deploy/helm/agent-bom/templates/controlplane-backup-cronjob.yaml`
- values: `deploy/helm/agent-bom/values.yaml`
- restore script: `deploy/ops/restore-postgres-backup.sh`
- CI proof: `.github/workflows/backup-restore.yml`

## Production Prerequisites

Before enabling the CronJob:

1. Create a dedicated backup bucket with public access blocked.
2. Enable bucket versioning and retention appropriate for your RPO/RTO.
3. Use SSE-KMS for regulated environments.
4. Attach a least-privilege IRSA or workload-identity role to the backup
   service account.
5. Confirm `pg_dump` and `pg_restore` major versions match the Postgres major
   version.
6. Store `AGENT_BOM_POSTGRES_MAINTENANCE_URL` in a maintenance-only secret
   manager entry, not inline values or the API app-credential Secret.

## Helm Values

Minimal shape:

```yaml
controlPlane:
  backup:
    enabled: true
    schedule: "0 3 * * *"
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/agent-bom-backup
    destination:
      bucket: agent-bom-prod-backups
      prefix: agent-bom/postgres
      bucketRegion: "<your-backup-bucket-region>"
      encryption:
        enabled: true
        mode: "aws:kms"
        kmsKeyId: alias/agent-bom-backups
```

Keep `bucketRegion` explicit. Do not rely on example regions for production.

## Manual Backup Check

Confirm the latest backup object exists:

```bash
export AWS_REGION="<your-backup-bucket-region>"
aws s3 ls "s3://agent-bom-prod-backups/agent-bom/postgres/" \
  --region "$AWS_REGION" \
  --recursive \
  --human-readable \
  --summarize
```

Check the CronJob:

```bash
kubectl -n agent-bom get cronjob agent-bom-control-plane-backup
kubectl -n agent-bom get jobs -l app.kubernetes.io/component=control-plane-backup
```

## Restore Drill

Use the migration/admin principal and the same PostgreSQL major version as
the dump. Create a staging database with the matching application release's
migrations, provision the required cluster roles, and recover the tenant-binding
keys from the independent operator channel before running the command. Keep
API traffic and collectors stopped throughout the drill.

The script fails closed before restoration if the authority table is missing or empty,
if a runtime role or PUBLIC can access it, or if the archive includes it. It
preserves that table and its contents, restores application ACLs, and handles
partition detachment and restoration in one transaction. A SQL/ACL failure rolls
back the entire restore, including the partition changes. An older administrator
dump containing authority keys requires a separate operator-reviewed recovery
procedure; do not grant the maintenance role access to make it readable.

Restore into a staging database first. Do not restore directly over production
until incident command has approved the data-loss window.

```bash
export AWS_REGION="<your-backup-bucket-region>"
export BACKUP_URI="s3://agent-bom-prod-backups/agent-bom/postgres/agent-bom-YYYYMMDDTHHMMSSZ.dump"
export RESTORE_POSTGRES_URL="postgresql://migration_admin:REDACTED@staging-postgres:5432/agent_bom"

deploy/ops/restore-postgres-backup.sh \
  "$BACKUP_URI" \
  "$RESTORE_POSTGRES_URL" \
  "$AWS_REGION"
```

Verify tenant-aware tables after restore:

```bash
psql "$RESTORE_POSTGRES_URL" -c "select count(*) from audit_log;"
psql "$RESTORE_POSTGRES_URL" -c "select tenant_id, count(*) from audit_log group by tenant_id order by tenant_id;"
```

Then run the control-plane smoke checks against the restored environment:

```bash
scripts/deploy/verify-eks-reference.sh \
  --cluster-name corp-ai \
  --region "$AWS_REGION" \
  --namespace agent-bom
```

## Production Restore Checklist

- Freeze scan schedules and external pushes before restore.
- Snapshot the current database if it is still reachable.
- Restore to a new database or schema first when time allows.
- Verify row counts, tenant distribution, audit export, and auth key state.
- Point the API deployment at the restored database.
- Restart API, worker, gateway, and UI deployments.
- Re-run health, metrics, and signed compliance evidence checks.
- Record the backup URI, operator, approval, start time, end time, and data
  loss window in the incident record.

## CI Guardrail

The backup workflow runs two complementary checks:

- A full migration-schema qualification uses a restricted maintenance dump,
  restores through the production script, and verifies all table counts, tenant
  isolation, preserved binding keys, and rollback after a missing ACL role.
- An object-store round trip uses synthetic tenant tables, uploads to MinIO,
  removes only the application tables, restores through the production script,
  and verifies row counts, tenant distribution and the protected authority.

It runs on pull requests and main changes to the backup path, migrations or
qualification test, and weekly to catch upstream image drift. These checks use
disposable PostgreSQL and synthetic data; they do not establish a production
RPO/RTO or replace an operator's restore rehearsal.
