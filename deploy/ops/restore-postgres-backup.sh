#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <s3-uri> <postgres-url> <aws-region> [local-file]" >&2
  exit 1
fi

s3_uri="$1"
postgres_url="$2"
aws_region="$3"
local_file="${4:-/tmp/agent-bom-restore.dump}"

# Restore application evidence without replacing the schema-owner-only binding
# authority. Provision the target with the matching release's migrations and
# recover its binding keys through the separate operator secret channel first.
authority_table="$(psql "$postgres_url" -X -v ON_ERROR_STOP=1 -Atc "SELECT to_regclass('public.agent_bom_tenant_binding_keys') IS NOT NULL")"
if [[ "$authority_table" != "t" ]]; then
  echo "Restore requires a migrated target with independently provisioned tenant-binding authority." >&2
  exit 1
fi
authority_private="$(psql "$postgres_url" -X -v ON_ERROR_STOP=1 -Atc "
  SELECT EXISTS (SELECT 1 FROM public.agent_bom_tenant_binding_keys) AND NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname IN
      ('agent_bom_app', 'agent_bom_readonly', 'agent_bom_rls_maintenance', 'agent_bom_maintenance')
    AND has_table_privilege(oid, 'public.agent_bom_tenant_binding_keys', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  ) AND NOT EXISTS (
    SELECT 1 FROM pg_class c, LATERAL aclexplode(c.relacl) a
    WHERE c.oid = 'public.agent_bom_tenant_binding_keys'::regclass AND a.grantee = 0
  )")"
if [[ "$authority_private" != "t" ]]; then
  echo "Restore rejected: tenant-binding authority is empty or accessible to a runtime role or PUBLIC." >&2
  exit 1
fi

aws s3 cp "$s3_uri" "$local_file" --region "$aws_region"
chmod 600 "$local_file"
archive_list="$(pg_restore --list "$local_file")"
if [[ "$archive_list" == *agent_bom_tenant_binding_keys* ]]; then
  echo "Restore rejected: this archive includes tenant-binding authority; use the separate operator recovery procedure." >&2
  exit 1
fi
# pg_restore --clean cannot drop an inherited partition constraint while its
# table remains attached. Detach inside the SAME transaction as restoration;
# a failed restore rolls the detachments and all restored objects back.
restore_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-bom-restore.XXXXXX")"
trap 'rm -rf -- "$restore_dir"' EXIT
pg_restore \
  --exit-on-error \
  --clean \
  --if-exists \
  --no-owner \
  --file "$restore_dir/restore.sql" \
  "$local_file"
cat > "$restore_dir/partitions.sql" <<'SQL'
DO $restore_partitions$
DECLARE
  partition RECORD;
BEGIN
  FOR partition IN
    SELECT pn.nspname AS parent_schema, p.relname AS parent_name,
           cn.nspname AS child_schema, c.relname AS child_name
    FROM pg_inherits i
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace pn ON pn.oid = p.relnamespace
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_namespace cn ON cn.oid = c.relnamespace
    WHERE p.relkind = 'p' AND c.relkind IN ('r', 'p')
      AND pn.nspname = 'public' AND cn.nspname = 'public'
  LOOP
    EXECUTE format('ALTER TABLE %I.%I DETACH PARTITION %I.%I',
                   partition.parent_schema, partition.parent_name,
                   partition.child_schema, partition.child_name);
  END LOOP;
END
$restore_partitions$;
SQL
psql "$postgres_url" -X --set ON_ERROR_STOP=1 --single-transaction \
  --file "$restore_dir/partitions.sql" --file "$restore_dir/restore.sql"
