"""Opt-in restore qualification using the full migrated schema and scoped dump role.

The administrator URL must refer to a disposable PostgreSQL cluster: migrations
provision the fixed application/maintenance roles. Only randomly named test
databases are dropped. Object-store transfer is covered by the backup workflow.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADMIN_URL = os.environ.get("AGENT_BOM_BACKUP_TEST_ADMIN_URL", "")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="Requires an explicitly disposable backup-test PostgreSQL cluster")


def test_maintenance_dump_restores_migrated_schema_without_binding_authority(tmp_path):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from agent_bom.api.storage.runtime_records import RuntimeObservationRecord

    required = ("pg_dump", "pg_restore", "psql")
    if any(shutil.which(command) is None for command in required):
        pytest.skip("PostgreSQL client tools are required")
    suffix = uuid4().hex[:12]
    databases = [f"backup_source_{suffix}", f"backup_restore_{suffix}"]
    admin_options = conninfo_to_dict(ADMIN_URL)
    key = os.urandom(32)
    key_id = hashlib.sha256(key).hexdigest()
    log = tmp_path / "commands.log"

    def run(command, *, env=None, check=True):
        result = subprocess.run(command, env=env, text=True, capture_output=True, cwd=ROOT, check=False)
        with log.open("a") as output:
            output.write(result.stdout + result.stderr)
        if check:
            assert result.returncode == 0, f"{command[0]} failed; inspect the private test log"
        return result

    def connect(database):
        return psycopg.connect(**{**admin_options, "dbname": database})

    def counts(database):
        with connect(database) as conn:
            tables = conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
            return {
                name: conn.execute(sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(name))).fetchone()[0]
                for (name,) in tables
            }

    created = []
    archive_role = f"backup_archive_{suffix}"
    try:
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(archive_role)))
            for database in databases:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                created.append(database)
                admin.execute(sql.SQL("ALTER DATABASE {} SET init.app_password='backup-test-app'").format(sql.Identifier(database)))
                admin.execute(
                    sql.SQL("ALTER DATABASE {} SET init.maintenance_password='backup-test-maintenance'").format(sql.Identifier(database))
                )
        from sqlalchemy.engine import URL

        for database in databases:
            query = {k: v for k, v in admin_options.items() if k not in {"user", "password", "dbname", "host", "port"}}
            host = admin_options.get("host", "localhost")
            if host.startswith("/"):
                query["host"] = host
                host = None
            url = URL.create(
                "postgresql+psycopg",
                username=admin_options.get("user"),
                password=admin_options.get("password"),
                host=host,
                port=int(admin_options.get("port", 5432)),
                database=database,
                query=query,
            )
            env = {**os.environ, "ALEMBIC_DATABASE_URL": url.render_as_string(hide_password=False)}
            for name in ("ALEMBIC_DATABASE_PASSWORD_FILE", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_MAINTENANCE_URL"):
                env.pop(name, None)
            run([sys.executable, "-m", "alembic", "-c", "deploy/supabase/postgres/alembic.ini", "upgrade", "head"], env=env)
            # Models recovery from the operator's separate secret channel.
            with connect(database) as conn:
                conn.execute("INSERT INTO public.agent_bom_tenant_binding_keys(key_id,key_material) VALUES (%s,%s)", (key_id, key))
        source, target = databases
        with connect(source) as conn:
            for tenant in ("backup-a", "backup-b"):
                for i in range(25):
                    record = RuntimeObservationRecord(tenant, f"event-{i}", "session", "2026-10-12T12:00:00Z", verdict="observed")
                    conn.execute(
                        "INSERT INTO runtime_observations(tenant_id,observation_id,session_id,observed_at,data) VALUES (%s,%s,%s,%s,%s)",
                        (tenant, record.observation_id, record.session_id, record.observed_at, json.dumps(record.to_dict())),
                    )
        with connect(source) as conn:
            conn.execute(sql.SQL("GRANT SELECT ON runtime_observations TO {}").format(sql.Identifier(archive_role)))
        expected = counts(source)
        maintenance = make_conninfo(
            **{**admin_options, "dbname": source, "user": "agent_bom_maintenance", "password": "backup-test-maintenance"}
        )
        env = {**os.environ, "PGOPTIONS": "-c app.bypass_rls=1"}
        archive = tmp_path / "application.dump"
        original = run(
            ["pg_dump", maintenance, "--enable-row-security", "--format=custom", "--file", str(tmp_path / "blocked.dump")],
            env=env,
            check=False,
        )
        assert original.returncode != 0 and "agent_bom_tenant_binding_keys" in original.stderr
        run(
            [
                "pg_dump",
                maintenance,
                "--enable-row-security",
                "--format=custom",
                "--exclude-table=public.agent_bom_tenant_binding_keys",
                "--file",
                str(archive),
            ],
            env=env,
        )
        assert "agent_bom_tenant_binding_keys" not in run(["pg_restore", "--list", str(archive)]).stdout
        # Use the production restore script; only its S3 download is substituted.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        aws = bin_dir / "aws"
        aws.write_text('#!/bin/sh\ncp "$BACKUP_TEST_ARCHIVE" "$4"\n')
        aws.chmod(0o700)
        restore_env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"], "BACKUP_TEST_ARCHIVE": str(archive)}
        restore_env.pop("PGOPTIONS", None)
        restore_command = [
            "bash",
            str(ROOT / "deploy/ops/restore-postgres-backup.sh"),
            "s3://test/application.dump",
            make_conninfo(**{**admin_options, "dbname": target}),
            "us-east-1",
            str(tmp_path / "download.dump"),
        ]
        with connect(target) as conn:
            conn.execute("GRANT SELECT ON public.agent_bom_tenant_binding_keys TO agent_bom_maintenance")
        assert run(restore_command, env=restore_env, check=False).returncode != 0
        with connect(target) as conn:
            conn.execute("REVOKE SELECT ON public.agent_bom_tenant_binding_keys FROM agent_bom_maintenance")
            conn.execute("DELETE FROM public.agent_bom_tenant_binding_keys")
        assert run(restore_command, env=restore_env, check=False).returncode != 0
        with connect(target) as conn:
            conn.execute("INSERT INTO public.agent_bom_tenant_binding_keys(key_id,key_material) VALUES (%s,%s)", (key_id, key))
        administrator_archive = tmp_path / "administrator.dump"
        run(["pg_dump", make_conninfo(**{**admin_options, "dbname": source}), "--format=custom", "--file", str(administrator_archive)])
        assert run(restore_command, env={**restore_env, "BACKUP_TEST_ARCHIVE": str(administrator_archive)}, check=False).returncode != 0
        # A missing ACL role fails late in restoration, after table creation and
        # data loading. The entire operation, including partition detachment,
        # must roll back to the untouched migrated target.
        with connect(source) as conn:
            conn.execute(sql.SQL("REVOKE SELECT ON runtime_observations FROM {}").format(sql.Identifier(archive_role)))
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(archive_role)))
        before_restore = counts(target)
        with connect(target) as conn:
            before_partitions = conn.execute("SELECT count(*) FROM pg_inherits").fetchone()[0]
        assert before_partitions > 0
        assert run(restore_command, env=restore_env, check=False).returncode != 0
        assert counts(target) == before_restore
        with connect(target) as conn:
            assert conn.execute("SELECT count(*) FROM pg_inherits").fetchone()[0] == before_partitions
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(archive_role)))
        run(restore_command, env=restore_env)
        assert counts(target) == expected
        with connect(target) as conn:
            assert (
                conn.execute("SELECT key_material FROM public.agent_bom_tenant_binding_keys WHERE key_id=%s", (key_id,)).fetchone()[0]
                == key
            )
            assert conn.execute("SELECT tenant_id,count(*) FROM runtime_observations GROUP BY tenant_id ORDER BY tenant_id").fetchall() == [
                ("backup-a", 25),
                ("backup-b", 25),
            ]
        for database in databases:
            with psycopg.connect(
                **{**admin_options, "dbname": database, "user": "agent_bom_maintenance", "password": "backup-test-maintenance"}
            ) as conn:
                assert not conn.execute(
                    "SELECT has_table_privilege(current_user,'public.agent_bom_tenant_binding_keys','SELECT')"
                ).fetchone()[0]
                assert conn.execute("SELECT count(*) FROM runtime_observations").fetchone()[0] == 0
                conn.execute("SELECT set_config('app.bypass_rls','1',true)")
                assert conn.execute("SELECT count(*) FROM runtime_observations").fetchone()[0] == 50
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            for database in reversed(created):
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(archive_role)))
