"""Contract for `scripts/check_postgres_schema_parity.py`.

CI builds an Alembic-only database and an init.sql-bootstrapped database in the
same job, then compares only their `alembic_version` strings. That proves the two
paths RAN the same revisions, not that they PRODUCED the same schema. These tests
pin the normalization (so unrelated dump noise never fails a build) and the
comparison (so a real column difference always does).

The live end-to-end run needs a Postgres server and belongs to the
`postgres-integration` CI job; everything below is pure text logic.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_postgres_schema_parity.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_postgres_schema_parity", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()

_TEAMS = textwrap.dedent("""\
    CREATE TABLE public.teams (
        team_id text NOT NULL,
        name text NOT NULL
    );
    """)


class TestNormalization:
    def test_server_preamble_is_ignored(self):
        noisy = "SET statement_timeout = 0;\nSET lock_timeout = 0;\n" + _TEAMS
        assert gate._statements(noisy) == gate._statements(_TEAMS)

    def test_comments_are_ignored(self):
        noisy = "--\n-- Name: teams; Type: TABLE\n--\n" + _TEAMS
        assert gate._statements(noisy) == gate._statements(_TEAMS)

    def test_restrict_meta_commands_are_ignored(self):
        """Newer pg_dump wraps the body in `\\restrict <random token>`."""
        a = "\\restrict AAAAAAAAAAAAAAAA\n" + _TEAMS + "\\unrestrict AAAAAAAAAAAAAAAA\n"
        b = "\\restrict BBBBBBBBBBBBBBBB\n" + _TEAMS + "\\unrestrict BBBBBBBBBBBBBBBB\n"
        assert gate._statements(a) == gate._statements(b)

    def test_database_level_statements_are_ignored(self):
        """The two databases have different names and settings by construction."""
        noisy = "ALTER DATABASE agent_bom SET init.app_password = 'x';\n" + _TEAMS
        assert gate._statements(noisy) == gate._statements(_TEAMS)

    def test_whitespace_and_ordering_do_not_matter(self):
        one = _TEAMS + "CREATE INDEX i ON public.teams (name);\n"
        two = "CREATE INDEX   i   ON public.teams (name);\n" + _TEAMS
        assert gate._statements(one) == gate._statements(two)


class TestAttributeVersion:
    """PostgreSQL 16.16 (CVE-2026-6460, backpatched to every supported branch) stores a per-column WAL LSN as the
    internal attoption ``pg_attver``. A server-matched pg_dump strips it; an older
    client prints it as ``ALTER COLUMN ... SET (pg_attver=<lsn>)``. The LSN is
    where the cluster's WAL happened to be, so it differs on every database."""

    def test_attribute_version_only_statements_are_ignored(self):
        a = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN team_id SET (pg_attver=38450424);\n"
        b = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN team_id SET (pg_attver=38466888);\n"
        assert gate._statements(a) == gate._statements(_TEAMS)
        assert gate.compare(a, b) == []

    def test_attribute_version_does_not_hide_a_real_attribute_option_difference(self):
        with_stats = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (pg_attver=38450424, n_distinct=5);\n"
        plain = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (pg_attver=38466888);\n"
        problems = gate.compare(with_stats, plain)
        assert len(problems) == 1
        assert "SET (n_distinct=5)" in problems[0]
        assert "pg_attver" not in problems[0]

    def test_a_real_attribute_option_value_difference_is_reported(self):
        five = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (n_distinct=5, pg_attver=1);\n"
        ten = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (pg_attver=2, n_distinct=10);\n"
        assert len(gate.compare(five, ten)) == 2

    def test_same_attribute_options_with_different_versions_match(self):
        a = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (n_distinct=5, pg_attver=1);\n"
        b = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (pg_attver=2, n_distinct=5);\n"
        assert gate.compare(a, b) == []

    def test_a_lookalike_option_name_is_not_stripped(self):
        a = _TEAMS + "ALTER TABLE ONLY public.teams ALTER COLUMN name SET (x_pg_attver=1);\n"
        assert gate.compare(a, _TEAMS)


class TestComparison:
    def test_identical_schemas_pass(self):
        assert gate.compare(_TEAMS, _TEAMS) == []

    def test_a_column_only_the_migration_creates_is_reported(self):
        with_column = _TEAMS.replace("name text NOT NULL", "name text NOT NULL,\n    extra text")
        problems = gate.compare(with_column, _TEAMS)
        assert any("MISSING from the init.sql bootstrap" in p for p in problems)

    def test_a_column_only_init_sql_creates_is_reported(self):
        with_column = _TEAMS.replace("name text NOT NULL", "name text NOT NULL,\n    extra text")
        problems = gate.compare(_TEAMS, with_column)
        assert any("MISSING from `alembic upgrade head`" in p for p in problems)

    def test_a_missing_index_is_reported(self):
        with_index = _TEAMS + "CREATE INDEX idx_teams_name ON public.teams (name);\n"
        assert gate.compare(with_index, _TEAMS)

    def test_a_column_type_change_is_reported(self):
        """`observed_at text` vs `timestamptz` is exactly the drift this caught."""
        retyped = _TEAMS.replace("name text NOT NULL", "name timestamp with time zone NOT NULL")
        assert gate.compare(_TEAMS, retyped)


class TestSecrets:
    def test_connection_passwords_are_redacted_in_errors(self):
        redacted = gate._redact("postgresql://owner:hunter2@127.0.0.1:5432/agent_bom")
        assert "hunter2" not in redacted


class TestCiWiring:
    def test_the_postgres_job_runs_the_parity_gate(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "scripts/check_postgres_schema_parity.py" in ci
        assert "--require-extension pg_trgm" in ci

    def test_the_bootstrap_path_replays_what_docker_mounts(self):
        """Docker loads 01-init.sql AND 02-runtime-schema.sql; CI must match."""
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "-f deploy/supabase/postgres/runtime-schema.sql" in ci
