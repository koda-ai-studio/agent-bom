#!/usr/bin/env python3
"""Assert two bootstrap paths produce the SAME Postgres schema, not just the same head.

agent-bom can reach a working control plane two ways:

  A. Alembic only — ``alembic upgrade head`` on an empty database.
  B. psql bootstrap — run ``init.sql``, ``alembic stamp 20260416_01``, then
     ``alembic upgrade head``.

CI already builds both in one job. Until now it compared only the
``alembic_version`` string, which proves the two paths *ran* the same revisions,
not that they *produced* the same schema. Those are different claims. The
convention in this repo is that a new column lands in a migration AND is
back-added to ``init.sql`` so fresh installs get it from the baseline; forget the
second edit and path B silently ships a database missing the column, with an
identical head. Every existing guard against that is a regex over SQL text —
none of them diffs two live databases.

So this compares the actual rendered schemas via ``pg_dump --schema-only``,
statement by statement. It also asserts the extensions the schema depends on are
really installed: ``pg_trgm`` is created in three places, one of them at runtime
by the application, where a permission error is deliberately swallowed — so
"we asked for it" was never the same as "it is there".

Usage:
    check_postgres_schema_parity.py --migration-url URL --bootstrap-url URL \\
        [--require-extension pg_trgm ...]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Noise that legitimately differs between two databases: server preamble, the
# database name itself, ownership, and comments.
# `\restrict`/`\unrestrict` are psql meta-commands newer pg_dump builds wrap the
# body in, each carrying a fresh random token — pure noise that would otherwise
# make every dump differ from every other dump.
_IGNORED_LINE = re.compile(
    r"^\s*(--|SET\s|SELECT pg_catalog\.set_config|\\connect|\\restrict|\\unrestrict|COMMENT ON EXTENSION)",
    re.I,
)
_IGNORED_STATEMENT = re.compile(r"^\s*(CREATE|DROP)\s+DATABASE\b|^\s*ALTER\s+DATABASE\b", re.I)

# PostgreSQL 16.16 and the same-day minor releases of the other supported
# branches (CVE-2026-6460) keep a per-column version in
# pg_attribute.attoptions under the internal key `pg_attver`. Its value is the
# WAL LSN at the time of the DDL, so it differs on every database, and DDL cannot
# set it (the server drops it on restore). A pg_dump of the same release strips
# it; a client built before it, of any major version (the CI runner's
# pg_dump 18.6 is one), prints it as
# `ALTER COLUMN c SET (pg_attver=<lsn>)`. Remove exactly that key, as upstream
# pg_dump does, and keep every real attribute option such as n_distinct.
_ATTRIBUTE_OPTIONS = re.compile(r"^(?P<head>ALTER TABLE .+ ALTER COLUMN .+ SET )\((?P<options>[^()]*)\)$", re.I)
_ATTRIBUTE_VERSION_OPTION = "pg_attver="


def _strip_attribute_version(statement: str) -> str:
    match = _ATTRIBUTE_OPTIONS.match(statement)
    if not match:
        return statement
    options = [option.strip() for option in match.group("options").split(",")]
    kept = [option for option in options if not option.startswith(_ATTRIBUTE_VERSION_OPTION)]
    if len(kept) == len(options):
        return statement
    if not kept:
        return ""
    return f"{match.group('head')}({', '.join(kept)})"


def _pg_dump(url: str) -> str:
    result = subprocess.run(
        [
            "pg_dump",
            "--schema-only",
            "--no-owner",
            "--no-acl",
            "--no-comments",
            "--no-publications",
            "--no-subscriptions",
            "--no-security-labels",
            "--no-tablespaces",
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"pg_dump failed for {_redact(url)}:\n{result.stderr.strip()}")
    return result.stdout


def _redact(url: str) -> str:
    return re.sub(r"//[^@/]*@", "//***@", url)


def _statements(dump: str) -> set[str]:
    """Normalize a dump into a comparable set of statements.

    A set, not a list: the two paths build objects in different orders, and
    ordering is not part of the contract. Content is.
    """
    kept: list[str] = []
    for line in dump.splitlines():
        if _IGNORED_LINE.match(line):
            continue
        kept.append(line)
    body = "\n".join(kept)
    statements: set[str] = set()
    for raw in body.split(";\n"):
        # Splitting on ";\n" leaves the final statement of a dump carrying its
        # terminator while every other one lost it, which would make a
        # statement's identity depend on where it happened to appear.
        statement = _strip_attribute_version(" ".join(raw.split()).rstrip(";").strip())
        if not statement or _IGNORED_STATEMENT.match(statement):
            continue
        statements.add(statement)
    return statements


def _installed_extensions(url: str) -> set[str]:
    result = subprocess.run(
        ["psql", url, "-Atc", "SELECT extname FROM pg_extension"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"psql extension probe failed for {_redact(url)}:\n{result.stderr.strip()}")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def compare(migration_dump: str, bootstrap_dump: str) -> list[str]:
    migration = _statements(migration_dump)
    bootstrap = _statements(bootstrap_dump)
    problems: list[str] = []
    for label, missing in (
        ("present after `alembic upgrade head` but MISSING from the init.sql bootstrap", migration - bootstrap),
        ("present after the init.sql bootstrap but MISSING from `alembic upgrade head`", bootstrap - migration),
    ):
        for statement in sorted(missing):
            problems.append(f"{label}:\n      {statement[:400]}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migration-url", required=True, help="Database built by `alembic upgrade head` alone.")
    parser.add_argument("--bootstrap-url", required=True, help="Database built by init.sql + stamp + upgrade.")
    parser.add_argument(
        "--require-extension",
        action="append",
        default=[],
        help="Extension that must actually be installed in BOTH databases.",
    )
    args = parser.parse_args(argv)

    problems = compare(_pg_dump(args.migration_url), _pg_dump(args.bootstrap_url))

    for url, label in ((args.migration_url, "migration-only"), (args.bootstrap_url, "init.sql bootstrap")):
        installed = _installed_extensions(url)
        for extension in args.require_extension:
            if extension not in installed:
                problems.append(f"{label} database is missing required extension {extension!r} (installed: {sorted(installed)})")

    if problems:
        print(f"ERROR: the two bootstrap paths do not agree ({len(problems)} difference(s)):\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nA column or index added to a migration must also be back-added to "
            "deploy/supabase/postgres/init.sql (and vice versa), or fresh installs "
            "and upgraded installs ship different schemas under the same Alembic head.",
            file=sys.stderr,
        )
        return 1

    print("Postgres schema parity passed — the migration-only and init.sql bootstrap paths render identical schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
