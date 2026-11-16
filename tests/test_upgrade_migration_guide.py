"""Keep operator upgrade instructions aligned with the migration chain."""

import re
from pathlib import Path

POSTGRES_DIR = Path(__file__).resolve().parents[1] / "deploy" / "supabase" / "postgres"
VERSIONS_DIR = POSTGRES_DIR / "alembic" / "versions"


def test_upgrade_guide_names_the_current_migration_head():
    revisions, parents = set(), set()
    for migration in VERSIONS_DIR.glob("*.py"):
        source = migration.read_text()
        revisions.update(re.findall(r'^revision\s*=\s*"([^"]+)"', source, re.MULTILINE))
        parents.update(re.findall(r'^down_revision\s*=\s*"([^"]+)"', source, re.MULTILINE))
    heads = revisions - parents
    assert len(heads) == 1
    guide = (POSTGRES_DIR.parents[2] / "docs" / "UPGRADING.md").read_text()
    assert f"Apply Postgres migrations through `{heads.pop()}`" in guide
