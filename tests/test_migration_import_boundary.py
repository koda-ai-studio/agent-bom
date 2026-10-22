"""Migration discovery must not initialize runtime audit signing."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _isolated_import(code: str) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(
        AGENT_BOM_POSTGRES_URL="postgresql://fixture:fixture@127.0.0.1:1/fixture",
        AGENT_BOM_REQUIRE_AUDIT_HMAC="1",
    )
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize(
    "code",
    [
        "from agent_bom.api.storage.job_revisions import POSTGRES_JOB_REVISIONS_V1; assert POSTGRES_JOB_REVISIONS_V1",
        "from alembic.script import ScriptDirectory; assert list(ScriptDirectory('deploy/supabase/postgres/alembic').walk_revisions())",
    ],
)
def test_migration_definitions_load_without_runtime_signing_secrets(code: str) -> None:
    if "alembic.script" in code:
        pytest.importorskip("alembic", reason="Full migration discovery requires the postgres extra")
    result = _isolated_import(code + "; import sys; assert 'agent_bom.api.audit_log' not in sys.modules")
    assert result.returncode == 0, result.stderr


def test_runtime_audit_still_rejects_missing_required_signing_key() -> None:
    result = _isolated_import("import agent_bom.api.audit_log")
    assert result.returncode != 0
    assert "AGENT_BOM_AUDIT_HMAC_KEY is required" in result.stderr
