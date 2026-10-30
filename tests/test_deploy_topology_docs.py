"""Deployment prose and release evidence follow the static Pages demo topology."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
DEMO_DEPLOY_WORKFLOW = WORKFLOWS / "demo-deploy-cloudrun.yml"
HOSTED_POC = ROOT / "docs" / "HOSTED_POC.md"
_WORKFLOW_PATH_RE = re.compile(r"\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)")


def _markdown_files() -> list[Path]:
    paths = sorted(ROOT.glob("*.md"))
    for directory in ("docs", "site-docs", "deploy"):
        paths.extend(sorted((ROOT / directory).rglob("*.md")))
    return paths


def test_docs_only_reference_workflows_that_exist() -> None:
    """Prose naming a deleted workflow sends operators to a file that is gone."""
    missing: list[str] = []
    for path in _markdown_files():
        for name in _WORKFLOW_PATH_RE.findall(path.read_text(encoding="utf-8")):
            if not (WORKFLOWS / name).is_file():
                missing.append(f"{path.relative_to(ROOT)} -> .github/workflows/{name}")

    assert missing == [], f"docs reference workflows that do not exist: {missing}"


def test_no_workflow_still_deploys_the_demo_to_retired_aws_infrastructure() -> None:
    """The demo VM is retired; automation targeting it must not stay armed.

    A workflow that assumes an IAM role to `ssm:SendCommand` a decommissioned
    instance is dead automation holding a live trust relationship, and it fired
    on the same `Release` completion as the Cloud Run deploy.
    """
    assert not (WORKFLOWS / "demo-redeploy.yml").exists(), "the retired EC2/SSM demo redeploy must not stay armed"

    offenders = [
        workflow.name for workflow in sorted(WORKFLOWS.glob("*.yml")) if "DEMO_INSTANCE_ID" in workflow.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"workflows still target the retired demo VM: {offenders}"


def test_hosted_poc_keeps_the_project_demo_and_the_self_host_runbook_distinct() -> None:
    doc = HOSTED_POC.read_text()
    assert "GitHub Pages" in doc
    assert "Self-host" in doc
    assert "persistent Postgres" in doc
    assert "no live scanner API" in doc
    assert "DEMO_GCP_" not in doc


def test_readme_shared_deployment_row_points_at_a_shared_deployment_profile() -> None:
    """The README's shared-deployment table must not route operators to the pilot.

    The self-host section promises "your VPC, Postgres, signed audit" and tells
    the reader to "configure real identity, TLS, PostgreSQL, encryption, and
    audit keys before exposing it" — then its only Docker Compose link was
    `docker-compose.pilot.yml`, which is loopback-bound, SQLite-persisted and
    runs `--allow-insecure-no-auth`. The pilot file's own header is honest; the
    routing was not.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pilot = (ROOT / "deploy" / "docker-compose.pilot.yml").read_text(encoding="utf-8")
    platform = (ROOT / "deploy" / "docker-compose.platform.yml").read_text(encoding="utf-8")

    # The premise: pilot really is the insecure single-workstation profile and
    # platform really is the Postgres-backed one. If either stops being true this
    # guard must be revisited rather than silently passing.
    assert "--allow-insecure-no-auth" in pilot
    assert "postgres" in platform.lower()
    assert "--allow-insecure-no-auth" not in platform

    _, _, self_host = readme.partition("## Self-host")
    shared, _, _ = self_host.partition("[Deployment overview]")
    assert "deploy/docker-compose.platform.yml" in shared, "shared-deployment table omits the platform profile"


def test_postgres_init_never_hardcodes_the_database_name() -> None:
    """`init.sql` must grant against the database it is running in.

    The platform compose parameterizes the database (`POSTGRES_DB:-agent_bom`),
    but `init.sql` granted `ON DATABASE agent_bom` literally. Any operator who
    set `POSTGRES_DB` hit `ERROR: database "agent_bom" does not exist`; init
    aborted mid-file and the following `alembic upgrade head` then died on a
    missing role *after* committing tables — a half-migrated database.
    """
    init_sql = (ROOT / "deploy" / "supabase" / "postgres" / "init.sql").read_text(encoding="utf-8")
    compose = (ROOT / "deploy" / "docker-compose.platform.yml").read_text(encoding="utf-8")

    # Premise: the database name really is operator-configurable.
    assert "POSTGRES_DB: ${POSTGRES_DB:-agent_bom}" in compose

    hardcoded = [line.strip() for line in init_sql.splitlines() if "ON DATABASE agent_bom" in line]
    assert not hardcoded, f"init.sql hardcodes the database name: {hardcoded}"


def test_public_demo_has_only_static_pages_deployment():
    assert not DEMO_DEPLOY_WORKFLOW.exists(), "retired Cloud Run deployment can recreate the demo"
    assert not (ROOT / "deploy/docker-compose.demo-override.yml").exists()
    docs = (WORKFLOWS / "docs.yml").read_text()
    build = (WORKFLOWS / "docs-build.yml").read_text()
    assert "actions/deploy-pages@" in docs
    assert "NEXT_PUBLIC_STATIC_DEMO: '1'" in build
    assert "verify-static-demo.mjs" in build
    for workflow in WORKFLOWS.glob("*.yml"):
        assert "DEMO_GCP_" not in workflow.read_text(), workflow.name
    runbook = HOSTED_POC.read_text()
    assert "https://koda-ai-studio.github.io/agent-bom/demo/" in runbook
    assert "GitHub Pages" in runbook
