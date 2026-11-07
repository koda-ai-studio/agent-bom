"""Demo profiles must start: the API refuses a non-loopback bind without real auth."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import click
import pytest
import yaml

from agent_bom.cli._server_posture import _enforce_auth_defaults

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/agent-bom"
EXAMPLES = CHART / "examples"
DEMO_PROFILES = ("eks-control-plane-sqlite-pilot-values.yaml", "synthetic-enterprise-story-values.yaml")
AUTH_ENV = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_SAML_IDP_ENTITY_ID",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
)


def _api_container(values_file: Path) -> dict:
    rendered = subprocess.run(  # noqa: S603, S607 - fixed binary, test-owned arguments
        ["helm", "template", "demo", str(CHART), "--values", str(values_file)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    for document in yaml.safe_load_all(rendered):
        if document and document["kind"] == "Deployment" and document["metadata"]["name"].endswith("-api"):
            return document["spec"]["template"]["spec"]["containers"][0]
    raise AssertionError("no API Deployment rendered")


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("profile", DEMO_PROFILES)
def test_demo_profile_requires_a_seeded_api_key_and_binds_authenticated(profile: str) -> None:
    container = _api_container(EXAMPLES / profile)
    env = {row["name"]: row for row in container["env"]}

    assert container["args"][container["args"].index("--host") + 1] == "0.0.0.0"
    assert "--allow-insecure-no-auth" not in container["args"]
    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API" not in env
    assert "AGENT_BOM_NO_AUTH_ROLE" not in env
    reference = env["AGENT_BOM_API_KEYS"]["valueFrom"]["secretKeyRef"]
    assert reference["name"] == "agent-bom-control-plane"
    assert reference["key"] == "AGENT_BOM_API_KEYS"
    assert not reference.get("optional"), "a missing key must stop the pod instead of starting it unauthenticated"


@pytest.mark.parametrize("values_file", sorted(EXAMPLES.glob("*-values.yaml")), ids=lambda path: path.name)
def test_no_shipped_profile_asks_for_anonymous_access(values_file: Path) -> None:
    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API" not in values_file.read_text(encoding="utf-8")


def test_secret_reference_documents_the_key_each_demo_profile_requires() -> None:
    blocks = (EXAMPLES / "control-plane-auth-secret.example.yaml").read_text(encoding="utf-8").split("---\n")
    block = next(block for block in blocks if "PROFILE: sqlite-pilot" in block)
    secret = yaml.safe_load(block)

    assert secret["metadata"]["name"] == "agent-bom-control-plane"
    assert set(secret["stringData"]) == {"AGENT_BOM_CONNECTIONS_KEY", "AGENT_BOM_API_KEYS"}
    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API" not in block.replace("# ", "")


def test_the_api_still_refuses_anonymous_non_loopback_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")

    with pytest.raises(click.ClickException, match="Refusing to expose"):
        _enforce_auth_defaults("api", "0.0.0.0", None, False)  # noqa: S104 - the bind under test


def test_a_seeded_key_satisfies_the_non_loopback_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_BOM_API_KEYS", "fixture" + "-pilot-key:admin")

    _enforce_auth_defaults("api", "0.0.0.0", None, False)  # noqa: S104 - the bind under test
