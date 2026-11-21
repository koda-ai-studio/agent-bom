"""`agent-bom connect` guidance works for a pip install and sees normal CLI logins."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cli import _connect_links as links


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AZURE_CONFIG_DIR", "CLOUDSDK_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")


@pytest.mark.parametrize(
    ("version", "ref"),
    [("0.115.5", "v0.115.5"), ("0.115.5.dev3", "main"), ("0.116.0rc1", "main")],
)
def test_links_pin_the_installed_release(monkeypatch: pytest.MonkeyPatch, version: str, ref: str) -> None:
    monkeypatch.setattr(links, "__version__", version)
    recipe = "scripts/provision/aws_readonly_policy.json"
    assert links.source_link(recipe).endswith(f"/blob/{ref}/{recipe}")
    assert links.source_link("deploy/terraform/connect-aws").endswith(f"/tree/{ref}/deploy/terraform/connect-aws")
    command = links.terraform_command("deploy/terraform/connect-aws")
    assert f'agent-bom.git//deploy/terraform/connect-aws?ref={ref}&depth=1"' in command
    assert command.startswith('terraform init -from-module="git::https://')


@pytest.mark.parametrize(
    ("provider", "relative"),
    [
        ("aws", ".aws/credentials"),
        ("aws", ".aws/config"),
        ("azure", ".azure/azureProfile.json"),
        ("gcp", ".config/gcloud/application_default_credentials.json"),
    ],
)
def test_cli_login_files_count_as_detected(home: Path, provider: str, relative: str) -> None:
    assert links.detected_login_files(provider) == []
    _touch(home / relative)
    assert links.detected_login_files(provider) == [f"~/{relative}"]


def test_relocated_login_files_are_followed(home: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    _touch(elsewhere / "creds")
    _touch(elsewhere / "gcloud" / "application_default_credentials.json")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(elsewhere / "creds"))
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(elsewhere / "gcloud"))
    assert links.detected_login_files("aws") == [str(elsewhere / "creds")]
    assert links.detected_login_files("gcp") == [str(elsewhere / "gcloud" / "application_default_credentials.json")]


def test_connect_card_names_no_repository_relative_paths(home: Path) -> None:
    from click.testing import CliRunner

    from agent_bom.cli import main

    _touch(home / ".azure/azureProfile.json")
    for provider in ("aws", "azure", "gcp", "snowflake"):
        result = CliRunner().invoke(main, ["connect", provider], env={"COLUMNS": "400"})
        assert result.exit_code == 0, result.output
        assert "terraform -chdir=" not in result.output
        assert "(see scripts/" not in result.output
        assert "-f scripts/" not in result.output
    azure = CliRunner().invoke(main, ["connect", "azure"], env={"COLUMNS": "400"}).output
    assert "Credentials detected: ~/.azure/azureProfile.json (not verified)" in azure
