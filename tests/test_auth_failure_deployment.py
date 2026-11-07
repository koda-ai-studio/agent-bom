"""Shipped profiles either identify clients behind a proxy or fail explicitly."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[1]
_CHART = _REPO / "deploy/helm/agent-bom"


def _preflight():
    spec = importlib.util.spec_from_file_location("abom_preflight_under_test", _REPO / "scripts/deploy/hosted_poc_preflight.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _helm(*args: str) -> subprocess.CompletedProcess:
    if shutil.which("helm") is None:
        pytest.skip("helm is not on PATH")
    return subprocess.run(["helm", "template", "release", str(_CHART), *args], capture_output=True, text=True)


def _api_env(rendered: str) -> dict[str, str]:
    for doc in yaml.safe_load_all(rendered):
        if isinstance(doc, dict) and doc.get("kind") == "Deployment" and doc["metadata"]["name"].endswith("-api"):
            container = doc["spec"]["template"]["spec"]["containers"][0]
            return {entry["name"]: entry.get("value", "") for entry in container.get("env", [])}
    raise AssertionError("no API deployment rendered")


_PLANE = ("--set", "controlPlane.enabled=true", "--set", "controlPlane.api.enabled=true", "--set", "controlPlane.migrations.enabled=false")
_INGRESS = (*_PLANE, "--set", "controlPlane.ingress.enabled=true")


def test_helm_ingress_without_proxy_settings_fails_with_the_setting_named():
    result = _helm(*_INGRESS)
    assert result.returncode != 0
    assert "controlPlane.api.trustedProxy" in result.stderr


def test_helm_ingress_with_proxy_settings_reaches_the_api_pod():
    result = _helm(
        *_INGRESS, "--set", "controlPlane.api.trustedProxy.hops=1", "--set", "controlPlane.api.trustedProxy.cidrs={10.1.0.0/16,10.2.0.0/16}"
    )
    assert result.returncode == 0, result.stderr
    env = _api_env(result.stdout)
    assert env["AGENT_BOM_TRUSTED_PROXY_HOPS"] == "1"
    assert env["AGENT_BOM_TRUSTED_PROXY_CIDRS"] == "10.1.0.0/16,10.2.0.0/16"


def test_helm_shared_source_can_be_accepted_explicitly():
    result = _helm(*_INGRESS, "--set", "controlPlane.api.trustedProxy.sharedSourceAccepted=true")
    assert result.returncode == 0, result.stderr
    assert "AGENT_BOM_TRUSTED_PROXY_HOPS" not in _api_env(result.stdout)


def test_helm_settings_supplied_by_a_secret_render_no_conflicting_values():
    result = _helm(*_INGRESS, "--set", "controlPlane.api.trustedProxy.fromSecret=true")
    assert result.returncode == 0, result.stderr
    assert "AGENT_BOM_TRUSTED_PROXY_CIDRS" not in _api_env(result.stdout)


def test_helm_settings_supplied_through_env_are_honoured():
    result = _helm(
        *_INGRESS,
        "--set",
        "controlPlane.api.env[0].name=AGENT_BOM_TRUSTED_PROXY_HOPS,controlPlane.api.env[0].value=1",
        "--set",
        "controlPlane.api.env[1].name=AGENT_BOM_TRUSTED_PROXY_CIDRS,controlPlane.api.env[1].value=10.0.0.0/8",
    )
    assert result.returncode == 0, result.stderr


def test_helm_without_ingress_needs_no_proxy_settings():
    result = _helm(*_PLANE)
    assert result.returncode == 0, result.stderr


def test_every_shipped_ingress_example_declares_trusted_proxies():
    examples = sorted((_CHART / "examples").glob("*-values.yaml"))
    assert examples
    declared = 0
    for path in examples:
        values = yaml.safe_load(path.read_text()) or {}
        plane = values.get("controlPlane") or {}
        if (plane.get("ingress") or {}).get("enabled"):
            trusted = (plane.get("api") or {}).get("trustedProxy") or {}
            assert (trusted.get("hops") and trusted.get("cidrs")) or trusted.get("fromSecret"), path.name
            declared += 1
    assert declared >= 1


def _service(path: str, name: str) -> dict:
    return yaml.safe_load((_REPO / "deploy" / path).read_text())["services"][name]


def test_hosted_overlay_sets_trusted_proxies():
    environment = _service("docker-compose.hosted-poc.yml", "api")["environment"]
    joined = "\n".join(environment)
    assert "AGENT_BOM_TRUSTED_PROXY_HOPS=${AGENT_BOM_TRUSTED_PROXY_HOPS:-1}" in joined
    assert "AGENT_BOM_TRUSTED_PROXY_CIDRS=${AGENT_BOM_TRUSTED_PROXY_CIDRS:-172.16.0.0/12,192.168.0.0/16}" in joined


@pytest.mark.parametrize("compose", ["docker-compose.platform.yml", "docker-compose.fullstack.yml"])
def test_base_profiles_pass_proxy_settings_through(compose):
    assert "AGENT_BOM_TRUSTED_PROXY_HOPS" in str(_service(compose, "api")["environment"])
    assert "AGENT_BOM_TRUSTED_PROXY_CIDRS" in str(_service(compose, "api")["environment"])


def _compose_config_with(hops: str, cidrs: str) -> list[str]:
    errors: list[str] = []
    _preflight()._validate_compose_config(errors, f"AGENT_BOM_TRUSTED_PROXY_HOPS: {hops}\nAGENT_BOM_TRUSTED_PROXY_CIDRS: {cidrs}\n")
    return [error for error in errors if "TRUSTED_PROXY" in error]


def test_hosted_preflight_rejects_missing_proxy_settings():
    assert _compose_config_with('""', '""')
    assert not _compose_config_with('"1"', '"10.0.0.0/8"')


# Secret files


def test_secrets_are_not_world_readable_and_can_reach_the_group(tmp_path, monkeypatch):
    preflight = _preflight()
    monkeypatch.setattr(preflight, "_secrets_dir", lambda _root: tmp_path)
    preflight._write_secret_files(tmp_path, force=False)
    names = (*preflight.REQUIRED_SECRET_FILES, *preflight.OPTIONAL_SECRET_FILES)
    assert names
    for name in names:
        info = (tmp_path / name).stat()
        assert stat.S_IMODE(info.st_mode) == 0o640, name
        assert info.st_gid == os.getgid()


def test_existing_world_readable_secrets_are_tightened_and_kept(tmp_path, monkeypatch):
    preflight = _preflight()
    monkeypatch.setattr(preflight, "_secrets_dir", lambda _root: tmp_path)
    existing = tmp_path / preflight.REQUIRED_SECRET_FILES[0]
    existing.write_text("kept")
    existing.chmod(0o644)
    preflight._write_secret_files(tmp_path, force=False)
    assert existing.read_text() == "kept"
    assert stat.S_IMODE(existing.stat().st_mode) == 0o640


def test_secret_file_symlink_is_refused(tmp_path, monkeypatch):
    preflight = _preflight()
    monkeypatch.setattr(preflight, "_secrets_dir", lambda _root: tmp_path)
    target = tmp_path / "elsewhere"
    target.write_text("x")
    (tmp_path / preflight.REQUIRED_SECRET_FILES[0]).symlink_to(target)
    with pytest.raises(ValueError):
        preflight._write_secret_files(tmp_path, force=False)


@pytest.mark.parametrize("compose", ["docker-compose.platform.yml", "docker-compose.fullstack.yml"])
@pytest.mark.parametrize("service", ["postgres", "migrate", "api"])
def test_services_reading_secrets_join_the_secrets_group(compose, service):
    definition = _service(compose, service)
    assert definition.get("secrets"), "service reads no secrets"
    assert definition["group_add"] == ["${AGENT_BOM_SECRETS_GID:-65534}"]


@pytest.mark.parametrize("compose", ["docker-compose.platform.yml", "docker-compose.fullstack.yml"])
def test_postgres_starts_as_its_own_user_so_it_keeps_the_group(compose):
    assert _service(compose, "postgres")["user"] == "postgres"


def test_make_targets_pass_the_operator_group():
    makefile = (_REPO / "Makefile").read_text()
    assert "AGENT_BOM_SECRETS_GID=$$(id -g) docker compose -f deploy/docker-compose.platform.yml" in makefile
    assert "AGENT_BOM_SECRETS_GID=$$(id -g) docker compose -f deploy/docker-compose.fullstack.yml" in makefile
