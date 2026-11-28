from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from scripts.deploy.mint_hosted_admin_key import main, mint_admin_key, write_raw_key_file


@pytest.fixture(autouse=True)
def isolated_key_store(monkeypatch: pytest.MonkeyPatch):
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    try:
        yield store
    finally:
        set_key_store(original)


def test_mint_hosted_admin_key_persists_admin_record(isolated_key_store: KeyStore) -> None:
    payload = mint_admin_key(
        tenant_id="customer-0",
        name="customer-0-admin",
        allow_inmemory=True,
    )

    verified = isolated_key_store.verify(payload.raw_key)
    assert verified is not None
    assert verified.role.value == "admin"
    assert verified.tenant_id == "customer-0"
    assert verified.scopes == ["*"]
    assert payload.raw_key != payload.metadata["key_prefix"]


def test_mint_hosted_admin_key_requires_persistent_store_without_test_escape() -> None:
    with pytest.raises(RuntimeError, match="AGENT_BOM_POSTGRES_URL"):
        mint_admin_key(tenant_id="customer-0", name="customer-0-admin")


def test_cli_writes_one_time_raw_key_to_private_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"

    assert (
        main(
            [
                "--tenant-id",
                "tenant-a",
                "--name",
                "admin",
                "--allow-inmemory",
                "--raw-key-file",
                str(raw_key_file),
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["tenant_id"] == "tenant-a"
    assert payload["role"] == "admin"
    assert "raw_key" not in payload
    assert payload["raw_key_file"] == str(raw_key_file)
    raw_key = raw_key_file.read_text(encoding="utf-8").strip()
    assert raw_key.startswith("abom_")
    assert stat.S_IMODE(raw_key_file.stat().st_mode) == 0o600
    assert os.environ.get("AGENT_BOM_POSTGRES_URL") is None


def test_cli_refuses_to_overwrite_raw_key_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"
    raw_key_file.write_text("existing\n", encoding="utf-8")

    assert (
        main(
            [
                "--tenant-id",
                "tenant-a",
                "--name",
                "admin",
                "--allow-inmemory",
                "--raw-key-file",
                str(raw_key_file),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "raw key file already exists" in captured.err
    assert raw_key_file.read_text(encoding="utf-8") == "existing\n"


def test_write_raw_key_file_force_overwrites_private_file(tmp_path: Path) -> None:
    raw_key_file = tmp_path / "customer0-admin.key"
    raw_key_file.write_text("existing\n", encoding="utf-8")

    write_raw_key_file(raw_key_file, "abom_new-key", force=True)

    assert raw_key_file.read_text(encoding="utf-8") == "abom_new-key\n"
    assert stat.S_IMODE(raw_key_file.stat().st_mode) == 0o600


def test_packaged_command_mints_through_the_installed_cli(isolated_key_store: KeyStore, tmp_path: Path) -> None:
    """The runtime image ships the package, not scripts/; the bootstrap must be a CLI command."""
    from click.testing import CliRunner

    from agent_bom.cli import main as cli

    raw_key_file = tmp_path / "admin.key"
    result = CliRunner().invoke(
        cli, ["auth", "mint-admin-key", "--tenant-id", "tenant-b", "--name", "ops", "--allow-inmemory", "--raw-key-file", str(raw_key_file)]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["tenant_id"] == "tenant-b" and payload["role"] == "admin"
    raw_key = raw_key_file.read_text(encoding="utf-8").strip()
    assert raw_key not in result.output
    assert stat.S_IMODE(raw_key_file.stat().st_mode) == 0o600
    assert isolated_key_store.verify(raw_key) is not None


def test_packaged_command_fails_closed_without_a_persistent_store(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from agent_bom.cli import main as cli

    result = CliRunner().invoke(cli, ["auth", "mint-admin-key", "--raw-key-file", str(tmp_path / "k")])
    assert result.exit_code == 1
    assert "check server logs and bootstrap configuration" in result.stderr
    assert not (tmp_path / "k").exists()


class _TenantScopedStore:
    """Mimics the Postgres store: writes need the tenant bound, and a fresh tenant must be provisioned."""

    def __init__(self, provisioned: set[str]) -> None:
        self.provisioned = provisioned
        self.calls: list[tuple[str, str, str]] = []

    def _bound(self) -> str:
        from agent_bom.api.postgres_common import _current_tenant

        return _current_tenant.get()

    def add(self, key) -> None:
        from agent_bom.api.api_key_record import TenantNotProvisionedError

        self.calls.append(("add", key.tenant_id, self._bound()))
        if key.tenant_id not in self.provisioned:
            raise TenantNotProvisionedError("Tenant is not provisioned")

    def provision_tenant_key(self, key, *, team_name: str) -> None:
        self.calls.append(("provision", key.tenant_id, self._bound()))
        self.provisioned.add(key.tenant_id)


@pytest.mark.parametrize("provisioned", [set(), {"customer-0"}])
def test_bootstrap_binds_the_tenant_and_provisions_a_fresh_one(monkeypatch: pytest.MonkeyPatch, provisioned: set[str]) -> None:
    """A fresh Postgres has no tenant row and enforces RLS on the bound tenant; both must be handled."""
    from agent_bom.api import admin_key_bootstrap
    from agent_bom.api.postgres_common import _current_tenant

    store = _TenantScopedStore(set(provisioned))
    monkeypatch.setattr(admin_key_bootstrap, "get_key_store", lambda: store)
    before = _current_tenant.get()

    admin_key_bootstrap.mint_admin_key(tenant_id="customer-0", name="admin", allow_inmemory=True)

    assert all(bound == "customer-0" for _, _, bound in store.calls)
    expected = [("add", "customer-0", "customer-0")] + ([] if provisioned else [("provision", "customer-0", "customer-0")])
    assert store.calls == expected
    assert _current_tenant.get() == before


def test_refused_key_file_never_mints_and_failed_mint_keeps_the_old_file(tmp_path, monkeypatch):
    import pytest

    from agent_bom.api import admin_key_bootstrap as bootstrap

    minted: list[str] = []

    def fake_mint(**kwargs):
        minted.append(kwargs["name"])
        return bootstrap.MintedAdminKey(raw_key="abom_fresh-key", metadata={"key_id": "k1"})

    monkeypatch.setattr(bootstrap, "mint_admin_key", fake_mint)
    existing = tmp_path / "k"
    existing.write_text("abom_old-key\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="raw key file already exists"):
        bootstrap.bootstrap_admin_key(tenant_id="t", name="refused", raw_key_file=existing)
    assert minted == []

    def failing_mint(**kwargs):
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(bootstrap, "mint_admin_key", failing_mint)
    with pytest.raises(RuntimeError, match="store unavailable"):
        bootstrap.bootstrap_admin_key(tenant_id="t", name="forced", raw_key_file=existing, force=True)
    assert existing.read_text(encoding="utf-8") == "abom_old-key\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["k"]

    monkeypatch.setattr(bootstrap, "mint_admin_key", fake_mint)
    payload = bootstrap.bootstrap_admin_key(tenant_id="t", name="forced", raw_key_file=existing, force=True)
    assert payload["raw_key_file"] == str(existing)
    assert existing.read_text(encoding="utf-8") == "abom_fresh-key\n"
    assert oct(existing.stat().st_mode & 0o777) == "0o600"
