"""Cargo workspace/path members are first-party code, never registry packages."""

from __future__ import annotations

from agent_bom.parsers.compiled_parsers import parse_cargo_packages

_REG = 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "c" * 64 + '"\n'

LOCK = (
    "version = 3\n"
    '[[package]]\nname = "core-lib"\nversion = "0.2.0"\ndependencies = ["serde"]\n'
    '[[package]]\nname = "cli"\nversion = "0.1.0"\ndependencies = ["core-lib", "clap"]\n'
    '[[package]]\nname = "vendored-helper"\nversion = "0.0.1"\n'
    f'[[package]]\nname = "serde"\nversion = "1.0.200"\n{_REG}'
    f'[[package]]\nname = "clap"\nversion = "4.5.4"\n{_REG}dependencies = ["clap_builder"]\n'
    f'[[package]]\nname = "clap_builder"\nversion = "4.5.2"\n{_REG}'
)


def _workspace(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\n[workspace.dependencies]\nserde = "1.0"\n')
    (tmp_path / "Cargo.lock").write_text(LOCK)
    for name, deps in (("core-lib", "serde = { workspace = true }\n"), ("cli", 'core-lib = { path = "../core-lib" }\nclap = "4"\n')):
        member = tmp_path / "crates" / name
        member.mkdir(parents=True)
        (member / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n[dependencies]\n{deps}')
    return tmp_path


def test_sourceless_lock_rows_are_first_party_and_excluded(tmp_path):
    packages = {p.name: p for p in parse_cargo_packages(_workspace(tmp_path))}
    assert set(packages) == {"serde", "clap", "clap_builder"}
    assert all(p.purl == f"pkg:cargo/{p.name}@{p.version}" for p in packages.values())


def test_registry_crates_used_by_members_are_direct(tmp_path):
    packages = {p.name: p for p in parse_cargo_packages(_workspace(tmp_path))}
    assert packages["serde"].is_direct is True
    assert packages["clap"].is_direct is True
    assert packages["clap_builder"].is_direct is False
    assert packages["clap_builder"].parent_package == "clap"


def test_member_manifest_under_locked_workspace_uses_lock_versions(tmp_path):
    root = _workspace(tmp_path)
    packages = {p.name: p.version for p in parse_cargo_packages(root / "crates" / "cli")}
    assert packages == {"serde": "1.0.200", "clap": "4.5.4", "clap_builder": "4.5.2"}


def test_member_manifest_without_owning_lock_keeps_declaration_fallback(tmp_path):
    member = tmp_path / "crates" / "solo"
    member.mkdir(parents=True)
    (member / "Cargo.toml").write_text('[package]\nname = "solo"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0"\n')
    (tmp_path / "Cargo.lock").write_text(LOCK)
    packages = parse_cargo_packages(member)
    assert [(p.name, p.version, p.version_source) for p in packages] == [("serde", "1.0", "manifest")]
