"""Every pnpm YAML document contributes inventory and rooted dependency edges."""

from agent_bom.parsers.node_parsers import parse_pnpm_lock
from agent_bom.scanners.state import capture_coverage_warnings


def test_two_lock_documents_preserve_both_dependency_trees(tmp_path):
    doc = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      ROOT: {specifier: '1.0.0', version: '1.0.0'}
packages:
  ROOT@1.0.0: {}
  CHILD@2.0.0: {}
snapshots:
  ROOT@1.0.0:
    dependencies: {CHILD: '2.0.0'}
  CHILD@2.0.0: {}
"""
    first = doc.replace("ROOT", "first").replace("CHILD", "first-child")
    second = doc.replace("ROOT", "second").replace("CHILD", "second-child")
    (tmp_path / "pnpm-lock.yaml").write_text("---\n" + first + "---\n" + second)
    with capture_coverage_warnings() as warnings:
        packages = {p.name: p for p in parse_pnpm_lock(tmp_path)}
    assert set(packages) == {"first", "first-child", "second", "second-child"}
    assert packages["first"].is_direct and packages["second"].is_direct
    assert packages["first-child"].parent_package == "first"
    assert packages["second-child"].parent_package == "second"
    assert not warnings


def test_shared_package_retains_parents_from_each_document(tmp_path):
    doc = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      ROOT: {version: '1.0.0'}
packages:
  ROOT@1.0.0: {}
  shared@2.0.0: {}
snapshots:
  ROOT@1.0.0:
    dependencies: {shared: '2.0.0'}
  shared@2.0.0: {}
"""
    (tmp_path / "pnpm-lock.yaml").write_text(doc.replace("ROOT", "first") + "---\n" + doc.replace("ROOT", "second"))
    packages = {p.name: p for p in parse_pnpm_lock(tmp_path)}
    parents = {p for e in packages["shared"].version_evidence for p in e.get("parent_stable_ids", [])}
    assert parents == {packages["first"].stable_id, packages["second"].stable_id}
    assert packages["shared"].parent_package is None
