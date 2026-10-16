"""Case-sensitive package coordinates must not match another module/artifact."""

import json

import pytest

from agent_bom.canonical_ids import canonical_package_id
from agent_bom.core.packages import canonical_package_key, normalize_package_name
from agent_bom.db.lookup import lookup_package, lookup_packages_batch
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file
from agent_bom.models import Package
from agent_bom.scanners.osv import osv_query_names
from agent_bom.scanners.package_scan import _is_version_affected


@pytest.mark.parametrize(
    "ecosystem,name,other,purl",
    [
        ("Go", "example.com/Team/Module", "example.com/team/module", "pkg:golang/example.com/Team/Module@1.0.0"),
        ("Maven", "org.example:Client", "org.example:client", "pkg:maven/org.example/Client@1.0.0"),
    ],
)
def test_case_sensitive_coordinates_keep_identity_and_matching_scope(tmp_path, ecosystem, name, other, purl):
    assert canonical_package_key(name, "1.0.0", ecosystem) != canonical_package_key(other, "1.0.0", ecosystem)
    assert canonical_package_id(name, "1.0.0", ecosystem) != canonical_package_id(other, "1.0.0", ecosystem)
    assert canonical_package_id(name, "1.0.0", ecosystem, purl) == canonical_package_id(name, "1.0.0", ecosystem)
    assert canonical_package_key(name, "1.0.0", ecosystem, purl) == canonical_package_key(name, "1.0.0", ecosystem)
    data = {
        "id": "OSV-CASE-TEST",
        "summary": "case fixture",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }
    assert _is_version_affected(data, name, "1.0.0", ecosystem)
    assert not _is_version_affected(data, other, "1.0.0", ecosystem)
    conn = init_db(tmp_path / "case.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        assert lookup_package(conn, ecosystem, name, "1.0.0")
        assert not lookup_package(conn, ecosystem, other, "1.0.0")
        query = [(ecosystem, normalize_package_name(n, ecosystem), "1.0.0") for n in (name, other)]
        result = lookup_packages_batch(conn, query)
        assert result[query[0]] and not result[query[1]]
    finally:
        conn.close()
    assert osv_query_names(Package(name=name, version="1.0.0", ecosystem=ecosystem.lower())) == [name]


def test_maven_purl_spelling_queries_osv_native_coordinates():
    assert osv_query_names(Package(name="org.example/Client", version="1.0.0", ecosystem="maven")) == ["org.example:Client"]


@pytest.mark.parametrize(
    "ecosystem,name,expected",
    [("pypi", "Some_Pkg", "some-pkg"), ("nuget", "System.Text.Json", "system.text.json"), ("npm", "Some-Pkg", "some-pkg")],
)
def test_case_insensitive_ecosystems_keep_their_own_normalization(ecosystem, name, expected):
    assert normalize_package_name(name, ecosystem) == expected


@pytest.mark.parametrize(
    "ecosystem,name,old_name",
    [("go", "example.com/Team/Module", "example.com/team/module"), ("maven", "org.example/Client", "org.example:client")],
)
def test_lossy_legacy_coordinates_are_only_unverified_candidates(tmp_path, ecosystem, name, old_name):
    from agent_bom.db.lookup import package_in_db, package_in_db_batch

    conn = init_db(tmp_path / "old-case.db")
    try:
        conn.execute("INSERT INTO vulns (id, summary, severity, source) VALUES ('old-case', 'legacy receipt', 'high', 'osv')")
        conn.execute(
            "INSERT INTO affected (vuln_id,ecosystem,package_name,introduced,fixed,last_affected,limit_version) VALUES (?,?,?,?,?,?,?)",
            ("old-case", ecosystem, old_name, "0", "2.0.0", "", None),
        )
        single = lookup_package(conn, ecosystem, name, "1.0.0")
        batch = lookup_packages_batch(conn, [(ecosystem, name, "1.0.0")])[(ecosystem, name, "1.0.0")]
        assert [item.id for item in single] == [item.id for item in batch] == ["old-case"]
        assert all(item.match_confidence_tier == "unverified_range" and item.fixed_version is None for item in single + batch)
        assert not package_in_db(conn, ecosystem, name)
        assert not package_in_db_batch(conn, [(ecosystem, name)])
        # A freshly imported differently-cased coordinate cannot borrow that legacy ambiguity.
        conn.execute("UPDATE affected SET limit_version = ''")
        assert not lookup_package(conn, ecosystem, name, "1.0.0")
        assert not lookup_packages_batch(conn, [(ecosystem, name, "1.0.0")])[(ecosystem, name, "1.0.0")]
    finally:
        conn.close()


def test_native_maven_coordinates_agree_in_single_batch_and_presence(tmp_path):
    from agent_bom.db.lookup import package_in_db, package_in_db_batch

    query = ("Maven", "org.example:Client", "1.0.0")
    data = {
        "id": "OSV-NATIVE",
        "summary": "native coordinate fixture",
        "affected": [
            {
                "package": {"ecosystem": query[0], "name": query[1]},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }
    conn = init_db(tmp_path / "native.db")
    try:
        _ingest_osv_file(conn, json.dumps(data).encode(), "fixture.json")
        assert (
            [item.id for item in lookup_packages_batch(conn, [query])[query]]
            == [item.id for item in lookup_package(conn, *query)]
            == ["OSV-NATIVE"]
        )
        assert package_in_db(conn, *query[:2])
        assert package_in_db_batch(conn, [query[:2]]) == {("maven", "org.example/Client")}
    finally:
        conn.close()
