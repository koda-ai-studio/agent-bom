"""`agent-bom check <pkg>` without a version checks the latest STABLE release.

Every ecosystem the check resolves (npm, PyPI, Maven, crates.io, Go) picks the
newest non-pre-release version. Only when a package has published nothing but
pre-releases does the newest pre-release get checked, and then the result says
so (``version_source="registry_latest_prerelease"``). When no registry answers
the result is honest about it (``version_source="unresolved"``) instead of
claiming a ``requested`` version of ``latest``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom import http_client, resolver, transitive
from agent_bom.cli import main
from agent_bom.models import Package
from agent_bom.resolvers.latest_stable import select_latest_stable


class _Response:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.content = json.dumps(payload or {}).encode()

    def json(self) -> Any:
        return self._payload


def _npm_latest(version: str) -> dict:
    return {"name": "lodash", "version": version, "license": "MIT"}


def _npm_packument(*versions: str, latest: str) -> dict:
    return {"name": "lodash", "dist-tags": {"latest": latest}, "versions": {v: {"version": v} for v in versions}}


def _maven_gav(*versions: str) -> dict:
    return {"response": {"docs": [{"g": "g", "a": "a", "v": v} for v in versions]}}


def _pypi(version: str) -> dict:
    return {"info": {"name": "requests", "version": version, "license": "Apache-2.0"}, "releases": {}}


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Fake registry: maps a URL substring to a response; records requested URLs."""
    routes: dict[str, Any] = {"_urls": []}
    scanned: list[Package] = []
    routes["_scanned"] = scanned

    async def _request(_client, _method, url, **kwargs):
        routes["_urls"].append(url)
        routes.setdefault("_headers", {})[url] = kwargs.get("headers") or {}
        for needle, response in routes.items():
            if not needle.startswith("_") and needle in url:
                return response
        return _Response(404, {})

    for module in (resolver, transitive):
        monkeypatch.setattr(module, "request_with_retry", _request)
    monkeypatch.setattr("agent_bom.version_utils.request_with_retry", _request)
    resolver._NPM_LATEST_CACHE.clear()
    resolver._PYPI_INFO_CACHE.clear()
    transitive._npm_packument_cache.clear()
    http_client.reset_rate_limit_breaker()

    async def _scan_packages(pkgs, **_kwargs):
        for pkg in pkgs:
            pkg.vulnerabilities = []
            scanned.append(pkg)

    async def _published(*_args, **_kwargs) -> bool:
        return True

    async def _no_osv_name_lookup(*_args, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.cli._check_published.version_published", _published)
    monkeypatch.setattr("agent_bom.mcp_tools.check_lookup._query_osv_by_name", _no_osv_name_lookup)
    return routes


def _check(*args: str, output_format: str = "json"):  # "console" for human output
    return CliRunner().invoke(main, ["check", *args, "--format", output_format])


def _payload(result) -> dict:
    assert result.output, result.stderr if hasattr(result, "stderr") else result
    return json.loads(result.output)


# ── shared selection rule ───────────────────────────────────────────────────


def test_select_latest_stable_skips_newer_prerelease() -> None:
    release = select_latest_stable(["3.0.0-beta3", "2.25.3", "2.25.2", "2.24.0"], "maven")
    assert release is not None
    assert (release.version, release.is_prerelease) == ("2.25.3", False)


def test_select_latest_stable_orders_by_ecosystem_rules_not_input_order() -> None:
    release = select_latest_stable(["4.17.21", "4.18.1", "5.0.0-alpha.1", "4.9.0"], "npm")
    assert release is not None
    assert release.version == "4.18.1"


def test_select_latest_stable_falls_back_to_newest_prerelease_and_flags_it() -> None:
    release = select_latest_stable(["1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-beta.9"], "npm")
    assert release is not None
    assert (release.version, release.is_prerelease) == ("1.0.0-rc.2", True)


def test_select_latest_stable_empty_is_none() -> None:
    assert select_latest_stable([], "pypi") is None
    assert select_latest_stable(["", "  "], "pypi") is None


# ── npm ─────────────────────────────────────────────────────────────────────


def test_npm_dist_tag_latest_is_the_stable_release(registry: dict[str, Any]) -> None:
    registry["registry.npmjs.org/lodash/latest"] = _Response(200, _npm_latest("4.18.1"))

    result = _check("lodash", "--ecosystem", "npm")

    assert result.exit_code == 0, result.output
    payload = _payload(result)
    assert (payload["version"], payload["version_source"]) == ("4.18.1", "registry_latest")
    assert payload["canonical_verdict"] == "clean"
    assert [p.version for p in registry["_scanned"]] == ["4.18.1"]
    # One small /latest document is enough; the full packument is not fetched.
    assert not any(url.endswith("/lodash") for url in registry["_urls"])


def test_npm_prerelease_latest_tag_falls_back_to_newest_stable_version(registry: dict[str, Any]) -> None:
    registry["registry.npmjs.org/lodash/latest"] = _Response(200, _npm_latest("5.0.0-beta.1"))
    registry["registry.npmjs.org/lodash"] = _Response(200, _npm_packument("4.17.21", "4.18.1", "5.0.0-beta.1", latest="5.0.0-beta.1"))

    payload = _payload(_check("lodash", "--ecosystem", "npm"))

    assert (payload["version"], payload["version_source"]) == ("4.18.1", "registry_latest")


def test_npm_only_prereleases_checks_newest_and_flags_it(registry: dict[str, Any]) -> None:
    registry["registry.npmjs.org/lodash/latest"] = _Response(200, _npm_latest("1.0.0-beta.2"))
    registry["registry.npmjs.org/lodash"] = _Response(200, _npm_packument("1.0.0-beta.1", "1.0.0-beta.2", latest="1.0.0-beta.2"))

    result = _check("lodash", "--ecosystem", "npm")

    assert result.exit_code == 0, result.output
    payload = _payload(result)
    assert (payload["version"], payload["version_source"]) == ("1.0.0-beta.2", "registry_latest_prerelease")


def test_npm_only_prereleases_text_output_says_so(registry: dict[str, Any]) -> None:
    registry["registry.npmjs.org/lodash/latest"] = _Response(200, _npm_latest("1.0.0-beta.2"))
    registry["registry.npmjs.org/lodash"] = _Response(200, _npm_packument("1.0.0-beta.2", latest="1.0.0-beta.2"))

    result = _check("lodash", "--ecosystem", "npm", output_format="console")

    assert result.exit_code == 0, result.output
    assert "1.0.0-beta.2" in result.output
    assert "pre-release; no stable release published" in result.output


# ── maven ───────────────────────────────────────────────────────────────────


def test_maven_skips_newer_prerelease_for_latest_stable(registry: dict[str, Any]) -> None:
    registry["core=gav"] = _Response(200, _maven_gav("3.0.0-beta3", "2.25.3", "2.25.2", "2.24.3"))

    payload = _payload(_check("org.apache.logging.log4j:log4j-core", "--ecosystem", "maven"))

    assert (payload["version"], payload["version_source"]) == ("2.25.3", "registry_latest")
    assert [p.version for p in registry["_scanned"]] == ["2.25.3"]


def test_maven_only_prereleases_is_flagged(registry: dict[str, Any]) -> None:
    # Maven orders qualifiers alpha < beta < milestone < rc, so RC2 is the newest here.
    registry["core=gav"] = _Response(200, _maven_gav("1.0.0-RC2", "1.0.0-RC1", "1.0.0-M1", "1.0.0-beta-2"))

    payload = _payload(_check("org.example:preview-only", "--ecosystem", "maven"))

    assert (payload["version"], payload["version_source"]) == ("1.0.0-RC2", "registry_latest_prerelease")


# ── cargo ───────────────────────────────────────────────────────────────────


def test_cargo_prefers_max_stable_version_and_identifies_itself(registry: dict[str, Any]) -> None:
    crate = {
        "crate": {"newest_version": "2.0.0-alpha.1", "max_version": "2.0.0-alpha.1", "max_stable_version": "1.0.219", "license": "MIT"}
    }
    registry["crates.io/api/v1/crates/serde"] = _Response(200, crate)

    payload = _payload(_check("serde", "--ecosystem", "cargo"))

    assert (payload["version"], payload["version_source"]) == ("1.0.219", "registry_latest")
    crate_urls = [url for url in registry["_urls"] if "crates.io" in url]
    assert crate_urls and registry["_headers"][crate_urls[0]].get("User-Agent", "").startswith("agent-bom/")


def test_maven_without_version_list_trusts_only_a_stable_latest_version(registry: dict[str, Any]) -> None:
    registry["rows=1&"] = _Response(200, {"response": {"docs": [{"latestVersion": "2.25.3"}]}})

    payload = _payload(_check("org.apache.logging.log4j:log4j-core", "--ecosystem", "maven"))

    assert (payload["version"], payload["version_source"]) == ("2.25.3", "registry_latest")


def test_maven_without_version_list_does_not_call_a_prerelease_the_only_release(registry: dict[str, Any]) -> None:
    registry["rows=1&"] = _Response(200, {"response": {"docs": [{"latestVersion": "3.0.0-beta3"}]}})

    result = _check("org.apache.logging.log4j:log4j-core", "--ecosystem", "maven")

    assert result.exit_code == 2, result.output
    payload = _payload(result)
    assert (payload["canonical_verdict"], payload["version_source"]) == ("incomplete", "unresolved")
    assert registry["_scanned"] == []


# ── pypi ────────────────────────────────────────────────────────────────────


def test_pypi_latest_stays_the_stable_release(registry: dict[str, Any]) -> None:
    registry["pypi.org/pypi/requests/json"] = _Response(200, _pypi("2.34.2"))

    payload = _payload(_check("requests", "--ecosystem", "pypi"))

    assert (payload["version"], payload["version_source"]) == ("2.34.2", "registry_latest")


def test_pypi_prerelease_only_project_is_flagged(registry: dict[str, Any]) -> None:
    registry["pypi.org/pypi/requests/json"] = _Response(200, _pypi("3.0.0rc1"))

    payload = _payload(_check("requests", "--ecosystem", "pypi"))

    assert (payload["version"], payload["version_source"]) == ("3.0.0rc1", "registry_latest_prerelease")


# ── failure path ────────────────────────────────────────────────────────────


def test_unreachable_registry_is_honest_about_resolving_nothing(registry: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    async def _down(*_args, **_kwargs):
        return None

    for module in (resolver, transitive):
        monkeypatch.setattr(module, "request_with_retry", _down)
    monkeypatch.setattr("agent_bom.version_utils.request_with_retry", _down)

    result = _check("lodash", "--ecosystem", "npm")

    assert result.exit_code == 2, result.output
    payload = _payload(result)
    assert payload["canonical_verdict"] == "incomplete"
    assert payload["version_source"] == "unresolved"
    assert payload["version_source"] != "requested"
    assert registry["_scanned"] == []
