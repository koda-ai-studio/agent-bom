"""The indexed advisory matcher returns exactly what the exhaustive walk returns, faster.

``match_advisories_against_reports`` used to try every advisory against every
package occurrence. The re-match job hands it up to ``MAX_FEED_ADVISORIES``
feed records per tenant, so the walk is now a per-run index keyed by package
identity and CPE product. These tests pin that the index is an optimisation
only: same rows, same order, same findings as the straightforward loop.
"""

from __future__ import annotations

import random
import time
from typing import Any

import pytest

from agent_bom.scanners import operator_advisory as oa
from agent_bom.scanners.operator_advisory import (
    AdvisoryMatchResult,
    AffectedProduct,
    FeedAffectedRange,
    OperatorAdvisory,
    iter_report_packages,
    match_advisories_against_reports,
)

_ECOSYSTEMS = ("pypi", "npm", "deb")
_NAMES = ("alpha", "beta", "gamma", "delta", "php8.2-cli", "php", "left-pad")
_VERSIONS = ("0.9", "1.0", "1.5", "2.0", "2.1", "8.3.30", "8.3.36", "2.0-1ubuntu1")
_FEED_IDS = ("CVE-2026-0001", "CVE-2026-0002", "GHSA-aaaa-bbbb-cccc")


def _reference(advisories: list[OperatorAdvisory], reports: list[dict[str, Any]], **kwargs: Any) -> AdvisoryMatchResult:
    """The exhaustive loop the index replaced, over the module's own per-advisory matcher."""
    result = AdvisoryMatchResult()
    for report in reports:
        result.reports_examined += 1
        observed = report.get("scan_completed_at")
        ctx = oa._ReportContext(
            str(report.get("scan_id") or ""),
            str(observed) if observed else None,
            kwargs.get("provenance", oa.OPERATOR_ADVISORY_PROVENANCE),
            kwargs.get("distro_verdict"),
        )
        for asset, package, owners in iter_report_packages(report):
            result.packages_examined += 1
            result.assets_examined.add((ctx.scan_id, asset["agent"], asset["server"]))
            occurrence = oa._Occurrence(asset, package, owners, ctx)
            for advisory in advisories:
                oa._match_package(advisory, occurrence, result)
    return result


def _product(rng: random.Random) -> AffectedProduct:
    kind = rng.random()
    ranges = [FeedAffectedRange.model_construct(introduced="0", fixed=rng.choice(_VERSIONS), last_affected=None, limit_version="")]
    if kind < 0.2:
        return AffectedProduct.model_construct(ecosystem=None, name=None, cpe_product="php:php", ranges=ranges, versions=[])
    if kind < 0.3:
        return AffectedProduct.model_construct(ecosystem=None, name=None, cpe_product="acme:widget", ranges=[], versions=["1.0", "2.0"])
    ecosystem = rng.choice(_ECOSYSTEMS + ("PyPI", "NPM"))
    name = rng.choice(_NAMES + ("Alpha",))
    if kind < 0.4:
        return AffectedProduct.model_construct(
            ecosystem=ecosystem, name=name, cpe_product=None, ranges=[], versions=[rng.choice(_VERSIONS)]
        )
    return AffectedProduct.model_construct(ecosystem=ecosystem, name=name, cpe_product=None, ranges=ranges, versions=[])


def _advisory(rng: random.Random, index: int) -> OperatorAdvisory:
    aliases = [rng.choice(_FEED_IDS)] if rng.random() < 0.3 else []
    return OperatorAdvisory.model_construct(
        id=f"OPS-{index:04d}",
        aliases=aliases,
        summary="randomised",
        severity=rng.choice(["critical", "high", "medium", "low"]),
        published_at=None,
        references=[],
        affected=[_product(rng) for _ in range(rng.randint(1, 3))],
    )


def _package(rng: random.Random) -> dict[str, Any]:
    package: dict[str, Any] = {"name": rng.choice(_NAMES), "version": rng.choice(_VERSIONS), "ecosystem": rng.choice(_ECOSYSTEMS)}
    if rng.random() < 0.2:
        package["cpe"] = f"cpe:2.3:a:php:php:{package['version']}:*:*:*:*:*:*:*"
    if rng.random() < 0.3:
        package["vulnerabilities"] = [{"id": rng.choice(_FEED_IDS), "fixed_version": rng.choice(_VERSIONS)}]
    if rng.random() < 0.1:
        package["source_package"] = "php8.2"
    return package


def _report(rng: random.Random, index: int) -> dict[str, Any]:
    agents = []
    for a in range(rng.randint(1, 2)):
        servers = []
        for s in range(rng.randint(1, 2)):
            packages: list[Any] = [_package(rng) for _ in range(rng.randint(0, 4))]
            if rng.random() < 0.2:
                packages.append({"name": "", "version": "1.0"})  # skipped by every walker
            servers.append({"name": f"srv-{s}", "packages": packages})
        agents.append({"name": f"agent-{a}", "mcp_servers": servers})
    return {"scan_id": f"scan-{index}", "scan_completed_at": "2026-10-01T00:00:00+00:00", "agents": agents}


def _verdict(identifiers: set[str], package: dict[str, Any]) -> Any:
    return None


@pytest.mark.parametrize("seed", range(40))
def test_indexed_matching_equals_the_exhaustive_walk(seed: int) -> None:
    rng = random.Random(seed)
    advisories = [_advisory(rng, i) for i in range(rng.randint(0, 12))]
    reports = [_report(rng, i) for i in range(rng.randint(0, 4))]
    kwargs: dict[str, Any] = {"provenance": rng.choice(["operator_advisory", "feed"])}
    if rng.random() < 0.5:
        kwargs["distro_verdict"] = _verdict

    indexed = match_advisories_against_reports(advisories, reports, **kwargs)
    expected = _reference(advisories, reports, **kwargs)

    assert indexed.to_dict() == expected.to_dict()
    assert indexed.rows == expected.rows
    assert indexed.assets_examined == expected.assets_examined


def test_matching_5000_packages_against_2000_advisories_is_fast() -> None:
    rng = random.Random(7)
    advisories = [
        OperatorAdvisory.model_construct(
            id=f"CVE-2026-{i:05d}",
            aliases=[],
            summary="bench",
            severity="high",
            published_at=None,
            references=[],
            affected=[
                AffectedProduct.model_construct(
                    ecosystem=rng.choice(("PyPI", "npm", "Go")),
                    name=f"pkg-{rng.randrange(1500)}",
                    cpe_product=None,
                    ranges=[
                        FeedAffectedRange.model_construct(
                            introduced="0", fixed=f"{rng.randrange(1, 9)}.0.0", last_affected=None, limit_version=""
                        )
                    ],
                    versions=[],
                )
            ],
        )
        for i in range(2000)
    ]
    packages = [
        {
            "name": f"pkg-{rng.randrange(1500)}",
            "version": f"{rng.randrange(1, 9)}.{rng.randrange(10)}.0",
            "ecosystem": rng.choice(("pypi", "npm", "go")),
        }
        for _ in range(5000)
    ]
    reports = [
        {
            "scan_id": f"scan-{i}",
            "agents": [{"name": "host", "mcp_servers": [{"name": "srv", "packages": packages[i * 500 : (i + 1) * 500]}]}],
        }
        for i in range(10)
    ]

    started = time.perf_counter()
    result = match_advisories_against_reports(advisories, reports, provenance="feed")
    elapsed = time.perf_counter() - started

    assert result.packages_examined == 5000
    assert result.rows, "the benchmark inputs are built to overlap"
    assert elapsed < 2.0, f"matching took {elapsed:.2f}s"
