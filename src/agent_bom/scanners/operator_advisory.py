"""Operator-declared advisories matched against stored inventory.

An emergency advisory lets an operator act on a disclosure before any feed
publishes it. Matching never rescans: it reads the packages already recorded in
stored scan reports and applies the shared ecosystem version comparators.

Precedence and honesty rules:

- Findings carry ``provenance = "operator_advisory"`` so they are never
  confused with feed-sourced records.
- When a stored package already carries a feed record whose id or alias equals
  the advisory id or one of its aliases, the feed record wins; the operator
  advisory is reported as ``superseded`` (an alias of the feed id), not a
  second finding.
- A version the comparator cannot order is ``indeterminate`` and makes the
  result incomplete; it is never reported as clean.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bom.core.versions import compare_version_order

OPERATOR_ADVISORY_PROVENANCE = "operator_advisory"
_ADVISORY_ID = re.compile(r"[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_CPE_PRODUCT = re.compile(r"[a-z0-9_.\-~%]{1,64}:[a-z0-9_.\-~%]{1,64}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+~_:\-]{0,63}")
_NAME = re.compile(r"[A-Za-z0-9@/._+:\-]{1,214}")


def _version(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not _VERSION.fullmatch(value):
        raise ValueError("version must be a plain version string")
    return value


class AffectedRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

    _check = field_validator("introduced", "fixed", "last_affected")(_version)

    @model_validator(mode="after")
    def _bounded(self) -> AffectedRange:
        if self.fixed and self.last_affected:
            raise ValueError("use fixed or last_affected, not both")
        return self


class AffectedProduct(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str | None = Field(default=None, max_length=32)
    name: str | None = Field(default=None, max_length=214)
    cpe_product: str | None = Field(default=None, description="CPE vendor:product, e.g. php:php")
    ranges: list[AffectedRange] = Field(default_factory=list, max_length=32)
    versions: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("cpe_product")
    @classmethod
    def _cpe(cls, value: str | None) -> str | None:
        if value is not None and not _CPE_PRODUCT.fullmatch(value.strip().lower()):
            raise ValueError("cpe_product must be vendor:product")
        return value.strip().lower() if value else None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        if value is not None and not _NAME.fullmatch(value.strip()):
            raise ValueError("invalid package name")
        return value.strip() if value else None

    @field_validator("versions")
    @classmethod
    def _versions(cls, values: list[str]) -> list[str]:
        return [v for v in (_version(item) for item in values) if v]

    @model_validator(mode="after")
    def _identity(self) -> AffectedProduct:
        if not self.cpe_product and not (self.ecosystem and self.name):
            raise ValueError("affected product needs ecosystem+name or cpe_product")
        if not self.ranges and not self.versions:
            raise ValueError("affected product needs ranges or versions")
        for item in self.ranges:
            if item.introduced and item.fixed:
                order = compare_version_order(item.introduced, item.fixed, (self.ecosystem or "generic").lower())
                if order is not None and order >= 0:
                    raise ValueError("introduced must precede fixed")
        return self


class OperatorAdvisory(BaseModel):
    """An advisory declared by the operator ahead of feed publication."""

    model_config = ConfigDict(extra="forbid")

    id: str
    aliases: list[str] = Field(default_factory=list, max_length=16)
    summary: str = Field(min_length=1, max_length=1000)
    severity: Literal["critical", "high", "medium", "low"]
    published_at: datetime | None = None
    references: list[str] = Field(default_factory=list, max_length=16)
    affected: list[AffectedProduct] = Field(min_length=1, max_length=64)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ADVISORY_ID.fullmatch(value.strip()):
            raise ValueError("id must look like CVE-YYYY-NNNN or PREFIX-ID")
        return value.strip()

    @field_validator("aliases")
    @classmethod
    def _aliases(cls, values: list[str]) -> list[str]:
        return [cls._id(value) for value in values]

    @field_validator("references")
    @classmethod
    def _references(cls, values: list[str]) -> list[str]:
        if any(not value.startswith("https://") or len(value) > 512 for value in values):
            raise ValueError("references must be https URLs")
        return values

    @property
    def identifiers(self) -> set[str]:
        return {self.id, *self.aliases}


@dataclass
class AdvisoryMatchResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    superseded: list[dict[str, Any]] = field(default_factory=list)
    indeterminate: list[dict[str, Any]] = field(default_factory=list)
    reports_examined: int = 0
    packages_examined: int = 0

    @property
    def complete(self) -> bool:
        return self.reports_examined > 0 and not self.indeterminate

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "superseded": self.superseded,
            "indeterminate": self.indeterminate,
            "reports_examined": self.reports_examined,
            "packages_examined": self.packages_examined,
            "complete": self.complete,
        }


def _cpe_product(package: dict[str, Any]) -> str | None:
    parts = str(package.get("cpe") or "").split(":")
    return f"{parts[3]}:{parts[4]}".lower() if len(parts) > 4 and parts[:2] == ["cpe", "2.3"] else None


def _identity_matches(product: AffectedProduct, package: dict[str, Any]) -> bool:
    if product.cpe_product and _cpe_product(package) == product.cpe_product:
        return True
    if not (product.ecosystem and product.name):
        return False
    return (
        str(package.get("ecosystem") or "").lower() == product.ecosystem.lower()
        and str(package.get("name") or "").lower() == product.name.lower()
    )


def _in_range(version: str, item: AffectedRange, ecosystem: str) -> bool | None:
    checks = []
    if item.introduced and item.introduced != "0":
        checks.append((item.introduced, lambda order: order >= 0))
    if item.fixed:
        checks.append((item.fixed, lambda order: order < 0))
    if item.last_affected:
        checks.append((item.last_affected, lambda order: order <= 0))
    for bound, accept in checks:
        order = compare_version_order(version, bound, ecosystem)
        if order is None:
            return None
        if not accept(order):
            return False
    return True


def _affected(product: AffectedProduct, version: str, ecosystem: str) -> tuple[bool | None, str | None]:
    """Return ``(affected, fixed_version)``; ``None`` means the version could not be ordered."""
    if version in product.versions:
        return True, None
    undetermined = False
    for item in product.ranges:
        verdict = _in_range(version, item, ecosystem)
        if verdict:
            return True, item.fixed
        undetermined = undetermined or verdict is None
    return (None, None) if undetermined else (False, None)


def _feed_id(advisory: OperatorAdvisory, package: dict[str, Any]) -> str | None:
    for vuln in package.get("vulnerabilities") or []:
        if not isinstance(vuln, dict) or vuln.get("provenance") == OPERATOR_ADVISORY_PROVENANCE:
            continue
        ids = {str(vuln.get("id") or ""), *(str(alias) for alias in vuln.get("aliases") or [])}
        if ids & advisory.identifiers:
            return str(vuln.get("id"))
    return None


def _report_packages(report: dict[str, Any]) -> Iterator[tuple[dict[str, str], dict[str, Any]]]:
    for agent in report.get("agents") or []:
        if not isinstance(agent, dict):
            continue
        for server in agent.get("mcp_servers") or []:
            if not isinstance(server, dict):
                continue
            for package in server.get("packages") or []:
                if isinstance(package, dict) and package.get("name") and package.get("version"):
                    yield {"agent": str(agent.get("name") or ""), "server": str(server.get("name") or "")}, package


def _finding(advisory: OperatorAdvisory, package: dict[str, Any], asset: dict[str, str], fixed: str | None, scan_id: str) -> dict[str, Any]:
    package_ref = {key: package.get(key) for key in ("name", "version", "ecosystem", "purl", "cpe", "stable_id") if package.get(key)}
    digest = hashlib.sha256("|".join([advisory.id, str(package.get("stable_id") or package.get("purl") or ""), *asset.values()]).encode())
    return {
        "id": f"operator-advisory:{digest.hexdigest()[:24]}",
        "advisory_id": advisory.id,
        "aliases": list(advisory.aliases),
        "summary": advisory.summary,
        "severity": advisory.severity,
        "provenance": OPERATOR_ADVISORY_PROVENANCE,
        "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
        "fixed_version": fixed,
        "package": package_ref,
        "asset": asset,
        "scan_id": scan_id or None,
    }


def _match_package(
    advisory: OperatorAdvisory, package: dict[str, Any], asset: dict[str, str], scan_id: str, out: AdvisoryMatchResult
) -> None:
    label = f"{package['name']}@{package['version']}"
    for product in advisory.affected:
        if not _identity_matches(product, package):
            continue
        affected, fixed = _affected(product, str(package["version"]), str(package.get("ecosystem") or "generic").lower())
        if affected is None:
            out.indeterminate.append({"advisory_id": advisory.id, "package": label, "reason": "version_incomparable"})
        elif affected:
            feed_id = _feed_id(advisory, package)
            if feed_id:
                out.superseded.append({"advisory_id": advisory.id, "feed_id": feed_id, "package": label})
            else:
                out.findings.append(_finding(advisory, package, asset, fixed, scan_id))
        return


def match_advisories_against_reports(advisories: Iterable[OperatorAdvisory], reports: Iterable[dict[str, Any]]) -> AdvisoryMatchResult:
    """Match operator advisories against stored scan reports without rescanning."""
    result = AdvisoryMatchResult()
    advisory_list = list(advisories)
    for report in reports:
        result.reports_examined += 1
        scan_id = str(report.get("scan_id") or "")
        for asset, package in _report_packages(report):
            result.packages_examined += 1
            for advisory in advisory_list:
                _match_package(advisory, package, asset, scan_id, result)
    return result
