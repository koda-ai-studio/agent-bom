"""Shared severity, location, redaction and rule-catalog helpers for SARIF exports."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Any, Optional

from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.models import Severity
from agent_bom.security import sanitize_sensitive_payload

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
    Severity.UNKNOWN: "note",
}


def _sarif_fingerprint_fields(
    *,
    stable_input: str,
    artifact_uri: str,
    start_line: int | None = 1,
) -> dict[str, dict[str, str]]:
    """Return SARIF fingerprints and GitHub partialFingerprints for dedup."""
    fields = {
        "fingerprints": {
            "agent-bom/v1": hashlib.sha256(stable_input.encode()).hexdigest(),
        },
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"{artifact_uri}:{start_line}".encode()).hexdigest(),
        },
    }
    if start_line is None or artifact_uri.startswith(("self-scan://", "pkg:", "package:")):
        fields.pop("partialFingerprints")
    return fields


# GitHub Security tab uses security-severity (0.0–10.0) for granular sorting.
# Ranges per docs.github.com: >9.0=critical, 7.0–8.9=high, 4.0–6.9=medium, 0.1–3.9=low
_SECURITY_SEVERITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.NONE: "0.0",
    Severity.UNKNOWN: "0.0",
}

# ``info`` is the unified findings stream's spelling for "reported, not a
# problem" — the same thing SARIF calls level ``none``. Every other label is
# read the way ``graph.severity.normalize_severity`` reads it, which is what
# ``Finding.__post_init__`` has already applied to anything in that stream.
_SARIF_INFO_LABELS = frozenset({"info", "informational"})


def _sarif_severity(label: object) -> tuple[str, str]:
    """Return ``(level, security-severity)`` for a finding severity label.

    Every result stream in a document resolves severity here. The unified
    finding, IaC, AI and CIS streams each used to carry an inline copy of these
    tables keyed by severity string; none of the copies had a ``none`` or
    ``unknown`` key and they fell back to ``warning`` / ``4.0``, so a finding
    rated ``none`` — or one the scanner could not rate — reached GitHub code
    scanning as Medium while the CVE stream in the same document reported it as
    ``note`` / ``0.0``. An unrecognised label resolves to ``unknown``: unrated
    is never silently promoted to a rating.
    """
    name = str(label or "").strip().lower()
    if name in _SARIF_INFO_LABELS:
        return _SARIF_SEVERITY_MAP[Severity.NONE], _SECURITY_SEVERITY_SCORE[Severity.NONE]
    try:
        severity = Severity(name)
    except ValueError:
        severity = Severity.UNKNOWN
    return _SARIF_SEVERITY_MAP[severity], _SECURITY_SEVERITY_SCORE[severity]


# Per-ecosystem manifest candidates, checked in order. Lets a SARIF result for
# a maven/go/cargo finding point at pom.xml/go.mod/Cargo.toml instead of all
# findings collapsing onto the first manifest in the directory.
_ECOSYSTEM_MANIFESTS: dict[str, tuple[str, ...]] = {
    "pypi": ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"),
    "npm": ("package.json",),
    "maven": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "gradle": ("build.gradle", "build.gradle.kts", "pom.xml"),
    "go": ("go.mod",),
    "cargo": ("Cargo.toml", "Cargo.lock"),
    "rubygems": ("Gemfile", "Gemfile.lock"),
    "composer": ("composer.json",),
    "nuget": ("packages.config",),
    "hex": ("mix.exs",),
    "pub": ("pubspec.yaml",),
    "conda": ("environment.yml", "environment.yaml"),
}


def _ecosystem_from_purl(identifier: Optional[str]) -> Optional[str]:
    """Extract the ecosystem from a purl identifier (``pkg:pypi/...`` → ``pypi``)."""
    if identifier and identifier.startswith("pkg:"):
        rest = identifier[4:]
        return rest.split("/", 1)[0].split("@", 1)[0].lower() or None
    return None


def _to_relative_path(path: str, ecosystem: Optional[str] = None) -> str:
    """Convert an absolute path to a relative path suitable for SARIF.

    GitHub Code Scanning requires relative paths from the repo root.
    Absolute paths cause "No summary of scanned files" in the Security tab.
    For dependency findings on a directory, points to the manifest of the
    finding's own ecosystem (so maven/go/cargo findings don't all collapse onto
    the first manifest), falling back to any present manifest.
    """

    p = Path(path)
    # If it's a directory (e.g., project root from --self-scan), point to manifest
    if p.is_dir():
        if ecosystem:
            for manifest in _ECOSYSTEM_MANIFESTS.get(ecosystem.lower(), ()):
                if (p / manifest).exists():
                    return manifest
        for manifest in ("pyproject.toml", "package.json", "go.mod", "Cargo.toml", "requirements.txt", "pom.xml"):
            if (p / manifest).exists():
                return manifest
        return "pyproject.toml"  # default fallback for Python projects

    # If it's an absolute path, try to make it relative to cwd
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            # Can't make relative — extract just the filename
            return p.name

    return path


def _sanitize_sarif_property(value: Any) -> Any:
    """Apply final defensive redaction before data leaves via SARIF.

    Property bags carry arbitrary nested evidence — scanner payloads, runtime
    capture, provenance — so they keep the conservative tier-A allowlist.
    """
    sanitized = sanitize_sensitive_payload(value, max_str_len=1000)
    if isinstance(sanitized, str):
        return None
    return redact_for_persistence({"details": sanitized}, EvidenceTier.SAFE_TO_STORE).get("details")


@dataclasses.dataclass
class _SarifCatalog:
    """Rules and results accumulated across finding families for one SARIF run."""

    rules: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    results: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    seen_rule_ids: set[str] = dataclasses.field(default_factory=set)

    def claim_rule(self, rule_id: str) -> bool:
        """Return True the first time a rule ID is seen, so its rule is emitted once."""
        if rule_id in self.seen_rule_ids:
            return False
        self.seen_rule_ids.add(rule_id)
        return True


def _sarif_location(uri: str, start_line: Any, *, scanned_artifact: str | None = None) -> dict[str, Any]:
    # Package identities are logical; code scanning needs the scanned image as a physical artifact.
    if uri.startswith(("self-scan://", "pkg:", "package:")):
        logical = {"logicalLocations": [{"fullyQualifiedName": uri}]}
        return {"physicalLocation": {"artifactLocation": {"uri": scanned_artifact}}, **logical} if scanned_artifact else logical
    location: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
    if type(start_line) is int and start_line > 0:
        location["region"] = {"startLine": start_line, "startColumn": 1}
    return {"physicalLocation": location}
