"""Tests for malicious package detection module."""

import pytest

from agent_bom.malicious import (
    check_typosquat,
    flag_malicious_from_vulns,
    is_malicious_vuln,
)
from agent_bom.models import Package, Severity, Vulnerability

# ─── MAL- prefix detection ───────────────────────────────────────────────────


def test_is_malicious_vuln_mal_prefix():
    assert is_malicious_vuln("MAL-2024-1234") is True


def test_is_malicious_vuln_mal_lowercase():
    assert is_malicious_vuln("mal-2024-5678") is True


def test_is_malicious_vuln_cve_not_malicious():
    assert is_malicious_vuln("CVE-2024-1234") is False


def test_is_malicious_vuln_ghsa_not_malicious():
    assert is_malicious_vuln("GHSA-xxxx-yyyy") is False


def test_is_malicious_vuln_osv_not_malicious():
    assert is_malicious_vuln("PYSEC-2024-123") is False


# ─── flag_malicious_from_vulns ───────────────────────────────────────────────


def test_flag_malicious_from_vulns_with_mal():
    pkg = Package(name="evil-pkg", version="1.0.0", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="MAL-2024-1234", summary="Malicious package", severity=Severity.CRITICAL),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert "MAL-2024-1234" in pkg.malicious_reason


def test_flag_malicious_from_vulns_without_mal():
    pkg = Package(name="normal-pkg", version="1.0.0", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="CVE-2024-1234", summary="Normal vuln", severity=Severity.HIGH),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is False
    assert pkg.malicious_reason is None


def test_flag_malicious_from_ghsa_malware_advisory_without_mal_id():
    # event-stream 3.3.6 reaches OSV only as GHSA-mh6f-8j2x-4483 tagged CWE-506.
    pkg = Package(name="event-stream", version="3.3.6", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="GHSA-mh6f-8j2x-4483", summary="flatmap-stream", severity=Severity.CRITICAL, cwe_ids=["CWE-506"]),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert "GHSA-mh6f-8j2x-4483" in pkg.malicious_reason


def test_flag_malicious_from_vulns_mixed():
    pkg = Package(name="sneaky-pkg", version="1.0.0", ecosystem="pypi")
    pkg.vulnerabilities = [
        Vulnerability(id="CVE-2024-1111", summary="Normal", severity=Severity.MEDIUM),
        Vulnerability(id="MAL-2024-9999", summary="Malicious!", severity=Severity.CRITICAL),
    ]
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is True
    assert "MAL-2024-9999" in pkg.malicious_reason


def test_flag_malicious_no_vulns():
    pkg = Package(name="safe-pkg", version="1.0.0", ecosystem="npm")
    flag_malicious_from_vulns(pkg)
    assert pkg.is_malicious is False


# ─── Typosquat detection ─────────────────────────────────────────────────────


def test_typosquat_detects_close_match_npm():
    # "expresss" is very close to "express"
    result = check_typosquat("expresss", "npm")
    assert result == "express"


def test_typosquat_detects_close_match_pypi():
    # "reqeusts" is close to "requests"
    result = check_typosquat("reqeusts", "pypi")
    assert result == "requests"


def test_typosquat_exact_match_not_flagged():
    result = check_typosquat("express", "npm")
    assert result is None


def test_typosquat_different_package_not_flagged():
    result = check_typosquat("totally-different-pkg", "npm")
    assert result is None


def test_typosquat_unknown_ecosystem():
    result = check_typosquat("some-pkg", "maven")
    assert result is None


def test_typosquat_case_insensitive():
    result = check_typosquat("Expresss", "npm")
    assert result == "express"


def test_typosquat_single_char_substitution_short_name():
    # `djanga` vs `django` is a single substitution scoring 0.833 < 0.85 — the
    # ratio gate misses it, the edit-distance-1 catch must not.
    assert check_typosquat("djanga", "pypi") == "django"


def test_typosquat_known_legitimate_successor_not_flagged():
    # `httpx2` is the real httpx successor by httpx's own author, and reaches
    # most dependency trees transitively through the openai SDK. It scores 0.909
    # against `httpx`, so without the allowlist the scanner calls a genuine
    # package MALICIOUS and fails any build that depends on openai.
    assert check_typosquat("httpx2", "pypi") is None
    assert check_typosquat("langchainhub", "pypi") is None


def test_typosquat_known_legitimate_preact_not_flagged():
    # Preact is an independently maintained, public npm package. Its name is
    # intentionally React-compatible, not a misspelling of ``react``.
    assert check_typosquat("preact", "npm") is None


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("bcryptjs", "npm"),
        ("expresso", "npm"),
        ("boto", "pypi"),
        ("fabric2", "pypi"),
        ("fabric3", "pypi"),
        ("pandasql", "pypi"),
        ("beautifulsoup", "pypi"),
        ("openapi", "pypi"),
    ],
)
def test_typosquat_registry_verified_neighbours_not_flagged(name, ecosystem):
    # Long-standing upstream projects whose names sit next to a popular package;
    # the install guard blocks on this verdict, so a false positive stops real work.
    assert check_typosquat(name, ecosystem) is None


def test_typosquat_recent_lookalike_still_flagged():
    assert check_typosquat("pydantic2", "pypi") == "pydantic"


def test_typosquat_numeric_suffix_still_flagged():
    # Guards the allowlist against being "simplified" into a rule that exempts
    # every trailing-digit name. `requests2`/`requests3` were real typosquat
    # campaigns — that shape must stay caught.
    assert check_typosquat("requests2", "pypi") == "requests"
    assert check_typosquat("requests3", "pypi") == "requests"
    assert check_typosquat("flask2", "pypi") == "flask"


def test_typosquat_legit_packages_not_flagged_no_regressions():
    from agent_bom.malicious import _POPULAR_PACKAGES

    legit_pypi = [
        "urllib3",
        "click",
        "rich",
        "pytest",
        "setuptools",
        "wheel",
        "certifi",
        "idna",
        "six",
        "jinja2",
        "werkzeug",
        "attrs",
        "packaging",
        "tqdm",
        "pyyaml",
        "typing-extensions",
        "pytz",
        "wrapt",
        "markupsafe",
        "poetry",
        "ruff",
        "mypy",
        "coverage",
        "hypothesis",
        "loguru",
        "starlette",
        "anyio",
        "sniffio",
        "greenlet",
        "protobuf",
    ] + list(_POPULAR_PACKAGES["pypi"])
    legit_npm = [
        "react-router",
        "vite",
        "rollup",
        "esbuild",
        "vitest",
        "jest",
        "ts-node",
        "pnpm",
        "yarn",
        "fastify",
        "koa",
        "ws",
        "ioredis",
        "pino",
        "winston",
        "undici",
        "tslib",
        "glob",
        "rimraf",
        "minimist",
        "semver",
        "debug",
        "ms",
        "node-fetch",
    ] + list(_POPULAR_PACKAGES["npm"])

    assert [n for n in legit_pypi if check_typosquat(n, "pypi")] == []
    assert [n for n in legit_npm if check_typosquat(n, "npm")] == []


def test_typosquat_short_names_not_over_flagged():
    # `core` (len 4) vs `cors` and `flash` (len 5) vs `flask` are legitimate
    # neighbours below the edit-distance-1 length gate — must stay clean.
    assert check_typosquat("core", "npm") is None
    assert check_typosquat("flash", "pypi") is None


def test_typosquat_pypi_torch():
    # "torcch" is close to "torch"
    result = check_typosquat("torcch", "pypi")
    assert result is not None


def test_typosquat_threshold_respected():
    # Low similarity should not flag
    result = check_typosquat("xyzabc", "npm", threshold=0.85)
    assert result is None


# ─── Integration with Package model ─────────────────────────────────────────


def test_package_is_malicious_defaults_false():
    pkg = Package(name="test", version="1.0", ecosystem="npm")
    assert pkg.is_malicious is False
    assert pkg.malicious_reason is None


def test_package_malicious_fields_settable():
    pkg = Package(
        name="evil",
        version="1.0",
        ecosystem="npm",
        is_malicious=True,
        malicious_reason="Known malicious package (MAL-2024-1234)",
    )
    assert pkg.is_malicious is True
    assert "MAL-2024-1234" in pkg.malicious_reason


# ─── Ranked typosquat reference (src/agent_bom/data/popular_packages.json) ──


@pytest.mark.parametrize(
    ("name", "ecosystem", "target"),
    [
        # Squats from public incident reports that the 28-name list missed.
        ("crossenv", "npm", "cross-env"),
        ("colourama", "pypi", "colorama"),
        ("jeIlyfish", "pypi", "jellyfish"),
        ("python3-dateutil", "pypi", "python-dateutil"),
        ("urlib3", "pypi", "urllib3"),
    ],
)
def test_typosquat_catches_documented_campaigns(name, ecosystem, target):
    assert check_typosquat(name, ecosystem) == target


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        # Established projects one edit from a target: recorded as established.
        ("psycopg2", "pypi"),
        ("enquirer", "npm"),
        ("through", "npm"),
        # Whole-token extensions of a target are plugins, not typos.
        ("opentelemetry-instrumentation-redis", "pypi"),
        ("eslint-plugin-react-hooks-extra", "npm"),
        # PyPI treats -, _ and . as the same name.
        ("python_dateutil", "pypi"),
        ("Typing_Extensions", "pypi"),
    ],
)
def test_typosquat_spares_established_neighbours(name, ecosystem):
    assert check_typosquat(name, ecosystem) is None


def test_typosquat_reference_is_sourced_and_small():
    import json
    from pathlib import Path

    from agent_bom import malicious

    data = json.loads((Path(malicious.__file__).parent / "data" / "popular_packages.json").read_text())
    assert set(data["sources"]) >= {"pypi", "npm", "curated", "established"}
    for eco in ("npm", "pypi"):
        assert 250 <= len(data["popular"][eco]) <= 500
        assert set(data["popular"][eco]) == set(malicious._POPULAR_PACKAGES[eco])
        assert not set(data["established"][eco]) & set(data["popular"][eco])
    assert {"urllib3", "colorama", "python-dateutil", "jellyfish"} <= set(data["popular"]["pypi"])
    assert "cross-env" in data["popular"]["npm"]


def test_typosquat_far_edits_on_long_names_are_not_squats():
    # A long shared prefix pushes the ratio past 0.85 even when three or more
    # characters differ; real squats are one or two edits away.
    assert check_typosquat("eslint-plugin-vitest", "npm") is None
