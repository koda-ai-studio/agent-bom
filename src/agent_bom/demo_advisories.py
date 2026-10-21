"""Curated advisory evidence for the bundled demo inventory.

These rows are intentionally narrow and are used only for
``agent-bom agents --demo`` and the hosted demo estate. They keep the
first-run demo deterministic when a developer or CI machine has no local
vulnerability DB, while still exercising the same SQLite lookup and
version-range parser used by real scans.

Every row uses a genuine, published advisory ID (CVE / GHSA / PYSEC) with a
real CWE and CVSS so the findings list, blast radius, and reachability
screenshots map to something an operator can look up. A subset is on the
CISA Known Exploited Vulnerabilities (KEV) catalog so the KEV differentiator
lights up in the demo.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from agent_bom.version_utils import compare_version_order


@dataclass(frozen=True)
class DemoAdvisory:
    ecosystem: str
    package: str
    introduced: str
    fixed: str
    vuln_id: str
    severity: str
    cvss_score: float
    summary: str
    cwe: str = ""
    is_kev: bool = False
    source: str = "demo-advisory"
    sample_version: str = ""
    # CISA KEV catalog ``dateAdded`` / ``dueDate`` for a KEV-listed advisory.
    kev_date_added: str = ""
    kev_due_date: str = ""
    # False for a range row that completes an advisory's shape for the matcher
    # (a second release line) without adding packages to the generated estate.
    estate_sample: bool = True


DEMO_ADVISORIES: tuple[DemoAdvisory, ...] = (
    # ── npm ───────────────────────────────────────────────────────────────
    DemoAdvisory(
        "npm",
        "express",
        "0",
        "4.19.2",
        "CVE-2024-29041",
        "medium",
        6.1,
        "Express open redirect via malformed URLs passed to res.location/redirect",
        sample_version="4.19.1",
        cwe="CWE-601",
    ),
    DemoAdvisory(
        "npm",
        "jsonwebtoken",
        "0",
        "9.0.0",
        "CVE-2022-23539",
        "high",
        8.1,
        "jsonwebtoken unrestricted key type could lead to legacy keys usage",
        sample_version="8.5.1",
        cwe="CWE-327",
    ),
    # GHSA-r683-j2x4-v87g fixes two release lines: ``< 2.6.7`` in 2.6.7 and
    # ``>= 3.0.0, < 3.1.1`` in 3.1.1. One 0→3.1.1 window told 2.x installs to
    # jump a major and flagged the fixed 2.6.7 as vulnerable.
    DemoAdvisory(
        "npm",
        "node-fetch",
        "3.0.0",
        "3.1.1",
        "CVE-2022-0235",
        "high",
        # GHSA-r683-j2x4-v87g: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H.
        8.8,
        "node-fetch leaks Cookie/Authorization headers on cross-origin redirect",
        sample_version="3.1.0",
        cwe="CWE-200",
    ),
    DemoAdvisory(
        "npm",
        "node-fetch",
        "0",
        "2.6.7",
        "CVE-2022-0235",
        "high",
        8.8,
        "node-fetch leaks Cookie/Authorization headers on cross-origin redirect",
        sample_version="2.6.1",
        cwe="CWE-200",
        estate_sample=False,
    ),
    DemoAdvisory(
        "npm",
        "axios",
        "0.8.1",
        "0.28.0",
        "CVE-2023-45857",
        "medium",
        6.5,
        "Axios can disclose the XSRF cookie token to another host through the X-XSRF-TOKEN request header",
        sample_version="0.27.2",
        cwe="CWE-352",
    ),
    DemoAdvisory(
        "npm",
        "axios",
        "1.0.0",
        "1.6.0",
        "CVE-2023-45857",
        "medium",
        6.5,
        "Axios can disclose the XSRF cookie token to another host through the X-XSRF-TOKEN request header",
        sample_version="1.4.0",
        cwe="CWE-352",
    ),
    DemoAdvisory(
        "npm",
        "ws",
        "0",
        "8.17.1",
        "CVE-2024-37890",
        "high",
        7.5,
        "ws denial of service when handling a request with many HTTP headers",
        sample_version="8.17.0",
        cwe="CWE-400",
    ),
    DemoAdvisory(
        "npm",
        "lodash",
        "0",
        "4.17.21",
        "CVE-2021-23337",
        "high",
        7.2,
        "lodash command injection via template() with tainted options",
        sample_version="4.17.20",
        cwe="CWE-77",
    ),
    # ── pypi ──────────────────────────────────────────────────────────────
    DemoAdvisory(
        "pypi",
        "pyyaml",
        "0",
        "5.4",
        "CVE-2020-14343",
        "critical",
        9.8,
        "PyYAML arbitrary code execution via yaml.full_load on untrusted input",
        sample_version="5.3",
        cwe="CWE-20",
    ),
    DemoAdvisory(
        "pypi",
        "langchain",
        "0",
        "0.0.247",
        "CVE-2023-36258",
        "critical",
        9.8,
        "LangChain arbitrary code execution via PALChain prompt-to-Python evaluation",
        sample_version="0.0.150",
        cwe="CWE-94",
    ),
    DemoAdvisory(
        "pypi",
        "pillow",
        "0",
        "10.0.1",
        "CVE-2023-4863",
        "high",
        8.8,
        "Pillow bundled libwebp heap buffer overflow — exploited in the wild (CISA KEV)",
        sample_version="9.0.0",
        cwe="CWE-787",
        is_kev=True,
        # CISA KEV catalog entry for CVE-2023-4863.
        kev_date_added="2023-09-13",
        kev_due_date="2023-10-04",
    ),
    DemoAdvisory(
        "pypi",
        "requests",
        "0",
        "2.31.0",
        "CVE-2023-32681",
        "medium",
        6.1,
        "Requests leaks Proxy-Authorization header to destination on redirect",
        sample_version="2.28.0",
        cwe="CWE-200",
    ),
    DemoAdvisory(
        "pypi",
        "cryptography",
        "0",
        "42.0.0",
        "CVE-2023-50782",
        "high",
        7.5,
        "pyca/cryptography Bleichenbacher timing oracle in RSA PKCS#1 v1.5 decryption",
        sample_version="39.0.0",
        cwe="CWE-208",
    ),
    DemoAdvisory(
        "pypi",
        "flask",
        "0",
        "2.3.2",
        "CVE-2023-30861",
        "high",
        7.5,
        "Flask session cookie disclosed to other clients via a caching proxy",
        sample_version="2.2.0",
        cwe="CWE-539",
    ),
    DemoAdvisory(
        "pypi",
        "werkzeug",
        "0",
        "2.2.3",
        "CVE-2023-25577",
        "high",
        7.5,
        "Werkzeug multipart form-data parsing denial of service",
        sample_version="2.2.2",
        cwe="CWE-400",
    ),
    DemoAdvisory(
        "pypi",
        "jinja2",
        "0",
        "3.1.3",
        "CVE-2024-22195",
        "medium",
        5.4,
        "Jinja2 cross-site scripting via the xmlattr filter with attacker-controlled keys",
        sample_version="3.1.2",
        cwe="CWE-79",
    ),
    DemoAdvisory(
        "pypi",
        "certifi",
        "0",
        "2023.7.22",
        "CVE-2023-37920",
        "high",
        7.5,
        "certifi trusted a compromised e-Tugra root certificate authority",
        sample_version="2023.5.7",
        cwe="CWE-345",
    ),
)

# OS-package advisories the seeded compute lane reports on its VMs. Ranges are
# the upstream OpenSSH releases NVD lists: CVE-2024-6387 affects 8.5p1 through
# 9.7p1 (fixed 9.8p1); CVE-2023-38408 affects releases before 9.3p2. Neither is
# on the CISA KEV catalog. Not seeded into the package advisory DB.
DEMO_HOST_ADVISORIES: tuple[DemoAdvisory, ...] = (
    DemoAdvisory(
        "openssh",
        "openssh",
        "8.5p1",
        "9.8p1",
        "CVE-2024-6387",
        "high",
        8.1,
        "OpenSSH sshd signal handler race condition allows unauthenticated remote code execution (regreSSHion)",
        sample_version="9.3p1",
        cwe="CWE-362",
        estate_sample=False,
    ),
    DemoAdvisory(
        "openssh",
        "openssh",
        "0",
        "9.3p2",
        "CVE-2023-38408",
        "critical",
        9.8,
        "OpenSSH ssh-agent PKCS#11 search path allows remote code execution through a forwarded agent",
        sample_version="9.3p1",
        cwe="CWE-428",
        estate_sample=False,
    ),
)

# The demo deliberately includes semver@7.5.2 as a clean package. This sentinel
# gives the deterministic demo DB package-level coverage without making that
# exact version vulnerable.
DEMO_CLEAN_COVERAGE_SENTINELS: tuple[DemoAdvisory, ...] = (
    DemoAdvisory(
        "npm",
        "semver",
        "0",
        "7.5.0",
        "DEMO-CLEAN-semver",
        "unknown",
        0.0,
        "Non-matching coverage sentinel for clean demo package semver@7.5.2",
        source="demo-clean-sentinel",
    ),
)


# Published FIRST EPSS scores (probability, percentile 0-100) for every demo
# advisory, pinned from api.first.org on the "as of" date below so the demo
# stays deterministic offline. One value per CVE: the demo scan, the generated
# estate and the compute lane read the same score, so every occurrence agrees.
DEMO_EPSS_AS_OF = "2026-10-20T00:00:00+00:00"
DEMO_EPSS_SOURCE = "first-epss-snapshot-2026-10-20"
DEMO_EPSS: dict[str, tuple[float, float]] = {
    "CVE-2020-14343": (0.05984, 93.240),
    "CVE-2021-23337": (0.21333, 97.583),
    "CVE-2022-0235": (0.01653, 76.224),
    "CVE-2022-23539": (0.00501, 41.674),
    "CVE-2023-25577": (0.01420, 72.470),
    "CVE-2023-30861": (0.01261, 69.223),
    "CVE-2023-32681": (0.02974, 87.074),
    "CVE-2023-36258": (0.01074, 64.451),
    "CVE-2023-37920": (0.00568, 46.017),
    "CVE-2023-38408": (0.79700, 99.606),
    "CVE-2023-45857": (0.00556, 45.336),
    "CVE-2023-4863": (0.99979, 99.981),
    "CVE-2023-50782": (0.01118, 65.655),
    "CVE-2024-22195": (0.00892, 58.793),
    "CVE-2024-29041": (0.00786, 55.382),
    "CVE-2024-37890": (0.01357, 71.276),
    "CVE-2024-6387": (0.99506, 99.946),
}


def demo_epss(advisory: DemoAdvisory) -> float | None:
    """The pinned published EPSS probability for one demo advisory (None when FIRST has none)."""
    pinned = DEMO_EPSS.get(advisory.vuln_id)
    return pinned[0] if pinned else None


def demo_epss_percentile(advisory: DemoAdvisory) -> float | None:
    pinned = DEMO_EPSS.get(advisory.vuln_id)
    return pinned[1] if pinned else None


def demo_advisory_window(vuln_id: str, package: str, version: str, ecosystem: str) -> DemoAdvisory | None:
    """The curated row whose ``[introduced, fixed)`` window holds ``version``, if any."""
    for advisory in DEMO_ADVISORIES:
        if (advisory.vuln_id, advisory.package) != (vuln_id, package):
            continue
        lower = compare_version_order(version, advisory.introduced, ecosystem) if advisory.introduced != "0" else 1
        upper = compare_version_order(version, advisory.fixed, ecosystem)
        if lower is not None and lower >= 0 and upper is not None and upper < 0:
            return advisory
    return None


def seed_demo_advisories(conn: sqlite3.Connection) -> None:
    """Insert deterministic demo advisory rows into an initialized DB."""

    for advisory in (*DEMO_ADVISORIES, *DEMO_CLEAN_COVERAGE_SENTINELS):
        conn.execute(
            """
            INSERT INTO vulns(
                id, summary, severity, cvss_score, fixed_version, cwe_ids, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET summary=excluded.summary, severity=excluded.severity,
                cvss_score=excluded.cvss_score, fixed_version=excluded.fixed_version,
                cwe_ids=excluded.cwe_ids, source=excluded.source
            """,
            (
                advisory.vuln_id,
                advisory.summary,
                advisory.severity,
                advisory.cvss_score,
                advisory.fixed,
                advisory.cwe,
                advisory.source,
            ),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO affected(
                vuln_id, ecosystem, package_name, introduced, fixed, last_affected
            ) VALUES (?, ?, ?, ?, ?, '')
            """,
            (
                advisory.vuln_id,
                advisory.ecosystem,
                advisory.package,
                advisory.introduced,
                advisory.fixed,
            ),
        )
        if advisory.is_kev:
            conn.execute(
                """
                INSERT OR REPLACE INTO kev_entries(
                    cve_id, date_added, due_date, product, vendor_project
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    advisory.vuln_id,
                    advisory.kev_date_added or None,
                    advisory.kev_due_date or None,
                    advisory.package,
                    advisory.ecosystem,
                ),
            )
        if (probability := demo_epss(advisory)) is not None:
            conn.execute(
                "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES (?, ?, ?, ?)",
                (advisory.vuln_id, probability, demo_epss_percentile(advisory), DEMO_EPSS_AS_OF),
            )
    conn.commit()
