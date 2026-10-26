"""Every outbound host the plugin-facing commands can reach.

The Claude Code and Codex plugin READMEs disclose this list, and
``tests/test_plugin_egress_hosts.py`` fails when a README omits a host or when
a scan-path module starts calling a host that is not declared here.
"""

from __future__ import annotations

from typing import Final

# Hosts reached by the lookup skills (checkup, scan, check, fix, affected,
# audit-mcp, bom) on a normal run.
LOOKUP_HOSTS: Final[dict[str, str]] = {
    "api.osv.dev": "vulnerability and malicious-package lookups",
    "api.github.com": "GitHub security advisories",
    "pypi.org": "PyPI package metadata, typosquat checks and latest versions",
    "registry.npmjs.org": "npm package metadata, typosquat checks and latest versions",
    "www.cisa.gov": "the CISA Known Exploited Vulnerabilities (KEV) catalog",
}

# Hosts reached only in the situation described.
CONDITIONAL_HOSTS: Final[dict[str, str]] = {
    "files.pythonhosted.org": "uv downloads the pinned release and its locked dependencies on first use",
    "github.com": "uv downloads a managed Python when no Python 3.11+ is installed; scan --repo clones the repository you name",
    "api.first.org": "EPSS exploit-probability scores when enrichment is on",
    "epss.empiricalsecurity.com": "EPSS scores for an advisory lookup or a local database update",
    "services.nvd.nist.gov": "NVD CVSS data when enrichment is on, and NVD-only CVE lookups",
    "api.securityscorecards.dev": "OpenSSF Scorecard results when scorecard enrichment is on",
    "api.deps.dev": "license and project metadata when the package registry has none",
    "proxy.golang.org": "Go module versions and dependencies",
    "sum.golang.org": "Go module checksums",
}

# Not a fixed host list: these are reached only when the user names them.
USER_NAMED_TARGETS: Final[str] = "container registries, git hosts and cloud provider APIs that you name"

DECLARED_HOSTS: Final[frozenset[str]] = frozenset(LOOKUP_HOSTS) | frozenset(CONDITIONAL_HOSTS)
