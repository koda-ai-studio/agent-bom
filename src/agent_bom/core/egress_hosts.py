"""Every outbound host the plugin-facing commands can reach.

The Claude Code and Codex plugin READMEs disclose this list, and
``tests/test_plugin_egress_hosts.py`` fails when a README omits a host or when
a scan-path module starts calling a host that is not declared here.
"""

from __future__ import annotations

from typing import Final

__all__ = ["CONDITIONAL_HOSTS", "DATABASE_UPDATE_HOSTS", "DECLARED_HOSTS", "LOOKUP_HOSTS", "USER_NAMED_TARGETS"]

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
    "raw.githubusercontent.com": (
        "the Node.js security working group core advisory index and CPython release headers, "
        "when a scanned image or host ships those runtimes, and the Node.js index during a local database update"
    ),
}

# Reached only when the local advisory database is refreshed: `agent-bom db update`,
# `--auto-update-db`, or the MCP scan tool with auto_update_db=true. No skill does this on its own.
DATABASE_UPDATE_HOSTS: Final[dict[str, str]] = {
    "osv-vulnerabilities.storage.googleapis.com": "OSV bulk advisory archives",
    "secdb.alpinelinux.org": "Alpine security database",
    "security-tracker.debian.org": "Debian security tracker",
    "deb.freexian.com": "Debian extended LTS security tracker",
    "epss.cyentia.com": "the older EPSS address, followed only as a redirect",
}

# Not a fixed host list: these are reached only when the user names them.
USER_NAMED_TARGETS: Final[str] = "container registries, git hosts and cloud provider APIs that you name"

DECLARED_HOSTS: Final[frozenset[str]] = frozenset(LOOKUP_HOSTS) | frozenset(CONDITIONAL_HOSTS) | frozenset(DATABASE_UPDATE_HOSTS)
