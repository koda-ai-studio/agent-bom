"""Go resolution."""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

import httpx

from agent_bom.coverage import record_manifest_parse_warning

logger = logging.getLogger(__name__)

_GOPROXY_URL = "https://proxy.golang.org"

_CHECKSUM_DB_URL = "https://sum.golang.org"

_UNRESOLVED_VERSIONS = frozenset({"latest", "(devel)", "", "unknown"})


def _validate_https_url(url: str, param_name: str = "url") -> None:
    """Raise ValueError if *url* does not use HTTPS.

    All Go public API calls must use HTTPS — no plain-HTTP allowed.
    """
    if not url.startswith("https://"):
        raise ValueError(f"{param_name} must use https:// — got {url!r}. Only HTTPS URLs are accepted.")


def _read_go_sum(go_sum: Path) -> dict[str, str] | None:
    # Build lookup table from go.sum: {module@version: h1:hash}
    # Skip /go.mod suffix lines — we verify the module zip hash only.
    sum_entries: dict[str, str] = {}
    if go_sum.exists():
        try:
            for line in go_sum.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                mod, ver_raw, h1 = parts[0], parts[1], parts[2]
                if ver_raw.endswith("/go.mod"):
                    continue  # skip go.mod hash lines
                ver = ver_raw.split("/")[0]
                sum_entries[f"{mod}@{ver}"] = h1
        except OSError as exc:
            logger.warning("Could not read go.sum at %s: %s", go_sum, exc)
            record_manifest_parse_warning(
                ecosystem="go",
                path=str(go_sum),
                detail="go.sum could not be read; Go checksum verification was not completed",
            )
            return None

    return sum_entries


def verify_go_checksums(
    go_sum: Path,
    modules: list[tuple[str, str]],
    checksum_db_url: str = _CHECKSUM_DB_URL,
    timeout: int = 10,
) -> dict[str, str]:
    """Check module ZIP hashes in go.sum against the HTTPS checksum database.

    Return module@version -> ok, mismatch or missing. Skip /go.mod entries
    and omit network failures after warning; mismatches indicate changed bytes.
    Public checksum queries need no credentials. Only the supplied modules
    are checked, with the caller-provided timeout.
    """
    _validate_https_url(checksum_db_url, "checksum_db_url")

    sum_entries = _read_go_sum(go_sum)
    if sum_entries is None:
        return {}

    results: dict[str, str] = {}
    for mod, ver in modules:
        # Ensure version has the v prefix for the lookup key
        ver_key = ver if ver.startswith("v") else f"v{ver}"
        key = f"{mod}@{ver_key}"

        if key not in sum_entries:
            results[key] = "missing"
            continue

        local_hash = sum_entries[key]

        # Fetch expected hash from the checksum database
        lookup_url = f"{checksum_db_url}/lookup/{mod}@{ver_key}"
        try:
            from agent_bom.http_client import fetch_bytes

            body = fetch_bytes(lookup_url, timeout=timeout).decode("utf-8", errors="replace")
        except (OSError, ValueError, ConnectionError, RuntimeError, httpx.HTTPError) as exc:
            logger.warning(
                "go.sum verification skipped for %s — checksum DB unreachable: %s",
                key,
                exc,
            )
            continue

        # The lookup response format (tile protocol):
        # Line 0: tree size
        # Line 1: hash (h1:BASE64=)
        # Line 2+: signed tree head
        db_hash: Optional[str] = None
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("h1:"):
                db_hash = line
                break

        if db_hash is None:
            logger.warning("Unexpected checksum DB response format for %s", key)
            continue

        results[key] = "ok" if local_hash == db_hash else "mismatch"

    return results


def resolve_go_version(
    module: str,
    version: str,
    proxy_url: str = _GOPROXY_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Go module version using the Go module proxy.

    Queries ``https://proxy.golang.org/{module}/@v/list`` for the available
    version list and returns the latest stable release (no pre-release
    suffixes such as ``-rc``, ``-alpha``, ``-beta``, or ``-pre``).

    If *version* is already pinned (not ``"latest"``, ``"(devel)"``,
    ``""`` or ``"unknown"``), it is returned immediately without any
    network call.

    Never raises — any network error causes the original version string to
    be returned so that parsing can continue uninterrupted.

    Args:
        module: The Go module path (e.g. ``"github.com/gin-gonic/gin"``).
        version: Current version string.  Pass ``"latest"`` or ``""`` to
            trigger resolution.
        proxy_url: Base URL of the Go module proxy.  Must be HTTPS.
            Defaults to ``https://proxy.golang.org``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"v1.9.1"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(proxy_url, "proxy_url")

    encoded_module = urllib.parse.quote(module, safe="")
    list_url = f"{proxy_url}/{encoded_module}/@v/list"

    try:
        from agent_bom.http_client import fetch_bytes

        body = fetch_bytes(list_url, timeout=timeout).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original version on any failure
        logger.warning(
            "GOPROXY version resolution failed for %s — returning original version: %s",
            module,
            exc,
        )
        return version

    _prerelease_re = re.compile(r"-(rc|alpha|beta|pre)[\d.]*$", re.IGNORECASE)

    stable_versions: list[str] = []
    for raw in body.splitlines():
        v = raw.strip()
        if not v:
            continue
        if _prerelease_re.search(v):
            continue
        stable_versions.append(v)

    if not stable_versions:
        return version

    def _semver_key(v: str) -> tuple[int, ...]:
        """Return a numeric tuple for semver comparison."""
        # Strip leading 'v' and any build metadata
        cleaned = v.lstrip("v").split("+")[0]
        parts = cleaned.split(".")
        result = []
        for part in parts:
            # Strip any non-numeric suffix (e.g. "1" from "1rc1")
            numeric = re.match(r"(\d+)", part)
            result.append(int(numeric.group(1)) if numeric else 0)
        return tuple(result)

    stable_versions.sort(key=_semver_key)
    return stable_versions[-1]
