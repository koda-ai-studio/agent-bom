"""Go resolution."""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import httpx

from agent_bom import http_client
from agent_bom.coverage import record_manifest_parse_warning

logger = logging.getLogger(__name__)

_GOPROXY_URL = "https://proxy.golang.org"

_CHECKSUM_DB_URL = "https://sum.golang.org"
_SUMDB_WORKERS = 8

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


def escape_module_path(value: str) -> str:
    """Go module case-encoding: every uppercase letter becomes ``!`` plus its lowercase form."""
    return "".join(f"!{char.lower()}" if char.isupper() else char for char in value)


def _record_hash(body: str, module: str, version: str) -> Optional[str]:
    """Zip hash from a sumdb lookup record: ``<module> <version> h1:<hash>`` after the record id."""
    for line in body.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == module and fields[1] == version and fields[2].startswith("h1:"):
            return fields[2]
    return None


def _sumdb_lookup(checksum_db_url: str, module: str, version: str, timeout: int) -> tuple[Optional[str], Optional[str]]:
    """Return ``(hash, failure)`` for one module; never raises."""
    lookup_url = f"{checksum_db_url}/lookup/{escape_module_path(module)}@{escape_module_path(version)}"
    try:
        body = http_client.fetch_bytes(lookup_url, timeout=timeout).decode("utf-8", errors="replace")
    except (OSError, ValueError, ConnectionError, RuntimeError, httpx.HTTPError) as exc:
        return None, f"checksum DB unreachable: {exc}"
    db_hash = _record_hash(body, module, version)
    return db_hash, None if db_hash else "unexpected checksum DB response format"


def verify_go_checksums(
    go_sum: Path,
    modules: list[tuple[str, str]],
    checksum_db_url: str = _CHECKSUM_DB_URL,
    timeout: int = 10,
) -> dict[str, str]:
    """Check module ZIP hashes in go.sum against the HTTPS checksum database.

    Return module@version -> ok, mismatch or missing. Lookups run on a small
    bounded pool; modules whose lookup fails are omitted and summarised in a
    single warning. Public checksum queries need no credentials.
    """
    _validate_https_url(checksum_db_url, "checksum_db_url")

    sum_entries = _read_go_sum(go_sum)
    if sum_entries is None:
        return {}

    results: dict[str, str] = {}
    pending: list[tuple[str, str]] = []
    for mod, ver in modules:
        ver_key = ver if ver.startswith("v") else f"v{ver}"
        if f"{mod}@{ver_key}" in sum_entries:
            pending.append((mod, ver_key))
        else:
            results[f"{mod}@{ver_key}"] = "missing"
    if not pending:
        return results

    with ThreadPoolExecutor(max_workers=min(_SUMDB_WORKERS, len(pending))) as pool:
        lookups = list(pool.map(lambda item: _sumdb_lookup(checksum_db_url, item[0], item[1], timeout), pending))
    failures: list[str] = []
    for (mod, ver_key), (db_hash, failure) in zip(pending, lookups):
        key = f"{mod}@{ver_key}"
        if db_hash is None:
            failures.append(f"{key} ({failure})")
            continue
        results[key] = "ok" if sum_entries[key] == db_hash else "mismatch"
    if failures:
        logger.warning("go.sum verification skipped for %d module(s), e.g. %s", len(failures), "; ".join(failures[:3]))
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
