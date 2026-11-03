"""Parse pnpm-lock.yaml package keys and dependency references per lockfile format.

Formats:
- v5.x: ``/name/1.0.0`` and ``/@scope/name/1.0.0``; peer suffixes follow ``_``
  (``/postcss-js/4.0.0_postcss@8.4.19``, scoped peers encoded with ``+``).
- v6.x: ``/name@1.0.0`` and ``/@scope/name@1.0.0``; peers in parentheses.
- v9.x: the same as v6 without the leading ``/``.
"""

from __future__ import annotations

import re

_NAME_SEGMENT = re.compile(r"^[A-Za-z0-9._~-][A-Za-z0-9._~-]*$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$")


def lockfile_major(document: dict) -> float:
    """Return the numeric ``lockfileVersion``; unknown values default to the v6+ format."""
    raw = document.get("lockfileVersion")
    try:
        return float(str(raw).strip("'\""))
    except (TypeError, ValueError):
        return 6.0


def _valid_name(name: str) -> bool:
    parts = name[1:].split("/") if name.startswith("@") else [name]
    expected = 2 if name.startswith("@") else 1
    return len(parts) == expected and all(_NAME_SEGMENT.match(part) for part in parts)


def _split_v5(key: str) -> tuple[str, str] | None:
    segments = key.split("/")
    width = 2 if key.startswith("@") else 1
    if len(segments) != width + 1:
        return None
    name = "/".join(segments[:width])
    version = segments[width].split("_", 1)[0]
    return name, version


def _split_v6(key: str) -> tuple[str, str] | None:
    name, sep, version = key.split("(", 1)[0].rpartition("@")
    return (name, version) if sep and name else None


def parse_pnpm_key(key: str, lockfile_version: float) -> tuple[str, str] | None:
    """Return the registry ``(name, version)`` a package key names, or None for non-registry keys."""
    if not isinstance(key, str):
        return None
    key = key.lstrip("/")
    if not key:
        return None
    parsed = _split_v5(key) if lockfile_version < 6 else _split_v6(key)
    if parsed is None:
        return None
    name, version = parsed
    if not _valid_name(name) or not _VERSION.match(version):
        return None
    return name, version


def pnpm_dependency_ref(name: str, value: object, lockfile_version: float) -> tuple[str, str] | None:
    """Return the ``(name, version)`` a dependency entry resolves to (peer suffix removed).

    ``value`` is a version (``3.2.45_vue@3.2.45`` in v5, ``3.3.4(vue@3.3.4)`` in v6+),
    an alias key (``/string-width/4.2.3``, ``string-width@4.2.3``) or a v6+
    importer mapping with a ``version`` field. ``link:``/``file:`` refs return None.
    """
    if isinstance(value, dict):
        value = value.get("version")
    if not isinstance(value, str):
        return None
    if value.startswith("/") or (lockfile_version >= 6 and "@" in value.split("(", 1)[0]):
        return parse_pnpm_key(value, lockfile_version)
    version = value.split("_", 1)[0] if lockfile_version < 6 else value.split("(", 1)[0]
    return (name, version) if _VERSION.match(version) else None
