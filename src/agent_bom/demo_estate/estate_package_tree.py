"""The recorded package tree of one estate image, several levels deep.

Per ecosystem an image declares one first-party service package (depth 0),
which pulls in the first-party platform SDK. A third-party package nests under
its real upstream parent when that parent is in the same image (``requests``
pulls in ``certifi``, ``flask`` pulls in ``werkzeug`` and ``jinja2``,
``langchain`` pulls in ``requests``); otherwise the service declares it or the
SDK pulls it in, alternating deterministically. First-party packages are
fictional and labelled ``first_party``: no advisory names them, so a clean
parent sits above a vulnerable child exactly as it does in a real lockfile.

The output is recorded lineage (``is_direct``, ``dependency_depth``,
``parent_package``) that :mod:`agent_bom.demo_estate.estate_packages` projects
with the live builder's own resolver.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

PackageRow = tuple[str, str, str, dict[str, str]]

_UPSTREAM_PARENTS: dict[tuple[str, str], str] = {
    ("pypi", "certifi"): "requests",
    ("pypi", "werkzeug"): "flask",
    ("pypi", "jinja2"): "flask",
    ("pypi", "requests"): "langchain",
}
_SDK_VERSION = "3.2.0"


def _service_name(ecosystem: str, workload_base: str) -> str:
    return f"@northstar/{workload_base}" if ecosystem == "npm" else f"northstar-{workload_base}"


def _sdk_name(ecosystem: str) -> str:
    return "@northstar/platform-sdk" if ecosystem == "npm" else "northstar-platform-sdk"


def _depth(key: tuple[str, str], parents: dict[tuple[str, str], str]) -> int:
    level, seen = 0, set()
    while key in parents and key not in seen:
        seen.add(key)
        key = (key[0], parents[key])
        level += 1
    return level


def image_package_tree(packages: Sequence[tuple[str, str, str]], *, workload_base: str, seed: int) -> list[PackageRow]:
    """``(name, version, ecosystem, tags)`` for every package of one image, first-party ones first."""
    present = {(ecosystem.lower(), name) for name, _version, ecosystem in packages}
    rows: list[tuple[str, str, str, dict[str, str]]] = []
    parents: dict[tuple[str, str], str] = {}
    for ecosystem in sorted({key[0] for key in present}):
        service, sdk = _service_name(ecosystem, workload_base), _sdk_name(ecosystem)
        rows.append((service, f"1.{seed % 9}.0", ecosystem, {"first_party": "true"}))
        rows.append((sdk, _SDK_VERSION, ecosystem, {"first_party": "true"}))
        parents[(ecosystem, sdk)] = service
    for name, version, ecosystem in packages:
        key = (ecosystem.lower(), name)
        upstream = _UPSTREAM_PARENTS.get(key)
        if upstream and (key[0], upstream) in present:
            parents[key] = upstream
        else:
            via_sdk = hashlib.sha256(f"package-parent|{seed}|{key[0]}|{name}".encode()).digest()[0] % 2
            parents[key] = _sdk_name(key[0]) if via_sdk else _service_name(key[0], workload_base)
        rows.append((name, version, ecosystem, {}))

    tree: list[PackageRow] = []
    for name, version, ecosystem, tags in rows:
        key = (ecosystem.lower(), name)
        parent = parents.get(key)
        if parent:
            lineage = {"is_direct": "false", "dependency_depth": str(_depth(key, parents)), "parent_package": parent}
        else:
            lineage = {"is_direct": "true", "dependency_depth": "0"}
        tree.append((name, version, ecosystem, {**tags, **lineage}))
    return tree


__all__ = ["image_package_tree"]
