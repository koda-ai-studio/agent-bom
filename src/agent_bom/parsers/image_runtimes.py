"""Language runtimes built from source in official container images.

Official language images (php, python, node, golang, ruby, eclipse-temurin)
compile or unpack the runtime into ``/usr/local`` or ``/opt`` and record the
release in the image config ``Env`` — no distro package database ever sees it.
Conventions, from the upstream Dockerfiles:

- docker-library/php: ``ENV PHP_VERSION 8.3.36``; default prefix, ``/usr/local/bin/php``
- docker-library/python: ``ENV PYTHON_VERSION 3.13.17``; ``/usr/local/bin/python3.13``
- nodejs/docker-node: ``ENV NODE_VERSION=22.23.4``; ``/usr/local/bin/node``
- docker-library/golang: ``ENV GOLANG_VERSION 1.27.3``; ``/usr/local/go/bin/go``
- docker-library/ruby: ``ENV RUBY_VERSION 3.4.11``; ``/usr/local/bin/ruby``
- adoptium/containers: ``ENV JAVA_VERSION=jdk-21.0.12.1+1``; ``/opt/java/openjdk/bin/java``

Env values are attacker-controllable image metadata, so only strict version
grammars are accepted. A runtime whose binary is present in the final layer
view is reported with ``binary`` provenance; env-only runtimes stay
``image-env``. Env-only runtimes that duplicate an installed distro package of
the same upstream release are dropped so one install is not counted twice.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from agent_bom.models import Package

_DOTTED = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,6}){1,3}")
_PYTHON = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}(?:(?:a|b|rc)[0-9]{1,2})?")
_TEMURIN = re.compile(r"jdk-([0-9]{1,3}(?:\.[0-9]{1,6}){0,3})(?:\+[0-9]{1,4})?")
_CPE_VERSION = re.compile(r"[0-9][0-9A-Za-z.]{0,31}")
_DISTRO_ECOSYSTEMS = frozenset({"deb", "apk", "rpm"})


def _dotted(value: str) -> str | None:
    return value if _DOTTED.fullmatch(value) else None


def _python(value: str) -> str | None:
    return value if _PYTHON.fullmatch(value) else None


def _temurin(value: str) -> str | None:
    match = _TEMURIN.fullmatch(value)
    return match[1] if match else None


@dataclass(frozen=True)
class RuntimeSpec:
    env: str
    name: str
    purl_namespace: str
    cpe_vendor: str
    cpe_product: str
    parse: Callable[[str], str | None]
    binaries: Callable[[str], tuple[str, ...]]
    distro_prefixes: tuple[str, ...]

    def cpe(self, version: str) -> str | None:
        if not _CPE_VERSION.fullmatch(version):
            return None
        return f"cpe:2.3:a:{self.cpe_vendor}:{self.cpe_product}:{version}:*:*:*:*:*:*:*"

    def purl(self, version: str) -> str:
        return f"pkg:generic/{self.purl_namespace}/{self.name}@{version}"


def _python_binaries(version: str) -> tuple[str, ...]:
    branch = ".".join(version.split(".")[:2])
    return (f"usr/local/bin/python{branch}",)


# CPE vendor:product pairs as published in the NVD CPE dictionary.
RUNTIME_SPECS: tuple[RuntimeSpec, ...] = (
    RuntimeSpec("PHP_VERSION", "php", "php", "php", "php", _dotted, lambda _v: ("usr/local/bin/php",), ("php",)),
    RuntimeSpec("PYTHON_VERSION", "cpython", "python", "python", "python", _python, _python_binaries, ("python",)),
    RuntimeSpec("NODE_VERSION", "node", "nodejs", "nodejs", "node.js", _dotted, lambda _v: ("usr/local/bin/node",), ("nodejs",)),
    RuntimeSpec("GOLANG_VERSION", "go", "golang", "golang", "go", _dotted, lambda _v: ("usr/local/go/bin/go",), ("golang",)),
    RuntimeSpec("RUBY_VERSION", "ruby", "ruby-lang", "ruby-lang", "ruby", _dotted, lambda _v: ("usr/local/bin/ruby",), ("ruby",)),
    RuntimeSpec(
        "JAVA_VERSION", "openjdk", "openjdk", "oracle", "openjdk", _temurin, lambda _v: ("opt/java/openjdk/bin/java",), ("openjdk",)
    ),
)
_SPEC_BY_NAME = {spec.name: spec for spec in RUNTIME_SPECS}


def runtime_spec(package: Package) -> RuntimeSpec | None:
    if package.ecosystem != "generic":
        return None
    return _SPEC_BY_NAME.get(package.name)


def _image_env(config: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(config, dict):
        return {}
    section = config.get("config") or config.get("Config") or {}
    env = section.get("Env") if isinstance(section, dict) else None
    if not isinstance(env, list):
        return {}
    pairs = (item.split("=", 1) for item in env if isinstance(item, str) and "=" in item)
    return {key: value.strip() for key, value in pairs}


def runtime_packages_from_config(config: dict[str, Any] | None) -> list[Package]:
    """Runtime components declared by an image config's ``Env``."""
    env = _image_env(config)
    packages: list[Package] = []
    for spec in RUNTIME_SPECS:
        version = spec.parse(env.get(spec.env, ""))
        if version is None:
            continue
        packages.append(
            Package(
                name=spec.name,
                version=version,
                ecosystem="generic",
                purl=spec.purl(version),
                cpe=spec.cpe(version),
                is_direct=False,
                resolved_from_registry=False,
                version_evidence=[{"type": "image_env", "variable": spec.env, "value": env[spec.env]}],
                discovery_provenance=_provenance("image-env", [spec.env]),
            )
        )
    return packages


def _provenance(source: str, observed_via: list[str]) -> dict[str, Any]:
    return {
        "source_type": "image_scan",
        "source": source,
        "observed_via": observed_via,
        "confidence": "high" if source == "binary" else "medium",
    }


def seed_image_runtimes(config: dict[str, Any] | None, packages_by_key: dict[tuple[str, str], Package], packages: list[Package]) -> None:
    """Register env-declared runtimes before layer stages so binaries attach occurrences."""
    for package in runtime_packages_from_config(config):
        packages_by_key[(package.name.lower(), package.ecosystem)] = package
        packages.append(package)


def runtime_binary_paths(package: Package) -> tuple[str, ...]:
    spec = runtime_spec(package)
    return spec.binaries(package.version) if spec else ()


def _upstream_version(version: str) -> str:
    without_epoch = version.split(":", 1)[-1]
    upstream = without_epoch.rsplit("-", 1)[0] if "-" in without_epoch else without_epoch
    return re.split(r"[+~]", upstream, maxsplit=1)[0]


def _distro_duplicate(spec: RuntimeSpec, version: str, distro_packages: Iterable[Package]) -> bool:
    return any(pkg.name.lower().startswith(spec.distro_prefixes) and _upstream_version(pkg.version) == version for pkg in distro_packages)


def _finalize(package: Package, spec: RuntimeSpec) -> None:
    package.cpe = spec.cpe(package.version)
    package.purl = spec.purl(package.version)
    binaries = set(spec.binaries(package.version))
    observed = [occ for occ in package.occurrences if occ.package_path and occ.package_path.removeprefix("./") in binaries]
    package.version_evidence = [item for item in package.version_evidence if item.get("type") != "binary"] + [
        {"type": "binary", "source_file": occ.package_path.removeprefix("./"), "layer_id": occ.layer_id}
        for occ in observed
        if occ.package_path
    ]
    env_vars = [str(item["variable"]) for item in package.version_evidence if item.get("type") == "image_env"]
    paths = [str(item["source_file"]).removeprefix("./") for item in package.version_evidence if item.get("source_file")]
    package.discovery_provenance = _provenance("binary" if package.occurrences else "image-env", [*env_vars, *paths])


def finalize_image_runtimes(packages: list[Package]) -> list[Package]:
    """Attach CPE identity and provenance; drop env-only distro duplicates."""
    distro = [pkg for pkg in packages if pkg.ecosystem in _DISTRO_ECOSYSTEMS]
    kept: list[Package] = []
    for package in packages:
        spec = runtime_spec(package)
        if spec is not None:
            if not package.occurrences and _distro_duplicate(spec, package.version, distro):
                continue
            _finalize(package, spec)
        kept.append(package)
    return kept
