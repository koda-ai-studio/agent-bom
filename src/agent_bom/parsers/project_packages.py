"""Collect and deduplicate package evidence from one project directory."""

from collections.abc import Callable
from pathlib import Path

from agent_bom.models import Package

# Lockfiles each parser reads. When one is present the parser takes its
# versions from it, so a concrete version it left at the default "detected"
# came from that lockfile; otherwise it came from the declaring manifest.
_PARSER_LOCKFILES: dict[str, tuple[str, ...]] = {
    "parse_npm_packages": ("package-lock.json", "npm-shrinkwrap.json"),
    "parse_yarn_lock": ("yarn.lock",),
    "parse_pnpm_lock": ("pnpm-lock.yaml",),
    "parse_bun_packages": ("bun.lock", "bun.lockb"),
    "parse_pip_packages": ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"),
    "parse_conda_environment": ("conda-lock.yml",),
    "parse_go_packages": ("go.sum",),
    "parse_cargo_packages": ("Cargo.lock",),
    "parse_gradle_packages": ("gradle.lockfile",),
    "parse_nuget_packages": ("packages.lock.json",),
    "parse_ruby_packages": ("Gemfile.lock",),
    "parse_php_packages": ("composer.lock",),
    "parse_swift_packages": ("Package.resolved",),
    "parse_hex_packages": ("mix.lock",),
    "parse_pub_packages": ("pubspec.lock",),
}
_INSTALLED_PARSERS = frozenset({"parse_conda_packages"})
_RANGE_CHARS = frozenset("^~<>=*|, ")


def _is_concrete(version: str) -> bool:
    return bool(version) and version not in {"unknown", "latest"} and not (_RANGE_CHARS & set(version))


def _evidence_source(parser_name: str, directory: Path) -> str:
    if parser_name in _INSTALLED_PARSERS:
        return "installed_package"
    lockfiles = _PARSER_LOCKFILES.get(parser_name, ())
    return "lockfile" if any((directory / name).is_file() for name in lockfiles) else "manifest"


def _stamp_version_source(parser: Callable[[Path], list[Package]], directory: Path, packages: list[Package]) -> list[Package]:
    """Record lockfile/manifest provenance on concrete versions the parser left unlabelled."""
    unlabelled = [p for p in packages if p.version_source == "detected" and not p.resolved_from_registry and _is_concrete(p.version)]
    if unlabelled:
        source = _evidence_source(getattr(parser, "__name__", ""), directory)
        for package in unlabelled:
            package.version_source = source
    return packages


def parse_project_packages(directory: Path) -> list[Package]:
    # Resolve the compatibility facade at call time to avoid import cycles.
    from agent_bom import parsers

    packages: list[Package] = []
    for parser in (
        parsers.parse_npm_packages,
        parsers.parse_yarn_lock,
        parsers.parse_pnpm_lock,
        parsers.parse_bun_packages,
        parsers.parse_pip_packages,
        parsers.parse_pip_compile_inputs,
        parsers.parse_conda_environment,
        parsers.parse_conda_packages,
        parsers.parse_go_packages,
        parsers.parse_cargo_packages,
        parsers.parse_maven_packages,
        parsers.parse_gradle_packages,
        parsers.parse_nuget_packages,
        parsers.parse_ruby_packages,
        parsers.parse_php_packages,
        parsers.parse_swift_packages,
        parsers.parse_hex_packages,
        parsers.parse_pub_packages,
    ):
        packages.extend(_stamp_version_source(parser, directory, parser(directory)))
    unique: dict[tuple[str, str, str], Package] = {}
    for package in packages:
        unique.setdefault((package.name, package.version, package.ecosystem), package)
    return list(unique.values())
