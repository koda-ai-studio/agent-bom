"""Dockerfile build-hygiene rules.

DOCKER-023  apt install without --no-install-recommends
DOCKER-024  apt/apk packages installed without a version pin
DOCKER-025  CMD/ENTRYPOINT overridden later in the same stage
DOCKER-026  Credential file copied into the image
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import PurePosixPath

from agent_bom.iac.dockerfile_rules import PKG_OPTION_TOKEN, DockerLine
from agent_bom.iac.models import IaCFinding

_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||[;|\n]")
_COMMAND_PREFIX = r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?"
_APT_INSTALL_RE = re.compile(_COMMAND_PREFIX + r"(?:apt-get|apt)\s+(?:" + PKG_OPTION_TOKEN + r"\s+)*install\b")
_APK_ADD_RE = re.compile(_COMMAND_PREFIX + r"apk\s+(?:-\S+\s+)*add\b")
_NO_RECOMMENDS_RE = re.compile(r"--no-install-recommends\b|APT::Install-Recommends=(?:false|0)\b", re.IGNORECASE)
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*(?::[a-z0-9]+)?$")
_APT_OPTIONS_WITH_VALUE = frozenset({"-o", "-t", "--target-release", "-c", "--config-file"})
_APK_OPTIONS_WITH_VALUE = frozenset({"-t", "--virtual", "-X", "--repository", "--root", "-p", "--arch", "--cache-dir", "--keys-dir"})
_MAX_NAMED_PACKAGES = 5

_CREDENTIAL_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".dockercfg", ".pgpass"}
)
_CREDENTIAL_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore")
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tmpl", ".tpl")
_CREDENTIAL_PATHS = ((".aws", "credentials"), (".docker", "config.json"), (".kube", "config"))


def _segments(run_body: str) -> list[str]:
    return [segment.strip() for segment in _SEGMENT_SPLIT_RE.split(run_body) if segment.strip()]


def _run_body(ln: DockerLine) -> str:
    """The shell part of a RUN, without BuildKit ``--mount``/``--network`` flags."""
    tokens = ln.stripped.split(None, 1)[1] if len(ln.stripped.split(None, 1)) > 1 else ""
    while tokens.startswith("--"):
        tokens = tokens.split(None, 1)[1] if len(tokens.split(None, 1)) > 1 else ""
    return tokens


def docker_023(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-023: apt install without --no-install-recommends."""
    for segment in _segments(_run_body(ln)):
        if _APT_INSTALL_RE.match(segment) and not _NO_RECOMMENDS_RE.search(segment):
            return [
                IaCFinding(
                    rule_id="DOCKER-023",
                    severity="low",
                    title="apt install without --no-install-recommends",
                    message=(
                        "apt installs recommended packages by default, adding software the image does not need. "
                        "Add --no-install-recommends to apt-get install."
                    ),
                    file_path=ln.rel_path,
                    line_number=ln.number,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.3", "NIST-CM-7"],
                    remediation="apt-get install -y --no-install-recommends <pkg>=<version>",
                )
            ]
    return []


def _package_args(segment: str, options_with_value: frozenset[str]) -> list[str]:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    verb = next((i for i, token in enumerate(tokens) if token in ("install", "add")), len(tokens))
    packages: list[str] = []
    skip_next = False
    for token in tokens[verb + 1 :]:
        if skip_next:
            skip_next = False
        elif token in options_with_value:
            skip_next = True
        elif not token.startswith("-"):
            packages.append(token)
    return packages


def _is_unpinned(token: str, pin_chars: str) -> bool:
    if any(char in token for char in pin_chars):
        return False
    return bool(_PACKAGE_NAME_RE.match(token))


def _unpinned_packages(run_body: str) -> list[str]:
    unpinned: list[str] = []
    for segment in _segments(run_body):
        if _APT_INSTALL_RE.match(segment):
            unpinned += [p for p in _package_args(segment, _APT_OPTIONS_WITH_VALUE) if _is_unpinned(p, "=/")]
        elif _APK_ADD_RE.match(segment):
            unpinned += [p for p in _package_args(segment, _APK_OPTIONS_WITH_VALUE) if _is_unpinned(p, "=~<>")]
    return unpinned


def docker_024(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-024: apt/apk packages without a version pin."""
    unpinned = _unpinned_packages(_run_body(ln))
    if not unpinned:
        return []
    named = ", ".join(unpinned[:_MAX_NAMED_PACKAGES]) + (
        f" (+{len(unpinned) - _MAX_NAMED_PACKAGES} more)" if len(unpinned) > _MAX_NAMED_PACKAGES else ""
    )
    return [
        IaCFinding(
            rule_id="DOCKER-024",
            severity="low",
            title="OS packages installed without a version pin",
            message=(
                f"Packages installed without a version: {named}. Unpinned packages make rebuilds pull "
                "whatever the mirror serves that day. Pin versions (apt: pkg=version, apk: pkg=version)."
            ),
            file_path=ln.rel_path,
            line_number=ln.number,
            category="dockerfile",
            compliance=["CIS-Docker-4.7", "NIST-CM-2", "NIST-SI-7"],
        )
    ]


def docker_025(keyword: str, overridden_line: int, rel_path: str) -> IaCFinding:
    """DOCKER-025: a CMD/ENTRYPOINT that a later one in the same stage overrides."""
    return IaCFinding(
        rule_id="DOCKER-025",
        severity="low",
        title=f"{keyword} overridden later in the same stage",
        message=(
            f"Only the last {keyword} in a build stage takes effect; this one is silently ignored. "
            f"Keep a single {keyword} per stage so the image runs what the file appears to say."
        ),
        file_path=rel_path,
        line_number=overridden_line,
        category="dockerfile",
        compliance=["NIST-CM-6"],
    )


def _copy_sources(text: str) -> list[str]:
    body = text.split(None, 1)[1].strip() if len(text.split(None, 1)) > 1 else ""
    flags_done = body
    while flags_done.startswith("--"):
        flags_done = flags_done.split(None, 1)[1].strip() if len(flags_done.split(None, 1)) > 1 else ""
    if flags_done.startswith("["):
        try:
            values = json.loads(flags_done.split("\n", 1)[0])
        except json.JSONDecodeError:
            return []
        return [str(v) for v in values[:-1]] if isinstance(values, list) else []
    tokens = flags_done.split("\n", 1)[0].split()
    return tokens[:-1]


def _is_credential_file(source: str) -> bool:
    path = PurePosixPath(source.rstrip("/"))
    name = path.name
    if name in _CREDENTIAL_NAMES or name.endswith(_CREDENTIAL_SUFFIXES):
        return True
    if name == ".env" or (name.startswith(".env.") and not name.endswith(_ENV_TEMPLATE_SUFFIXES)):
        return True
    parts = path.parts
    return any(parts[-2:] == pair for pair in _CREDENTIAL_PATHS)


def docker_026(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-026: COPY/ADD of a credential file into the image."""
    sources = [source for source in _copy_sources(ln.stripped) if _is_credential_file(source)]
    if not sources:
        return []
    return [
        IaCFinding(
            rule_id="DOCKER-026",
            severity="high",
            title="Credential file copied into the image",
            message=(
                f"{ln.stripped.split(None, 1)[0].upper()} puts {', '.join(sources[:_MAX_NAMED_PACKAGES])} into an image layer, "
                "where anyone who can pull the image can read it, even if a later layer deletes it. "
                "Mount it at build time with RUN --mount=type=secret or inject it at runtime."
            ),
            file_path=ln.rel_path,
            line_number=ln.number,
            category="dockerfile",
            compliance=["CIS-Docker-4.10", "NIST-IA-5", "NIST-SC-28"],
        )
    ]
