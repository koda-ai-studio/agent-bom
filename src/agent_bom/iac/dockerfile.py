"""Dockerfile misconfiguration scanner.

Scans Dockerfiles for common security misconfigurations using line-by-line
regex-based analysis.  No external tools required.

Rules
-----
DOCKER-001  FROM uses :latest or no tag
DOCKER-002  Final stage runs as root (last USER is root, or no USER at all)
DOCKER-003  Hardcoded secrets in ENV
DOCKER-004  ADD used instead of COPY (ADD can fetch remote URLs)
DOCKER-005  RUN with curl|sh or wget|bash (pipe install)
DOCKER-006  No HEALTHCHECK directive
DOCKER-007  RUN apt-get/apk/yum without --no-cache or rm -rf /var/cache
DOCKER-008  Exposed port 22 (SSH)
DOCKER-009  COPY . . without .dockerignore (may copy secrets)
DOCKER-010  FROM with unpinned base image (no hash pin)
DOCKER-011  COPY --chown with UID 0 (root ownership)
DOCKER-012  RUN chmod 777 (world-writable files)
DOCKER-013  EXPOSE range of ports (excessive surface)
DOCKER-014  RUN with sudo (unnecessary privilege escalation)
DOCKER-015  ARG used for secrets (visible in image history)
DOCKER-016  Multiple FROM without multi-stage naming
DOCKER-017  RUN pip install without --no-cache-dir
DOCKER-018  WORKDIR uses relative path
DOCKER-019  SHELL instruction overrides default shell
DOCKER-020  RUN with net=host (container shares host network during build)
DOCKER-021  COPY --chmod grants world-writable permissions
DOCKER-022  ADD fetches remote URL

Instructions are evaluated as logical lines (continuations joined, heredoc
bodies attached; see ``dockerfile_parse``) and reported at their first line.
Runtime rules (DOCKER-002) look at the final build stage only, following
``FROM <stage>`` inheritance; ``FROM`` rules resolve global ``ARG`` defaults
and skip stage aliases and unresolvable references.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from agent_bom.iac.dockerfile_parse import Stage, parse_arg, parse_from, parse_instructions, resolve_args
from agent_bom.iac.dockerfile_rules import (
    _CACHE_CLEANUP_RE,
    _CHMOD_777_RE,
    _COPY_CHMOD_777_RE,
    _NET_HOST_RE,
    _PIP_NO_CACHE_RE,
    _PIPE_INSTALL_RE,
    _PKG_INSTALL_RE,
    _REMOTE_ADD_RE,
    _SECRET_ENV_RE,
    _SUDO_RE,
    DockerLine,
    docker_001_010,
    docker_002,
    docker_003,
    docker_004_022,
    docker_005_007,
    docker_008,
    docker_009,
    docker_011,
    docker_012,
    docker_013,
    docker_014,
    docker_015,
    docker_017,
    docker_018,
    docker_019,
    docker_020,
    docker_021,
    is_root_user,
)
from agent_bom.iac.models import IaCFinding

__all__ = [
    "_CACHE_CLEANUP_RE",
    "_CHMOD_777_RE",
    "_COPY_CHMOD_777_RE",
    "_NET_HOST_RE",
    "_PIPE_INSTALL_RE",
    "_PIP_NO_CACHE_RE",
    "_PKG_INSTALL_RE",
    "_REMOTE_ADD_RE",
    "_SECRET_ENV_RE",
    "_SUDO_RE",
    "scan_dockerfile",
]

DockerCheck = Callable[[DockerLine], list[IaCFinding]]

# Per-line rules in evaluation order, keyed by the instruction prefix they guard on.
DOCKER_LINE_RULES: tuple[tuple[str, DockerCheck], ...] = (
    ("ENV ", docker_003),
    ("ADD ", docker_004_022),
    ("RUN ", docker_005_007),
    ("EXPOSE ", docker_008),
    ("COPY ", docker_009),
    ("COPY ", docker_011),
    ("COPY ", docker_021),
    ("RUN ", docker_012),
    ("EXPOSE ", docker_013),
    ("RUN ", docker_014),
    ("ARG ", docker_015),
    ("RUN ", docker_017),
    ("WORKDIR ", docker_018),
    ("SHELL ", docker_019),
    ("RUN ", docker_020),
)


def _checks_by_prefix() -> dict[str, tuple[DockerCheck, ...]]:
    by_prefix: dict[str, list[DockerCheck]] = {}
    for prefix, check in DOCKER_LINE_RULES:
        by_prefix.setdefault(prefix, []).append(check)
    return {prefix: tuple(checks) for prefix, checks in by_prefix.items()}


_CHECKS_BY_PREFIX = _checks_by_prefix()


def _from_findings(ln: DockerLine, text: str, stages: list[Stage], args: dict[str, str]) -> list[IaCFinding]:
    raw_image, alias = parse_from(text)
    parent = next((stage for stage in reversed(stages) if stage.alias and stage.alias == raw_image.lower()), None)
    image = None if parent is not None else resolve_args(raw_image, args)
    stages.append(Stage(from_line=ln.number, image=image, alias=alias.lower() if alias else None, parent=parent))
    return docker_001_010(ln, image) if image else []


def _final_stage_user_findings(stage: Stage, rel_path: str) -> list[IaCFinding]:
    user, user_line = stage.effective_user()
    if user is not None:
        if not is_root_user(user):
            return []
        text = f"USER {user}"
        return docker_002(DockerLine(stripped=text, upper=text.upper(), number=user_line, rel_path=rel_path, dockerignore_exists=False))
    base = (stage.base_image() or "").lower().split("@", 1)[0]
    if base.rsplit(":", 1)[-1].endswith("nonroot"):
        return []
    return [
        IaCFinding(
            rule_id="DOCKER-002",
            severity="high",
            title="No USER directive (runs as root)",
            message=(
                "The final build stage sets no USER, so the container runs as root by default. Add a USER directive with a non-root user."
            ),
            file_path=rel_path,
            line_number=stage.from_line,
            category="dockerfile",
            compliance=["CIS-Docker-4.1", "NIST-AC-6"],
        )
    ]


def scan_dockerfile(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single Dockerfile for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Dockerfile.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    rel_path = str(path)
    findings: list[IaCFinding] = []

    has_healthcheck = False
    dockerignore_exists = (path.parent / ".dockerignore").exists()
    stages: list[Stage] = []
    global_args: dict[str, str] = {}

    for instruction in parse_instructions(content):
        stripped = instruction.text
        if len(stripped.split(None, 1)) < 2:
            continue
        upper = stripped.upper()
        prefix = instruction.keyword + " "
        ln = DockerLine(stripped=stripped, upper=upper, number=instruction.line, rel_path=rel_path, dockerignore_exists=dockerignore_exists)
        if prefix == "FROM ":
            findings.extend(_from_findings(ln, stripped, stages, global_args))
        elif prefix == "ARG " and not stages:
            name, default = parse_arg(stripped)
            global_args[name] = default
        elif prefix == "USER " and stages:
            stages[-1].user = stripped.split(None, 1)[1].strip()
            stages[-1].user_line = instruction.line
        elif prefix == "HEALTHCHECK ":
            has_healthcheck = True
        for check in _CHECKS_BY_PREFIX.get(prefix, ()):
            findings.extend(check(ln))

    if stages:
        findings.extend(_final_stage_user_findings(stages[-1], rel_path))
    # DOCKER-006: No HEALTHCHECK
    if not has_healthcheck:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-006",
                severity="low",
                title="No HEALTHCHECK directive",
                message=(
                    "No HEALTHCHECK instruction found. Add a HEALTHCHECK to enable "
                    "container health monitoring and automatic restart on failure."
                ),
                file_path=rel_path,
                line_number=1,
                category="dockerfile",
                compliance=["CIS-Docker-4.6", "NIST-SI-4"],
            )
        )

    return findings
