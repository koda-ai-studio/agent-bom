"""Dockerfile rule checks.

Each ``docker_NNN`` function evaluates the rule(s) for one instruction line and
returns their findings. ``scan_dockerfile`` dispatches every line to the checks
registered for its instruction (see ``DOCKER_LINE_RULES``).
"""

from __future__ import annotations

import re
import shlex
from typing import NamedTuple

from agent_bom.iac.models import IaCFinding

# New rule patterns
_CHMOD_777_RE = re.compile(r"chmod\s+(?:-[A-Za-z]+\s+)*0?777\b", re.IGNORECASE)
_COPY_CHMOD_777_RE = re.compile(r"--chmod\s*=\s*0?777\b", re.IGNORECASE)
_REMOTE_ADD_RE = re.compile(r"\bhttps?://", re.IGNORECASE)
_SUDO_RE = re.compile(r"\bsudo\b", re.IGNORECASE)
# ``uv pip install`` spells the same opt-out ``--no-cache``.
_PIP_NO_CACHE_RE = re.compile(r"pip3?\s+install(?!.*--no-cache(?:-dir)?\b)", re.IGNORECASE)
_NET_HOST_RE = re.compile(r"--network\s*=\s*host", re.IGNORECASE)

# Regex patterns for secret-like ENV variable names
SECRET_ENV_NAME_RE = re.compile(
    r"(?:API[_\-]?KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE[_\-]?KEY|"
    r"ACCESS[_\-]?KEY|AUTH[_\-]?TOKEN|BEARER|DB_PASS)",
    re.IGNORECASE,
)
_SECRET_ENV_RE = SECRET_ENV_NAME_RE
_INTERPOLATED_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*(?:[:?-][^}]*)?\}?$")
_NON_SECRET_VALUES = frozenset({"true", "false", "yes", "no", "on", "off", "none", "null"})

# Pipe install patterns: curl ... | sh, wget ... | bash, etc.
_PIPE_INSTALL_RE = re.compile(
    r"(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh|python|perl)",
    re.IGNORECASE,
)

# One package-manager option token with exactly one parse: ``-flag``, or ``Word::Word`` that never
# starts with ``-``, so runs of colon or dash-colon tokens cannot backtrack exponentially.
PKG_OPTION_TOKEN = r"(?:-\S*|(?:[^\s:-][^\s:]*)?(?:::[^\s:]*)+)"

# Package manager install without cache cleanup
_PKG_INSTALL_RE = re.compile(
    r"\b(?:apt-get|apt|apk|yum|dnf|microdnf|zypper)\s+(?:" + PKG_OPTION_TOKEN + r"\s+)*(?:install|add)\b",
    re.IGNORECASE,
)

# Cleanup in the same RUN, or a BuildKit cache mount that keeps the cache out of the layer.
_CACHE_CLEANUP_RE = re.compile(
    r"(?:--no-cache\b|rm\s+-(?:rf|fr)\s+/var/(?:cache|lib/apt)|\bapt(?:-get)?\s+clean|"
    r"\b(?:yum|dnf|microdnf|zypper)\s+clean\b|--mount=type=cache)",
    re.IGNORECASE,
)


class DockerLine(NamedTuple):
    """One non-comment Dockerfile line as the rule checks see it."""

    stripped: str
    upper: str
    number: int
    rel_path: str
    dockerignore_exists: bool


def docker_001_010(ln: DockerLine, image: str) -> list[IaCFinding]:
    """DOCKER-001 (FROM uses :latest or no tag) and DOCKER-010 (no digest pin) for a resolved base image."""
    findings: list[IaCFinding] = []
    if image.lower() != "scratch" and "@" not in image:
        if ":" not in image.rsplit("/", 1)[-1]:
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-001",
                    severity="high",
                    title="FROM uses no tag (defaults to :latest)",
                    message=(f"Image '{image}' has no explicit tag. Pin to a specific version tag for reproducible builds."),
                    file_path=ln.rel_path,
                    line_number=ln.number,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.7", "NIST-CM-6"],
                )
            )
        elif image.endswith(":latest"):
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-001",
                    severity="high",
                    title="FROM uses :latest tag",
                    message=(f"Image '{image}' uses the :latest tag. Pin to a specific version for reproducible builds."),
                    file_path=ln.rel_path,
                    line_number=ln.number,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.7", "NIST-CM-6"],
                )
            )

    # DOCKER-010 is independent of DOCKER-001: a mutable tag and a missing
    # digest are separate controls, and pinning a version tag fixes only one.
    if image.lower() != "scratch" and "@sha256:" not in image:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-010",
                severity="medium",
                title="FROM without digest pin",
                message=(f"Image '{image}' is not pinned by digest (sha256). Use @sha256:<hash> to guarantee immutable base images."),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.7", "NIST-SI-7"],
            )
        )
    return findings


def is_root_user(user: str) -> bool:
    """``root`` / ``0`` with or without a group."""
    return user.split(":", 1)[0].strip().strip("'\"") in ("root", "0")


def docker_002(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-002: the final stage's last USER is root."""
    findings: list[IaCFinding] = []
    user_val = ln.stripped.split(maxsplit=1)[1].strip() if len(ln.stripped.split()) > 1 else ""
    if is_root_user(user_val):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-002",
                severity="high",
                title="Container runs as root",
                message=("USER is set to root. Containers should run as a non-root user to limit blast radius of exploits."),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.1", "NIST-AC-6"],
            )
        )
    return findings


def env_pairs(body: str) -> list[tuple[str, str]]:
    """``KEY=VALUE ...`` pairs (or the legacy single ``KEY VALUE`` form) of an ENV instruction."""
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    if tokens and "=" not in tokens[0]:
        return [(tokens[0], " ".join(tokens[1:]))]
    return [(key.strip(), value.strip()) for key, sep, value in (token.partition("=") for token in tokens) if sep]


def is_hardcoded_secret(name: str, value: str) -> bool:
    """A secret-named variable holding a literal secret value.

    ``*_FILE`` variables and absolute paths point at a mounted secret file
    (the recommended pattern); interpolations, booleans and numbers are not
    literal secrets.
    """
    value = value.strip().strip("'\"")
    if not SECRET_ENV_NAME_RE.search(name) or not value or name.upper().endswith(("_FILE", "_PATH", "_DIR")):
        return False
    if _INTERPOLATED_RE.match(value) or value.startswith("/") or value.lower() in _NON_SECRET_VALUES:
        return False
    return not value.isdigit()


def docker_003(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-003: Hardcoded secrets in ENV (every pair on the line)."""
    findings: list[IaCFinding] = []
    for key, value in env_pairs(ln.stripped[4:].strip()):
        if not is_hardcoded_secret(key, value) or len(value.strip("'\"")) < 8:
            continue
        findings.append(
            IaCFinding(
                rule_id="DOCKER-003",
                severity="critical",
                title="Hardcoded secret in ENV",
                message=(
                    f"ENV variable '{key}' appears to contain a hardcoded secret. "
                    "Use build args with --secret, multi-stage builds, or runtime "
                    "secret injection instead."
                ),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.10", "NIST-IA-5"],
            )
        )
    return findings


def docker_004_022(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-004 (ADD instead of COPY) and DOCKER-022 (ADD fetches a remote URL)."""
    findings: list[IaCFinding] = []
    # A remote ADD is DOCKER-022 (high); DOCKER-004 covers only local ADD.
    if not _REMOTE_ADD_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-004",
                severity="medium",
                title="ADD used instead of COPY",
                message=(
                    "ADD can fetch remote URLs and auto-extract archives, introducing "
                    "supply chain risk. Use COPY unless you specifically need ADD features."
                ),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.9", "NIST-CM-7"],
            )
        )
    else:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-022",
                severity="high",
                title="ADD fetches a remote URL",
                message=(
                    "ADD downloads remote content during the image build. Fetch artifacts in a verified step and pin checksums before COPY."
                ),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.9", "NIST-SI-7", "NIST-CM-7"],
            )
        )
    return findings


def docker_005_007(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-005 (pipe install) and DOCKER-007 (package install without cache cleanup)."""
    findings: list[IaCFinding] = []
    run_body = ln.stripped[4:]
    if _PIPE_INSTALL_RE.search(run_body):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-005",
                severity="medium",
                title="Pipe install detected (curl|sh)",
                message=("Piping remote scripts directly to a shell bypasses integrity checks. Download, verify checksums, then execute."),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.9", "NIST-SI-7"],
            )
        )

    # DOCKER-007: Package install without cache cleanup
    if _PKG_INSTALL_RE.search(run_body) and not _CACHE_CLEANUP_RE.search(run_body):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-007",
                severity="high",
                title="Package install without cache cleanup",
                message=(
                    "Package manager install without --no-cache or cache removal "
                    "increases image size and attack surface. Add --no-cache or "
                    "'&& rm -rf /var/cache/*' after install."
                ),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.3", "NIST-CM-7"],
            )
        )
    return findings


def docker_008(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-008: EXPOSE 22."""
    findings: list[IaCFinding] = []
    ports = ln.stripped.split()[1:]
    for port in ports:
        port_num = port.split("/")[0]  # handle "22/tcp"
        if port_num == "22":
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-008",
                    severity="medium",
                    title="SSH port exposed",
                    message=(
                        "Port 22 (SSH) is exposed. Containers should not run SSH daemons — use 'docker exec' or orchestrator tools instead."
                    ),
                    file_path=ln.rel_path,
                    line_number=ln.number,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.5", "NIST-CM-7"],
                )
            )
    return findings


def docker_009(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-009: COPY . . without .dockerignore."""
    findings: list[IaCFinding] = []
    args = ln.stripped.split()
    if len(args) >= 3 and args[1] == "." and args[2] == ".":
        if not ln.dockerignore_exists:
            findings.append(
                IaCFinding(
                    rule_id="DOCKER-009",
                    severity="high",
                    title="COPY . . without .dockerignore",
                    message=(
                        "COPY . . copies the entire build context into the image. "
                        "Without a .dockerignore, secrets, .git, and other sensitive "
                        "files may be included. Create a .dockerignore file."
                    ),
                    file_path=ln.rel_path,
                    line_number=ln.number,
                    category="dockerfile",
                    compliance=["CIS-Docker-4.10", "NIST-CM-6"],
                )
            )
    return findings


def docker_011(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-011: COPY --chown with UID 0."""
    findings: list[IaCFinding] = []
    if "--chown=0" in ln.stripped.lower():
        findings.append(
            IaCFinding(
                rule_id="DOCKER-011",
                severity="medium",
                title="COPY --chown=0 (root ownership)",
                message="COPY with --chown=0 explicitly sets root ownership. Use a non-root UID.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.1", "NIST-AC-6"],
            )
        )
    return findings


def docker_021(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-021: COPY --chmod=777."""
    findings: list[IaCFinding] = []
    if _COPY_CHMOD_777_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-021",
                severity="high",
                title="COPY --chmod grants world-writable permissions",
                message=("COPY --chmod=777 makes copied files world-writable. Use the least-permissive mode required by the runtime user."),
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.8", "NIST-AC-3", "NIST-CM-6"],
            )
        )
    return findings


def docker_012(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-012: RUN chmod 777."""
    findings: list[IaCFinding] = []
    if _CHMOD_777_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-012",
                severity="high",
                title="RUN chmod 777 (world-writable files)",
                message="chmod 777 makes files world-writable. Use specific permissions (e.g. 755 for dirs, 644 for files).",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.8", "NIST-AC-3"],
            )
        )
    return findings


def docker_013(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-013: EXPOSE range of ports."""
    findings: list[IaCFinding] = []
    if "-" in ln.stripped.split(None, 1)[-1]:
        findings.append(
            IaCFinding(
                rule_id="DOCKER-013",
                severity="medium",
                title="EXPOSE port range (excessive attack surface)",
                message="Exposing a range of ports increases attack surface. Expose only specific required ports.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-5.8", "NIST-CM-7"],
            )
        )
    return findings


def docker_014(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-014: RUN with sudo."""
    findings: list[IaCFinding] = []
    if _SUDO_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-014",
                severity="medium",
                title="RUN with sudo (unnecessary privilege escalation)",
                message="sudo in Dockerfile is unnecessary — RUN already executes as the current user. Remove sudo.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.1", "NIST-AC-6"],
            )
        )
    return findings


def docker_015(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-015: ARG used for secrets."""
    findings: list[IaCFinding] = []
    if SECRET_ENV_NAME_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-015",
                severity="critical",
                title="ARG used for secrets (visible in image history)",
                message="ARG values are stored in image history. Use BuildKit secrets (--mount=type=secret) instead.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.10", "NIST-SC-12"],
            )
        )
    return findings


def docker_017(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-017: RUN pip install without --no-cache-dir."""
    findings: list[IaCFinding] = []
    if _PIP_NO_CACHE_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-017",
                severity="low",
                title="pip install without --no-cache-dir",
                message="pip caches downloaded packages. Add --no-cache-dir to reduce image size.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.9"],
            )
        )
    return findings


def docker_018(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-018: WORKDIR uses relative path."""
    findings: list[IaCFinding] = []
    target = ln.stripped.split(None, 1)[-1].strip().strip("'\"")
    if not target.startswith(("/", "$")) and not re.match(r"^[A-Za-z]:[\\/]", target):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-018",
                severity="low",
                title="WORKDIR uses relative path",
                message="Use absolute paths in WORKDIR for clarity and predictability.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-4.9"],
            )
        )
    return findings


def docker_019(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-019: SHELL instruction overrides default."""
    findings: list[IaCFinding] = []
    findings.append(
        IaCFinding(
            rule_id="DOCKER-019",
            severity="medium",
            title="SHELL instruction overrides default shell",
            message="Custom SHELL changes RUN behavior. Ensure it's intentional and documented.",
            file_path=ln.rel_path,
            line_number=ln.number,
            category="dockerfile",
            compliance=["NIST-CM-6"],
        )
    )
    return findings


def docker_020(ln: DockerLine) -> list[IaCFinding]:
    """DOCKER-020: RUN with --network=host."""
    findings: list[IaCFinding] = []
    if _NET_HOST_RE.search(ln.stripped):
        findings.append(
            IaCFinding(
                rule_id="DOCKER-020",
                severity="high",
                title="RUN with --network=host (shares host network during build)",
                message="--network=host in RUN exposes host network during build. Use default bridge network.",
                file_path=ln.rel_path,
                line_number=ln.number,
                category="dockerfile",
                compliance=["CIS-Docker-5.1", "NIST-SC-7"],
            )
        )
    return findings
