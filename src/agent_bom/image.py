"""Native Docker image scanning — extract packages from container images.

Primary strategy:

1. **Docker save + native OCI parser**:
   - ``docker inspect`` to confirm the image exists / pull if needed
   - ``docker save`` to a temporary tarball
   - parse layers natively via :mod:`agent_bom.oci_parser`

Fallback strategy:

2. **Docker export + filesystem parser**:
   - ``docker create`` + ``docker export`` to a temporary tarball
   - scan package manager files directly from the container filesystem

The scanner is native-first and must fail loudly if package extraction fails.

Usage from cli.py::

    from agent_bom.image import scan_image, ImageScanError
    packages, strategy = scan_image("myapp:latest")
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from agent_bom.config import _bool
from agent_bom.core.settings import env_raw
from agent_bom.http_client import is_offline
from agent_bom.image_evidence.base_image import attribute_packages
from agent_bom.image_evidence.daemon import daemon_registry_reference
from agent_bom.image_evidence.model import active_image_evidence
from agent_bom.models import Package, PermissionProfile, Severity, Vulnerability
from agent_bom.oci_registry.client import RegistryError
from agent_bom.oci_registry.manifests import open_client
from agent_bom.oci_registry.platforms import PlatformNotFoundError
from agent_bom.oci_registry.policy import LOCAL_POLICY, RegistryPolicy
from agent_bom.oci_registry.pull import scan_registry_image
from agent_bom.oci_registry.reference import ReferenceError, parse_reference
from agent_bom.oci_registry.supply_chain import discover_supply_chain, resolve_base_layers
from agent_bom.sbom import parse_cyclonedx
from agent_bom.scanners.risk import cvss_to_severity, severity_from_label
from agent_bom.security import validate_image_ref

_logger = logging.getLogger(__name__)
_PLATFORM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){1,2}$")


class ImageScanError(Exception):
    """Raised when an image cannot be scanned."""


# ─── Legacy external-scanner helpers (kept for auth/env compatibility) ──────

_GRYPE_TYPE_MAP: dict[str, str] = {
    "java-archive": "maven",
    "npm": "npm",
    "python": "pypi",
    "go-module": "go",
    "rust-crate": "cargo",
    "gem": "gem",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "dotnet": "nuget",
    "binary": "binary",
}


def _grype_available() -> bool:
    return shutil.which("grype") is not None


def _validate_platform(platform: Optional[str]) -> Optional[str]:
    if platform is None:
        return None
    if not _PLATFORM_RE.match(platform):
        from agent_bom.security import SecurityError

        raise SecurityError(f"Invalid container platform: {platform!r}")
    return platform


def _build_scanner_env(
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    user_env_prefix: str = "GRYPE",
) -> dict[str, str] | None:
    """Build subprocess env dict with registry auth credentials.

    Returns None (inherit parent env) when no auth is configured.
    """
    user = registry_user or os.environ.get("AGENT_BOM_REGISTRY_USER")
    passwd = registry_pass or os.environ.get("AGENT_BOM_REGISTRY_PASS")
    if not user or not passwd:
        return None
    env = dict(os.environ)
    env[f"{user_env_prefix}_REGISTRY_AUTH_USERNAME"] = user
    env[f"{user_env_prefix}_REGISTRY_AUTH_PASSWORD"] = passwd
    return env


def _cvss_score_from_grype_vulnerability(vuln_data: dict) -> Optional[float]:
    for cvss in vuln_data.get("cvss", []):
        metrics = cvss.get("metrics", {})
        score = metrics.get("baseScore")
        if score is not None:
            return float(score)
    return None


def _severity_from_grype_vulnerability(vuln_data: dict, cvss_score: Optional[float]) -> Severity:
    severity = severity_from_label(vuln_data.get("severity"))
    if severity == Severity.UNKNOWN and cvss_score is not None:
        return cvss_to_severity(cvss_score)
    return severity


def _related_grype_vulnerabilities(match: dict, vuln_data: dict) -> list[dict]:
    related: list[dict] = []
    for source in (match.get("relatedVulnerabilities"), vuln_data.get("relatedVulnerabilities")):
        if isinstance(source, list):
            related.extend(item for item in source if isinstance(item, dict))
    return related


def _debian_related_cve_fallback(match: dict, vuln_data: dict) -> tuple[Optional[Severity], Optional[float]]:
    vuln_id = str(vuln_data.get("id") or "")
    if not vuln_id.startswith("DEBIAN-CVE-"):
        return None, None
    for related in _related_grype_vulnerabilities(match, vuln_data):
        related_id = str(related.get("id") or "")
        if not related_id.startswith("CVE-"):
            continue
        related_score = _cvss_score_from_grype_vulnerability(related)
        related_severity = _severity_from_grype_vulnerability(related, related_score)
        if related_severity != Severity.UNKNOWN or related_score is not None:
            return related_severity, related_score
    return None, None


def _image_grype_fallback_enabled() -> bool:
    return _bool("AGENT_BOM_IMAGE_GRYPE_FALLBACK", False)


def _packages_from_grype_json(data: dict) -> list[Package]:
    """Build Package objects with pre-populated vulnerabilities from Grype JSON."""
    pkg_map: dict[tuple[str, str, str], Package] = {}

    for match in data.get("matches", []):
        artifact = match.get("artifact", {})
        vuln_data = match.get("vulnerability", {})

        raw_type = artifact.get("type", "").lower()
        ecosystem = _GRYPE_TYPE_MAP.get(raw_type, raw_type or "unknown")
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        if not name or not version:
            continue

        key = (ecosystem, name, version)
        if key not in pkg_map:
            pkg_map[key] = Package(name=name, version=version, ecosystem=ecosystem)

        pkg = pkg_map[key]

        vuln_id = vuln_data.get("id", "")
        if not vuln_id:
            continue

        cvss_score = _cvss_score_from_grype_vulnerability(vuln_data)
        severity = _severity_from_grype_vulnerability(vuln_data, cvss_score)
        if severity == Severity.UNKNOWN and cvss_score is None:
            fallback_severity, fallback_score = _debian_related_cve_fallback(match, vuln_data)
            if fallback_score is not None:
                cvss_score = fallback_score
            if fallback_severity is not None:
                severity = fallback_severity

        fix_info = vuln_data.get("fix", {})
        fixed_versions = fix_info.get("versions", [])
        fixed_version = fixed_versions[0] if fixed_versions else None

        if not any(v.id == vuln_id for v in pkg.vulnerabilities):
            pkg.vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=vuln_data.get("description", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    fixed_version=fixed_version,
                )
            )

    return list(pkg_map.values())


def _run_grype_json(
    target: str,
    *,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
    timeout: int = 300,
) -> dict:
    """Run Grype against a target and return parsed JSON."""
    platform = _validate_platform(platform)
    cmd = ["grype", target, "-o", "json", "--quiet"]
    if platform:
        cmd += ["--platform", platform]
    env = _build_scanner_env(registry_user, registry_pass, "GRYPE")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        raise ImageScanError("grype not found")
    except subprocess.TimeoutExpired:
        raise ImageScanError(f"grype timed out scanning {target}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ImageScanError(f"grype exited {result.returncode}: {stderr[:200]}")

    stdout = result.stdout.strip()
    if not stdout:
        raise ImageScanError("grype produced empty output")

    # Grype may print log lines before JSON on some versions; parse the last JSON object.
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        data = None
        for idx, char in enumerate(stdout):
            if char != "{":
                continue
            try:
                data, _end = decoder.raw_decode(stdout[idx:])
            except json.JSONDecodeError:
                continue
        if data is None:
            raise ImageScanError("grype produced invalid JSON")
        return data


def _scan_with_grype(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
) -> list[Package]:
    """Run Grype and return packages with vulnerabilities pre-populated.

    Grype returns packages + CVEs in a single call, covering all ecosystems
    (npm, cargo, go modules, maven, gems, .NET, deb, rpm, apk, Python).
    No secondary OSV query is needed for image packages.
    """
    image_ref = validate_image_ref(image_ref)
    data = _run_grype_json(
        image_ref,
        registry_user=registry_user,
        registry_pass=registry_pass,
        platform=platform,
    )
    return _packages_from_grype_json(data)


def _grype_archive_target(tar_path: Path) -> str:
    """Return the Grype target string for a saved image archive."""
    resolved = tar_path.resolve()
    if resolved.is_dir():
        return f"oci-dir:{resolved}"
    suffix = resolved.suffix.lower()
    if suffix in {".tar", ".tgz"} or resolved.name.endswith(".tar.gz"):
        return f"docker-archive:{resolved}"
    return f"oci-archive:{resolved}"


def _scan_archive_with_grype(tar_path: str | Path) -> list[Package]:
    """Run Grype against a docker save / OCI archive tarball or layout directory."""
    path = Path(tar_path)
    if not path.exists():
        raise ImageScanError(f"Image archive not found: {tar_path}")
    target = _grype_archive_target(path)
    data = _run_grype_json(target)
    return _packages_from_grype_json(data)


# ─── Syft strategy ────────────────────────────────────────────────────────────


def _syft_available() -> bool:
    return shutil.which("syft") is not None


def _scan_with_syft(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
) -> list[Package]:
    """Run Syft and parse its CycloneDX JSON output."""
    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    cmd = ["syft", image_ref, "-o", "cyclonedx-json", "--quiet"]
    if platform:
        cmd += ["--platform", platform]
    env = _build_scanner_env(registry_user, registry_pass, "SYFT")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except FileNotFoundError:
        raise ImageScanError("syft not found")
    except subprocess.TimeoutExpired:
        raise ImageScanError(f"syft timed out scanning {image_ref}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ImageScanError(f"syft exited {result.returncode}: {stderr[:200]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ImageScanError(f"syft produced invalid JSON: {e}")

    return parse_cyclonedx(data)


# ─── Docker CLI fallback ──────────────────────────────────────────────────────


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_inspect(image_ref: str, platform: Optional[str] = None) -> dict:
    """Return docker inspect output for the image (pulls if needed)."""
    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    try:
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        raise ImageScanError("docker not found")

    if result.returncode != 0:
        # Try pulling first
        pull_cmd = ["docker", "pull"]
        if platform:
            pull_cmd += ["--platform", platform]
        pull_cmd.append(image_ref)
        pull = subprocess.run(
            pull_cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if pull.returncode != 0:
            # Keep the daemon's own reason. `_docker_available` only proves the
            # binary exists, so the common failure here is a stopped daemon or a
            # missing registry credential — both unactionable without the stderr.
            reason = (pull.stderr or pull.stdout or "").strip().splitlines()
            detail = f" — {reason[-1][:300]}" if reason else ""
            raise ImageScanError(f"Image not found locally and pull failed: {image_ref}{detail}")
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )

    try:
        return json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError) as e:
        raise ImageScanError(f"docker inspect output parse error: {e}")


def detect_image_privileges(image_ref: str) -> PermissionProfile:
    """Extract privilege info from a Docker image (without running it).

    Uses ``docker inspect --type image`` to check:
    - Config.User: empty/"0"/"root" → runs_as_root
    - Config.ExposedPorts → network_access
    - Config.Volumes → filesystem_write
    """
    try:
        data = _docker_inspect(image_ref)
    except ImageScanError:
        return PermissionProfile()

    config = data.get("Config", {})

    user = config.get("User", "")
    runs_as_root = user in ("", "0", "root")

    exposed_ports = config.get("ExposedPorts") or {}
    network_access = bool(exposed_ports)

    volumes = config.get("Volumes") or {}
    filesystem_write = bool(volumes)

    return PermissionProfile(
        runs_as_root=runs_as_root,
        network_access=network_access,
        filesystem_write=filesystem_write,
    )


def detect_container_privileges(container_id: str) -> PermissionProfile:
    """Extract privilege info from a running or created container.

    Uses ``docker inspect`` on a container to check:
    - Config.User → runs_as_root
    - HostConfig.Privileged → container_privileged
    - HostConfig.CapAdd/CapDrop → capabilities
    - HostConfig.SecurityOpt → security_opt
    - HostConfig.NetworkMode → network_access (host mode)
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return PermissionProfile()

    if result.returncode != 0:
        return PermissionProfile()

    try:
        data = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError):
        return PermissionProfile()

    config = data.get("Config", {})
    host_config = data.get("HostConfig", {})

    user = config.get("User", "")
    runs_as_root = user in ("", "0", "root")

    container_privileged = host_config.get("Privileged", False)

    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []
    capabilities = [c for c in cap_add if c not in cap_drop]

    security_opt = host_config.get("SecurityOpt") or []

    network_mode = host_config.get("NetworkMode", "")
    network_access = network_mode in ("host", "bridge", "default", "")

    return PermissionProfile(
        runs_as_root=runs_as_root,
        container_privileged=container_privileged,
        capabilities=capabilities,
        security_opt=security_opt,
        network_access=network_access,
    )


def _packages_from_tar(tar_path: Path | str) -> list[Package]:
    """Extract packages from a ``docker export`` filesystem tar.

    The flattened filesystem goes through the same bounded walk and package
    extractors as image layers; any limit it crosses is a recorded coverage gap.
    """
    from agent_bom.parsers.oci_rootfs import scan_rootfs_tar

    return scan_rootfs_tar(Path(tar_path))


def _record_daemon_inspect(data: object) -> None:
    """Registry digest and platform of a daemon image, for signature lookup and evidence."""
    evidence = active_image_evidence()
    if evidence is None or not isinstance(data, dict):
        return
    ref = daemon_registry_reference(evidence.reference, data.get("RepoDigests"))
    if ref:
        evidence.registry, evidence.repository, evidence.digest = ref.registry, ref.repository, ref.digest
    os_name, arch = data.get("Os"), data.get("Architecture")
    if os_name and arch:
        evidence.platform = f"{os_name}/{arch}" + (f"/{data['Variant']}" if data.get("Variant") else "")


def _scan_with_docker(image_ref: str, platform: Optional[str] = None) -> list[Package]:
    """Scan a Docker image natively and fail if no packages can be extracted."""
    from agent_bom.oci_parser import OCIParseError, scan_oci

    image_ref = validate_image_ref(image_ref)
    platform = _validate_platform(platform)
    platform_args = ["--platform", platform] if platform else []

    _record_daemon_inspect(_docker_inspect(image_ref, platform=platform))

    with tempfile.TemporaryDirectory() as tmpdir:
        oci_tar_path = Path(tmpdir) / "image.tar"
        save = subprocess.run(
            ["docker", "save", *platform_args, "-o", str(oci_tar_path), image_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if save.returncode != 0:
            stderr = (save.stderr or "").strip()
            raise ImageScanError(f"docker save failed: {stderr[:200]}")

        try:
            packages, _strategy = scan_oci(oci_tar_path)
        except OCIParseError as exc:
            _logger.debug("Native OCI parse failed for %s: %s", image_ref, exc)
        else:
            if packages:
                return packages
            _logger.debug("Native OCI parse returned 0 packages for %s; falling back to docker export", image_ref)

    container_id: Optional[str] = None
    try:
        # Create a stopped container
        result = subprocess.run(
            ["docker", "create", *platform_args, image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise ImageScanError(f"docker create failed: {result.stderr.strip()[:200]}")
        container_id = result.stdout.strip()

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "fs.tar"

            export = subprocess.run(
                ["docker", "export", "-o", str(tar_path), container_id],
                capture_output=True,
                timeout=300,
            )
            if export.returncode != 0:
                raise ImageScanError("docker export failed")

            packages = _packages_from_tar(tar_path)
            if packages:
                return packages

        raise ImageScanError(
            f"Native image scan extracted 0 packages from {image_ref}. This is likely an extraction or parser failure, not a clean scan."
        )

    finally:
        if container_id:
            try:
                rm_result = subprocess.run(
                    ["docker", "rm", container_id],
                    capture_output=True,
                    timeout=30,
                )
                if rm_result.returncode != 0:
                    import logging as _logging

                    _logging.getLogger(__name__).warning(
                        "docker rm %s failed (exit %d): %s",
                        container_id,
                        rm_result.returncode,
                        rm_result.stderr.strip()[:100],
                    )
            except (subprocess.TimeoutExpired, OSError) as cleanup_err:
                import logging as _logging

                _logging.getLogger(__name__).warning("docker rm %s error: %s", container_id, cleanup_err)


# ─── Public API ───────────────────────────────────────────────────────────────


def detect_multi_arch(image_ref: str) -> list[str]:
    """Detect platforms available in a multi-arch manifest list.

    Uses ``docker manifest inspect`` to list available platforms.
    Returns list of platform strings like ``["linux/amd64", "linux/arm64"]``.
    Returns empty list if not a manifest list or docker is unavailable.
    """
    image_ref = validate_image_ref(image_ref)
    if not _docker_available():
        return []
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    platforms: list[str] = []
    for manifest in data.get("manifests", []):
        p = manifest.get("platform", {})
        os_name = p.get("os", "")
        arch = p.get("architecture", "")
        if os_name and arch:
            variant = p.get("variant", "")
            platform_str = f"{os_name}/{arch}"
            if variant:
                platform_str += f"/{variant}"
            platforms.append(platform_str)
    return platforms


PULL_MODES = ("auto", "registry", "daemon")


def _pull_mode(pull_mode: Optional[str], server_context: bool = False) -> str:
    mode = (pull_mode or env_raw("AGENT_BOM_IMAGE_PULL_MODE") or "auto").strip().lower()
    if mode not in PULL_MODES:
        raise ImageScanError(f"Unknown image pull mode {mode!r}; expected one of {', '.join(PULL_MODES)}")
    # A server-side scan never reaches the Docker daemon unless the operator chose daemon mode:
    # the daemon pulls with the host's ambient credentials and network and holds other tenants' images.
    return "registry" if server_context and mode == "auto" else mode


def _names_registry_host(image_ref: str) -> bool:
    """Whether the reference's first path component is a registry host (distribution reference grammar)."""
    first, sep, _rest = image_ref.split("@", 1)[0].partition("/")
    return bool(sep) and ("." in first or ":" in first or first == "localhost")


def _local_daemon_has_image(image_ref: str) -> bool:
    """Whether the local Docker image store already holds ``image_ref`` (never pulls)."""
    if not _docker_available():
        return False
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _prefers_local_image(image_ref: str, mode: str, server_context: bool) -> bool:
    """Auto mode scans a local image named by a host-less reference instead of resolving it to Docker Hub."""
    return mode == "auto" and not server_context and not _names_registry_host(image_ref) and _local_daemon_has_image(image_ref)


def _scan_from_registry(
    image_ref: str, registry_user: Optional[str], registry_pass: Optional[str], platform: Optional[str], policy: RegistryPolicy
) -> list[Package]:
    packages = scan_registry_image(image_ref, platform=platform, registry_user=registry_user, registry_pass=registry_pass, policy=policy)
    if not packages:
        raise ImageScanError(
            f"Native image scan extracted 0 packages from {image_ref}. This is likely an extraction or parser failure, not a clean scan."
        )
    return packages


def _daemon_supply_chain(image_ref: str, registry_user: Optional[str], registry_pass: Optional[str]) -> None:
    """Look up signatures/referrers for a daemon-scanned image by its registry digest (online only)."""
    evidence = active_image_evidence()
    if evidence is None:
        return
    if is_offline():
        evidence.signature = {"status": "unknown", "detail": "Offline scan: the registry was not queried for signatures."}
        return
    if not (evidence.registry and evidence.repository and evidence.digest):
        evidence.signature = {"status": "unknown", "detail": "The local image has no unambiguous repository-qualified registry digest."}
        return
    try:
        ref = parse_reference(f"{evidence.registry}/{evidence.repository}@{evidence.digest}")
        with open_client(ref, registry_user, registry_pass) as client:
            discover_supply_chain(client, evidence, None)
    except (ReferenceError, RegistryError) as exc:
        evidence.signature = {"status": "unknown", "detail": f"Signature lookup failed: {exc}"}


def _attribute_base_image(
    packages: list[Package], registry_user: Optional[str], registry_pass: Optional[str], policy: RegistryPolicy = LOCAL_POLICY
) -> None:
    evidence = active_image_evidence()
    if evidence is None or evidence.base_image is None:
        return
    if not is_offline():
        resolve_base_layers(evidence, lambda ref: open_client(ref, registry_user, registry_pass, policy=policy), policy)
    attribute_packages(evidence, packages)


def scan_image(
    image_ref: str,
    registry_user: Optional[str] = None,
    registry_pass: Optional[str] = None,
    platform: Optional[str] = None,
    pull_mode: Optional[str] = None,
    server_context: bool = False,
) -> tuple[list[Package], str]:
    """Scan a container image and return (packages, strategy_used).

    Strategy order (``pull_mode="auto"``, the default):
    0. A reference without a registry host (``acme/app:dev``) that the local
       Docker daemon already holds is scanned from the daemon: it would
       otherwise resolve to a same-named, possibly squatted Docker Hub image.
    1. Registry pull over the OCI distribution API — no Docker daemon needed
       (strategy ``"registry"``).
    2. Only if that fails: Docker save → native OCI parser, then Docker export
       (strategy ``"native"``). ``pull_mode="daemon"`` skips the registry and
       ``pull_mode="registry"`` never touches the daemon. ``--offline`` scans
       never contact a registry.

    ``server_context=True`` (API scan jobs, the MCP server) applies the
    server-side registry policy (see :mod:`agent_bom.oci_registry.policy`) and
    never uses the Docker daemon unless the operator set daemon mode.

    Raises:
        ImageScanError: If neither path can produce a package inventory.
    """
    validate_image_ref(image_ref)
    _validate_platform(platform)
    mode = _pull_mode(pull_mode, server_context)
    policy = RegistryPolicy.for_server() if server_context else LOCAL_POLICY
    registry_failure: str | None = None
    local_first = _prefers_local_image(image_ref, mode, server_context)
    if mode != "daemon" and not is_offline() and not local_first:
        try:
            packages = _scan_from_registry(image_ref, registry_user, registry_pass, platform, policy)
        except (RegistryError, ReferenceError, PlatformNotFoundError, ImageScanError, OSError) as exc:
            registry_failure = str(exc)
            if mode == "registry":
                raise ImageScanError(f"Registry pull failed for {image_ref}: {registry_failure}") from exc
        else:
            _attribute_base_image(packages, registry_user, registry_pass, policy)
            return packages, "registry"
    elif mode == "registry":
        raise ImageScanError("Registry pull mode needs network access; --offline scans can only use the Docker daemon or --image-tar.")

    prefix = f"Registry pull failed ({registry_failure}). " if registry_failure else ""
    if not _docker_available():
        raise ImageScanError(
            f"{prefix}Docker is not available. Install Docker to enable native image scanning, "
            "or use 'docker save <image> -o image.tar' and pass the tarball with --image-tar."
        )
    evidence = active_image_evidence()
    if registry_failure:
        _logger.warning("Registry pull failed for %s; falling back to the local Docker daemon: %s", image_ref, registry_failure)
        if evidence is not None:
            evidence.note(f"Registry pull failed ({registry_failure}); scanned through the local Docker daemon instead.")
    if evidence is not None:
        evidence.restart()
        evidence.source = "daemon"
        if local_first:
            evidence.note(
                f"{image_ref} has no registry host and exists as a local Docker image; scanned the local Docker image, "
                "not a same-named Docker Hub image."
            )
    packages = _scan_with_docker(image_ref, platform)
    _daemon_supply_chain(image_ref, registry_user, registry_pass)
    _attribute_base_image(packages, registry_user, registry_pass)
    return packages, "native"


def scan_image_tar(tar_path: str) -> tuple[list[Package], str]:
    """Scan a pre-saved OCI image tarball or layout directory — no Docker/Syft/Grype required.

    Accepts tarballs created by ``docker save``, ``skopeo copy``, or ``crane pull``.

    Args:
        tar_path: Path to the image tarball (``.tar``) or OCI layout directory.

    Returns:
        A tuple ``(packages, strategy)`` where strategy is ``"oci-tarball"``
        or ``"oci-layout-dir"``.

    Raises:
        ImageScanError: If the tarball cannot be parsed.
    """
    from agent_bom.oci_parser import OCIParseError, scan_oci

    path = Path(tar_path)
    if not path.exists():
        raise ImageScanError(f"Image tarball not found: {tar_path}")
    try:
        packages, strategy = scan_oci(path)
    except OCIParseError as e:
        raise ImageScanError(f"OCI parse error: {e}") from e

    if _image_grype_fallback_enabled() and _grype_available():
        try:
            grype_packages = _scan_archive_with_grype(path)
        except ImageScanError as exc:
            _logger.debug("Grype archive fallback skipped for %s: %s", tar_path, exc)
        else:
            if grype_packages:
                grype_vulns = sum(len(pkg.vulnerabilities) for pkg in grype_packages)
                if grype_vulns > 0 or len(grype_packages) > len(packages):
                    return grype_packages, "grype-archive"

    return packages, strategy


def image_to_purl(image_ref: str) -> str:
    """Convert a Docker image reference to a Package URL.

    Examples:
      nginx:1.25               → pkg:oci/nginx:1.25
      ghcr.io/org/app:v1.0.0  → pkg:oci/org/app:v1.0.0?repository_url=ghcr.io
    """
    if "://" in image_ref:
        # Strip protocol if someone passes a full URL
        image_ref = image_ref.split("://", 1)[1]

    parts = image_ref.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        # Has a registry hostname
        registry, rest = parts
        return f"pkg:oci/{rest}?repository_url={registry}"
    else:
        return f"pkg:oci/{image_ref}"
