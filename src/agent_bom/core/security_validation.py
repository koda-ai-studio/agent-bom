"""Input validation for files, packages, URLs, and MCP launch configuration.

Launcher validation is configuration hygiene, not process isolation. Network
validation rejects non-public destinations unless explicitly overridden and
always rejects cloud metadata endpoints.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path

from agent_bom.core.settings import env_raw

logger = logging.getLogger("agent_bom.security")

# Recognized MCP server launcher binaries (package managers, runtimes, and
# container tools commonly used to launch MCP servers).
#
# This list is a misconfiguration/typo guard for the stdio proxy spawn path —
# it is NOT a sandbox and NOT an isolation boundary. Every binary here can
# execute arbitrary code with the proxy's full host privileges; membership
# only means the command *shape* looks like a plausible MCP launcher. The
# actual execution control is container isolation via
# ``agent_bom.proxy_sandbox`` (``--isolate`` / AGENT_BOM_MCP_SANDBOX).
KNOWN_MCP_LAUNCHERS = {
    # JavaScript/TypeScript runtimes & package managers
    "npx",
    "npm",
    "node",
    "deno",
    "bun",
    "tsx",
    # Python runtimes & package managers
    "python",
    "python3",
    "uvx",
    "uv",
    "pipx",
    # Go
    "go",
    # Java/JVM
    "java",
    "mvn",
    "gradle",
    # .NET
    "dotnet",
    # Ruby
    "ruby",
    "bundle",
    # Rust
    "cargo",
    # Container tools (MCP servers often run in containers)
    "docker",
    "podman",
    # Common MCP server launchers
    "mcp",
    "mcp-server",
}

# Dangerous environment variables that should never be set
DANGEROUS_ENV_VARS = {
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",  # Can be used for code injection
    "NODE_OPTIONS",  # Can inject malicious code
}

# Shell metacharacters rejected by validate_arguments. agent-bom itself spawns
# MCP servers via an exec array (never a shell), so these characters are not
# interpreted on our spawn path; the check flags configs that appear to expect
# shell interpolation. Config hygiene, not an execution control.
SHELL_METACHARACTERS = {";", "|", "&", "$", "`", "<", ">", "\n", "\r"}


class SecurityError(Exception):
    """Raised when a security validation fails."""

    pass


_NOT_A_SANDBOX = (
    "This check guards against misconfigured server commands only — it is not a sandbox. "
    "Use container isolation (--isolate) to restrict what a server can do."
)
# ``python3.13``, ``node22``, ``npx-cli.js``: a launcher name plus a version or
# package-manager shim suffix still names the same launcher.
_LAUNCHER_NAME_RE = re.compile(r"^(?P<base>[a-z][a-z0-9-]*?)(?:[-._]?\d+(?:\.\d+)*)?(?:-cli)?(?:\.(?:js|cjs|mjs|py|sh|cmd|exe))?$")


def _launcher_basename_known(name: str) -> bool:
    lowered = name.lower()
    if lowered in KNOWN_MCP_LAUNCHERS:
        return True
    match = _LAUNCHER_NAME_RE.match(lowered)
    return bool(match and match.group("base") in KNOWN_MCP_LAUNCHERS)


def _unrecognized(label: str) -> SecurityError:
    recognized = ", ".join(sorted(KNOWN_MCP_LAUNCHERS))
    return SecurityError(f"Command '{label}' is not a recognized MCP launcher. Recognized launchers: {recognized}. {_NOT_A_SANDBOX}")


def _require_launcher_file(command: str) -> None:
    """Accept an absolute launcher path only when the file it names checks out.

    The basename must be a known launcher, the path must be normalized (no
    ``.``/``..`` segments), and the file — after following symlinks — must
    exist, be a regular executable file that is not world-writable, in a
    directory that is not world-writable (sticky bit included: ``/tmp`` is
    never a launcher home). A symlink's target must itself name a launcher
    (``python`` -> ``python3.13``, ``npx`` -> ``npx-cli.js``). Messages carry
    the basename only.
    """
    path = Path(command)
    name = path.name
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise SecurityError(f"Command '{name}' must be a bare launcher name or a normalized absolute path. {_NOT_A_SANDBOX}")
    if not _launcher_basename_known(name):
        raise _unrecognized(name)
    try:
        resolved = path.resolve(strict=True)
        link_parent_mode = path.parent.stat().st_mode
        target = resolved.stat()
        target_parent_mode = resolved.parent.stat().st_mode
    except (OSError, RuntimeError):
        raise SecurityError(f"Launcher '{name}' does not exist at the configured absolute path. {_NOT_A_SANDBOX}") from None
    if resolved.name != name and not _launcher_basename_known(resolved.name):
        raise SecurityError(f"Launcher '{name}' resolves to '{resolved.name}', which is not a recognized MCP launcher. {_NOT_A_SANDBOX}")
    if not stat.S_ISREG(target.st_mode):
        raise SecurityError(f"Launcher '{name}' is not a regular file. {_NOT_A_SANDBOX}")
    if not target.st_mode & 0o111:
        raise SecurityError(f"Launcher '{name}' is not executable. {_NOT_A_SANDBOX}")
    if target.st_mode & stat.S_IWOTH:
        raise SecurityError(f"Launcher '{name}' is world-writable; any local user could replace it. {_NOT_A_SANDBOX}")
    if (link_parent_mode | target_parent_mode) & stat.S_IWOTH:
        raise SecurityError(f"Launcher '{name}' sits in a world-writable directory; any local user could swap it. {_NOT_A_SANDBOX}")
    logger.debug("Absolute-path launcher '%s' accepted (resolves to a '%s' file)", name, resolved.name)


def require_recognized_launcher(command: str) -> None:
    """
    Require that *command* is a recognized MCP launcher binary.

    This is a launch-hygiene check that catches typos and obviously
    misconfigured server commands before the proxy spawns them. It provides
    NO isolation: every recognized launcher (``python``, ``node``,
    ``docker``, …) can still execute arbitrary code as the host user.
    Passing this check must never be read as "the server is sandboxed" —
    the real execution control is container isolation via
    ``agent_bom.proxy_sandbox`` (``--isolate``).

    A bare name must be in :data:`KNOWN_MCP_LAUNCHERS`. An absolute path
    (``/Users/me/.venv/bin/python``, as Claude Desktop-style configs write it)
    is accepted when its basename is a known launcher and the file passes the
    checks in :func:`_require_launcher_file`; relative paths are rejected.

    Args:
        command: The launcher command to check

    Raises:
        SecurityError: If command is not a recognized MCP launcher
    """
    if command in KNOWN_MCP_LAUNCHERS:
        logger.debug(f"Command '{command}' is a recognized MCP launcher")
        return
    if "/" in command or "\\" in command:
        _require_launcher_file(command)
        return
    raise _unrecognized(command)


def validate_arguments(args: list[str]) -> None:
    """
    Reject command arguments containing shell metacharacters.

    Config-hygiene check: agent-bom spawns MCP servers via an exec array
    (never through a shell), so these characters are not interpreted on our
    spawn path. An argument that contains them was almost certainly written
    for shell interpolation and indicates a misconfigured server entry.
    This is not an execution control and confers no isolation.

    Args:
        args: List of command arguments

    Raises:
        SecurityError: If shell metacharacters found
    """
    for arg in args:
        for char in SHELL_METACHARACTERS:
            if char in arg:
                raise SecurityError(f"Dangerous character '{char}' found in argument: {arg}")
    logger.debug(f"Validated {len(args)} argument(s) successfully")


def validate_environment(env: dict[str, str]) -> None:
    """
    Validate environment variables for dangerous settings.

    Args:
        env: Dictionary of environment variables

    Raises:
        SecurityError: If dangerous environment variable found
    """
    for var in env:
        if var in DANGEROUS_ENV_VARS:
            raise SecurityError(f"Dangerous environment variable '{var}' not allowed")
    logger.debug(f"Validated {len(env)} environment variable(s)")


def validate_path(
    path: str | Path,
    must_exist: bool = False,
    restrict_to_home: bool = False,
    allowed_roots: Sequence[Path] = (),
) -> Path:
    """
    Validate and normalize a file path.

    Args:
        path: Path to validate
        must_exist: If True, path must exist
        restrict_to_home: If True, path must resolve inside the user's home directory
            or inside one of ``allowed_roots``
        allowed_roots: Additional already-resolved directories accepted when
            ``restrict_to_home`` is set

    Returns:
        Validated and normalized Path object

    Raises:
        SecurityError: If path is invalid or contains path traversal
    """
    path = Path(path).expanduser()

    # Resolve to absolute path (prevents path traversal)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path '{path}': {e}")

    # Restrict to home / configured roots (MCP server user-provided paths). The
    # check runs on the resolved path, so a symlink out of a root is rejected.
    if restrict_to_home and not any(resolved.is_relative_to(root) for root in (Path.home().resolve(), *allowed_roots)):
        if allowed_roots:
            raise SecurityError(f"Path resolves outside home directory and configured workspace roots: {path}")
        raise SecurityError(f"Path resolves outside home directory: {path}")

    # Check for path traversal attempts (on unresolved path)
    if ".." in path.parts:
        logger.warning(f"Path traversal attempt detected: {path}")
        raise SecurityError(f"Path traversal not allowed: {path}")

    # Check if path must exist
    if must_exist and not resolved.exists():
        raise SecurityError(f"Path does not exist: {resolved}")

    logger.debug(f"Validated path: {resolved}")
    return resolved


def validate_file_size(path: Path, max_size_bytes: int = 10 * 1024 * 1024) -> None:
    """
    Validate that a file is not too large (DoS prevention).

    Args:
        path: Path to file
        max_size_bytes: Maximum allowed file size (default 10MB)

    Raises:
        SecurityError: If file is too large
    """
    try:
        size = os.path.getsize(path)
        if size > max_size_bytes:
            raise SecurityError(f"File too large: {size} bytes (max: {max_size_bytes} bytes)")
        logger.debug(f"File size OK: {size} bytes")
    except OSError as e:
        raise SecurityError(f"Cannot check file size: {e}")


def validate_json_file(path: Path) -> dict:
    """
    Safely load and validate a JSON file.

    Args:
        path: Path to JSON file

    Returns:
        Parsed JSON data

    Raises:
        SecurityError: If file is invalid or too large
    """
    # Validate path
    path = validate_path(path, must_exist=True)

    # Check file size (DoS prevention)
    validate_file_size(path)

    # Load JSON safely (json.load is safe, doesn't execute code)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Successfully loaded JSON from {path}")
        return data
    except json.JSONDecodeError as e:
        raise SecurityError(f"Invalid JSON in {path}: {e}")
    except (OSError, UnicodeDecodeError) as e:
        raise SecurityError(f"Cannot read file {path}: {e}")


# Cloud instance-metadata endpoints are never a legitimate egress target, even
# under the private-egress operator override (AWS/GCP/Azure/OCI, Alibaba Cloud).
_CLOUD_METADATA_HOSTS = frozenset({"169.254.169.254", "100.100.100.200", "metadata.google.internal"})


def _unwrap_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def _is_non_public_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address that is not publicly routable unicast.

    ``is_private`` alone misses CGNAT shared space (100.64.0.0/10, where the
    Alibaba Cloud metadata service lives) and multicast.
    """
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or not addr.is_global
    )


def validate_package_name(name: str, ecosystem: str) -> None:
    """
    Validate package name follows ecosystem conventions.

    Args:
        name: Package name
        ecosystem: Package ecosystem (npm, pypi, go, cargo)

    Raises:
        SecurityError: If package name is invalid
    """
    if not name or not isinstance(name, str):
        raise SecurityError(f"Invalid package name: {name}")

    # Ecosystem-specific validation
    if ecosystem == "npm":
        # Scan existing packages too: npm's legacy names allow uppercase and
        # URL-safe punctuation, including dots. Publishing rules are stricter.
        if (
            not re.fullmatch(r"(@[a-zA-Z0-9._~!'()*-]+/)?[a-zA-Z0-9._~!'()*-]+", name)
            or name.startswith((".", "_", "-"))
            or name.rsplit("/", 1)[-1].startswith(".")
            or name.lower() in {"node_modules", "favicon.ico"}
        ):
            raise SecurityError(f"Invalid npm package name: {name}")

    elif ecosystem == "pypi":
        # PyPI: alphanumeric, hyphens, underscores, dots
        if not re.fullmatch(r"[a-zA-Z0-9-_.]+", name):
            raise SecurityError(f"Invalid PyPI package name: {name}")

    elif ecosystem == "go":
        # Go: domain/path format
        if not re.fullmatch(r"[a-zA-Z0-9-_.\/]+", name):
            raise SecurityError(f"Invalid Go package name: {name}")

    elif ecosystem == "cargo":
        # Rust: alphanumeric, hyphens, underscores
        if not re.fullmatch(r"[a-zA-Z0-9-_]+", name):
            raise SecurityError(f"Invalid Cargo package name: {name}")

    logger.debug(f"Package name validated: {name} ({ecosystem})")


def create_safe_subprocess_env() -> dict[str, str]:
    """
    Create a minimal, safe environment for subprocess execution.

    Returns:
        Dictionary with minimal safe environment variables
    """
    # Only include essential environment variables
    safe_env = {
        "PATH": env_raw("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": env_raw("HOME", "/tmp"),  # nosec B108 - safe fallback for subprocess when HOME not set
        "LANG": env_raw("LANG", "en_US.UTF-8"),
    }

    # Add npm/node specific vars if present
    if (registry := env_raw("NPM_CONFIG_REGISTRY")) is not None:
        safe_env["NPM_CONFIG_REGISTRY"] = registry

    return safe_env


# Docker/OCI image reference pattern — must start with alphanum, no shell metacharacters
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]+$")


def validate_image_ref(ref: str) -> str:
    """Validate a Docker/OCI image reference.

    Rejects references starting with ``-`` (argument injection) and those
    containing shell metacharacters.

    Returns:
        The validated reference string.

    Raises:
        SecurityError: If the reference is invalid.
    """
    if not ref or not _IMAGE_REF_RE.match(ref):
        raise SecurityError(f"Invalid image reference: {ref!r}")
    return ref
