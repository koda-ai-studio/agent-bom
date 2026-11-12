#!/usr/bin/env python3
"""Build the remote-MCP agent-bom lookup package for the OpenAI plugin directory.

A separate listing from the skills-only package in ``integrations/codex``: it
declares one remote, no-login MCP server (``deploy/docker/Dockerfile.public-mcp``)
that serves only the ``public`` profile's lookup tools. This script packs
``integrations/openai-mcp`` with an explicit allowlist, checks the manifests
against the limits in the directory's submission and submission-errors pages
(final-submission limits where they are stricter), and writes a reproducible
ZIP to ``dist/agent-bom-openai-mcp-plugin.zip``.

Usage::

    python scripts/build_openai_mcp_plugin_zip.py
    python scripts/build_openai_mcp_plugin_zip.py --output /tmp/agent-bom-openai-mcp-plugin.zip
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "integrations" / "openai-mcp"
DEFAULT_OUTPUT = ROOT / "dist" / "agent-bom-openai-mcp-plugin.zip"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
OAUTH_HOST = "agent-bom-mcp.up.railway.app"

_ALLOWED = (
    re.compile(r"plugin\.json"),
    re.compile(r"mcp\.json"),
    re.compile(r"README\.md"),
    re.compile(r"LICENSE"),
    re.compile(r"assets/[a-z0-9-]+\.png"),
)
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_COLOR = re.compile(r"#[0-9A-Fa-f]{6}")
_MENTION = re.compile(r"(^|\s)@[A-Za-z0-9_-]")
_TEXT_LIMITS = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
_SINGLE_LINE = ("displayName", "shortDescription", "developerName")
_URL_KEYS = ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL")
_ICON_KEYS = ("logo", "composerIcon")
_FORBIDDEN_KEYS = ("apps", "hooks", "skills", "mcpServers", "requires_local_executor", "test_credentials", "reviewer_instructions")
_POSITIVE_FIELDS = {"description", "prompt", "tools_triggered", "expected_behavior"}
_POSITIVE_OPTIONAL = {"file_attachment_urls", "expected_output_url"}
_SERVER_KEYS = {"type", "url"}
_MAX_IMAGE_BYTES = 5 * 1024 * 1024


class PackageError(ValueError):
    """The package would be rejected by the directory, or would misdescribe the server."""


def _served_tools() -> frozenset[str]:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.mcp_tools.profiles import get_profile

    tools = get_profile("public").tools
    if not tools:
        raise PackageError("the public profile registers no tools")
    return tools


def validate_names(names: list[str]) -> None:
    for name in names:
        if ".." in name.split("/") or not any(pattern.fullmatch(name) for pattern in _ALLOWED):
            raise PackageError(f"{name}: not allowed in the remote MCP package")


def _https_url(value: Any, field: str, limit: int) -> None:
    if not isinstance(value, str) or len(value) > limit:
        raise PackageError(f"{field} must be an HTTPS URL of at most {limit} characters")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or "@" in parts.netloc:
        raise PackageError(f"{field} must be an HTTPS URL without credentials")


def _luminance(color: str) -> float:
    channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _png_side(path: Path) -> int:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) > _MAX_IMAGE_BYTES:
        raise PackageError(f"{path.name}: icons must be PNG files of at most 5 MiB")
    width, height = struct.unpack(">II", data[16:24])
    if width != height or not 48 <= width <= 4096:
        raise PackageError(f"{path.name}: icons must be square, 48 to 4096 pixels")
    return int(width)


def _validate_top_level(manifest: dict[str, Any], openai: dict[str, Any]) -> None:
    for key in _FORBIDDEN_KEYS:
        if key in manifest or key in openai or key in openai.get("review", {}):
            raise PackageError(f"manifest declares `{key}`, which this remote MCP package must not carry")
    name = manifest.get("name")
    if not isinstance(name, str) or len(name) > 64 or not _NAME.fullmatch(name):
        raise PackageError("name must be at most 64 lowercase letters, digits and single hyphens")
    version = manifest.get("version")
    if not isinstance(version, str) or len(version) > 64 or not _SEMVER.fullmatch(version):
        raise PackageError("version must be a semantic version such as 1.0.0")
    description = manifest.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        raise PackageError("description must be 1-1024 characters")
    author = manifest.get("author")
    if not isinstance(author, dict) or not isinstance(author.get("name"), str) or not 0 < len(author["name"]) <= 120:
        raise PackageError("author.name must be 1-120 characters")
    if "url" in author:
        _https_url(author["url"], "author.url", 2048)
    if "homepage" in manifest:
        _https_url(manifest["homepage"], "homepage", 2048)


def _validate_interface(interface: dict[str, Any], plugin: Path) -> list[str]:
    for key, limit in _TEXT_LIMITS.items():
        value = interface.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise PackageError(f"interface.{key} must be 1-{limit} characters")
        if key in _SINGLE_LINE and "\n" in value:
            raise PackageError(f"interface.{key} must be a single line")
    if not isinstance(interface.get("category"), str) or not interface["category"]:
        raise PackageError("interface.category is required")
    capabilities = interface.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) > 20:
        raise PackageError("interface.capabilities must be a list of at most 20 entries")
    if any(not isinstance(item, str) or not item or len(item) > 120 or "\n" in item for item in capabilities):
        raise PackageError("interface.capabilities entries must be single lines of 1-120 characters")
    for key in _URL_KEYS:
        _https_url(interface.get(key), f"interface.{key}", 1024)
    prompts = interface.get("defaultPrompt")
    if not isinstance(prompts, list) or not 0 < len(prompts) <= 3:
        raise PackageError("interface.defaultPrompt needs 1-3 prompts")
    normalized = [" ".join(str(prompt).split()).casefold() for prompt in prompts]
    if len(set(normalized)) != len(normalized):
        raise PackageError("interface.defaultPrompt entries must be unique")
    for prompt in prompts:
        if not isinstance(prompt, str) or len(prompt) > 128 or "\n" in prompt or _MENTION.search(prompt):
            raise PackageError("interface.defaultPrompt entries must be single lines of at most 128 characters without @mentions")
    for key, background in (("brandColor", "#FFFFFF"), ("brandColorDark", "#212121")):
        color = interface.get(key)
        if color is None:
            continue
        if not isinstance(color, str) or not _COLOR.fullmatch(color) or _contrast(color, background) < 2:
            raise PackageError(f"interface.{key} must be #RRGGBB with at least 2:1 contrast against {background}")
    referenced = []
    for key in _ICON_KEYS:
        relative = interface.get(key)
        if not isinstance(relative, str) or not relative.startswith("./"):
            raise PackageError(f"interface.{key} must be a package path starting with ./")
        target = (plugin / relative).resolve()
        if not target.is_relative_to(plugin.resolve()) or not target.is_file():
            raise PackageError(f"interface.{key}: {relative} is missing or outside the plugin")
        _png_side(target)
        referenced.append(relative[2:])
    return referenced


def _validate_review(review: dict[str, Any], tools: frozenset[str]) -> None:
    cases = review.get("test_cases")
    if not isinstance(cases, dict):
        raise PackageError("review.test_cases is required")
    positive, negative = cases.get("positive"), cases.get("negative")
    if not isinstance(positive, list) or len(positive) != 5 or not isinstance(negative, list) or len(negative) != 3:
        raise PackageError("review.test_cases needs exactly 5 positive and 3 negative cases")
    for case in positive:
        if not isinstance(case, dict) or not _POSITIVE_FIELDS <= set(case) or set(case) - _POSITIVE_FIELDS - _POSITIVE_OPTIONAL:
            raise PackageError(f"positive cases need exactly {sorted(_POSITIVE_FIELDS)} plus optional {sorted(_POSITIVE_OPTIONAL)}")
        if any(not isinstance(case[key], str) or not case[key].strip() for key in _POSITIVE_FIELDS):
            raise PackageError("positive case fields must be non-empty strings")
        triggered = {name.strip() for name in case["tools_triggered"].split(",")}
        if not triggered <= tools:
            raise PackageError(f"positive case triggers {sorted(triggered - tools)}, which the public server has not served")
    for case in negative:
        if not isinstance(case, dict) or set(case) != {"description", "prompt"} or not all(str(value).strip() for value in case.values()):
            raise PackageError("negative cases need exactly a non-empty description and prompt")


def validate_manifest(manifest: dict[str, Any], plugin: Path = PLUGIN) -> list[str]:
    """Check plugin.json; return the package-relative files it references."""
    openai = manifest.get("extensions", {}).get("com.openai")
    if not isinstance(openai, dict):
        raise PackageError("manifest needs extensions.com.openai")
    _validate_top_level(manifest, openai)
    interface = openai.get("interface")
    if not isinstance(interface, dict):
        raise PackageError("extensions.com.openai.interface is required")
    referenced = _validate_interface(interface, plugin)
    _validate_review(openai.get("review") or {}, _served_tools())
    notes = (openai.get("publication") or {}).get("release_notes")
    if not isinstance(notes, str) or not notes.strip():
        raise PackageError("publication.release_notes is required")
    return referenced


def validate_mcp_config(config: Any) -> str:
    """Check mcp.json; return the declared server URL."""
    servers = config.get("mcpServers") if isinstance(config, dict) else None
    if not isinstance(servers, dict):
        raise PackageError("mcp.json needs an mcpServers object")
    if len(servers) != 1:
        raise PackageError("mcp.json must declare exactly one remote MCP server")
    name, server = next(iter(servers.items()))
    if not str(name).strip() or not isinstance(server, dict):
        raise PackageError("the MCP server needs a name and an object value")
    extra = sorted(set(server) - _SERVER_KEYS)
    if extra:
        raise PackageError(f"MCP server keys {extra} are not allowed: no headers, clientSecret or other credentials")
    if server.get("type") != "streamable-http":
        raise PackageError("MCP server type must be streamable-http")
    url = server.get("url")
    _https_url(url, "MCP server url", 2048)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        raise PackageError("MCP server url must have no query or fragment")
    if parts.path != "/mcp":
        raise PackageError("MCP server url path must be /mcp")
    if parts.hostname == OAUTH_HOST:
        raise PackageError("MCP server url names the OAuth server; this package lists the public lookup server")
    return str(url)


def collect(plugin: Path = PLUGIN) -> dict[str, Path]:
    """Map archive names to source files, allowlisted and validated."""
    files: dict[str, Path] = {
        "plugin.json": plugin / "plugin.json",
        "mcp.json": plugin / "mcp.json",
        "README.md": plugin / "README.md",
        "LICENSE": ROOT / "LICENSE",
    }
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        raise PackageError(f"missing package files: {missing}")
    for relative in validate_manifest(json.loads(files["plugin.json"].read_text(encoding="utf-8")), plugin):
        files[relative] = plugin / relative
    validate_mcp_config(json.loads(files["mcp.json"].read_text(encoding="utf-8")))
    validate_names(list(files))
    return files


def write_zip(files: dict[str, Path], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[name].read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="ZIP path to write")
    args = parser.parse_args(argv)
    try:
        files = collect()
    except PackageError as exc:
        print(f"build_openai_mcp_plugin_zip: {exc}", file=sys.stderr)
        return 1
    write_zip(files, args.output)
    print(f"wrote {args.output} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
