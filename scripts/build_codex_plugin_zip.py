#!/usr/bin/env python3
"""Build the skills-only agent-bom package for the public Codex plugin directory.

The directory accepts a ZIP whose plugin has no lifecycle hooks, no app
references (``apps`` / ``.app.json``) and, for a local plugin, no MCP
configuration: local plugins are listed as skills-only. This script packs
``integrations/codex`` with an explicit allowlist, validates the manifests
against the listing limits, and writes a reproducible ZIP (fixed timestamps
and order) to ``dist/agent-bom-codex-plugin.zip``.

Usage::

    python scripts/build_codex_plugin_zip.py
    python scripts/build_codex_plugin_zip.py --output /tmp/agent-bom-codex-plugin.zip
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

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "integrations" / "codex"
DEFAULT_OUTPUT = ROOT / "dist" / "agent-bom-codex-plugin.zip"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)

_ALLOWED = (
    re.compile(r"plugin\.json"),
    re.compile(r"\.codex-plugin/plugin\.json"),
    re.compile(r"README\.md"),
    re.compile(r"LICENSE"),
    re.compile(r"skills/[a-z0-9-]+/SKILL\.md"),
    re.compile(r"assets/[a-z0-9-]+\.png"),
)
_FORBIDDEN = re.compile(r"(^|/)(hooks(/|$)|hooks\.json$|\.app\.json$|\.?mcp\.json$)")
_TEXT_LIMITS = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
_URL_KEYS = ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL")
_ICON_KEYS = ("logo", "composerIcon")
_MAX_IMAGE_BYTES = 5 * 1024 * 1024


class PackageError(ValueError):
    """The package would be rejected by the public directory."""


def validate_names(names: list[str]) -> None:
    for name in names:
        if _FORBIDDEN.search(name) or not any(pattern.fullmatch(name) for pattern in _ALLOWED):
            raise PackageError(f"{name}: not allowed in the public skills-only package")


def _interface(manifest: dict[str, Any]) -> dict[str, Any]:
    interface = manifest.get("extensions", {}).get("com.openai", {}).get("interface")
    if interface is None:
        interface = manifest.get("interface")
    if not isinstance(interface, dict):
        raise PackageError("manifest has no interface")
    return interface


def validate_manifest(manifest: dict[str, Any]) -> None:
    openai = manifest.get("extensions", {}).get("com.openai", {})
    for key in ("apps", "hooks", "mcpServers"):
        if key in manifest or key in openai:
            raise PackageError(f"manifest declares `{key}`, which a skills-only listing cannot carry")
    interface = _interface(manifest)
    for key, limit in _TEXT_LIMITS.items():
        value = interface.get(key)
        if not isinstance(value, str) or not value or len(value) > limit:
            raise PackageError(f"interface.{key} must be 1-{limit} characters")
    prompts = interface.get("defaultPrompt", [])
    if len(prompts) > 3 or any(len(prompt) > 128 for prompt in prompts):
        raise PackageError("interface.defaultPrompt allows at most 3 prompts of at most 128 characters")
    for key in _URL_KEYS:
        url = interface.get(key, "")
        if not url.startswith("https://") or len(url) > 1024 or "@" in url or "#" in url.split("/")[2]:
            raise PackageError(f"interface.{key} must be an HTTPS URL without credentials")


def _png_square_side(path: Path) -> int:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) > _MAX_IMAGE_BYTES:
        raise PackageError(f"{path.name}: icons must be PNG files of at most 5 MiB")
    width, height = struct.unpack(">II", data[16:24])
    if width != height or width < 48:
        raise PackageError(f"{path.name}: icons must be square and at least 48x48 pixels")
    return int(width)


def validate_references(manifest: dict[str, Any], plugin: Path) -> list[str]:
    """Return the package-relative paths the manifest references, checked."""
    interface = _interface(manifest)
    referenced = [interface[key] for key in _ICON_KEYS] + list(interface.get("screenshots", []))
    names = []
    for relative in referenced:
        if not relative.startswith("./"):
            raise PackageError(f"{relative}: manifest paths must start with ./")
        target = (plugin / relative).resolve()
        if not target.is_relative_to(plugin.resolve()) or not target.is_file():
            raise PackageError(f"{relative}: referenced file is missing or outside the plugin")
        if relative in (interface[key] for key in _ICON_KEYS):
            _png_square_side(target)
        names.append(relative[2:])
    return names


def collect(plugin: Path = PLUGIN) -> dict[str, Path]:
    """Map archive names to source files, allowlisted and validated."""
    files: dict[str, Path] = {
        "plugin.json": plugin / "plugin.json",
        ".codex-plugin/plugin.json": plugin / ".codex-plugin" / "plugin.json",
        "README.md": plugin / "README.md",
        "LICENSE": ROOT / "LICENSE",
    }
    for skill in sorted((plugin / "skills").glob("*/SKILL.md")):
        files[f"skills/{skill.parent.name}/SKILL.md"] = skill
    for name in ("plugin.json", ".codex-plugin/plugin.json"):
        manifest = json.loads(files[name].read_text(encoding="utf-8"))
        validate_manifest(manifest)
        for relative in validate_references(manifest, plugin):
            files[relative] = plugin / relative
    if not any(name.startswith("skills/") for name in files):
        raise PackageError("package has no skills")
    validate_names(list(files))
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        raise PackageError(f"missing package files: {missing}")
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="ZIP path to write")
    args = parser.parse_args(argv)
    try:
        files = collect()
    except PackageError as exc:
        print(f"build_codex_plugin_zip: {exc}", file=sys.stderr)
        return 1
    write_zip(files, args.output)
    print(f"wrote {args.output} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
