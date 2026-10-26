"""Every place that downloads packages trusts only CA stores fixed for the emSign/eMudhra key compromise.

uv before 0.13.4 and pip before 26.2.2 bundle their own trust stores and keep
trusting the compromised intermediates even when the OS store is fixed;
certifi is fixed from 2026.10.19 (GHSA-6q48-6c7w-9gw2).
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
UV_FLOOR, PIP_FLOOR, CERTIFI_FLOOR = Version("0.13.4"), Version("26.2.2"), Version("2026.10.19")


def _files(*patterns: str) -> list[Path]:
    return sorted({path for pattern in patterns for path in ROOT.glob(pattern) if path.is_file()})


def test_images_build_with_a_fixed_uv() -> None:
    stale = []
    for path in _files("Dockerfile*", "deploy/**/Dockerfile*", "integrations/**/Dockerfile*"):
        for version in re.findall(r"ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)", path.read_text()):
            if Version(version) < UV_FLOOR:
                stale.append(f"{path.relative_to(ROOT)}: uv {version}")
    assert stale == []


def test_ci_installs_a_fixed_uv() -> None:
    stale = []
    for path in _files(".github/workflows/*.yml", ".github/actions/*/action.yml"):
        text = path.read_text()
        for match in re.finditer(r"setup-uv@[^\n]*\n(?:\s+with:\n)?(?:\s+\w[\w-]*:.*\n)*?\s+version:\s*[\"']?(\d+\.\d+\.\d+)", text):
            if Version(match.group(1)) < UV_FLOOR:
                stale.append(f"{path.relative_to(ROOT)}: uv {match.group(1)}")
    assert stale == []


def test_workflows_upgrade_pip_before_installing_with_it() -> None:
    unsafe = []
    for path in _files(".github/workflows/*.yml"):
        for line in path.read_text().splitlines():
            # `uv pip install` runs uv's own installer, covered by the uv floor above.
            if re.search(r"(?<!uv )\bpip install\b", line) and "pip>=" not in line and "--upgrade pip" not in line:
                text = path.read_text()
                if f"pip>={PIP_FLOOR}" not in text:
                    unsafe.append(f"{path.relative_to(ROOT)}: {line.strip()}")
    assert unsafe == []


def test_every_lockfile_resolves_a_fixed_certifi() -> None:
    stale = []
    for path in _files("uv.lock", "**/uv.lock"):
        if ".ci-local" in path.parts or "node_modules" in path.parts:
            continue
        for version in re.findall(r'name = "certifi"\nversion = "([^"]+)"', path.read_text()):
            if Version(version) < CERTIFI_FLOOR:
                stale.append(f"{path.relative_to(ROOT)}: certifi {version}")
    assert stale == []
