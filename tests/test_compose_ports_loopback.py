"""Every shipped compose file publishes ports on loopback by default; exposing a service is an explicit operator choice."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = re.compile(r"^(?:127\.0\.0\.1|\$\{[A-Z_]+:-127\.0\.0\.1\}):")


def test_compose_ports_bind_loopback_by_default() -> None:
    exposed = []
    files = sorted(ROOT.glob("deploy/**/docker-compose*.yml")) + sorted(ROOT.glob("docker-compose*.yml"))
    assert files
    for path in files:
        services = (yaml.safe_load(path.read_text()) or {}).get("services") or {}
        for name, service in services.items():
            for port in (service or {}).get("ports") or []:
                if not LOOPBACK.match(str(port)):
                    exposed.append(f"{path.relative_to(ROOT)}: {name} {port}")
    assert exposed == []
