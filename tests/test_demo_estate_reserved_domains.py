"""Demo identities live on reserved domains, and generated names are well formed.

The public demo must not name an identity that could belong to someone real.
Email-shaped principals (users, service accounts, owners) therefore use only
RFC 2606 / RFC 6761 reserved names. Provider API endpoints and documentation
links are protocol constants, not identities, and are not email-shaped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_bom.demo_estate.enterprise_composition import build_demo_estate

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
DEMO_SOURCES = (
    *sorted((SRC / "demo_estate").rglob("*.py")),
    *sorted((SRC / "demo_estate" / "data").glob("*.jsonl")),
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_RESERVED_TLDS = (".example", ".invalid", ".test", ".localhost")
_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


def _reserved(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return domain.endswith(_RESERVED_TLDS) or any(domain == d or domain.endswith("." + d) for d in _RESERVED_DOMAINS)


def test_reserved_domain_predicate():
    assert _reserved("northstar.example")
    assert _reserved("nh-ml-prod.iam.example")
    assert _reserved("mail.example.com")
    assert not _reserved("showcase-demo.iam.gserviceaccount.com")
    assert not _reserved("example.com.evil.io")


def test_demo_sources_use_only_reserved_identity_domains():
    offenders = sorted(
        f"{path.relative_to(SRC)}:{match.group(0)}"
        for path in DEMO_SOURCES
        for match in _EMAIL_RE.finditer(path.read_text())
        if not _reserved(match.group(1))
    )
    assert offenders == []


def test_built_demo_estate_uses_only_reserved_identity_domains():
    estate = build_demo_estate(tenant_id="default")
    blob = json.dumps([asset.model_dump() for asset in estate.assets], default=str)
    offenders = sorted({m.group(0) for m in _EMAIL_RE.finditer(blob) if not _reserved(m.group(1))})
    assert offenders == []


def test_generated_demo_names_have_no_empty_segments():
    estate = build_demo_estate(tenant_id="default")
    malformed = sorted(
        {value for asset in estate.assets for value in (asset.display_name, asset.native_id, asset.asset_id) if value and "--" in value}
    )
    assert malformed == []
