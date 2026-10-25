"""Write the advisory-source catalog the screenshot and demo fixtures serve.

The catalog comes from ``CANONICAL_INTEL_SOURCES`` so the fixture lists the
same sources, names and terms the product reports. Feed-run receipts are
added by the fixture itself. ``--check`` fails when the file is stale.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "ui" / "fixtures" / "intel-sources.json"


def catalog() -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.intel_lookup import CANONICAL_INTEL_SOURCES

    return {
        "evidence": "Source catalog from agent_bom.intel_lookup.CANONICAL_INTEL_SOURCES; sync receipts are simulated by the fixture.",
        "sources": [
            {
                "source_id": s.source_id,
                "display_name": s.display_name,
                "tier": s.source_tier,
                "source_tier": s.source_tier,
                "kind": s.kind,
                "source_url": s.source_url,
                "homepage_url": s.homepage_url,
                "license_or_terms_url": s.license_or_terms_url,
                "license": s.license,
                "robots_policy": s.robots_policy,
                "crawl_delay_seconds": s.crawl_delay_seconds,
                "connector_type": s.connector_type,
                "enabled": s.enabled,
                "owner": s.owner,
                "parser_version": s.parser_version,
                "validation_status": s.validation_status,
                "support_status": s.support_status,
                "redistribution": s.redistribution,
                "description": s.description,
                "sync_meta_source": s.sync_meta_source,
            }
            for s in CANONICAL_INTEL_SOURCES
        ],
    }


def render() -> str:
    return json.dumps(catalog(), indent=2) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUTPUT.exists() or OUTPUT.read_text() != text:
            sys.stderr.write(f"{OUTPUT.relative_to(ROOT)} is stale; run python ui/scripts/generate-intel-sources-fixture.py\n")
            return 1
        return 0
    OUTPUT.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
