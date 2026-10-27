"""Every AGENT_BOM_* env var the runtime writes must also be read somewhere.

A write-only flag looks like configuration but changes nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
_WRITE = re.compile(r'os\.environ(?:\[\s*"(AGENT_BOM_[A-Z0-9_]+)"\s*\]\s*=(?!=)|\.setdefault\(\s*"(AGENT_BOM_[A-Z0-9_]+)")')


def test_every_written_agent_bom_env_var_is_read() -> None:
    sources = [path.read_text(encoding="utf-8") for path in SRC.rglob("*.py")]
    written: set[str] = set()
    for text in sources:
        for match in _WRITE.finditer(text):
            written.add(match.group(1) or match.group(2))
    assert written, "pattern matched nothing; guard is broken"

    without_writes = [_WRITE.sub("", text) for text in sources]
    write_only = sorted(name for name in written if not any(f'"{name}"' in text for text in without_writes))
    assert write_only == [], f"env vars set but never read: {write_only}"
