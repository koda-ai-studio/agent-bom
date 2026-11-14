"""The per-tenant promotion stamp every worker sharing a current-estate projection cache reads.

Its whole text is the promotion epoch (compared for equality). It also names
the promoted generation and the projection format it was built with, so a
restarted or sibling worker without an in-process cache can serve that
generation while a newer one builds.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from agent_bom.graph.adjacency_page import CURRENT_ESTATE_SCAN_PREFIX


def read_stamp(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def write_stamp(path: str, format_tag: str, identity: str) -> None:
    """Callers hold the promotion file lock; ``os.replace`` keeps lock-free reads whole."""
    staging = f"{path}.{os.getpid()}.{threading.get_ident()}"
    with open(staging, "w", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()}:{time.time_ns()}:{os.urandom(8).hex()} {format_tag} {identity}")
    os.replace(staging, path)


def promoted_id(epoch: str, format_tag: str) -> str:
    """The generation a stamp recorded; empty for a stamp from another projection format or release."""
    parts = epoch.split(" ")
    if len(parts) == 3 and parts[1] == format_tag and parts[2].startswith(CURRENT_ESTATE_SCAN_PREFIX):
        return parts[2]
    return ""
