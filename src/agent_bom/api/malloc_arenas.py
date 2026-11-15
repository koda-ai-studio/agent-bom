"""Cap glibc malloc arenas in the API process.

glibc gives each thread that allocates concurrently its own arena, up to eight
per CPU. The API runs ingest, current-graph builds, warm-ups and request
threads side by side; heap one thread frees stays in its arena, so the process
holds the high-water mark of every arena at once. On the small-self-hosted
workflow profile (glibc 2.39, Python 3.11, 2026-11-14) that was about 425 MiB
of a 1.8-1.9 GiB peak: two arenas held the peak at 1.40-1.52 GiB with the same
findings and fewer CPU-seconds.

Applied once when the API server module loads, before its worker threads
start. An operator's ``MALLOC_ARENA_MAX`` is honoured by glibc itself and left
alone. musl (the Alpine API image) and other C libraries are untouched.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import platform
from typing import Any

from agent_bom.core.settings import env_is_set

logger = logging.getLogger(__name__)

#: ``M_ARENA_MAX`` from glibc's ``<malloc.h>``.
M_ARENA_MAX = -8
API_MALLOC_ARENAS = 2

#: ``None`` until the server module applies the cap; then whether it took effect.
APPLIED: bool | None = None


def _glibc() -> Any | None:
    if platform.system() != "Linux" or platform.libc_ver()[0] != "glibc":
        return None
    try:
        return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
    except OSError:
        return None


def limit_malloc_arenas() -> bool:
    """Set ``M_ARENA_MAX`` to :data:`API_MALLOC_ARENAS`; True when glibc accepted it."""
    if env_is_set("MALLOC_ARENA_MAX"):
        return False
    libc = _glibc()
    if libc is None:
        return False
    accepted = bool(libc.mallopt(M_ARENA_MAX, API_MALLOC_ARENAS))
    if not accepted:
        logger.debug("glibc refused M_ARENA_MAX=%d", API_MALLOC_ARENAS)
    return accepted


def apply_api_malloc_tuning() -> bool:
    """Apply the arena cap once per process."""
    global APPLIED
    if APPLIED is None:
        APPLIED = limit_malloc_arenas()
    return APPLIED


__all__ = ["API_MALLOC_ARENAS", "APPLIED", "M_ARENA_MAX", "apply_api_malloc_tuning", "limit_malloc_arenas"]
