"""Bounded retention for the current-estate projection cache.

The API keeps one rebuildable SQLite projection per backing store under
``<state dir>/current-estate-cache``. Every distinct backing-store locator
(a SQLite path or a Postgres URL) mints a new file and nothing in the read
path ever retires an old one, so dev and test databases accumulate caches
indefinitely. The sweep here keeps the newest few, drops the rest by age,
and never touches the projection the calling process is about to use.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from agent_bom import config
from agent_bom.core.settings import env_raw
from agent_bom.storage.state_home import state_dir

logger = logging.getLogger(__name__)

CACHE_DIRNAME = "current-estate-cache"
_SIBLING_SUFFIXES = ("-wal", "-shm")
_DAY_SECONDS = 86_400.0


def cache_directory() -> Path:
    return state_dir() / CACHE_DIRNAME


def sqlite_locator(db_path: str | Path) -> str:
    return "sqlite:" + str(Path(db_path).expanduser().resolve())


def postgres_locator() -> str:
    return "postgres:" + (env_raw("AGENT_BOM_POSTGRES_URL") or env_raw("AGENT_BOM_DB") or "").strip()


def configured_locator(sqlite_db_path: str | Path) -> str:
    """The locator the API would project for the backing store its environment selects."""
    if (env_raw("AGENT_BOM_POSTGRES_URL") or "").strip():
        return postgres_locator()
    if (env_raw("AGENT_BOM_DB") or "").strip().lower().startswith(("postgres://", "postgresql://")):
        return postgres_locator()
    return sqlite_locator(sqlite_db_path)


def cache_path_for(locator: str) -> Path:
    digest = hashlib.sha256(json.dumps(locator, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()
    return cache_directory() / f"{digest[:24]}.db"


def cache_files(path: Path) -> list[Path]:
    """The projection file and the WAL siblings SQLite keeps beside it."""
    return [path, *(Path(f"{path}{suffix}") for suffix in _SIBLING_SUFFIXES)]


def cache_bytes(path: Path) -> int:
    total = 0
    for member in cache_files(path):
        try:
            total += member.stat().st_size
        except OSError:
            continue
    return total


def last_used(path: Path) -> float:
    """Newest modification time across the file and its WAL siblings.

    Raises OSError when the projection file itself cannot be stat'ed, so a
    caller never decides the fate of a file it could not inspect.
    """
    newest = path.stat().st_mtime
    for sibling in cache_files(path)[1:]:
        try:
            newest = max(newest, sibling.stat().st_mtime)
        except OSError:
            continue
    return newest


def sweep_projection_cache(
    directory: Path,
    *,
    active: Path | None,
    keep_latest: int,
    max_age_days: int,
    now: float | None = None,
    dry_run: bool = False,
) -> list[Path]:
    """Return the stale ``*.db`` projections removed (or, when *dry_run*, that would be).

    The newest *keep_latest* files by last use always stay; anything beyond
    them, or older than *max_age_days* (``<= 0`` disables the age rule), goes
    along with its ``-wal``/``-shm`` siblings. *active* is never removed. A
    file that cannot be inspected or deleted is left in place and not reported.
    """
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    resolved_active = active.resolve() if active is not None else None
    stamped: list[tuple[float, Path]] = []
    for path in entries:
        if path.suffix != ".db":
            continue
        try:
            if path.is_file():
                stamped.append((last_used(path), path))
        except OSError:
            logger.debug("projection cache sweep skipped an unreadable file")
    stamped.sort(key=lambda item: item[0], reverse=True)
    moment = time.time() if now is None else now
    cutoff = moment - max_age_days * _DAY_SECONDS if max_age_days > 0 else None
    removed: list[Path] = []
    for index, (used, path) in enumerate(stamped):
        if resolved_active is not None and path.resolve() == resolved_active:
            continue
        if index < max(keep_latest, 0) and (cutoff is None or used >= cutoff):
            continue
        if dry_run or _remove(path):
            removed.append(path)
    return removed


def sweep_sibling_projections(active: Path) -> None:
    """Sweep the cache directory *active* lives in with the configured bounds; never raises."""
    try:
        sweep_projection_cache(
            active.parent,
            active=active,
            keep_latest=config.CURRENT_ESTATE_CACHE_KEEP_LATEST,
            max_age_days=config.CURRENT_ESTATE_CACHE_MAX_AGE_DAYS,
        )
    except Exception:  # noqa: BLE001  # broad-except: cache hygiene must never block store construction
        logger.debug("current-estate projection cache sweep failed")


def _remove(path: Path) -> bool:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        logger.debug("projection cache sweep could not remove a stale file")
        return False
    for sibling in cache_files(path)[1:]:
        try:
            sibling.unlink(missing_ok=True)
        except OSError:
            logger.debug("projection cache sweep could not remove a WAL sibling")
    return True
