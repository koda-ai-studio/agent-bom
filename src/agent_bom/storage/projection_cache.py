"""Bounded retention for the current-estate projection cache.

The API keeps one rebuildable SQLite projection per backing store under
``<state dir>/current-estate-cache``. Every distinct backing-store locator
(a SQLite path or a Postgres URL) mints a new file and nothing in the read
path ever retires an old one, so dev and test databases accumulate caches
indefinitely. The sweep here keeps the newest few and drops the rest by age.

A store holds a shared advisory lock on ``<projection>.lease`` for its lifetime
and the sweep removes a file only under an exclusive lock on that marker, so a
projection in use by any live process is never removed. The operating system
drops the lock when a holder dies, so a crash leaves nothing to clean up by
hand. Where locks are unavailable the sweep removes nothing.
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from agent_bom import config
from agent_bom.core.file_lock import UNSUPPORTED_LOCK_ERRNOS, release_lock, try_exclusive_lock, try_shared_lock
from agent_bom.core.settings import env_raw
from agent_bom.storage.state_home import state_dir

logger = logging.getLogger(__name__)

CACHE_DIRNAME = "current-estate-cache"
_SIBLING_SUFFIXES = ("-wal", "-shm")
_LEASE_SUFFIX = ".lease"
_DAY_SECONDS = 86_400.0
# A sweep holds a marker exclusively only while it unlinks a few files.
_LEASE_WAIT_SECONDS = 5.0
_LEASE_RETRY_SECONDS = 0.01


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


def lease_path(path: Path) -> Path:
    """The marker a live store locks.

    It is separate from the projection because closing any descriptor on a
    SQLite file drops SQLite's own POSIX locks on it.
    """
    return Path(f"{path}{_LEASE_SUFFIX}")


class _Lease:
    """A held shared lock. Safe to release twice: a closed descriptor number may already be reused."""

    def __init__(self, fd: int) -> None:
        self._fd: int | None = fd
        self._guard = threading.Lock()

    def __call__(self) -> None:
        with self._guard:
            fd, self._fd = self._fd, None
        if fd is not None:
            release_lock(fd, exclusive=False)


def _no_lease() -> None:
    return None


def _on_current_marker(fd: int, marker: Path) -> bool:
    """False when a sweep unlinked the marker while this descriptor waited for its lock.

    Windows cannot unlink an open file, so only POSIX can reach that state.
    """
    if os.name == "nt":
        return True
    try:
        return os.path.samestat(os.fstat(fd), os.stat(marker))
    except FileNotFoundError:
        return False


def _open_marker(marker: Path) -> int | None:
    try:
        return os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
    except PermissionError:
        # Windows refuses to open a file another process is deleting.
        if os.name == "nt":
            return None
        raise


def acquire_projection_lease(path: Path, *, wait_seconds: float = _LEASE_WAIT_SECONDS) -> Callable[[], None]:
    """Hold *path* against every sweep until the returned callable runs.

    Waits out a sweep working on this file, then raises ``TimeoutError`` rather
    than use the file unprotected. Where the filesystem has no advisory locks
    the result holds nothing, which is safe because the sweep cannot lock there
    either and so removes nothing.
    """
    marker = lease_path(path)
    deadline = time.monotonic() + wait_seconds
    while True:
        fd = _open_marker(marker)
        if fd is not None:
            try:
                if try_shared_lock(fd) and _on_current_marker(fd, marker):
                    return _Lease(fd)
            except OSError as exc:
                release_lock(fd, exclusive=False)
                if exc.errno not in UNSUPPORTED_LOCK_ERRNOS:
                    raise
                logger.warning("Advisory file locks are unavailable for the projection cache; stale projections will not be swept")
                return _no_lease
            release_lock(fd, exclusive=False)
        if time.monotonic() >= deadline:
            raise TimeoutError(f"projection lease busy: {marker.name}")
        threading.Event().wait(_LEASE_RETRY_SECONDS)


def open_durable_projection(locator: str) -> tuple[Path, Callable[[], None]] | None:
    """Create and hold the private cache file for *locator*; None when it cannot be held.

    The lease comes before the file: a sweep in another process could otherwise
    remove the file between its creation and the lock.
    """
    path = cache_path_for(locator)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        release = acquire_projection_lease(path)
        try:
            os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
            os.chmod(path, 0o600)
        except OSError:
            release()
            raise
    except OSError:
        return None
    return path, release


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
    along with its siblings and marker. *active* and any file a live holder has
    leased are never removed. A file that cannot be inspected, locked or deleted
    is left in place and not reported, in a dry run too. A marker whose
    projection is gone is removed once nobody holds it; a dry run leaves it.
    """
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    resolved_active = active.resolve() if active is not None else None
    stamped: list[tuple[float, Path]] = []
    for path in entries:
        if path.name.endswith(f".db{_LEASE_SUFFIX}") and not dry_run:
            projection = path.with_name(path.name.removesuffix(_LEASE_SUFFIX))
            if not projection.exists():
                _reclaim(projection, dry_run=False)
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
        if _reclaim(path, dry_run=dry_run):
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


def _reclaim(path: Path, *, dry_run: bool) -> bool:
    """Remove *path*, or in a dry run confirm it could go; False while a holder has it or locks fail."""
    marker = lease_path(path)
    marker_existed = marker.exists()
    try:
        fd = os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        logger.debug("projection cache sweep could not open a lease marker")
        return False
    held = reclaimed = drop_marker = False
    try:
        held = try_exclusive_lock(fd)
        reclaimed = held and (dry_run or _remove(path))
        drop_marker = reclaimed and not (dry_run and marker_existed)
        # POSIX: unlink under the lock so a waiter finds its marker gone and reopens.
        if drop_marker and os.name != "nt":
            _discard(marker)
    except OSError:
        logger.debug("projection cache sweep could not lock a lease marker; leaving the file in place")
    finally:
        release_lock(fd, exclusive=held)
    # Windows: an open file cannot be unlinked. A store that opens the marker
    # after this release makes this unlink fail, so it cannot lose its marker.
    if drop_marker and os.name == "nt":
        _discard(marker)
    return reclaimed


def _discard(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.debug("projection cache sweep could not remove a companion file")


def _remove(path: Path) -> bool:
    """Delete a projection and its siblings. Callers hold its marker exclusively, so no store uses them."""
    try:
        path.unlink()
    except FileNotFoundError:
        # Another sweep or the store already removed it; absence is the goal.
        pass
    except OSError:
        logger.debug("projection cache sweep could not remove a stale file")
        return False
    marker = lease_path(path)
    # The stores' per-tenant promotion locks and stamps are named <projection>.<tenant digest>.{lock,epoch}.
    companions = [member for member in path.parent.glob(f"{glob.escape(path.name)}.*") if member != marker]
    for member in [*cache_files(path)[1:], *companions]:
        _discard(member)
    return True
