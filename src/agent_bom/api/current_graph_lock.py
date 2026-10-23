"""In-process reader/writer lock over the current-estate projection."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from starlette.exceptions import HTTPException


class ProjectionLock:
    """Readers share the projection; resolve and retire are exclusive.

    A waiting writer blocks new readers so a steady read stream cannot starve a
    rebuild. A thread that already reads may read again, but it may not escalate:
    waiting for its own shared hold would deadlock, so that is a 409 instead.
    """

    def reading_here(self) -> bool:
        with self._cond:
            return bool(self._reads.get(threading.get_ident()))

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._reads: dict[int, int] = {}
        self._writer: int | None = None
        self._writer_depth = 0
        self._waiting_writers = 0

    @contextmanager
    def shared(self) -> Iterator[None]:
        me = threading.get_ident()
        with self._cond:
            if self._writer != me and not self._reads.get(me):
                while self._writer is not None or self._waiting_writers:
                    self._cond.wait()
            self._reads[me] = self._reads.get(me, 0) + 1
        try:
            yield
        finally:
            with self._cond:
                if self._reads[me] == 1:
                    del self._reads[me]
                    self._cond.notify_all()
                else:
                    self._reads[me] -= 1

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        me = threading.get_ident()
        with self._cond:
            if self._writer == me:
                self._writer_depth += 1
            else:
                if self._reads.get(me):
                    raise HTTPException(409, "Current estate changed during the read; restart the query.")
                self._waiting_writers += 1
                try:
                    while self._writer is not None or self._reads:
                        self._cond.wait()
                finally:
                    self._waiting_writers -= 1
                self._writer, self._writer_depth = me, 1
        try:
            yield
        finally:
            with self._cond:
                self._writer_depth -= 1
                if not self._writer_depth:
                    self._writer = None
                    self._cond.notify_all()
