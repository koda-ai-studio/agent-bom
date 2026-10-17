"""Scheduling opportunities for bounded CPU batches on shared API workers."""

import time
from collections.abc import Iterable, Iterator
from typing import TypeVar

T = TypeVar("T")


def iter_with_handoffs(items: Iterable[T], *, enabled: bool = True) -> Iterator[T]:
    """Let the event loop and other workers run between five-record batches.

    A zero-duration sleep can immediately reacquire the interpreter lock. A
    short positive wait gives runnable peers a scheduling opportunity without
    adding workers or buffering another page. The OS may wait longer; this is
    not a latency guarantee. Callers retain their transaction and lease.
    """
    for index, item in enumerate(items):
        if enabled and index and index % 5 == 0:
            time.sleep(0.0001)
        yield item
