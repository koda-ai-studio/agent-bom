"""Scan-scoped memo for :func:`agent_bom.security.sanitize_text`.

Report building redacts the same package, layer and provenance strings once
per finding; an image with thousands of CVEs on one package otherwise repeats
identical regex work per finding. The memo lives in a ContextVar entered for
one scan, is bounded by the total characters of its inputs, and is cleared when
the scan ends, so no input string outlives the scan that produced it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

SANITIZE_TEXT_MEMO_CHAR_BUDGET = 8_000_000


class TextMemo(dict[tuple[str, int], str]):
    """Redaction results for one scan, bounded by the total characters of their inputs."""

    __slots__ = ("chars",)

    def __init__(self) -> None:
        super().__init__()
        self.chars = 0

    def remember(self, key: tuple[str, int], result: str) -> None:
        size = len(key[0])
        if self.chars + size <= SANITIZE_TEXT_MEMO_CHAR_BUDGET:
            self[key] = result
            self.chars += size


_SANITIZE_TEXT_MEMO: ContextVar[TextMemo | None] = ContextVar("agent_bom_sanitize_text_memo", default=None)


@contextmanager
def sanitize_text_memo() -> Iterator[TextMemo]:
    """Memoize text redaction until the outermost scan scope exits."""
    memo = _SANITIZE_TEXT_MEMO.get()
    if memo is not None:
        yield memo
        return
    memo = TextMemo()
    token = _SANITIZE_TEXT_MEMO.set(memo)
    try:
        yield memo
    finally:
        _SANITIZE_TEXT_MEMO.reset(token)
        memo.clear()


def memoized_text(value: object, max_len: int, compute: Callable[[object, int], str]) -> str:
    memo = _SANITIZE_TEXT_MEMO.get()
    if memo is None or type(value) is not str:
        return compute(value, max_len)
    key = (value, max_len)
    cached = memo.get(key)
    if cached is None:
        cached = compute(value, max_len)
        memo.remember(key, cached)
    return cached
