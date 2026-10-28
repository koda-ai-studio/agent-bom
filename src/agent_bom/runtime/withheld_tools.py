"""Gateway memory of tools withheld for poisoned descriptions.

The stdio proxy keeps ``session.withheld_tools`` for the life of one session.
The gateway relay has no session, so this registry remembers, per
``(tenant, upstream)``, which tool names ``--injection-mode enforce`` stripped
from a ``tools/list`` result, and lets the forwarding stage refuse a later
``tools/call`` made with a cached name. Entries expire (TTL) and the whole
registry is bounded (oldest entry evicted first), so a hostile catalog cannot
grow process memory. The registry is process-local: a replica that never saw
the poisoned listing does not refuse the call (it still inspects the result).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable, Iterable

MAX_WITHHELD_ENTRIES = 4096
DEFAULT_WITHHELD_TTL_SECONDS = 24 * 60 * 60
_MAX_KEY_PART = 512

_Key = tuple[str, str, str]


class WithheldToolRegistry:
    """Bounded TTL + LRU set of ``(tenant, upstream, tool)`` triples."""

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_WITHHELD_TTL_SECONDS,
        max_entries: int = MAX_WITHHELD_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = float(ttl_seconds)
        self._max = max(1, int(max_entries))
        self._clock = clock
        self._entries: OrderedDict[_Key, float] = OrderedDict()

    def __len__(self) -> int:
        self._expire()
        return len(self._entries)

    @staticmethod
    def _key(tenant_id: str, upstream: str, tool: str) -> _Key | None:
        parts = (str(tenant_id), str(upstream), str(tool))
        if any(not part or len(part) > _MAX_KEY_PART for part in parts):
            return None
        return parts

    def _expire(self) -> None:
        now = self._clock()
        while self._entries:
            key, expires_at = next(iter(self._entries.items()))
            if expires_at > now:
                break
            self._entries.popitem(last=False)

    def update(self, tenant_id: str, upstream: str, *, withheld: Iterable[str], clean: Iterable[str]) -> None:
        """Apply one inspected ``tools/list`` page: clean names are restored, withheld names (re)armed."""
        self._expire()
        for name in clean:
            key = self._key(tenant_id, upstream, name)
            if key is not None:
                self._entries.pop(key, None)
        expires_at = self._clock() + self._ttl
        for name in withheld:
            key = self._key(tenant_id, upstream, name)
            if key is None:
                continue
            self._entries.pop(key, None)
            self._entries[key] = expires_at
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def is_withheld(self, tenant_id: str, upstream: str, tool: str) -> bool:
        self._expire()
        key = self._key(tenant_id, upstream, tool)
        return key is not None and key in self._entries
