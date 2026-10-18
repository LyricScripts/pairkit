"""Live updates, so the desktop switches from "waiting for phone" the moment
the phone scans or approves. In-process implementation; with several server
processes, back it with Redis pub/sub behind the same two methods."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Event:
    offer_id: str
    type: str  # claimed | approved | denied | collected | expired
    data: dict[str, Any] = field(default_factory=dict)


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue[Event]]] = defaultdict(set)

    async def publish(self, event: Event) -> None:
        for q in list(self._subs.get(event.offer_id, ())):
            q.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self, offer_id: str) -> AsyncIterator[asyncio.Queue[Event]]:
        q: asyncio.Queue[Event] = asyncio.Queue()
        self._subs[offer_id].add(q)
        try:
            yield q
        finally:
            self._subs[offer_id].discard(q)
            if not self._subs[offer_id]:
                del self._subs[offer_id]
