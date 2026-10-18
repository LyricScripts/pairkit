"""Storage interface and an in-memory implementation.

A production store (Redis, Postgres) implements the same four methods. The
important one is ``swap``: a compare-and-set on ``version``, so two requests
racing on the same offer (a double scan, approve vs. expiry) can never both
win.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from .models import LinkedDevice, Offer


class Store(Protocol):
    async def add_offer(self, offer: Offer) -> None: ...
    async def get_offer(self, offer_id: str) -> Offer | None: ...
    async def find_offer_by_secret(self, secret_hash: str) -> Offer | None: ...
    async def swap(self, old: Offer, new: Offer) -> bool:
        """Replace ``old`` with ``new`` only if the stored version still equals ``old.version``."""
        ...

    async def put_device(self, device: LinkedDevice) -> None: ...
    async def get_device(self, device_id: str) -> LinkedDevice | None: ...
    async def list_devices(self, user_id: str) -> list[LinkedDevice]: ...


class MemoryStore:
    """For tests and single-process apps. Data is lost on restart."""

    def __init__(self) -> None:
        self._offers: dict[str, Offer] = {}
        self._by_secret: dict[str, str] = {}
        self._devices: dict[str, LinkedDevice] = {}
        self._lock = asyncio.Lock()

    async def add_offer(self, offer: Offer) -> None:
        async with self._lock:
            self._offers[offer.id] = offer
            self._by_secret[offer.secret_hash] = offer.id

    async def get_offer(self, offer_id: str) -> Offer | None:
        return self._offers.get(offer_id)

    async def find_offer_by_secret(self, secret_hash: str) -> Offer | None:
        oid = self._by_secret.get(secret_hash)
        return self._offers.get(oid) if oid else None

    async def swap(self, old: Offer, new: Offer) -> bool:
        async with self._lock:
            current = self._offers.get(old.id)
            if current is None or current.version != old.version:
                return False
            self._offers[old.id] = new
            return True

    async def put_device(self, device: LinkedDevice) -> None:
        self._devices[device.id] = device

    async def get_device(self, device_id: str) -> LinkedDevice | None:
        return self._devices.get(device_id)

    async def list_devices(self, user_id: str) -> list[LinkedDevice]:
        return sorted(
            (d for d in self._devices.values() if d.user_id == user_id),
            key=lambda d: d.linked_at,
            reverse=True,
        )
