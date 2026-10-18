"""The pairing state machine.

    PENDING --claim--> CLAIMED --approve--> APPROVED --collect--> COLLECTED
       |                  |  \\--deny--> DENIED
       +------ (time) ----+--------------------------> EXPIRED

Each device proves which side it is with a private key it received when it
joined: the shower gets ``shower_key`` from ``create_offer``, the scanner gets
``claimer_key`` from ``claim``. The QR secret alone is never enough to read an
offer or collect a grant, so a photo of the QR taken over someone's shoulder is
useless once the real phone has scanned it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from . import security
from .events import Event, EventBus
from .models import DeviceInfo, Grant, GrantTo, LinkedDevice, Offer, State
from .store import MemoryStore, Store

FINAL_EVENTS = frozenset({"collected", "denied", "expired"})

IssueGrant = Callable[[str, tuple[str, ...], LinkedDevice], Awaitable[Grant]]
RevokeGrant = Callable[[LinkedDevice], Awaitable[None]]


class PairingError(Exception):
    """``code`` is stable and safe to show; adapters map it to an HTTP status."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class PairingHooks:
    """The only two places pairkit touches the app's own auth."""

    issue_grant: IssueGrant
    revoke_grant: RevokeGrant | None = None


@dataclass
class PairingConfig:
    offer_ttl: timedelta = timedelta(minutes=2)
    collect_ttl: timedelta = timedelta(minutes=1)  # time to pick up a grant after approval
    allowed_scopes: frozenset[str] | None = None  # None = any scope
    watch_poll_s: float = 5.0  # how often a live stream re-checks expiry while idle
    claim_limiter: security.RateLimiter = field(default_factory=security.RateLimiter)


@dataclass(frozen=True)
class CreatedOffer:
    offer_id: str
    secret: str  # goes in the QR code
    shower_key: str  # stays on the showing device
    expires_at: datetime

    def qr_payload(self, base_url: str) -> str:
        """URL to encode in the QR. The secret sits in the fragment (#...), which
        browsers never send to servers, so it stays out of access logs."""
        return f"{base_url.rstrip('/')}#{self.secret}"


@dataclass(frozen=True)
class Claimed:
    offer_id: str
    claimer_key: str  # stays on the scanning device
    grant_to: GrantTo
    scopes: tuple[str, ...]
    shower: DeviceInfo  # shown on the phone: "Sign in on Chrome on Windows?"
    expires_at: datetime


@dataclass(frozen=True)
class OfferView:
    """What either party may see about an offer. Never contains secrets or the grant."""

    offer_id: str
    state: State
    grant_to: GrantTo
    scopes: tuple[str, ...]
    expires_at: datetime
    shower: DeviceInfo
    scanner: DeviceInfo | None


def _utcnow() -> datetime:
    return datetime.now(UTC)


class PairingService:
    def __init__(
        self,
        hooks: PairingHooks,
        store: Store | None = None,
        events: EventBus | None = None,
        config: PairingConfig | None = None,
        now: Callable[[], datetime] = _utcnow,
    ):
        self.hooks = hooks
        self.store: Store = store or MemoryStore()
        self.events = events or EventBus()
        self.config = config or PairingConfig()
        self.now = now

    # ---- shower side -----------------------------------------------------

    async def create_offer(
        self,
        grant_to: GrantTo | str,
        scopes: Iterable[str],
        shower: DeviceInfo,
        user_id: str | None = None,
    ) -> CreatedOffer:
        grant_to = GrantTo(grant_to)
        scopes = tuple(sorted(set(scopes)))
        if not scopes:
            raise PairingError("invalid_scopes", "at least one scope is required")
        allowed = self.config.allowed_scopes
        if allowed is not None and not set(scopes) <= allowed:
            raise PairingError("invalid_scopes", f"not allowed: {sorted(set(scopes) - allowed)}")
        if grant_to is GrantTo.SCANNER and not user_id:
            raise PairingError("not_allowed", "lending access to a scanner requires a signed-in shower")
        if grant_to is GrantTo.SHOWER and user_id:
            raise PairingError("not_allowed", "a signed-in device cannot ask to be signed in")

        secret, shower_key, now = security.new_secret(), security.new_secret(), self.now()
        offer = Offer(
            id=security.new_id(),
            grant_to=grant_to,
            scopes=scopes,
            state=State.PENDING,
            created_at=now,
            expires_at=now + self.config.offer_ttl,
            secret_hash=security.hash_secret(secret),
            shower_key_hash=security.hash_secret(shower_key),
            shower=shower,
            user_id=user_id,
        )
        await self.store.add_offer(offer)
        return CreatedOffer(offer.id, secret, shower_key, offer.expires_at)

    # ---- scanner side ----------------------------------------------------

    async def claim(
        self, secret: str, scanner: DeviceInfo, user_id: str | None = None, client_key: str = ""
    ) -> Claimed:
        if not self.config.claim_limiter.allow(client_key or scanner.ip or "anon"):
            raise PairingError("rate_limited", "too many attempts, wait a minute")
        offer = await self.store.find_offer_by_secret(security.hash_secret(secret or ""))
        if offer is None:
            raise PairingError("invalid", "this code is not valid")
        offer = await self._fresh(offer)
        if offer.state is State.EXPIRED:
            raise PairingError("expired", "this code has expired, refresh it")
        if offer.state is not State.PENDING:
            raise PairingError("already_used", "this code was already scanned")
        if offer.grant_to is GrantTo.SHOWER and not user_id:
            raise PairingError("not_allowed", "sign in on this device first")

        claimer_key = security.new_secret()
        updated = offer.evolve(
            state=State.CLAIMED,
            scanner=scanner,
            claimer_key_hash=security.hash_secret(claimer_key),
            user_id=offer.user_id if offer.grant_to is GrantTo.SCANNER else user_id,
        )
        if not await self.store.swap(offer, updated):
            raise PairingError("already_used", "this code was already scanned")
        await self._emit(updated, "claimed", scanner=scanner.describe())
        return Claimed(updated.id, claimer_key, updated.grant_to, updated.scopes, updated.shower, updated.expires_at)

    # ---- approver (whichever side has access) ----------------------------

    async def approve(self, offer_id: str, user_id: str) -> OfferView:
        offer = await self._approvable(offer_id, user_id)
        receiver = offer.scanner if offer.grant_to is GrantTo.SCANNER else offer.shower
        device = LinkedDevice(
            id=security.new_id(),
            user_id=user_id,
            scopes=offer.scopes,
            device=receiver or DeviceInfo(),
            linked_at=self.now(),
            via=offer.grant_to,
        )
        grant = await self.hooks.issue_grant(user_id, offer.scopes, device)
        updated = offer.evolve(
            state=State.APPROVED, grant=grant, device_id=device.id, expires_at=self.now() + self.config.collect_ttl
        )
        if not await self.store.swap(offer, updated):
            if self.hooks.revoke_grant:  # lost a race: take back what we just issued
                await self.hooks.revoke_grant(device)
            raise PairingError("conflict", "this pairing changed, try again")
        await self.store.put_device(device)
        await self._emit(updated, "approved")
        return self._view(updated)

    async def deny(self, offer_id: str, user_id: str) -> OfferView:
        offer = await self._approvable(offer_id, user_id)
        updated = offer.evolve(state=State.DENIED)
        if not await self.store.swap(offer, updated):
            raise PairingError("conflict", "this pairing changed, try again")
        await self._emit(updated, "denied")
        return self._view(updated)

    # ---- receiving side --------------------------------------------------

    async def collect(self, offer_id: str, key: str) -> Grant:
        """Hand the grant to the receiving device, exactly once."""
        offer = await self._get(offer_id)
        receiver_hash = offer.claimer_key_hash if offer.grant_to is GrantTo.SCANNER else offer.shower_key_hash
        if not security.matches(key, receiver_hash):
            raise PairingError("invalid", "not the receiving device")
        offer = await self._fresh(offer)
        if offer.state is State.EXPIRED:
            raise PairingError("expired", "this pairing has expired")
        if offer.state is not State.APPROVED or offer.grant is None:
            raise PairingError("wrong_state", f"pairing is {offer.state}")
        updated = offer.evolve(state=State.COLLECTED, grant=None)  # forget the token
        if not await self.store.swap(offer, updated):
            raise PairingError("already_used", "this grant was already collected")
        await self._emit(updated, "collected")
        return offer.grant

    # ---- either party ----------------------------------------------------

    async def status(self, offer_id: str, key: str) -> OfferView:
        offer = await self._fresh(await self._party(offer_id, key))
        return self._view(offer)

    async def watch(self, offer_id: str, key: str) -> AsyncIterator[Event]:
        """Events for one offer, starting with its current state, until it ends."""
        offer = await self._party(offer_id, key)
        async with self.events.subscribe(offer_id) as q:
            offer = await self._fresh(await self._get(offer_id))
            yield Event(offer.id, "state", {"state": offer.state.value})
            if offer.state.final:
                return
            # Events already queued are delivered in order even if the offer has
            # moved on since; the stream ends only after a final event.
            while True:
                if q.empty():
                    offer = await self._get(offer_id)
                    timeout = max(0.0, (offer.expires_at - self.now()).total_seconds())
                    try:
                        event = await asyncio.wait_for(
                            q.get(), timeout=min(timeout + 0.05, self.config.watch_poll_s)
                        )
                    except TimeoutError:
                        await self._fresh(await self._get(offer_id))  # publishes "expired" if due
                        continue
                else:
                    event = q.get_nowait()
                yield event
                if event.type in FINAL_EVENTS:
                    return

    # ---- linked devices --------------------------------------------------

    async def list_devices(self, user_id: str) -> list[LinkedDevice]:
        return [d for d in await self.store.list_devices(user_id) if d.active]

    async def revoke_device(self, device_id: str, user_id: str) -> LinkedDevice:
        device = await self.store.get_device(device_id)
        if device is None or device.user_id != user_id:
            raise PairingError("not_found", "no such device")
        if not device.active:
            return device
        revoked = replace(device, revoked_at=self.now())
        await self.store.put_device(revoked)
        if self.hooks.revoke_grant:
            await self.hooks.revoke_grant(revoked)
        return revoked

    # ---- internals -------------------------------------------------------

    async def _get(self, offer_id: str) -> Offer:
        offer = await self.store.get_offer(offer_id)
        if offer is None:
            raise PairingError("not_found", "no such pairing")
        return offer

    async def _party(self, offer_id: str, key: str) -> Offer:
        offer = await self._get(offer_id)
        if not (security.matches(key, offer.shower_key_hash) or security.matches(key, offer.claimer_key_hash)):
            raise PairingError("not_found", "no such pairing")  # don't reveal that it exists
        return offer

    async def _approvable(self, offer_id: str, user_id: str) -> Offer:
        offer = await self._fresh(await self._get(offer_id))
        if offer.user_id is None or offer.user_id != user_id:
            raise PairingError("not_found", "no such pairing")
        if offer.state is State.EXPIRED:
            raise PairingError("expired", "this pairing has expired")
        if offer.state is not State.CLAIMED:
            raise PairingError("wrong_state", f"pairing is {offer.state}")
        return offer

    async def _fresh(self, offer: Offer) -> Offer:
        """Expire lazily: any read past the deadline moves the offer to EXPIRED."""
        if offer.state.final or self.now() < offer.expires_at:
            return offer
        expired = offer.evolve(state=State.EXPIRED, grant=None)
        if await self.store.swap(offer, expired):
            if offer.state is State.APPROVED and offer.device_id:
                device = await self.store.get_device(offer.device_id)
                if device:  # approved but never collected: undo it
                    await self.revoke_device(device.id, device.user_id)
            await self._emit(expired, "expired")
            return expired
        return await self._get(offer.id)

    async def _emit(self, offer: Offer, type_: str, **data: Any) -> None:
        await self.events.publish(Event(offer.id, type_, data))

    @staticmethod
    def _view(offer: Offer) -> OfferView:
        return OfferView(
            offer.id, offer.state, offer.grant_to, offer.scopes, offer.expires_at, offer.shower, offer.scanner
        )
