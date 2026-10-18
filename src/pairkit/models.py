"""Data model for pairing.

Every pairing has three roles:

- the **shower** displays the QR code (usually a desktop),
- the **scanner** scans it (usually a phone),
- the **approver** is whichever of the two already has access.

``grant_to`` decides who ends up with new access:

- ``GrantTo.SCANNER``: the shower is signed in and lends limited access to the
  scanner ("use my phone as a camera for this desktop"). The shower approves.
- ``GrantTo.SHOWER``: the scanner is signed in and signs the shower in
  ("WhatsApp Web"). The scanner approves.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum


class GrantTo(StrEnum):
    SCANNER = "scanner"
    SHOWER = "shower"


class State(StrEnum):
    PENDING = "pending"  # QR shown, nobody has scanned it
    CLAIMED = "claimed"  # scanned, waiting for the approver
    APPROVED = "approved"  # approved, grant waiting to be collected
    COLLECTED = "collected"  # receiving device picked up its grant (final)
    DENIED = "denied"  # approver said no (final)
    EXPIRED = "expired"  # timed out (final)

    @property
    def final(self) -> bool:
        return self in (State.COLLECTED, State.DENIED, State.EXPIRED)


@dataclass(frozen=True)
class DeviceInfo:
    """What a device says about itself, shown to the approver before they approve."""

    label: str = ""  # e.g. "Chrome on Windows"
    user_agent: str = ""
    ip: str = ""

    def describe(self) -> str:
        return self.label or self.user_agent or "Unknown device"


@dataclass(frozen=True)
class Grant:
    """What the app's ``issue_grant`` hook returns: the access handed to the receiving device."""

    token: str
    expires_at: datetime | None = None
    data: dict = field(default_factory=dict)  # anything else the app wants to pass along


@dataclass(frozen=True)
class Offer:
    id: str
    grant_to: GrantTo
    scopes: tuple[str, ...]
    state: State
    created_at: datetime
    expires_at: datetime
    secret_hash: str  # hash of the QR secret; the secret itself is never stored
    shower_key_hash: str  # proves a request comes from the device showing the QR
    shower: DeviceInfo
    user_id: str | None = None  # who has access; set at creation or at claim
    scanner: DeviceInfo | None = None
    claimer_key_hash: str | None = None  # proves a request comes from the device that scanned
    grant: Grant | None = None  # held only until collected
    device_id: str | None = None  # linked-device record created on approval
    version: int = 0  # for compare-and-set in stores

    def evolve(self, **changes) -> Offer:
        return replace(self, version=self.version + 1, **changes)

    @property
    def receiver(self) -> str:
        return "scanner" if self.grant_to is GrantTo.SCANNER else "shower"


@dataclass(frozen=True)
class LinkedDevice:
    """A device that was granted access through pairing. Users can list and revoke these."""

    id: str
    user_id: str
    scopes: tuple[str, ...]
    device: DeviceInfo
    linked_at: datetime
    via: GrantTo
    revoked_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None
