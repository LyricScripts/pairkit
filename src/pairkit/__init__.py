"""pairkit: QR-code device pairing for any app.

Use a phone as a camera for a desktop session, or sign a desktop in from a
phone (WhatsApp Web style), with one small, framework-free core.
"""

from .events import Event, EventBus
from .models import DeviceInfo, Grant, GrantTo, LinkedDevice, Offer, State
from .security import RateLimiter
from .service import (
    Claimed,
    CreatedOffer,
    OfferView,
    PairingConfig,
    PairingError,
    PairingHooks,
    PairingService,
)
from .store import MemoryStore, Store

__all__ = [
    "Claimed",
    "CreatedOffer",
    "DeviceInfo",
    "Event",
    "EventBus",
    "Grant",
    "GrantTo",
    "LinkedDevice",
    "MemoryStore",
    "Offer",
    "OfferView",
    "PairingConfig",
    "PairingError",
    "PairingHooks",
    "PairingService",
    "RateLimiter",
    "State",
    "Store",
]
__version__ = "0.1.0"
